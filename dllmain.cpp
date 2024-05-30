#include <Windows.h>
#include "Console.h"

// Access the Instruction Pointer Register in 32 and 64 bit architectures
#if _WIN64
#define instr_ptr Rip
#else
#define instr_ptr Eip
#endif

Console console;

// Store the original address of the function
UINT_PTR func_addr = (UINT_PTR)&MessageBoxW;

// Store the old opcode that we will replace with 0xCC
CHAR original_opcode = 0;

CHAR overwrite_opcode(PCHAR address, CHAR new_opcode)
{
	// Change the protection so we can overwrite the pointer, store the old protection
	DWORD old_protection{};
	VirtualProtect(address, 1, PAGE_READWRITE, &old_protection);

	// Overwrite the address with a pointer to another function
	CHAR old_opcode = *address;
	*address = new_opcode;

	// Restore the old protection
	VirtualProtect(address, 1, old_protection, &old_protection);

	return old_opcode;
}

int WINAPI hookedMessageBox(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	fprintf(console.stream, "Executing hook function\n");

	// Execute the true function from the hook with changed arguments
	// The true function still has the changed byte (0xCC) at its start
	// - we can temporarily change the byte back to the original byte
	original_opcode = overwrite_opcode((PCHAR)func_addr, original_opcode);

	LPCTSTR lpCaptionChanged = L"Hooked MessageBox";
	int retval = MessageBoxW(hWnd, lpText, lpCaptionChanged, uType);

	original_opcode = overwrite_opcode((PCHAR)func_addr, original_opcode);

	return retval;
}

// Used to pass to the Structured/Vectored Exception Handler
LONG WINAPI ExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo)
{
	// Check if the ExceptionFilter caught the exception of the INT3 opcode or another unrelated exception
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		// Check if the address of the exception matches the address of the hooked function
		if ((UINT_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress == func_addr)
		{
			fprintf(console.stream, "Breakpoint hit, replacing the instruction pointer ...\n");

			// Use the ContextRecord to view/modify the arguments of the hooked function
			PCONTEXT debug_context = ExceptionInfo->ContextRecord;

			// deviate the execution of the program to the hook function
			debug_context->instr_ptr = (UINT_PTR)hookedMessageBox;

			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

LPCSTR module_name = "user32.dll";
LPCSTR function_name = "MessageBoxW";

DWORD WINAPI testHook(PVOID base)
{
	fprintf(console.stream, "Testing the hook ...\n");
	MessageBoxW(NULL, L"Testing the hook", L"Testing", MB_OK);
	return 0;
}

// When using the Vectored Exception Handler, this is used to remove the VEH
// (unused when using SEH instead)
PVOID VEH_Handle = nullptr;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		// The DisableThreadLibraryCalls function lets a DLL disable the DLL_THREAD_ATTACH and DLL_THREAD_DETACH notification calls.
		//  This can be a useful optimization for multithreaded applications that have many DLLs, frequently createand delete threads,
		//  and whose DLLs do not need these thread - level notifications of attachment/detachment.
		DisableThreadLibraryCalls(hModule);

		if (!console.open())
		{
			// Indicate DLL loading failed
			return FALSE;
		}

		// replace the opcode at the start of the true function
		original_opcode = overwrite_opcode((PCHAR)func_addr, (CHAR)0xCC);

		fprintf(console.stream, "Setting Exception Filter.\n");
		// Set the Exception Handler (choose SEH or VEH!)
		SetUnhandledExceptionFilter(ExceptionFilter);
		// VEH_Handle = AddVectoredExceptionHandler(1, ExceptionFilter);

		// Test: open a MessageBox
		CreateThread(nullptr, NULL, testHook, hModule, NULL, nullptr);
	}

	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
	{
		fprintf(console.stream, "Uninstalling the hook ...\n");

		// Remove the Exception Handler (choose SEH or VEH!)
		SetUnhandledExceptionFilter(NULL);
		// RemoveVectoredExceptionHandler(VEH_Handle);

		overwrite_opcode((PCHAR)func_addr, original_opcode);

		// Open a MessageBox to allow reading the output
		MessageBoxW(NULL, L"Press Ok to close", L"Closing", NULL);
	}
	}
	return TRUE;
}
