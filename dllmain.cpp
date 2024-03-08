#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include "Console.h"

Console console;

// This stub function contains the first instruction of the function with the breakpoint
// => then the function jumps to the second instruction of the original function 
// => this way we execute every instruction of the original function without triggering another exception and an infinite loop
DWORD func_addr = NULL;
DWORD func_addr_offset = NULL;
void __declspec(naked) MessageBoxW_trampoline(void) {
	__asm {
		mov edi, edi
		jmp[func_addr_offset]
	}
	// Note: To find the first instruction of the hook function, you can use documentation (if available) or Ghidra
	// => Make sure you analyze the correct DLL (32-bit in SysWOW64 folder or 64-bit in System32 folder).
	// Note: it should also be possible to dynamically copy the instructions at func_addr instead of hardcoding it in assembly here
}

// print the content of the registers and the stack to the console 
void print_parameters(PCONTEXT debug_context) {
	fprintf(console.stream, "Registers:\n");
	fprintf(console.stream, "EAX: %X EBX: %X\n", debug_context->Eax, debug_context->Ebx);
	fprintf(console.stream, "ECX: %X EDX: %X\n", debug_context->Ecx, debug_context->Edx);
	fprintf(console.stream, "ESP: %X EBP: %X\n", debug_context->Esp, debug_context->Ebp);
	fprintf(console.stream, "ESI: %X EDI: %X\n", debug_context->Esi, debug_context->Edi);

	// ESP is the stack pointer, all parameters are on the stack
	// To find the parameters, you can use documentation (if available) or a decompiler like Ghidra.
	fprintf(console.stream, "Function parameters:\n");
	fprintf(console.stream, "HWND: %p\n", (HWND)(*(PDWORD)(debug_context->Esp + 0x4)));

	// MessageBoxW uses wide strings
	fwprintf(console.stream, L"lptext:    %s\n", (LPCWSTR)(*(PDWORD)(debug_context->Esp + 0x8)));
	fwprintf(console.stream, L"lpcaption: %s\n", (LPCWSTR)(*(PDWORD)(debug_context->Esp + 0xC)));

	fprintf(console.stream, "type: % X\n", (UINT)(*(PDWORD)(debug_context->Esp + 0x10)));
	// Example: 23h == MB_ICONQUESTION + MB_YESNOCANCEL
}

// Change the stack to update the caption shown in the MessageBox
LPCWSTR hook_caption = L"Hooked MessageBox";
void modify_stack(PCONTEXT debug_context) {
	DWORD oldProtection{};
	VirtualProtect((LPVOID)(debug_context->Esp + 0xC), sizeof(PDWORD), PAGE_READWRITE, &oldProtection);
	*(PDWORD)(debug_context->Esp + 0xC) = (DWORD)hook_caption;
	VirtualProtect((LPVOID)(debug_context->Esp + 0xC), sizeof(PDWORD), oldProtection, &oldProtection);
}


// Used to pass to the Structured/Vectored Exception Handler
LONG WINAPI ExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo) {
	// Check if the ExceptionFilter caught the 0xCC opcode exception or another unrelated exception
	// The 0xCC opcode causes an EXCEPTION_BREAKPOINT 
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
		// Check if the address of the exception matches the address of the hooked function
		if ((DWORD)ExceptionInfo->ExceptionRecord->ExceptionAddress == func_addr) {
			// Use the ContextRecord to view/modify the arguments of the hooked function
			PCONTEXT debug_context = ExceptionInfo->ContextRecord;
			fprintf(console.stream, "Breakpoint hit, reading registers and function parameters ...\n");
			print_parameters(debug_context);

			fprintf(console.stream, "Modifying parameters on stack\n");
			modify_stack(debug_context);

			fprintf(console.stream, "Using trampoling\n");
			debug_context->Eip = (DWORD)&MessageBoxW_trampoline;

			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

LPCSTR module_name = "user32.dll";
LPCSTR function_name = "MessageBoxW";

DWORD WINAPI testHook(PVOID base) {
	fprintf(console.stream, "Testing the hook ...\n");
	MessageBoxW(NULL, L"Testing the hook", L"Testing", MB_OK);

	return 0;
}

CHAR overwrite_address(PCHAR address, CHAR new_opcode) {
	// Change the protection so we can overwrite the pointer, store the old protection
	DWORD old_protection{};
	VirtualProtect(address, 1, PAGE_READWRITE, &old_protection);

	// Overwrite the address with the given opcode, store the old opcode to return
	CHAR old_opcode = *address;
	*address = new_opcode;

	// Restore the old protection
	VirtualProtect(address, 1, old_protection, &old_protection);

	return old_opcode;
}

// When using the Vectored Exception Handler, this is used to remove the VEH
// (unused when using SEH instead) 
PVOID VEH_Handle = nullptr;

// Store the original opcode to restore when unhooking
CHAR original_opcode = 0;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		//The DisableThreadLibraryCalls function lets a DLL disable the DLL_THREAD_ATTACH and DLL_THREAD_DETACH notification calls.
		// This can be a useful optimization for multithreaded applications that have many DLLs, frequently createand delete threads, 
		// and whose DLLs do not need these thread - level notifications of attachment/detachment.
		DisableThreadLibraryCalls(hModule);

		if (!console.open()) {
			// Indicate DLL loading failed
			return FALSE;
		}

		// Find the address of the true Function
		HMODULE h_module = GetModuleHandleA(module_name);
		if (h_module == NULL) {
			fprintf(console.stream, "Unable to retrieve handle for module %s\n", module_name);
			return FALSE;
		}
		func_addr = (DWORD)GetProcAddress(h_module, function_name);
		func_addr_offset = func_addr + 0x2; // jump over first instruction (instruction 'mov edi, edi' is 2 bytes long => view in Ghidra)

		// Replace the address with 0xCC opcode
		original_opcode = overwrite_address((PCHAR)func_addr, (CHAR)0xCC);

		fprintf(console.stream, "Setting Exception Filter.\n");
		// Set the Exception Handler (choose SEH or VEH!)
		SetUnhandledExceptionFilter(ExceptionFilter);
		//VEH_Handle = AddVectoredExceptionHandler(1, ExceptionFilter);

		// Test: also set for this thread and call function
		CreateThread(nullptr, NULL, testHook, hModule, NULL, nullptr);

	}

	case DLL_THREAD_ATTACH: break;
	case DLL_THREAD_DETACH: break;
	case DLL_PROCESS_DETACH: {
		fprintf(console.stream, "Uninstalling the hook ...\n");

		// Remove the Exception Handler (choose SEH or VEH!)
		SetUnhandledExceptionFilter(NULL);
		//RemoveVectoredExceptionHandler(VEH_Handle);

		// Replace the address with 0xCC opcode
		overwrite_address((PCHAR)func_addr, original_opcode);

		// Open a MessageBox to allow reading the output
		MessageBoxW(NULL, L"Press Ok to close", L"Closing", NULL);
	}
	}
	return TRUE;
}

