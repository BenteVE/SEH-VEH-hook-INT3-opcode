# Structered/Vectored Exception Handler hook

A demo of a Structured or Vectored Exception Handler (SEH/VEH) hook using INT3 opcode to trigger the exception.

## Structured/Vectored Exception Handler

Structured Exception Handling (SEH) is a mechanism for handling both hardware and software exceptions.
This enables applications to have complete control over the handling of exceptions and provides support for debuggers.
Vectored Exception Handling is an extension to Structured Exception Handling.

When an exception is raised, a list of ExceptionFilters will be traversed until a handler for that particular exception is found.
Once the ExceptionFilter is finished handling the exception, it can return control to the rest of the application.

## SEH/VEH hook

To install a SEH hook, we will first inject the DLL in this project using a [DLL injector](https://github.com/BenteVE/DLL-Injector).
This DLL contains a hook function, an ExceptionFilter and an installation function.

To install the hook, we can use `SetUnhandledExceptionFilter` for an SEH hook or `SetVectoredExceptionHandler` for a VEH hook.
In both cases, the ExceptionFilter can be the same.

Inside the ExceptionFilter, we can change instruction pointer in the `ContextRecord` to point to our hook function.
Once the ExceptionFilter is done, this will cause the program continue from that function.

![Demo](doc/SEH-hook.png)

Now we only need a way to trigger the exception when the target function is executed.
In this implementation we overwrite the first byte of the target function implementation with the INT3 opcode (0xCC).
When we now call the original function from inside the hook function, the exception would be triggered again and an infinite loop would start.
To avoid this, we will simply overwrite the restore the original byte at the start of the hook, and overwrite it again at the end.

The triggering and recovering from the exceptions can be accomplished in multiple different ways.
For some alternative implementations of a SEH/VEH hook, you can view:

- [SEH/VEH hook triggering exception with Debug Registers and recovering with an assembly trampoline](https://github.com/BenteVE/SEH-VEH-hook-Debug-Registers-Breakpoint)
- [SEH/VEH hook using Page Guard exceptions](https://github.com/BenteVE/SEH-VEH-hook-Page-Guard-Exception)

## Demo

In this particular implementation, we will hook the `MessageBoxW` function in the `user32.dll`.
The hook function will simply call the original function with a modified argument to replace the title.

1. Clone the repository:

    ```bash
    git clone https://github.com/BenteVE/SEH-VEH-hook-INT3-opcode.git
    ```

2. Build the DLL for the desired architecture (x86 or x64) using Visual Studio.
   The architecture of the DLL should match the architecture of the target program and the used DLL injector.

3. Use a DLL injector to inject the built DLL into the target process.
   The injector used here is available in another [repository](https://github.com/BenteVE/DLL-Injector) with a detailed explanation.

4. Trigger an action that uses a `MessageBox` in the target program to verify that the hook worked.
   For Notepad++, attempting to close an unsaved file does this:

    ![Demo](doc/demo.gif)
