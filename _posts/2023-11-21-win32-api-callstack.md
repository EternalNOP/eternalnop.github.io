---
layout: single
classes: wide
title:  "Win32 API Callstack"
date:   2023-11-16 17:01:57 +0100
---

This blog post will walk through the complete call stack process of calling a Win32 API function and how it transitions to the low-level hard drive driver. This project is compiled with Visual Studio 2022 and run on a standard Windows 11 system.

The API function that will be tested is [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).

# The difference between CreateFileA and CreateFileW

In terms of using the Win32 API function, the only difference between the two is the lpFileName variable type. When specifying CreateFile in Visual Studio, it will default to the wide version of the function if there is an ANSII or Wide version. The Windows kernel works with wide characters so if you use CreateFileA, the contents of the lpFileName parameter will be converted to wide characters before the transition to kernel mode is made.

## CreateFileW

```cpp
HANDLE CreateFileW(
  [in]           LPCWSTR               lpFileName,
  [in]           DWORD                 dwDesiredAccess,
  [in]           DWORD                 dwShareMode,
  [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  [in]           DWORD                 dwCreationDisposition,
  [in]           DWORD                 dwFlagsAndAttributes,
  [in, optional] HANDLE                hTemplateFile
);
```

## CreateFileA

```cpp
HANDLE CreateFileA(
  [in]           LPCSTR                lpFileName,
  [in]           DWORD                 dwDesiredAccess,
  [in]           DWORD                 dwShareMode,
  [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  [in]           DWORD                 dwCreationDisposition,
  [in]           DWORD                 dwFlagsAndAttributes,
  [in, optional] HANDLE                hTemplateFile
);
```

The program that will be tested is minimalistic because the scope of this blog is to dive deep into the Win32 API call stack. The full path where the executable is executed on my local VM is C:\Users\Admin\Desktop\callstack.exe

```c
#include <Windows.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, int nCmdShow) {
    CreateFileW("test.txt", GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    
    return 0;
}
```

# Stepping through the process

[Microsoft documentation](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170) shows that the first four arguments of a function are stored in registers (they depend on the position and type of argument that is passed). In a left to right order the registers that are used are RCX, RDX, R8, and R9. From the screenshot, RCX and EDX (lower 32-bits of RDX) have values stored in them.

| Parameter | Register |
| --- | --- |
| 1 | RCX |
| 2 | RDX |
| 3 | R8 |
| 4 | R9 |

The first parameter to CreateFileW is lpFileName which will have the value of “test.txt”. If a full path is not specified, the current directory is where the file will be created. From the screenshot the string (wide char array), a lea instruction is used in order to load the address the string is located at into the RCX register. The second parameter is dwDesiredAccess which technically holds 2 values, GENERIC_READ (80000000) and GENERIC_WRITE (40000000). If both GENERIC_READ and GENERIC_WRITE are XOR’ed, the result is C0000000 which is the value that is stored in EDX via a mov instruction. Both r9d (lower 32-bits of r9) and r8d (lower 32-bits of r8) are XOR’ed with each other to zero out themselves. This makes sense for both the third and fourth parameters of CreateFileW that is 0 for dwShareMode and NULL for lpSecurityAttributes.

After all the instructions are stepped over, all the corresponding registers hold their respective values. RCX holds “test.txt”, RDX holds C000000, and both R8 and R9 are 0.

With the first 4 arguments of CreateFileW in their respective registers, the first CreateFileW can be called that is located in kernel32.dll. When CreateFileW for kernel32.dll is stepped into, it immediately calls another CreateFileW function that is located in kernelbase.dll.

![Disassembly of lpFileName](/assets/img/Win32-API-Callstack/disassemblylpFileName.png)

![lpFileName Stored in RCX](/assets/img/Win32-API-Callstack/regsitrylpFileName.png)

![CreateFileW Call in kernelbase.dll](/assets/img/Win32-API-Callstack/kernel32CreateFileW.png)

Decompiling kernel32.dll to find out what happens within that DLL’s CreateFileW shows that another CreateFileW function is called located in API-MS-WIN-CORE-FILE-L1-1-0.dll. PowerShell can be used to find out what this resolves to. To find out more information about what this library is (API Sets) I highly recommend you check out this SpecterOps blog post.

[https://posts.specterops.io/understanding-the-function-call-stack-f08b5341efa4](https://posts.specterops.io/understanding-the-function-call-stack-f08b5341efa4)

![Resolving kernelbase.dll CreateFileW](/assets/img/Win32-API-Callstack/kernelbaseResolve.png)

The API set resolves to kernelbase.dll which is where a lot of the initialization and preparation of the function begins.

![kernel32.dll CreateFileW Disassembly](/assets/img/Win32-API-Callstack/kernel32CreateFileWDisassembly.png)

The start of the implementation for CreateFileW starts with kernelbase.dll. Taking a step back to just focus on the callstack process for CreateFileW because reverse engineering every part of the application is out of scope for this topic. The function prepares to be transitioned to kernel mode by converting the lpFileName to its NT path name which ends up being “\\??\\C:\\Users\\Admin\\Desktop\\test.txt”, calling [SbSelectProcedure](http://undoc.airesoft.co.uk/ntdll.dll/SbSelectProcedure.php) within ntdll.dll. The next step is a little unusual which I haven’t seen before when looking at the standard Windows callstack process. In the past within kernelbase.dll, NtCreateFile is called within ntdll.dll, but now NtCreateFile is called within apphelp.dll. Current Microsoft symbols do not show for apphelp.dll but just by observing the disassembly and monitoring the registry values, a high-level overview can be found.

![Untitled](/assets/img/Win32-API-Callstack/apphelpUndocumentedFunctionCall.png)

What the called functions within apphelp.dll do is get the address for NtCreateFile from the address of ntdll.dll and store it within the RAX register. My knowledge of x64 assembly is poor at best so I am not going to attempt to reverse engineer what is entirely happening within apphelp.dll.

![apphelp.dll Storing ntdll.dll Address](/assets/img/Win32-API-Callstack/apphelpStoreNtdllAddress.png)

Another undocumented function within apphelp.dll is called that just jumps to the value stored within RAX, which is the address of NtCreateFile within ntdll.dll.

![apphelp.dll Call RAX Jump Function](/assets/img/Win32-API-Callstack/apphelpUndocumentedFunctionCall.png)

![apphelp.dll Function RAX Jump](/assets/img/Win32-API-Callstack/apphelpJmpRAX.png)

NtCreateFile is called by moving a decimal value into the EAX register. The value of EAX before syscall is called is the type of function that will be used after transitioning to kernel mode. The values for a lot of syscall values can be found here: [https://j00ru.vexillium.org/syscalls/nt/64/](https://j00ru.vexillium.org/syscalls/nt/64/). In this case the value of 55 is moved into the EAX register which corresponds to NtCreateFile.

![Disassembly of NtCreateFile Syscall](/assets/img/Win32-API-Callstack/ntCreateFileDisassembly.png)

The process so far is listed below

![Userland Callstack Process](/assets/img/Win32-API-Callstack/userlandCallstack.png)