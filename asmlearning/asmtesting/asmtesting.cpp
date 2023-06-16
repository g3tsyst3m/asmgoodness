#include <iostream>
#include <windows.h>
#include <stdio.h>

/*
https://web.archive.org/web/20120106112542/http://projectshellcode.com/node/20
https://packetstormsecurity.com/files/137384/Windows-x86-WinExec-cmd.exe-0-Shellcode.html
https://www.prowaretech.com/articles/current/assembly/x86/tutorial/page-12
https://stackoverflow.com/questions/39968807/storing-dword-into-address
*/

int main()
{
    LPCSTR mycmd = "cmd.exe";
    
    HMODULE kernel32addr = LoadLibrary(TEXT("kernel32.dll"));
    printf("Kernel32 Address: 0x%p\n", kernel32addr);

    //HMODULE k2 = GetModuleHandle(L"ntdll.dll");
    //printf("0x%p\n", k2);
    FARPROC exitprocaddr=GetProcAddress(kernel32addr, "ExitProcess");
    printf("ExitProcess Address: 0x%p\n", exitprocaddr);
    FARPROC winexecaddr = GetProcAddress(kernel32addr, "WinExec");
    printf("WinExec Address: 0x%p\n", winexecaddr);

    FARPROC getprocaddr = GetProcAddress(kernel32addr, "GetProcAddress");
    printf("GetProcAddress Address: 0x%p\n", getprocaddr);

    FARPROC loadlibaddr = GetProcAddress(kernel32addr, "LoadLibraryA");
    printf("LoadLibrary Address: 0x%p\n", loadlibaddr);

    HMODULE user32addr = LoadLibrary(TEXT("user32.dll"));
    printf("User32 Address: 0x%p\n", user32addr);

    FARPROC msgboxaddr = GetProcAddress(user32addr, "MessageBoxA");
    printf("MessageBox Address: 0x%p\n", msgboxaddr);

    _asm
    {
        mov ebx, mycmd; ebx now points to the string

        xor eax, eax; empties out eax
        push eax; push null onto stack as empty parameter value
        push ebx; push the command string onto the stack
        mov ebx, winexecaddr; place address of WinExec into ebx
        call ebx; call WinExec(path, showcode)

        xor eax, eax; zero the register again to clear WinExec return value(return values are often returned into eax)
        push eax; push null onto stack as empty parameter value
        mov ebx, exitprocaddr; place address of ExitProcess into ebx
        call ebx; call ExitProcess(0);
               
    }
}

