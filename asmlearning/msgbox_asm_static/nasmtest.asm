BITS 32

section .data
section .bss
section .text
  global main   ; must be declared for linker
;gcc download: https://winlibs.com/#download-release
;nasm download: https://www.nasm.us/
;nasm -f win32 -o example1.o example1.asm
;ld -m i386pe -o example1 example1.o
;objdump -M intel -d example1

;elf32_x86_64: ELF for x64-32, aka x32 — 32-bit x86-64 binaries
;elf_i386: ELF for i386 — 32-bit i386 binaries
;i386linux: a.out for i386
;i386pep: PE+ for x86-64 — Windows-format 64-bit binaries
;i386pe: PE for i386 — Windows-format 32-bit binaries

;https://github.com/ShiftMediaProject/VSNASM

;mov [ecx, [eax] moves the value pointed to by eax
;mov ecx, eax moves the address held by eax
;mov [ecx], eax moves the address held by eax into the value pointed to by ecx 

main:
        jmp short loadlibstring
        Retstringgained:
        pop edx                           ;string "user32.dll"

        mov ebx, 0x76D70910               ; be sure to update this! LoadLibraryA
        push edx                          ; User32.dll
        call ebx                          ; call LoadLibraryA - eax holds User32.dll
        mov [ebp-0x4], eax               ; store it for retrieval later

        jmp short msgboxstring
        retmsgboxstring:
        pop edx                           ; MessageBoxA string
        push edx                          ; push 2nd param (MessageBoxA) GetProcAddress(, "MessageBoxA");
        mov ecx, [ebp-0x4]               ; grab user32.dll address
        push ecx                          ; push 1st param, user32.dll address GetProcAddress(&User32Address, "MessageBoxA");
        mov eax, 0x76D58400               ; be suer to update this! getprocaddress
        call eax                          ; eax now holds address of MessageBoxA
        mov [ebp-0x8], eax               ; store it for retrieval later

        jmp short msgboxhey
        retmsgboxhey:
        pop ecx
        xor eax, eax
        mov ebx, [ebp-0x8]
        push eax
        push ecx
        push ecx
        push eax
        call ebx                        ; pop the messagebox
        
        endit:
        xor eax, eax
        push eax
        mov ebx, 0x76D66FB0             ;be sure to update this! ExitProcess
        call ebx

        msgboxstring:
            call retmsgboxstring
            db "MessageBoxA"
            db 0x00
		loadlibstring:
            call Retstringgained    
            db "User32.dll"
            db 0x00
		msgboxhey:
            call retmsgboxhey    
            db "ya did it!"
            db 0x00