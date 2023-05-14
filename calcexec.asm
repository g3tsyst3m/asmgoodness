;nasm -f win32 -o calcexec.o calcexec.asm
;ld -m i386pe -o calcasm.exe calcexec.o

;elf32_x86_64: ELF for x64-32, aka x32 — 32-bit x86-64 binaries
;elf_i386: ELF for i386 — 32-bit i386 binaries
;i386linux: a.out for i386
;i386pep: PE+ for x86-64 — Windows-format 64-bit binaries
;i386pe: PE for i386 — Windows-format 32-bit binaries
                        
section .data
section .bss
section .text
  global _start   ; must be declared for linker

_start:
  xor  ecx, ecx         ; zero out ecx
  push ecx              ; string terminator 0x00 for "cmd.exe" string
  push 0x6578652e       ; exe. : 6578652e
  push 0x646D63        ; cmd : 636c6163
  ;push 0x6578652e      ;.exe  
  ;push 0x636c6163      ;calc

  mov  eax, esp         ; save pointer to "calc.exe" string in eax

  ; UINT WinExec([in] LPCSTR lpCmdLine, [in] UINT   uCmdShow);
  inc  ecx              ; uCmdShow = 1
  push ecx              ; push uCmdShow *ptr to stack ex: WinExec("", --> 1);
  push eax              ; lpcmdLine *ptr to stack in 1st position ex: WinExec("cmd.exe" <--)
  mov  ebx, 0x76770590  ; call WinExec() function addr in kernel32.dll
  call ebx

  ; void ExitProcess([in] UINT uExitCode);
  xor  eax, eax         ; zero out eax
  push eax              ; push 0
  mov  eax, 0x76739560  ; call ExitProcess function addr in kernel32.dll
  call eax              ; execute the ExitProcess function