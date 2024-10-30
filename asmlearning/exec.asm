;rcx: Used for the first parameter (lpApplicationName).
;rdx: Used for the second parameter (lpCommandLine).
;r8: Used for the third parameter (lpProcessAttributes).
;r9: Used for the fourth parameter (lpThreadAttributes).
;rax used for return values

;nasm -fwin64 exec.asm
;gcc exec.obj -o exec.exe


section .text
        global main
		;we'd use the below externs if we didn't have the hardcoded addresses
		;*********************************************************************
        ;extern printf 
		;extern WinExec
        ;extern exit
main:
        sub       rsp, 40 ;(0x28)
		mov       r14, 0x7ffa635bae20     ;r14 is random, i just decided to go with this one
        mov       rcx, message ;rcx for 1st
        call      r14

        section .data
message:
        db "User32.dll", 0
		
		
