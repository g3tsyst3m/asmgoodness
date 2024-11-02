; Parse PEB and find kernel32
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
add rbx, r8                   ; Add defrerenced signature offset to kernel32 base. Store in RBX.
mov edx, [rbx+0x88]           ; Offset from PE32 Signature to Export Address Table
add rdx, r8                   ; RDX = kernel32.dll + RVA ExportTable = ExportTable Address
mov r10d, [rdx+0x14]          ; Number of functions
xor r11, r11                  ; Zero R11 before use
mov r11d, [rdx+0x20]          ; AddressOfNames RVA
add r11, r8                   ; AddressOfNames VMA


mov rcx, r10                      ; Set loop counter

mov rax, 0x00737365726464           ; ddress, 0 (include null byte)
push rax
mov rax, 0x41636F7250746547   ; GetProcA 
push rax
mov rax, rsp	
jmp kernel32findfunction

; Loop over Export Address Table to find WinApi names
kernel32findfunction: 
    jecxz FunctionNameNotFound    ; Loop around this function until we find WinExec
    xor ebx,ebx                   ; Zero EBX for use
    mov ebx, [r11+4+rcx*4]        ; EBX = RVA for first AddressOfName
    add rbx, r8                   ; RBX = Function name VMA / add kernel32 base address to RVA and get WinApi name
    dec rcx                       ; Decrement our loop by one, this goes from Z to A
   
    ; Load first 8 bytes of "LoadLibrary"
    mov r9, qword [rax]                ; R9 = "GetProcA"
    cmp [rbx], r9                      ; Compare first 8 bytes
    jnz kernel32findfunction            ; If not equal, continue loop
     
    ; Check next part for "aryA" (4 bytes)
    mov r9d, dword [rax + 8]           ; R9 = "ddress"
    cmp [rbx + 8], r9d                 ; Compare remaining part
    jz FunctionNameFound               ; If match, function found
	jnz kernel32findfunction

FunctionNameFound:
push rcx
jmp OrdinalLookupSetup

FunctionNameNotFound:
nop
nop
int3
int3

;=====================================================
;now, we use ordinals lookup to get the actual address
;=====================================================
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
   js getprocaddress

;======================================================
;execute the api(s)
;======================================================
   
getprocaddress:
; --- prepare to call GetProcAddress ---
; Prepare arguments for GetProcAddress:
pop r15                         ;temporary use
mov r12, r15                    ;save for permanent use
mov rdi, r8                     ; make a copy of kernel32 base address for future needs
mov rcx, r8                     ; RCX = handle to kernel32.dll (first argument)
; Load "LoadLibraryA" onto the stack
mov rax, 0x0041797261           ; aryA, 0 (include null byte)
push rax
mov rax, 0x7262694C64616F4C   ; LoadLibr 
push rax
mov rdx, rsp	                 ; RDX points to "LoadLibraryA" (second argument)
sub rsp, 0x30                    ; decimal 48 ( 3 x 16 bytes)
call r15                         ; Call GetProcAddress

add rsp, 0x30
mov r15, rax                     ;holds LoadLibraryA!

getexitprocess:
mov r14, r12                        ;temporary assignment of GetProcess handle
mov rcx, rdi                     ; RCX = handle to kernel32.dll (first argument)
; Load "LoadLibraryA" onto the stack
mov rax, 0x00737365           ; ess, 0 (include null byte)
push rax
mov rax, 0x636F725074697845   ; ExitProc 
push rax
mov rdx, rsp	                 ; RDX points to "LoadLibraryA" (second argument)
sub rsp, 0x30
call r14                         ; Call GetProcAddress

add rsp, 0x30
mov r14, rax                     ;holds ExitProcess!

loadlibraryloader:
mov rax, 0x006C6C              ; add "ll" string to RAX
push rax                       ; push RAX to stack
mov rax, 0x642E323372657375    ; Add "user32.d" string to RAX.
push rax                       ; Push RAX to stack
mov rcx, rsp                   ; Move a pointer to User32.dll into RCX.
;mov rcx, message
sub rsp, 0x30
call r15

mov rdi, rax                   ;holds User32

getMsgboxaddr:
; --- prepare to call GetProcAddress ---
; Prepare arguments for GetProcAddress:
mov rcx, rdi                     ; RCX = handle to user32.dll (first argument)
; Load "MessageBoxA" onto the stack
mov rax, 0x0                     ; Null terminate the string
push rax
mov rax, 0x41786F      ; Load "oxA" into RAX
push rax
mov rax, 0x426567617373654D      ; Load "MessageB" into RAX                  
push rax
mov rdx, rsp                     ; RDX points to "MessageBoxA" (second argument)
sub rsp, 0x28
call r12                         ; Call GetProcAddress

mov r15, rax
messageboxfinally: 
    mov rcx, 0                     ; hWnd = NULL (no owner window)
	mov rax, 0x006D                ;m, 0
	push rax
	mov rax, 0x3374737973743367    ;g3tsyst3
	push rax
	mov rdx, rsp            ; lpText = pointer to message
    
    mov r8, rsp                 ; lpCaption = pointer to title
    mov r9d, 0                      ; uType = MB_OK (OK button only)

    sub rsp, 0x30
    call r15                        ; Call MessageBoxA
	add rsp, 0x30
	
exitcleanly:
mov ecx, 0
call r14 ;ExitProcess