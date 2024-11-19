BITS 64
SECTION .text
global main
main:
    sub rsp, 0x28             ; Allocate space on the stack for local variables
    and rsp, 0xFFFFFFFFFFFFFFF0 ; Align rsp to 16-byte boundary

    ; Push the first string "CreateProcessA" onto the stack
    mov rax, 0x909041737365636F    ; 'ocessA'
    shl rax, 0x10                 ; 0000000073736500
    shr rax, 0x10                 ; 0000000000737365
    push rax                      ; Stack: 'Create' (low byte) -> 0x73736563
    mov rax, 0x7250657461657243    ; 'CreatePr'
    push rax                      ; Stack: 'CreateProcessA'
    mov rdi, rsp                  ; RDI points to "CreateProcessA"

    ; Push the second string "CreateProcessW" onto the stack
    mov rax, 0x909057737365636F    ; 'ocessW'
    shl rax, 0x10                 ; 0000000073736500
    shr rax, 0x10                 ; 0000000000737365
    push rax                      ; Stack: 'Create' (low byte) -> 0x73736563
    mov rax, 0x7250657461657243    ; 'CreatePr'
    push rax                      ; Stack: 'CreateProcessW'
    mov rbx, rsp                  ; RBX points to "CreateProcessW"

    ; Call the compare loop
    call compare_loop

xor rcx, rcx   ; Clear RCX (counter)
xor rdx, rdx   ; Clear RDX (no reason to clear, just for sanity)

compare_loop:
    ; Load the current byte from both strings
    movzx rdx, byte [rdi]  ; Load current byte of string A into RDX
    movzx r8, byte [rbx]   ; Load current byte of string B into R8

    cmp dl, 0x0            ; Check if byte in string A is null (string terminator)
    je foundit                 ; If null, jump to the end of comparison

    cmp r8b, dl             ; Compare the byte in string A with byte in string B
    jne mismatch           ; If not equal, jump to mismatch handling

    ; If the bytes match, move to the next byte in both strings
    inc rdi                ; Move to the next byte in string A
    inc rbx                ; Move to the next byte in string B
    jmp compare_loop       ; Repeat the loop

foundit:
nop
nop
nop
int3

mismatch:
    xor r15, r15
    int3

