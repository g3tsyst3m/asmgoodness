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

;https://github.com/ShiftMediaProject/VSNASM

main:

		; form new stack frame
		push ebp
		mov ebp, esp

		; allocate local variables and initialize them to 0
		sub esp, 0x1C
		xor eax, eax
		mov [ebp - 0x4], eax			; Kernel32 address
		mov [ebp - 0x8], eax			; GetProcessAddress
		mov [ebp - 0xC], eax			; WinExec
		mov [ebp - 0x10], eax			; ExitProcess
	
	;Finding base address of kernel32.dll
 
	xor ecx,ecx
	mov eax,[fs:0x30] ;loading PEB(Process Environment Block) in Eax 
	mov eax,[eax+0xc] ;Eax=PEB->Ldr
	mov esi,[eax+0x14] ;Eax=Peb->Ldr.InMemOrderModuleList
	lodsd ;Loads ESI into Eax=second module of InMemOrderModuleList (ntdll.dll)
	xchg eax,esi ;Eax=Esi ,Esi=Eax
	lodsd ;Eax=third module of InMemOrderModuleList (kernel32.dll)
	mov ebx,[eax+0x10] ;Ebx=base Address of Kernel32.dll (PVOID Dllbase)

	;Finding Export table of Kernel32.dll
 
	mov edx,[ebx+0x3c] ;(kernel32.dll base address+0x3c)=DOS->e_lfanew
	add edx,ebx ;(DOS->e_lfanew+base address of kernel32.dll)=PE Header
	mov edx,[edx+0x78] ;(PE Header+0x78)=DataDirectory->VirtualAddress
	add edx,ebx ; (DataDirectory->VirtualAddress+kernel32.dll base address)=Export table of kernel32.dll (IMAGE_EXPORT_DIRECTORY)
	mov esi,[edx+0x20] ;(IMAGE_EXPORT_DIRECTORY+0x20)=AddressOfNames
	add esi,ebx ; ESI=(AddressOfNames+kernel32.dll base address)=kernel32.dll AddressOfNames
	xor ecx,ecx
	

	;finding GetProcAddress function name
	;ESI holds offset
	Get_func:
 
	inc ecx ;Incrementing the Ordinal
	lodsd ;Get name Offset
	add eax,ebx ;(name offset+kernel32.dll base address)=Get Function name
	cmp dword [eax],0x50746547 ;GetP
	jnz Get_func
	cmp dword [eax+0x4],0x41636f72 ; rocA
	jnz Get_func
	cmp dword [eax+0x8],0x65726464 ; ddre
	jnz Get_func

	;finding the address of GetProcAddress
 
	mov esi,[edx+0x24] ;Esi=(IMAGE_EXPORT_DIRECTORY+0x24)=AddressOfNameOrdinals
	add esi,ebx ;(AddressOfNameOrdinals+base address of kernel32.dll)=AddressOfNameOrdinals of kernel32.dll
	mov cx,[esi+ecx*2] ;CX=Number of Function
	dec ecx
	mov esi,[edx+0x1c] ;(IMAGE_EXPORT_DIRECTORY+0x1c)=AddressOfFunctions
	add esi,ebx ;ESI=beginning of Address table
	mov edx,[esi+ecx*4] ;EDX=Pointer(offset)
	add edx,ebx ;Edx=Address of GetProcAddress

	;backup address of GetProcAddress
	mov [ebp-0x8], edx
	;backing up kernel32.dll base address
	mov [ebp-0x4], ebx

	jmp short wexecstr
        retwexec:
        pop edx                           ; WinExec string
        push edx                          ; push 2nd param (WinExec) GetProcAddress(, "WinExec");
        mov ecx, [ebp-0x4]               ; grab Kernel32 address
        push ecx						  ;push kernel32 as 1st param GetProcAddress(&Kernel32, "WinExec");
		mov ecx, [ebp-0x8]               ; ; grab GetProcAddress
        call ecx                          ; eax now holds address of WinExec Function
        mov [ebp-0xC], eax               ; store Winexec addr for retrieval later


	jmp short cmdstr
		cmdstrret:
		pop ecx							;cmd.exe string
		xor edx,edx
		mov ebx, [ebp-0xC]				; WinExec function address
		push edx						; 2nd param, 0
		push ecx						; cmd.exe
		call ebx						;WinExec("cmd.exe", 0);
		
	jmp short exitprocstr
        exitprocret:
        pop edx                           ; ExitProcess string
        push edx                          ; push 2nd param (ExitProcess) GetProcAddress(, "ExitProcess");
        mov ecx, [ebp-0x4]               ; grab Kernel32 address
        push ecx						  ;push kernel32 as 1st param GetProcAddress(&Kernel32, "ExitProcess");
		mov ecx, [ebp-0x8]               ; ; grab GetProcAddress
        call ecx                          ; eax now holds address of ExitProcess Function
        mov [ebp-0x10], eax               ; store ExitProcess addr for retrieval later

		xor eax,eax
		push eax						; push 0
		mov ebx, [ebp-0x10]				; load ExitProcess Address
		call ebx						; call ExitProcess

	exitprocstr:
        call exitprocret
        db "ExitProcess"
        db 0x00
	cmdstr:
        call cmdstrret
        db "cmd.exe"
        db 0x00
	wexecstr:
        call retwexec
        db "WinExec"
        db 0x00

