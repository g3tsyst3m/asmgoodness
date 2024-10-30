# 1. Define C# code in PowerShell to call GetModuleHandle and GetProcAddress
Add-Type @"
using System;
using System.Runtime.InteropServices;

public class WinAPI {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
}
"@

# 2. Get the base address of kernel32.dll
$kernel32Base = [WinAPI]::GetModuleHandle("kernel32.dll")
if ($kernel32Base -eq [IntPtr]::Zero) { throw "Failed to get Kernel32.dll base address!" }

# 3. Get the address of GetProcAddress in kernel32.dll
$getProcAddressAddr = [WinAPI]::GetProcAddress($kernel32Base, "GetProcAddress")
if ($getProcAddressAddr -eq [IntPtr]::Zero) { throw "Failed to get GetProcAddress address!" }

# 4. Get the address of WinExec in kernel32.dll
$winExecAddr = [WinAPI]::GetProcAddress($kernel32Base, "WinExec")
if ($winExecAddr -eq [IntPtr]::Zero) { throw "Failed to get WinExec address!" }

# 5. Format addresses to hexadecimal strings for NASM
$kernel32BaseHex = $kernel32Base.ToInt64().ToString("X")
$getProcAddressAddrHex = $getProcAddressAddr.ToInt64().ToString("X")
$winExecAddrHex = $winExecAddr.ToInt64().ToString("X")

# Output the addresses (for debugging, you can remove this if not needed)
Write-Host "Kernel32.dll Base Address: 0x$kernel32BaseHex"
Write-Host "GetProcAddress Address: 0x$getProcAddressAddrHex"
Write-Host "WinExec Address: 0x$winExecAddrHex"

# 6. Prepare NASM x64 assembly code that will use the addresses dynamically
$assemblyCode = @"
section .data
    winexec_addr dq 0x$winExecAddrHex
    getproc_addr dq 0x$getProcAddressAddrHex
    kernel32_base dq 0x$kernel32BaseHex

section .text
    global _start

_start:
    ; Load the address of WinExec into rax
    mov rax, [winexec_addr]

    ; Prepare arguments for WinExec
    mov rcx, message ; Pointer to command ("notepad.exe")
    mov rdx, 1       ; uCmdShow (SW_SHOWNORMAL)

    ; Call WinExec
    call rax

    ; Exit process after execution
    mov rax, 60      ; syscall: exit
    xor rdi, rdi     ; status 0
    syscall          ; invoke syscall

section .data
    message db 'notepad.exe', 0
"@

# 7. Save the assembly code to a file
$asmFile = "exec.asm"
Set-Content -Path $asmFile -Value $assemblyCode

# 8. Assemble the code with NASM
$binaryFile = "exec.o"
nasm -f win64 -o $binaryFile $asmFile

# 9. Link the object file into an executable
$executable="execnotepad"
ld -m i386pep -o $executable $binaryFile
objdump -M intel -d $executable

# 10. Execute the file from PowerShell
Start-Process -FilePath $executable
