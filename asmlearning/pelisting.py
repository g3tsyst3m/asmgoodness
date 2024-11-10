import pefile

def list_exports(dll_path):
    # Load the DLL
    pe = pefile.PE(dll_path)

    # Check if the DLL has an export directory
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        base_ordinal = pe.DIRECTORY_ENTRY_EXPORT.struct.Base  # Use 'Base' instead of 'OrdinalBase'
        print("Ordinal | Function Name")
        print("------------------------")
        
        # Iterate over all exported symbols
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            # Adjust the ordinal to start from 0
            adjusted_ordinal = exp.ordinal - base_ordinal
            function_name = exp.name.decode() if exp.name else '<No Name>'
            print(f"{adjusted_ordinal} | {function_name}")
    else:
        print("No export directory found.")

# Replace 'user32.dll' with the path to your DLL
dll_path = "C:\\Windows\\System32\\kernel32.dll"
list_exports(dll_path)
