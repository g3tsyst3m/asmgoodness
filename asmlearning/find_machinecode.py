import re

# Path to the assembly file
filename = "shellcodez.txt"

# Regular expression to match hex values in the format: space-hexvalue-space
pattern = r'\b([0-9a-f]{2})\b'

shellcode = []

with open(filename, "r") as file:
    for line in file:
        # Find all two-character hex matches
        matches = re.findall(pattern, line, re.IGNORECASE)
        
        if matches:
            # Convert matches to byte format and add them to shellcode list
            shellcode.extend(matches)

# Print the shellcode in separate lines for better readability
print("Shellcode:")
for i in range(0, len(shellcode), 20):  # Adjust number of bytes per line as needed
    print("    \"" + "".join(f"\\x{byte}" for byte in shellcode[i:i+20]) + "\"")
