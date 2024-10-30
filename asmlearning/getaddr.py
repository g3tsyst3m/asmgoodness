import ctypes

# Load kernel32.dll
baseApi = ctypes.WinDLL("user32.dll")

# Get the address of the desired API
apiaddr = baseApi.MessageBoxA

# Print the address
print(f"Address of Api: {hex(ctypes.cast(apiaddr, ctypes.c_void_p).value)}")
