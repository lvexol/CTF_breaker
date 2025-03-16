from Crypto.PublicKey import RSA
from sage.all import factor
from pwn import remote

HOST = "83.136.252.221"
PORT = 48398  # Use an integer for the port number

# Connect to the remote server
r = remote(HOST, PORT)

for i in range(5):
    r.recvuntil(b'Can you crack this pumpkin\xf0\x9f\x8e\x83?\n')
    
    # Receive and process the public key
    public_key = r.recvuntil(b"-END PUBLIC KEY-\n")
    public_key = RSA.import_key(public_key)
    
    # Factorize the modulus to get p and q
    p, q = factor(public_key.n)
    
    # Send the factors back to the server
    r.sendlineafter(b"enter your first pumpkin = ", str(int(p)).encode())
    r.sendlineafter(b"enter your second pumpkin = ", str(int(q)).encode())
    
    print(f"{i + 1} Round Complete!")
    r.recvline()
    
# Receive any remaining data
response = r.recv(1024)
print(response.decode())

