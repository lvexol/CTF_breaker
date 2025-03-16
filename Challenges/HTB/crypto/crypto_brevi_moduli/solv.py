from pwn import *
from Crypto.PublicKey import RSA
from sympy import factorint
import sys
import os

def get_flag():
    e = 65537
    for _ in range(5):
        io.recvuntil(b'Round ')
        print(io.recvline().split()[0].decode())
        io.recvuntil(b'?\n')
        
        # Retrieve the RSA public key
        key = RSA.importKey(io.recvuntil(b'-----END PUBLIC KEY-----\n'))
        n, e = key.n, key.e
        
        # Factorize n using sympy
        factors = factorint(n)
        p, q = list(factors.keys())
        
        # Send the factors back
        io.sendlineafter(b'pumpkin = ', str(p).encode())
        io.sendlineafter(b'pumpkin = ', str(q).encode())
        
        # Receive the flag
        io.recvline()
        flag = io.recvline().strip().decode()
    
    return flag

def pwn():
    flag = get_flag()
    print(flag)

if __name__ == '__main__':
    if args.REMOTE:
        # Parse remote host and port from command-line arguments
        host_port = sys.argv[1].split(':')
        HOST = host_port[0]
        PORT = int(host_port[1])
        
        # Connect to the remote challenge server
        io = remote(HOST, PORT, level='error')
    else:
        # Switch to the local challenge directory and start the server process
        os.chdir('../challenge')
        io = process(['python3', 'server.py'], level='error')
    
    # Execute the pwn function
    pwn()

