#!/usr/bin/env python3

import hashlib
import bcrypt
import argon2
import itertools
import string
import time
from concurrent.futures import ThreadPoolExecutor
from argparse import ArgumentParser
from typing import Optional
import os
from tqdm import tqdm

class HashCracker:
    def __init__(self):
        self.algorithms = {
            'md5': self._md5_hash,
            'sha256': self._sha256_hash,
            'sha512': self._sha512_hash,
            'bcrypt': self._bcrypt_hash,
            'argon2': self._argon2_hash
        }
        
        self.charset = {
            'lower': string.ascii_lowercase,
            'upper': string.ascii_uppercase,
            'digits': string.digits,
            'special': string.punctuation
        }
        
    def _md5_hash(self, password: str) -> str:
        return hashlib.md5(password.encode()).hexdigest()
    
    def _sha256_hash(self, password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()
    
    def _sha512_hash(self, password: str) -> str:
        return hashlib.sha512(password.encode()).hexdigest()
    
    def _bcrypt_hash(self, password: str) -> str:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    def _argon2_hash(self, password: str) -> str:
        ph = argon2.PasswordHasher()
        return ph.hash(password)
    
    def verify_hash(self, hash_type: str, password: str, hash_to_check: str) -> bool:
        if hash_type == 'bcrypt':
            try:
                return bcrypt.checkpw(password.encode(), hash_to_check.encode())
            except Exception:
                return False
        elif hash_type == 'argon2':
            try:
                ph = argon2.PasswordHasher()
                return ph.verify(hash_to_check, password)
            except Exception:
                return False
        else:
            generated_hash = self.algorithms[hash_type](password)
            return generated_hash == hash_to_check
    
    def dictionary_attack(self, hash_to_crack: str, hash_type: str, 
                         wordlist_path: str, num_threads: int = 4) -> Optional[str]:
        print(f"[*] Starting dictionary attack using {wordlist_path}")
        
        def check_word(word):
            word = word.strip()
            if self.verify_hash(hash_type, word, hash_to_crack):
                return word
            return None
        
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                words = f.readlines()
            
            with ThreadPoolExecutor(max_workers=num_threads) as executor:
                for result in tqdm(executor.map(check_word, words), total=len(words)):
                    if result:
                        return result
                        
        except FileNotFoundError:
            print(f"[-] Wordlist not found: {wordlist_path}")
            return None
            
        return None
    
    def brute_force_attack(self, hash_to_crack: str, hash_type: str, 
                          min_length: int = 1, max_length: int = 8,
                          char_sets: list = None) -> Optional[str]:
        if char_sets is None:
            char_sets = ['lower', 'digits']
            
        charset = ''.join(self.charset[char_set] for char_set in char_sets)
        print(f"[*] Starting brute-force attack with charset: {charset}")
        print(f"[*] Testing lengths from {min_length} to {max_length}")
        
        for length in range(min_length, max_length + 1):
            print(f"[*] Testing length {length}")
            for guess in tqdm(itertools.product(charset, repeat=length)):
                password = ''.join(guess)
                if self.verify_hash(hash_type, password, hash_to_crack):
                    return password
        
        return None

def main():
    parser = ArgumentParser(description="Advanced Password Hash Cracking Tool")
    parser.add_argument("--hash", required=True, help="Hash to crack")
    parser.add_argument("--type", required=True, 
                       choices=['md5', 'sha256', 'sha512', 'bcrypt', 'argon2'],
                       help="Hash algorithm type")
    parser.add_argument("--mode", required=True,
                       choices=['dictionary', 'bruteforce'],
                       help="Attack mode")
    parser.add_argument("--wordlist", help="Path to wordlist for dictionary attack")
    parser.add_argument("--min-length", type=int, default=1,
                       help="Minimum length for brute force attack")
    parser.add_argument("--max-length", type=int, default=8,
                       help="Maximum length for brute force attack")
    parser.add_argument("--charset", nargs='+',
                       choices=['lower', 'upper', 'digits', 'special'],
                       default=['lower', 'digits'],
                       help="Character sets to use for brute force attack")
    parser.add_argument("--threads", type=int, default=4,
                       help="Number of threads for dictionary attack")
    
    args = parser.parse_args()
    
    cracker = HashCracker()
    start_time = time.time()
    result = None
    
    try:
        if args.mode == 'dictionary':
            if not args.wordlist:
                print("[-] Wordlist is required for dictionary attack")
                return
            result = cracker.dictionary_attack(
                args.hash, args.type, args.wordlist, args.threads
            )
        else:  # bruteforce
            result = cracker.brute_force_attack(
                args.hash, args.type, args.min_length, 
                args.max_length, args.charset
            )
        
        end_time = time.time()
        
        if result:
            print(f"\n[+] Password found: {result}")
            print(f"[+] Time taken: {end_time - start_time:.2f} seconds")
        else:
            print("\n[-] Password not found")
            print(f"[+] Time taken: {end_time - start_time:.2f} seconds")
            
    except KeyboardInterrupt:
        print("\n[-] Attack interrupted by user")
        print(f"[+] Time elapsed: {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    main()