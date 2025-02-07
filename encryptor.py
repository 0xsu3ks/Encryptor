import os
import sys
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path: str, key: bytes, iv: bytes):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    with open(file_path, 'wb') as f:
        f.write(iv + ciphertext)

def decrypt_file(file_path: str, key: bytes):
    backend = default_backend()
    with open(file_path, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    with open(file_path, 'wb') as f:
        f.write(plaintext)

def process_directory(directory: str, key: bytes, encrypt: bool):
    iv = os.urandom(16)
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if encrypt:
                encrypt_file(file_path, key, iv)
                print(f"[+] {file_path} encrypted")
            else:
                decrypt_file(file_path, key)
                print(f"[+] {file_path} decrypted")

def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt directories and subdirectories using AES encryption.")
    parser.add_argument('--key', required=True, help="Encryption/Decryption key")
    parser.add_argument('--dir', required=True, help="Directory to process")
    parser.add_argument('--encrypt', action='store_true', help="Encrypt the directory")
    parser.add_argument('--decrypt', action='store_true', help="Decrypt the directory")
    parser.add_argument('--yes', action='store_true', help="Confirm the action")

    args = parser.parse_args()

    if not args.yes:
        print("Please confirm the action with --yes")
        sys.exit(1)

    if args.encrypt and args.decrypt:
        print("Please specify either --encrypt or --decrypt, not both.")
        sys.exit(1)

    salt = b'\x00' * 16  # You can use a more secure way to generate and store salt
    key = derive_key(args.key, salt)

    if args.encrypt:
        process_directory(args.dir, key, encrypt=True)
    elif args.decrypt:
        process_directory(args.dir, key, encrypt=False)
    else:
        print("Please specify either --encrypt or --decrypt.")
        sys.exit(1)

if __name__ == "__main__":
    main()
