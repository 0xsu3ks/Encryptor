import os
import sys
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

CHUNK_SIZE = 64 * 1024  # 64KB chunks

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
        with open(file_path + '.enc', 'wb') as out_f:
            out_f.write(iv)  # write iv at the beginning of the file
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                if len(chunk) != CHUNK_SIZE:
                    chunk = padder.update(chunk) + padder.finalize()
                else:
                    chunk = padder.update(chunk)
                encrypted_chunk = encryptor.update(chunk)
                out_f.write(encrypted_chunk)
            out_f.write(encryptor.finalize())

    os.remove(file_path)
    os.rename(file_path + '.enc', file_path)

def decrypt_file(file_path: str, key: bytes):
    backend = default_backend()
    with open(file_path, 'rb') as f:
        iv = f.read(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        with open(file_path + '.dec', 'wb') as out_f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                decrypted_chunk = decryptor.update(chunk)
                if len(chunk) != CHUNK_SIZE:
                    decrypted_chunk = unpadder.update(decrypted_chunk) + unpadder.finalize()
                out_f.write(decrypted_chunk)
            out_f.write(decryptor.finalize())

    os.remove(file_path)
    os.rename(file_path + '.dec', file_path)

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

def process_file(file_path: str, key: bytes, encrypt: bool):
    iv = os.urandom(16)
    if encrypt:
        encrypt_file(file_path, key, iv)
        print(f"[+] {file_path} encrypted")
    else:
        decrypt_file(file_path, key)
        print(f"[+] {file_path} decrypted")

def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt directories and subdirectories or a single file using AES encryption.")
    parser.add_argument('--key', required=True, help="Encryption/Decryption key")
    parser.add_argument('--dir', help="Directory to process")
    parser.add_argument('--file', help="File to process")
    parser.add_argument('--encrypt', action='store_true', help="Encrypt the directory or file")
    parser.add_argument('--decrypt', action='store_true', help="Decrypt the directory or file")
    parser.add_argument('--yes', action='store_true', help="Confirm the action")

    args = parser.parse_args()

    if not args.yes:
        print("Please confirm the action with --yes")
        sys.exit(1)

    if args.encrypt and args.decrypt:
        print("Please specify either --encrypt or --decrypt, not both.")
        sys.exit(1)

    if not args.dir and not args.file:
        print("Please specify either --dir or --file.")
        sys.exit(1)

    salt = b'\x00' * 16  # You can use a more secure way to generate and store salt
    key = derive_key(args.key, salt)

    if args.dir:
        if args.encrypt:
            process_directory(args.dir, key, encrypt=True)
        elif args.decrypt:
            process_directory(args.dir, key, encrypt=False)
    elif args.file:
        if args.encrypt:
            process_file(args.file, key, encrypt=True)
        elif args.decrypt:
            process_file(args.file, key, encrypt=False)
    else:
        print("Please specify either --encrypt or --decrypt.")
        sys.exit(1)

if __name__ == "__main__":
    main()
