import os
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode, urlsafe_b64decode
from getpass import getpass

# Constants
SALT_SIZE = 16
KEY_SIZE = 32
IV_SIZE = 16
TAG_SIZE = 16
KDF_ITERATIONS_MAP = {
    'low': 10000,
    'medium': 100000,
    'high': 500000,
}

def derive_key(password: str, salt: bytes, level: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS_MAP[level],
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path: str, password: str, level: str) -> None:
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt, level)
    iv = os.urandom(IV_SIZE)

    with open(file_path, 'rb') as f:
        plaintext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    # Store metadata
    metadata = {
        'salt': urlsafe_b64encode(salt).decode(),
        'iv': urlsafe_b64encode(iv).decode(),
        'tag': urlsafe_b64encode(tag).decode(),
        'level': level,
    }

    with open(file_path + '.enc', 'wb') as f:
        f.write(ciphertext)

    with open(file_path + '.meta', 'w') as f:
        json.dump(metadata, f)

def decrypt_file(file_path: str, password: str) -> None:
    with open(file_path.replace('.enc', '') + '.meta', 'r') as f:
        metadata = json.load(f)

    salt = urlsafe_b64decode(metadata['salt'].encode())
    iv = urlsafe_b64decode(metadata['iv'].encode())
    tag = urlsafe_b64decode(metadata['tag'].encode())
    level = metadata['level']

    key = derive_key(password, salt, level)

    with open(file_path, 'rb') as f:
        ciphertext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    with open(file_path.replace('.enc', ''), 'wb') as f:
        f.write(plaintext)

def get_encryption_level():
    level = input("Select encryption level (low, medium, high): ")
    if level not in KDF_ITERATIONS_MAP:
        print("Invalid encryption level. Please choose 'low', 'medium', or 'high'.")
        level = get_encryption_level()
    return level

def get_file_path():
    file_path = input("Enter the file path: ")
    if not os.path.isfile(file_path):
        print("File does not exist. Please enter a valid file path.")
        file_path = get_file_path()
    return file_path

def main():
    password = getpass("Enter your password: ")
    action = input("Do you want to (e)ncrypt or (d)ecrypt? ")

    if action.lower() == 'e':
        file_path = get_file_path()
        level = get_encryption_level()
        encrypt_file(file_path, password, level)
        print("File encrypted successfully.")
    elif action.lower() == 'd':
        file_path = get_file_path()
        decrypt_file(file_path, password)
        print("File decrypted successfully.")
    else:
        print("Invalid action.")

if __name__ == "__main__":
    main()
