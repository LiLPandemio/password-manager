import os
import json
import base64
import getpass
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey
from pynput import keyboard
import curses

# Agregado: función para generar claves RSA
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    return private_key, public_key

# Agregado: función para cargar la clave privada cifrada
def load_encrypted_private_key(password):
    try:
        with open("private_key.pem", "rb") as key_file:
            content = key_file.read()

        salt = content[:16]
        encrypted_private_key = content[16:]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())

        private_key = serialization.load_pem_private_key(
            encrypted_private_key,
            password=key,
            backend=default_backend()
        )
        return private_key

    except (InvalidKey, ValueError):
        print("Error: Incorrect password or invalid private key file.")
        return None

# Agregado: función para guardar la clave privada cifrada
def save_encrypted_private_key(private_key, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    encrypted_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(key)
    )

    with open("private_key.pem", "wb") as key_file:
        key_file.write(salt + encrypted_private_key)


def main():
    print("Welcome to the password manager!")
    
if __name__ == "__main__":
    main()
