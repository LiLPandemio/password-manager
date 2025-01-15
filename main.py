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

# Agregado: funciones para cifrar y descifrar contraseñas
def encrypt_password(public_key, password):
    encrypted = public_key.encrypt(
        password.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()


# Integración: interfaz interactiva con gestión de contraseñas
def main():
    data = load_passwords()
    private_key, public_key = generate_rsa_keys()

    if not os.path.exists("private_key.pem"):
        print("Setting up for the first time.\n")
        password = getpass.getpass("Create a password to secure your private key: ")
        save_encrypted_private_key(private_key, password)
    else:
        password = getpass.getpass("Enter your password to unlock private key: ")
        private_key = load_encrypted_private_key(password)
        if not private_key:
            return

    while True:
        print("\nOptions:")
        print("1. Search or add password")
        print("2. Exit")

        choice = input("Choose an option: ")

        if choice == "1":
            def search_ui(stdscr):
                return interactive_search(stdscr, data)

            domain, is_new = curses.wrapper(search_ui)

            if is_new:
                username = input("Enter username: ")
                password = getpass.getpass("Enter password: ")
                data[domain] = {
                    "username": username,
                    "password": encrypt_password(public_key, password)
                }
                save_passwords(data)
                print(f"Password for '{domain}' added successfully!")
            else:
                entry = data.get(domain, {})
                encrypted_password = entry.get("password")
                username = entry.get("username")
                master_password = getpass.getpass("Enter your master password to decrypt: ")
                private_key = load_encrypted_private_key(master_password)
                if private_key:
                    print(f"Domain: {domain}")
                    print(f"Username: {username}")
                    print(f"Password: {decrypt_password(private_key, encrypted_password)}")

        elif choice == "2":
            break

        else:
            print("Invalid option. Try again.")


# Agregado: búsqueda interactiva con interfaz usando curses
def interactive_search(stdscr, data):
    curses.curs_set(0)
    stdscr.clear()

    search_query = ""
    selected_index = 0

    while True:
        stdscr.clear()
        matches = [domain for domain in data if search_query.lower() in domain.lower()]
        matches.append(f"-- Add password for '{search_query}' --")

        stdscr.addstr(0, 0, f"Search: {search_query}")

        for idx, domain in enumerate(matches):
            if idx == selected_index:
                stdscr.addstr(idx + 1, 0, domain, curses.A_REVERSE)
            else:
                stdscr.addstr(idx + 1, 0, domain)

        key = stdscr.getch()

        if key == curses.KEY_UP:
            selected_index = max(0, selected_index - 1)
        elif key == curses.KEY_DOWN:
            selected_index = min(len(matches) - 1, selected_index + 1)
        elif key == curses.KEY_BACKSPACE or key == 127 or key == 8:
            search_query = search_query[:-1]
            selected_index = 0
        elif key == 10:  # Enter
            if selected_index == len(matches) - 1:
                return search_query, True
            return matches[selected_index], False
        elif 32 <= key <= 126:
            search_query += chr(key)
            selected_index = 0


# Agregado: funciones para guardar y cargar contraseñas
def save_passwords(data):
    with open("passwords.enc", "w") as file:
        json.dump(data, file)

def load_passwords():
    if os.path.exists("passwords.enc"):
        with open("passwords.enc", "r") as file:
            return json.load(file)
    return {}


def decrypt_password(private_key, encrypted_password):
    decrypted = private_key.decrypt(
        base64.b64decode(encrypted_password),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()


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
