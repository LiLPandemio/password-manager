# Password Manager

Este proyecto es un gestor de contraseñas seguro implementado en Python. Permite cifrar y almacenar contraseñas utilizando criptografía de clave pública RSA y algoritmos de derivación de claves para proteger la clave privada. Se diseño para un proyecto en la universidad.

## Características
- Generación de claves RSA (clave privada y clave pública).
- Almacenamiento seguro de la clave privada utilizando PBKDF2 y AES.
- Cifrado y descifrado de contraseñas con la clave pública y privada respectivamente.
- Gestión interactiva de contraseñas con búsqueda y almacenamiento de nuevos datos.
- Interfaz de búsqueda implementada con `curses`.


## Requisitos
- Python 3.8 o superior
- Dependencias de Python:
  - `cryptography`
  - `pynput`
  - `curses`
- Archivo `passwords.enc` generado automáticamente al guardar contraseñas.
- Archivo `private_key.pem` para almacenar la clave privada cifrada.
