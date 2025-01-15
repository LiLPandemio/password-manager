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

## Instalación
1. Clona este repositorio:
   ```bash
   git clone https://github.com/lilpandemio/password-manager.git
   cd password-manager
   ```

2. Instala las dependencias:
   ```bash
   pip install -r requirements.txt
   ```

## Uso
1. Ejecuta el programa:
   ```bash
   python main.py
   ```

2. Durante el primer uso, se te pedirá que configures una contraseña maestra para proteger tu clave privada. 

3. Opciones principales:
   - Buscar o añadir contraseñas nuevas.
   - Cifrar y almacenar información sensible asociada a dominios.
   - Recuperar contraseñas cifradas usando la clave privada.

## Funcionalidades del Programa
### `generate_rsa_keys`
- **Descripción:** Genera un par de claves RSA (pública y privada).
- **Entrada:** Ninguna.
- **Salida:** `(private_key, public_key)`.

### `save_encrypted_private_key`
- **Descripción:** Guarda la clave privada en un archivo, cifrada con una contraseña.
- **Entrada:** `private_key` (clave privada RSA), `password` (contraseña maestra).
- **Salida:** Ninguna. Crea un archivo `private_key.pem`.

### `load_encrypted_private_key`
- **Descripción:** Carga y descifra la clave privada almacenada en el archivo.
- **Entrada:** `password` (contraseña maestra).
- **Salida:** Clave privada descifrada o `None` si falla.

### `encrypt_password`
- **Descripción:** Cifra una contraseña utilizando la clave pública RSA.
- **Entrada:** `public_key` (clave pública), `password` (contraseña a cifrar).
- **Salida:** Contraseña cifrada (string base64).

### `decrypt_password`
- **Descripción:** Descifra una contraseña cifrada con RSA.
- **Entrada:** `private_key` (clave privada), `encrypted_password` (contraseña cifrada en base64).
- **Salida:** Contraseña descifrada.

### `save_passwords`
- **Descripción:** Guarda las contraseñas cifradas en un archivo JSON.
- **Entrada:** `data` (diccionario de contraseñas).
- **Salida:** Ninguna. Crea o actualiza el archivo `passwords.enc`.

### `load_passwords`
- **Descripción:** Carga las contraseñas almacenadas del archivo.
- **Entrada:** Ninguna.
- **Salida:** Diccionario de contraseñas cargado desde el archivo.

### `interactive_search`
- **Descripción:** Permite buscar dominios interactivamente.
- **Entrada:** `stdscr` (pantalla curses), `data` (diccionario de contraseñas).
- **Salida:** `(search_query, is_new)` indicando el dominio seleccionado o nuevo.

## Seguridad
- Las claves y contraseñas están protegidas utilizando estándares modernos de cifrado.
- El uso de `PBKDF2` agrega una capa adicional de seguridad al proteger la clave privada.

## Créditos
- Marc Moreno
- Adria Vidosa
