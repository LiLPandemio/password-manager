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

## Seguridad
- Las claves y contraseñas están protegidas utilizando estándares modernos de cifrado.
- El uso de `PBKDF2` agrega una capa adicional de seguridad al proteger la clave privada.

## Créditos
- Marc Moreno
- Adria Vidosa