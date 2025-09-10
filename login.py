#!/usr/bin/env python3
import argparse
import json
import os
import sys
import getpass
import hashlib
import hmac
import secrets
from typing import Dict

DB_PATH = "users_db.json"
PBKDF_ALGO = "sha256"
PBKDF_ITER = 200_000   # Iteraciones (sube si tu PC lo permite)
SALT_BYTES = 16        # 128 bits

def load_db() -> Dict[str, dict]:
    if not os.path.exists(DB_PATH):
        return {}
    with open(DB_PATH, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
            if isinstance(data, dict):
                return data
            return {}
        except json.JSONDecodeError:
            return {}

def save_db(db: Dict[str, dict]) -> None:
    with open(DB_PATH, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)

def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac(PBKDF_ALGO, password.encode("utf-8"), salt, iterations)

def register(username: str) -> None:
    db = load_db()
    if username in db:
        print(f"[!] El usuario '{username}' ya existe.")
        sys.exit(1)


    pw1 = getpass.getpass("Nueva contraseña: ")
    pw2 = getpass.getpass("Repite la contraseña: ")
    if pw1 != pw2:
        print("[!] Las contraseñas no coinciden.")
        sys.exit(1)
    if len(pw1) < 8:
        print("[!] Usa al menos 8 caracteres por seguridad.")
        sys.exit(1)

    salt = os.urandom(SALT_BYTES)
    key = derive_key(pw1, salt, PBKDF_ITER)

    db[username] = {
        "salt": salt.hex(),
        "iterations": PBKDF_ITER,
        "hash": key.hex(),
        "roles": ["user"]   # opcional: puedes manejar roles
    }
    save_db(db)
    print(f"[+] Usuario '{username}' registrado correctamente.")

def login(username: str) -> None:
    db = load_db()
    user = db.get(username)
    if not user:
        print("[!] Usuario o contraseña inválidos.")
        sys.exit(1)

    password = getpass.getpass("Contraseña: ")

    salt = bytes.fromhex(user["salt"])
    iterations = int(user["iterations"])
    expected = bytes.fromhex(user["hash"])

    candidate = derive_key(password, salt, iterations)

    if hmac.compare_digest(candidate, expected):
        token = secrets.token_urlsafe(24)  # “token de sesión” simple para demo
        print("[+] Login exitoso.")
        print(f"   Usuario: {username}")
        print(f"   Token (demo): {token}")
    else:
        print("[!] Usuario o contraseña inválidos.")
        sys.exit(1)

def change_password(username: str) -> None:
    db = load_db()
    user = db.get(username)
    if not user:
        print("[!] Usuario no existe.")
        sys.exit(1)

    # Verificación de identidad
    current = getpass.getpass("Contraseña actual: ")
    salt = bytes.fromhex(user["salt"])
    iterations = int(user["iterations"])
    expected = bytes.fromhex(user["hash"])
    if not hmac.compare_digest(derive_key(current, salt, iterations), expected):
        print("[!] Contraseña actual incorrecta.")
        sys.exit(1)

    pw1 = getpass.getpass("Nueva contraseña: ")
    pw2 = getpass.getpass("Repite la nueva contraseña: ")
    if pw1 != pw2:
        print("[!] Las contraseñas no coinciden.")
        sys.exit(1)
    if len(pw1) < 8:
        print("[!] Usa al menos 8 caracteres por seguridad.")
        sys.exit(1)

    new_salt = os.urandom(SALT_BYTES)
    new_key = derive_key(pw1, new_salt, PBKDF_ITER)
    user["salt"] = new_salt.hex()
    user["iterations"] = PBKDF_ITER
    user["hash"] = new_key.hex()
    save_db(db)
    print("[+] Contraseña actualizada.")

def main():
    parser = argparse.ArgumentParser(
        description="Simulador de login con PBKDF2-HMAC (hashlib) y getpass."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_reg = sub.add_parser("register", help="Registrar nuevo usuario")
    p_reg.add_argument("username", help="Nombre de usuario")

    p_log = sub.add_parser("login", help="Iniciar sesión")
    p_log.add_argument("username", help="Nombre de usuario")

    p_chg = sub.add_parser("changepw", help="Cambiar contraseña")
    p_chg.add_argument("username", help="Nombre de usuario")

    args = parser.parse_args()

    if args.cmd == "register":
        register(args.username)
    elif args.cmd == "login":
        login(args.username)
    elif args.cmd == "changepw":
        change_password(args.username)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
