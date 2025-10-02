import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import secrets
import string
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

def load_private_key(pem_data: bytes, password: bytes = None):
    return load_pem_private_key(pem_data, password)

def load_public_key(pem_data: bytes):
    return load_pem_public_key(pem_data)

def generate_strong_password(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits + "-_"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generate_rsa_keypair(key_size: int = 4096):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def export_private_key(private_key, password: str = None) -> bytes:
    if not password:
        password = generate_strong_password()

    encryption_algo = serialization.BestAvailableEncryption(password.encode())

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algo,
    )
    return private_bytes, password

def export_public_key(public_key) -> bytes:
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_bytes

def save_rsa_keypair_to_files(
    private_key,
    public_key,
    private_path: str,
    public_path: str,
    password: str = None,
) -> str:
    private_bytes, used_password = export_private_key(private_key, password)

    public_bytes = export_public_key(public_key)

    os.makedirs(os.path.dirname(private_path) or ".", exist_ok=True)
    with open(private_path, "wb") as f:
        f.write(private_bytes)

    os.makedirs(os.path.dirname(public_path) or ".", exist_ok=True)
    with open(public_path, "wb") as f:
        f.write(public_bytes)

    return used_password
