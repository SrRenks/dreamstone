import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from .keys import (
    generate_rsa_keypair,
    save_rsa_keypair_to_files,
)

def encrypt(plaintext: bytes, public_key):
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    return {
        "ciphertext": ciphertext,
        "encrypted_key": encrypted_key,
        "nonce": nonce,
    }

from typing import Optional, Dict, Any

def encrypt_with_auto_key(
    data: bytes,
    public_key=None,
    key_size: int = 4096,
    save_keys: bool = False,
    private_path: Optional[str] = None,
    public_path: Optional[str] = None,
    password: Optional[str] = None,
) -> Dict[str, Any]:
    if public_key is None:
        private_key, public_key = generate_rsa_keypair(key_size=key_size)
        saved_password = None
        if save_keys and private_path and public_path:
            saved_password = save_rsa_keypair_to_files(
                private_key, public_key, private_path, public_path, password
            )
    else:
        private_key = None
        saved_password = None

    encrypted = encrypt(data, public_key)

    return {
        "payload": encrypted,
        "private_key": private_key,
        "public_key": public_key,
        "password": saved_password,
    }
