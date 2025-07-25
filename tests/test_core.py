import base64
import pytest

from dreamstone.core.keys import (
    generate_rsa_keypair,
    save_rsa_keypair_to_files,
    load_private_key,
    load_public_key,
)
from dreamstone.core.encryption import encrypt, encrypt_with_auto_key
from dreamstone.core.decryption import decrypt
from dreamstone.models.payload import EncryptedPayload


@pytest.fixture
def keypair(tmp_path):
    priv_path = tmp_path / "test_priv.pem"
    pub_path = tmp_path / "test_pub.pem"

    private_key, public_key = generate_rsa_keypair()
    password = save_rsa_keypair_to_files(private_key, public_key, str(priv_path), str(pub_path), password=None)
    return {
        "private_key_path": priv_path,
        "public_key_path": pub_path,
        "password": password,
    }


def test_generate_and_save_keys(keypair):
    assert keypair["private_key_path"].exists()
    assert keypair["public_key_path"].exists()
    assert isinstance(keypair["password"], str)
    assert len(keypair["password"]) > 0


def test_encrypt_decrypt_roundtrip(keypair, tmp_path):
    with open(keypair["public_key_path"], "rb") as f:
        public_key = load_public_key(f.read())
    with open(keypair["private_key_path"], "rb") as f:
        private_key = load_private_key(f.read(), password=keypair["password"].encode())

    plaintext = b"Hello, Dreamstone test!"

    encrypted_result = encrypt(plaintext, public_key)
    payload = EncryptedPayload(**encrypted_result)

    decrypted = decrypt(
        encrypted_key=payload.encrypted_key,
        nonce=payload.nonce,
        ciphertext=payload.ciphertext,
        private_key=private_key,
    )

    assert decrypted == plaintext


def test_encrypt_with_auto_key_and_decrypt(tmp_path):
    plaintext = b"Auto key encryption test message"

    priv_path = tmp_path / "auto_priv.pem"
    pub_path = tmp_path / "auto_pub.pem"

    result_dict = encrypt_with_auto_key(
        plaintext,
        public_key=None,
        save_keys=True,
        private_path=str(priv_path),
        public_path=str(pub_path),
        password=None,
    )

    assert priv_path.exists()
    assert pub_path.exists()
    assert "payload" in result_dict
    assert "password" in result_dict

    payload = EncryptedPayload(**result_dict["payload"])

    with open(priv_path, "rb") as f:
        private_key = load_private_key(f.read(), password=result_dict["password"].encode())

    decrypted = decrypt(
        encrypted_key=payload.encrypted_key,
        nonce=payload.nonce,
        ciphertext=payload.ciphertext,
        private_key=private_key,
    )

    assert decrypted == plaintext


def test_encrypt_invalid_base64():
    invalid_b64 = "!!invalidbase64!!"
    with pytest.raises(Exception):
        base64.b64decode(invalid_b64)
