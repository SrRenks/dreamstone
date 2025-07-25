# Dreamstone

Dreamstone is a Python library and CLI tool for asymmetric encryption using RSA and AES-GCM, enabling easy key generation, data encryption, and decryption of files or base64-encoded data.

---

## Installation

Install with Poetry (recommended):

```bash
poetry install
poetry run dreamstone --help
```

Or via pip (when available):

```bash
pip install dreamstone
dreamstone --help
```

---

## CLI Usage

### Generate RSA key pair

```bash
dreamstone genkey --private-path private.pem --public-path public.pem
```

### Encrypt a file

```bash
dreamstone encrypt-file --input-file secrets.txt --public-key-file public.pem --output-file encrypted.json
```

### Encrypt base64 data and generate keys

```bash
dreamstone encrypt-file \
  --input-data "TWluaGEgbWVuc2FnZW0gc2VjcmV0YQ==" \
  --private-key-path private.pem \
  --public-key-path public.pem \
  --output-file encrypted.json
```

### Decrypt file and print to stdout

```bash
dreamstone decrypt-file encrypted.json --private-key-file private.pem --password YOUR_PASSWORD_HERE
```

### Decrypt file and save output

```bash
dreamstone decrypt-file encrypted.json --private-key-file private.pem --password YOUR_PASSWORD_HERE --output-file decrypted.txt
```

---

## Python Usage Examples

```python
from dreamstone.core.keys import generate_rsa_keypair, save_rsa_keypair_to_files, load_private_key, load_public_key
from dreamstone.core.encryption import encrypt, encrypt_with_auto_key
from dreamstone.core.decryption import decrypt
from dreamstone.models.payload import EncryptedPayload

# Generate RSA key pair and save to files
private_key, public_key = generate_rsa_keypair()
password = save_rsa_keypair_to_files(private_key, public_key, "private.pem", "public.pem", password=None)
print(f"Generated keys saved. Use this password to decrypt: {password}")

# Encrypt raw data with existing public key
with open("public.pem", "rb") as f:
    pub_key = load_public_key(f.read())

plaintext = b"My secret message"
enc_result = encrypt(plaintext, pub_key)
payload = EncryptedPayload(**enc_result)

# Save encrypted payload JSON
with open("encrypted.json", "w") as f:
    f.write(payload.to_json())

# Decrypt the payload with private key and password
with open("private.pem", "rb") as f:
    priv_key = load_private_key(f.read(), password=password.encode())

decrypted = decrypt(
    encrypted_key=payload.encrypted_key,
    nonce=payload.nonce,
    ciphertext=payload.ciphertext,
    private_key=priv_key,
)

print("Decrypted message:", decrypted.decode())
```

---

## License

MIT License

---

## Contact

For issues and contributions, please open an issue or pull request on the repository.
