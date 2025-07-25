# Dreamstone

**Dreamstone** is a modern Python library and CLI tool for secure hybrid encryption using RSA (asymmetric) + AES-GCM (symmetric). It enables you to easily generate keys, encrypt/decrypt files or base64 data, and handle encrypted payloads as JSON. Usable both as a library and CLI.

---

## Features

- 🔐 RSA + AES-GCM hybrid encryption
- 🔧 Key generation with password protection (optional)
- 📁 Encrypt/decrypt files or base64 strings
- 🧪 Output and input in structured JSON
- 🧰 CLI with short aliases for scripting
- 🐍 Easily embeddable in Python apps

---

## Installation

```bash
poetry install
poetry run dreamstone --help
````

For production use (once published):

```bash
pip install dreamstone
```

---

## CLI Commands

Each command has long and short versions.

| Command        | Alias | Description                    |
| -------------- | ----- | ------------------------------ |
| `genkey`       | `gk`  | Generate RSA key pair          |
| `encrypt-file` | `enc` | Encrypt file or base64 string  |
| `decrypt-file` | `dec` | Decrypt encrypted JSON payload |

---

### 🔐 Generate RSA Key Pair

```bash
dreamstone genkey \
  --private-path private.pem \
  --public-path public.pem \
  --password "mypassword"
```

#### Arguments

| Argument         | Alias | Required | Description                     |
| ---------------- | ----- | -------- | ------------------------------- |
| `--private-path` | `-pr` | ✅        | Path to save private key        |
| `--public-path`  | `-pu` | ✅        | Path to save public key         |
| `--password`     | `-pw` | ❌        | Password to encrypt private key |
| `--no-password`  | `-np` | ❌        | Skip password protection        |

---

### 🔒 Encrypt File or Base64

```bash
dreamstone encrypt-file \
  --input-file secret.txt \
  --public-key-file public.pem \
  --output-file encrypted.json
```

Or encrypt base64 data directly:

```bash
dreamstone encrypt-file \
  --input-data "SGVsbG8gd29ybGQ=" \
  --output-file encrypted.json
```

#### Arguments

| Argument             | Alias | Required | Description                                    |
| -------------------- | ----- | -------- | ---------------------------------------------- |
| `--input-file`       | `-i`  | ❌        | Path to input file                             |
| `--input-data`       | `-d`  | ❌        | Raw base64-encoded input data                  |
| `--public-key-file`  | `-k`  | ❌        | Path to public key (auto-generated if omitted) |
| `--output-file`      | `-o`  | ✅        | Output path for encrypted JSON                 |
| `--private-key-path` | `-pr` | ❌        | Where to save generated private key            |
| `--public-key-path`  | `-pu` | ❌        | Where to save generated public key             |
| `--password`         | `-pw` | ❌        | Password for generated private key             |

---

### 🔓 Decrypt JSON Payload

```bash
dreamstone decrypt-file \
  encrypted.json \
  --private-key-file private.pem \
  --password "mypassword" \
  --output-file decrypted.txt
```

#### Arguments

| Argument             | Alias | Required | Description                     |
| -------------------- | ----- | -------- | ------------------------------- |
| `input_path`         | -     | ✅        | Encrypted JSON file path        |
| `--private-key-file` | `-k`  | ✅        | RSA private key file            |
| `--password`         | `-p`  | ❌        | Password to decrypt private key |
| `--output-file`      | `-o`  | ❌        | Output file for decrypted data  |

---

## Output JSON Format

Encrypted output is stored as a JSON object:

```json
{
  "encrypted_key": "base64...",
  "nonce": "base64...",
  "ciphertext": "base64...",
  "algorithm": "AES-GCM",
  "key_type": "RSA"
}
```

---

## Python Example

```python
from dreamstone.core.keys import generate_rsa_keypair
from dreamstone.core.encryption import encrypt
from dreamstone.core.decryption import decrypt
from dreamstone.models.payload import EncryptedPayload

# Generate keypair
priv, pub = generate_rsa_keypair()

# Encrypt
payload_dict = encrypt(b"secret", pub)
payload = EncryptedPayload(**payload_dict)

# Decrypt
decrypted = decrypt(
    encrypted_key=payload.encrypted_key,
    nonce=payload.nonce,
    ciphertext=payload.ciphertext,
    private_key=priv
)

print(decrypted.decode())  # "secret"
```

---

## License

MIT License

---

## Author

By me, Renks
