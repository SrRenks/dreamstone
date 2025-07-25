import base64

class EncryptedPayload:
    def __init__(self, ciphertext: bytes, encrypted_key: bytes, nonce: bytes):
        self.ciphertext = ciphertext
        self.encrypted_key = encrypted_key
        self.nonce = nonce

    def to_dict(self):
        return {
            "ciphertext": self.ciphertext.hex(),
            "encrypted_key": self.encrypted_key.hex(),
            "nonce": self.nonce.hex(),
        }

    def to_json(self) -> str:
        import base64, json
        return json.dumps({
            "ciphertext": base64.b64encode(self.ciphertext).decode(),
            "encrypted_key": base64.b64encode(self.encrypted_key).decode(),
            "nonce": base64.b64encode(self.nonce).decode(),
        })

    @staticmethod
    def from_dict(data: dict) -> "EncryptedPayload":
        return EncryptedPayload(
            ciphertext=base64.b64decode(data["ciphertext"]),
            encrypted_key=base64.b64decode(data["encrypted_key"]),
            nonce=base64.b64decode(data["nonce"]),
        )