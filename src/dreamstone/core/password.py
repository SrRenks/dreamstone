import base64
import secrets


def generate_strong_password(length: int = 32) -> str:
    raw = secrets.token_bytes(length)
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")
