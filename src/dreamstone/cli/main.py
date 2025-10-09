import sys
import logging
import json
from pathlib import Path
import typer
from typing import Optional
from rich.logging import RichHandler
import logging
from dreamstone.core.keys import (
    generate_rsa_keypair,
    save_rsa_keypair_to_files,
    load_private_key,
    load_public_key,
)
from dreamstone.core.encryption import encrypt
from dreamstone.core.decryption import decrypt
from dreamstone.models.payload import EncryptedPayload
from rich.logging import RichHandler
import base64
import hashlib
import os

app = typer.Typer()
logger = logging.getLogger("dreamstone")
logger.setLevel(logging.INFO)
logger.handlers.clear()
handler = RichHandler(rich_tracebacks=True, markup=True, console=None)
logger.addHandler(handler)

LOG_LEVELS = ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"]

def setup_logging(log_level: str):
    level = getattr(logging, log_level.upper(), logging.WARNING)
    logger.setLevel(level)

def get_key_path(key: Optional[Path], hash_id: str, key_type: str, secrets_dir: Path) -> Path:
    if key:
        key_path = Path(key)
        if key_path.is_dir():
            key_path = key_path / f"{key_type}_{hash_id}.pem"
    else:
        key_path = secrets_dir / f"{key_type}_{hash_id}.pem"

    return key_path
def resolve_path(path: Path) -> Path:

    if not path.exists():
        return path
    i = 1
    while True:
        new_path = path.with_name(f"{path.stem}_{i}{path.suffix}")
        if not new_path.exists():
            return new_path
        i += 1

def genkey_command(
    private_key: Optional[Path] = typer.Option(None, "--private-key", "-pv", help="Path to save private key PEM"),
    public_key: Optional[Path] = typer.Option(None, "--public-key", "-pb", help="Path to save public key PEM"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="Password to protect private key. If not given, generates a strong one."),
    password_path: Optional[Path] = typer.Option(None, "--password-path", "-pp", help="Optional path to save generated password"),
    no_show_password: bool = typer.Option(False, "--no-show-password", "-nsp", help="No show generated password in terminal after auto gen if none is provided"),
    overwrite: bool = typer.Option(False, "--overwrite", "-f", help="Overwrite existing keys without asking"),
    log_level: str = typer.Option("WARNING", "--log-level", "-ll", help=f"Logging level, one of {LOG_LEVELS}"),
):
    setup_logging(log_level)

    priv_path = Path(private_key) if private_key else Path("private_key.pem")
    pub_path = Path(public_key) if public_key else Path("public_key.pem")

    if not overwrite:
        priv_path = resolve_path(priv_path)
        pub_path = resolve_path(pub_path)

    generated_private_key, generated_public_key = generate_rsa_keypair()
    saved_password = save_rsa_keypair_to_files(
        generated_private_key,
        generated_public_key,
        str(priv_path),
        str(pub_path),
        password,
    )

    logger.info(f"Private key saved to {priv_path}")
    logger.info(f"Public key saved to {pub_path}")

    if not password and saved_password and not no_show_password:
        typer.secho("Generated password (save it securely):", fg="yellow")
        typer.secho(saved_password, fg="green", bold=True)

    if password_path:
        os.makedirs(password_path.parent, exist_ok=True)
        password_path.write_text(saved_password or password, encoding="utf-8")
        logger.info(f"Password saved to {password_path}")

    return saved_password or password

app.command("genkey")(genkey_command)
app.command("gk")(genkey_command)

def encrypt_command(
    input: str = typer.Argument(..., help="Input string or path to file to encrypt"),
    out: Path = typer.Option(..., "--out", "-o", help="Where to save encrypted payload JSON"),
    b64: bool = typer.Option(False, "--base64", "-b64", help="Indicates if input is base64"),
    private_key: Optional[Path] = typer.Option(None, "--private-key", "-pv", help="Path to private key PEM (used or to be created)"),
    public_key: Optional[Path] = typer.Option(None, "--public-key", "-pb", help="Path to a public key PEM file (existing or to be created)"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="Password to protect private key PEM"),
    password_path: Optional[Path] = typer.Option(None, "--password-path", "-pp", help="Optional path to save generated password"),
    no_show_password: bool = typer.Option(False, "--no-show-password", "-nsp", help="No show generated password in terminal after auto gen if none is provided"),
    log_level: str = typer.Option("WARNING", "--log-level", "-ll", help=f"Logging level, one of {LOG_LEVELS}")) -> str:

    setup_logging(log_level)

    input_path = Path(input)
    if input_path.is_dir():
        typer.echo(f"Error: '{input_path}' is a directory, expected a file.", err=True)
        raise typer.Exit(code=1)

    try:
        if b64:
            data = base64.b64decode(input)

        elif input_path.is_file():
            data = input_path.read_bytes()

        elif input_path.suffix:
            raise FileNotFoundError(f"Input file does not exist: {input}")

        else:
            data = input.encode()

    except (FileNotFoundError, OSError, ValueError) as e:
        logger.error(f"Invalid input: {e}")
        raise typer.Exit(code=1)

    if public_key is not None and public_key.is_file():
        logger.debug(f"Loading existing public key from {public_key}")
        public_key_obj = load_public_key(public_key.read_bytes())
        result = encrypt(data, public_key_obj)
        payload = EncryptedPayload(**result)
        logger.info("Encrypted using provided public key.")
    else:
        logger.info("No valid public key found. Generating new RSA key pair.")

        secrets_dir = out.parent / "secrets"
        secrets_dir.mkdir(parents=True, exist_ok=True)

        hash_id = hashlib.sha256(data[:16]).hexdigest()[:8]

        private_key_path = get_key_path(private_key, hash_id, "private", secrets_dir)
        public_key_path  = get_key_path(public_key, hash_id, "public", secrets_dir)

        private_key_path.parent.mkdir(parents=True, exist_ok=True)
        public_key_path.parent.mkdir(parents=True, exist_ok=True)

        saved_password = genkey_command(
            private_key=private_key_path,
            public_key=public_key_path,
            password=password,
            no_show_password=no_show_password,
            password_path=password_path,
            log_level=log_level,
        )

        if saved_password:
            typer.echo(f"Generated password: {saved_password}")

        public_key_obj = load_public_key(public_key_path.read_bytes())
        result = encrypt(data, public_key_obj)
        payload = EncryptedPayload(**result)

    out.write_text(payload.to_json())
    logger.info(f"Encrypted payload saved to {out}")

app.command("encrypt")(encrypt_command)
app.command("enc")(encrypt_command)

def decrypt_command(
    payload: Path = typer.Argument(..., help="Path to encrypted JSON payload"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Path to save decrypted output (if not given prints to stdout)"),
    private_key: Path = typer.Option(..., "--private-key", "-pv", help="Private key PEM file to decrypt with"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="Password for private key PEM (if encrypted)"),
    password_path: Optional[Path] = typer.Option(None, "--password-path", "-pp", help="File containing password for private key PEM"),
    log_level: str = typer.Option("WARNING", "--log-level", "-ll", help=f"Logging level, one of {LOG_LEVELS}")):
    setup_logging(log_level)

    payload = Path(payload)
    if payload.is_dir():
        typer.echo(f"Error: '{payload}' is a directory, expected a file.", err=True)
        raise typer.Exit(code=1)

    logger.debug("Loading encrypted payload")
    with open(payload, "r") as f:
        data = json.load(f)
    payload = EncryptedPayload.from_dict(data)

    if password_path:
        password = password_path.read_text(encoding="utf-8").strip()

    logger.debug("Loading private key")
    with open(private_key, "rb") as f:
        try:
            private_key_obj = load_private_key(f.read(), password=password.encode() if password else None)
        except ValueError:
            logger.error("Failed to load private key — incorrect password or invalid file.")
            raise typer.Exit(code=1)

    logger.debug("Decrypting data")
    plaintext = decrypt(
        encrypted_key=payload.encrypted_key,
        nonce=payload.nonce,
        ciphertext=payload.ciphertext,
        private_key=private_key_obj,
    )

    if out:
        Path(out).write_bytes(plaintext)
        logger.info(f"Decrypted data saved to {out}")

    else:
        try:
            typer.echo(plaintext.decode("utf-8"))
        except UnicodeDecodeError:
            sys.stdout.buffer.write(plaintext)
        logger.info("Decrypted data written to stdout")

app.command("decrypt")(decrypt_command)
app.command("dec")(decrypt_command)

if __name__ == "__main__":
    app()
