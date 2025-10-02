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
from dreamstone.core.encryption import encrypt, encrypt_with_auto_key
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
def genkey_command(
    private_path: Optional[Path] = typer.Option(None, "--private-path", "-prip", help="Path to save private key PEM"),
    public_path: Optional[Path] = typer.Option(None, "--public-path", "-pubp", help="Path to save public key PEM"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="Password to protect private key. If not given, generates a strong one."),
    no_show_password: bool = typer.Option(False, "--no-show-password", "-nsp", help="No show generated password in terminal after auto gen if none is provided"),
    password_path: Optional[Path] = typer.Option(None, "--password-path", "-pp", help="Optional path to save generated password"),
    log_level: str = typer.Option("WARNING", "--log-level", "-ll", help=f"Logging level, one of {LOG_LEVELS}"),
):
    setup_logging(log_level)
    private_key, public_key = generate_rsa_keypair()
    saved_password = save_rsa_keypair_to_files(
        private_key,
        public_key,
        str(private_path),
        str(public_path),
        password,
    )

    logger.info(f"Private key saved to {private_path}")
    logger.info(f"Public key saved to {public_path}")

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
    input_file: Optional[Path] = typer.Option(None, "--input-file", "-if", help="File to encrypt"),
    input_data: Optional[str] = typer.Option(None, "--input-data", "-id", help="Base64-encoded data to encrypt"),
    base64_input: bool = typer.Option(False, "--base64", "-b64", help="Indicates if input is base64"),
    public_key_file: Optional[Path] = typer.Option(
        None, "--public-key-file", "-pkf", help="Public key PEM file to encrypt with (if omitted, keys are generated)"
    ),
    private_key_path: Optional[Path] = typer.Option(
        None, "--private-key-path", "-prikp", help="Where to save private key PEM if keys are generated"
    ),
    public_key_path: Optional[Path] = typer.Option(
        None, "--public-key-path", "-pubkp", help="Where to save public key PEM if keys are generated"
    ),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="Password to protect private key PEM"),
    no_show_password: bool = typer.Option(False, "--no-show-password", "-nsp", help="No show generated password in terminal after auto gen if none is provided"),
    password_path: Optional[Path] = typer.Option(None, "--password-path", "-pp", help="Optional path to save generated password"),
    output_file: Path = typer.Option(..., "--output-file", "-of", help="Where to save encrypted payload JSON"),
    key_output_dir: Path = typer.Option(Path("secrets"), "--key-output-dir", "-kod", help="Directory to save keys if paths not provided"),
    log_level: str = typer.Option("WARNING", "--log-level", "-ll", help=f"Logging level, one of {LOG_LEVELS}"),
):
    setup_logging(log_level)

    if not input_file and not input_data:
        logger.error("You must provide either --input-file or --input-data")
        raise typer.Exit(code=1)
    if input_file and input_data:
        logger.error("You must provide only one of --input-file or --input-data, not both")
        raise typer.Exit(code=1)

    if input_file:
        data = input_file.read_bytes()
    else:
        try:
            data = base64.b64decode(input_data) if base64_input else input_data.encode("utf-8")
        except Exception as e:
            logger.error(f"Invalid input: {e}")
            raise typer.Exit(code=1)

    if public_key_file:
        logger.debug(f"Loading public key from {public_key_file}")
        with open(public_key_file, "rb") as f:
            public_key = load_public_key(f.read())
        result = encrypt(data, public_key)
        payload = EncryptedPayload(**result)
        saved_password = None
        logger.info(f"Encrypted using provided public key.")

    else:
        logger.info("No public key provided. Generating new RSA key pair via genkeygenkey_command.")
        secrets_dir = key_output_dir
        secrets_dir.mkdir(parents=True, exist_ok=True)

        hash_id = hashlib.sha256(data[:16]).hexdigest()[:8]

        if not private_key_path:
            private_key_path = secrets_dir / f"private_{hash_id}.pem"
        if not public_key_path:
            public_key_path = secrets_dir / f"public_{hash_id}.pem"

        saved_password = genkey_command(
            private_path=private_key_path,
            public_path=public_key_path,
            password=password,
            no_show_password=no_show_password,
            password_path=password_path,
            log_level=log_level,
        )

        with open(private_key_path, "rb") as f:
            private_key = load_private_key(f.read(), password=saved_password.encode() if saved_password else None)
        with open(public_key_path, "rb") as f:
            public_key = load_public_key(f.read())

        result = encrypt(data, public_key)
        payload = EncryptedPayload(**result)
        saved_password = password

    with open(output_file, "w") as f:
        f.write(payload.to_json())
    logger.info(f"Encrypted payload saved to {output_file}")

app.command("encrypt")(encrypt_command)
app.command("enc")(encrypt_command)

def decrypt_command(
    encrypted_file: Path = typer.Argument(..., help="Path to encrypted JSON payload"),
    private_key_file: Path = typer.Option(..., "--private-key-file", "-pkf", help="Private key PEM file to decrypt with"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="Password for private key PEM (if encrypted)"),
    password_path: Optional[Path] = typer.Option(None, "--password-path", "-pp", help="File containing password for private key PEM"),
    output_file: Optional[Path] = typer.Option(None, "--output-file", "-of", help="Path to save decrypted output (if not given prints to stdout)"),
    log_level: str = typer.Option("WARNING", "--log-level", "-ll", help=f"Logging level, one of {LOG_LEVELS}"),
):
    setup_logging(log_level)

    if password_path:
        password = password_path.read_text(encoding="utf-8").strip()

    logger.debug("Loading private key")
    with open(private_key_file, "rb") as f:
        private_key = load_private_key(f.read(), password=password.encode() if password else None)

    logger.debug("Loading encrypted payload")

    with open(encrypted_file, "r") as f:
        data = json.load(f)
    payload = EncryptedPayload.from_dict(data)

    logger.debug("Decrypting data")
    plaintext = decrypt(
        encrypted_key=payload.encrypted_key,
        nonce=payload.nonce,
        ciphertext=payload.ciphertext,
        private_key=private_key,
    )

    if output_file:
        Path(output_file).write_bytes(plaintext)
        logger.info(f"Decrypted data saved to {output_file}")

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
