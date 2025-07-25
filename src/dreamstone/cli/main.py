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

app = typer.Typer()
logger = logging.getLogger("dreamstone")
logger.setLevel(logging.INFO)
logger.handlers.clear()
handler = RichHandler(rich_tracebacks=True, markup=True)
logger.addHandler(handler)


def setup_logging(verbose: bool):
    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)


@app.command()
def genkey(
    private_path: Path = typer.Option(..., help="Path to save private key PEM"),
    public_path: Path = typer.Option(..., help="Path to save public key PEM"),
    password: Optional[str] = typer.Option(None, help="Password to protect private key. If not given, generates a strong one."),
    verbose: bool = typer.Option(False, help="Enable verbose logging"),
):
    setup_logging(verbose)
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
    if not password:
        logger.warning(
            f"\033[93mNo password was provided. "
            f"A strong password was generated: \033[92m{saved_password}\033[93m ← Save this password securely. "
            f"Without it you will NOT be able to decrypt.\033[0m"
        )

@app.command()
def encrypt_file(
    input_file: Optional[Path] = typer.Option(None, help="File to encrypt"),
    input_data: Optional[str] = typer.Option(None, help="Base64-encoded data to encrypt"),
    public_key_file: Optional[Path] = typer.Option(
        None, help="Public key PEM file to encrypt with (if omitted, keys are generated)"
    ),
    private_key_path: Optional[Path] = typer.Option(
        None, help="Where to save private key PEM if keys are generated"
    ),
    public_key_path: Optional[Path] = typer.Option(
        None, help="Where to save public key PEM if keys are generated"
    ),
    password: Optional[str] = typer.Option(None, help="Password to protect private key PEM"),
    output_file: Path = typer.Option(..., help="Where to save encrypted payload JSON"),
    verbose: bool = typer.Option(False, help="Enable verbose logging"),
):
    setup_logging(verbose)

    if not input_file and not input_data:
        logger.error("You must provide either --input-file or --input-data")
        raise typer.Exit(code=1)

    if input_file and input_data:
        logger.error("You must provide only one of --input-file or --input-data, not both")
        raise typer.Exit(code=1)

    if input_file:
        data = input_file.read_bytes()
    else:
        import base64
        try:
            data = base64.b64decode(input_data)
        except Exception as e:
            logger.error(f"Invalid base64 data in --input-data: {e}")
            raise typer.Exit(code=1)

    if public_key_file:
        logger.debug(f"Loading public key from {public_key_file}")
        with open(public_key_file, "rb") as f:
            public_key = load_public_key(f.read())

        result = encrypt(data, public_key)
        payload = EncryptedPayload(**result)
        logger.info(f"Using provided public key to encrypt.")
        saved_password = None

    else:
        logger.info("No public key provided. Generating new RSA key pair.")
        if not (private_key_path and public_key_path):
            logger.error("To generate keys, you must provide --private-key-path and --public-key-path")
            raise typer.Exit(code=1)

        result_dict = encrypt_with_auto_key(
            data,
            public_key=None,
            save_keys=True,
            private_path=str(private_key_path),
            public_path=str(public_key_path),
            password=password,
        )
        payload = EncryptedPayload(**result_dict["payload"])
        saved_password = result_dict["password"]

        logger.info(f"Private key saved to {private_key_path}")
        logger.info(f"Public key saved to {public_key_path}")
        if saved_password:
            logger.warning("[yellow]No password was provided. A strong password was generated: [green]{}[/green] ← Save this password securely. Without it you will NOT be able to decrypt.[/yellow]".format(saved_password))

    with open(output_file, "w") as f:
        f.write(payload.to_json())

    logger.info(f"Encrypted payload saved to {output_file}")

@app.command()
def decrypt_file(
    encrypted_file: Path = typer.Argument(..., help="Path to encrypted JSON payload"),
    private_key_file: Path = typer.Option(..., help="Private key PEM file to decrypt with"),
    password: Optional[str] = typer.Option(None, help="Password for private key PEM (if encrypted)"),
    output_file: Optional[Path] = typer.Option(None, help="Path to save decrypted output (if not given prints to stdout)"),
    verbose: bool = typer.Option(False, help="Enable verbose logging"),
):
    setup_logging(verbose)
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
        sys.stdout.buffer.write(plaintext)
        logger.info("Decrypted data written to stdout")


if __name__ == "__main__":
    app()
