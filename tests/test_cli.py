import pytest
import re
from pathlib import Path
from typer.testing import CliRunner
from dreamstone.cli.main import app
import logging
import base64
import json

runner = CliRunner()

def remove_ansi_escape(text: str) -> str:
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_escape.sub('', text)

def remove_rich_markup(text: str) -> str:
    return re.sub(r'\[[^\]]+\]', '', text)

@pytest.fixture(autouse=True)
def reset_logger():
    logger = logging.getLogger("dreamstone")
    handlers = logger.handlers[:]
    for h in handlers:
        h.close()
        logger.removeHandler(h)
    from rich.logging import RichHandler
    handler = RichHandler(rich_tracebacks=True, markup=True)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    yield
    handlers = logger.handlers[:]
    for h in handlers:
        h.close()
        logger.removeHandler(h)

def test_encrypt_with_input_data_and_decrypt_stdout(tmp_path, caplog):
    plaintext = "Secret message for stdout."
    encrypted_file = tmp_path / "encrypted_stdout.json"
    with caplog.at_level(logging.WARNING, logger="dreamstone"):
        result_encrypt = runner.invoke(app, [
            "encrypt",
            "--input-data", plaintext,
            "--output-file", str(encrypted_file),
            "--key-output-dir", str(tmp_path),
        ])

    assert result_encrypt.exit_code == 0
    assert encrypted_file.exists()
    logs_clean = "\n".join(remove_ansi_escape(r.getMessage()) for r in caplog.records)
    logs_clean = remove_rich_markup(logs_clean)
    match = re.search(r"A strong password was generated: ([\w\-]+)", logs_clean)
    password = match.group(1).strip() if match else None
    assert password is not None, "password not generated on log"

    priv_keys = list(tmp_path.glob("private_*.pem"))
    assert priv_keys, "private key pem file not founnd"

    private_key_file = priv_keys[0]
    decrypt_args = [
        "decrypt",
        str(encrypted_file),
        "--private-key-file", str(private_key_file),
        "--password", password,
    ]
    result_decrypt = runner.invoke(app, decrypt_args)

    assert result_decrypt.exit_code == 0
    assert plaintext in result_decrypt.stdout

def test_genkey_creates_files_and_warns_password(tmp_path, caplog):
    private_path = tmp_path / "priv.pem"
    public_path = tmp_path / "pub.pem"

    with caplog.at_level(logging.WARNING, logger="dreamstone"):
        result = runner.invoke(app, [
            "genkey",
            "--private-path", str(private_path),
            "--public-path", str(public_path),
        ])

    assert result.exit_code == 0
    assert private_path.exists()
    assert public_path.exists()
    logs_clean = "\n".join(remove_ansi_escape(r.getMessage()) for r in caplog.records)
    logs_clean = remove_rich_markup(logs_clean)
    assert "A strong password was generated:" in logs_clean

def test_genkey_with_password(tmp_path):
    private_path = tmp_path / "priv.pem"
    public_path = tmp_path / "pub.pem"
    password = "myStrongPassword123!"

    result = runner.invoke(app, [
        "genkey",
        "--private-path", str(private_path),
        "--public-path", str(public_path),
        "--password", password,
    ])

    assert result.exit_code == 0
    assert private_path.exists()
    assert public_path.exists()
    assert "A strong password was generated:" not in result.output

def test_encrypt_and_decrypt_with_input_file(tmp_path, caplog):
    input_file = tmp_path / "input.txt"
    input_file.write_text("text to encrypt")

    encrypted_file = tmp_path / "encrypted.json"

    private_path = tmp_path / "priv.pem"
    public_path = tmp_path / "pub.pem"

    with caplog.at_level(logging.WARNING, logger="dreamstone"):
        runner.invoke(app, [
            "genkey",
            "--private-path", str(private_path),
            "--public-path", str(public_path),
        ])

    logs_clean = "\n".join(remove_ansi_escape(r.getMessage()) for r in caplog.records)
    logs_clean = remove_rich_markup(logs_clean)
    match = re.search(r"A strong password was generated: ([\w\-]+)", logs_clean)
    password = match.group(1).strip() if match else None
    assert password is not None, "password not generated on log"

    result_encrypt = runner.invoke(app, [
        "encrypt",
        "--input-file", str(input_file),
        "--public-key-file", str(public_path),
        "--output-file", str(encrypted_file),
    ])
    assert result_encrypt.exit_code == 0
    assert encrypted_file.exists()

    result_decrypt = runner.invoke(app, [
        "decrypt",
        str(encrypted_file),
        "--private-key-file", str(private_path),
        "--password", password,
    ])
    assert result_decrypt.exit_code == 0
    assert "text to encrypt" in result_decrypt.stdout

def test_encrypt_and_decrypt_with_base64_input(tmp_path, caplog):
    plaintext = "text base64 for testing"
    b64_input = base64.b64encode(plaintext.encode()).decode()
    encrypted_file = tmp_path / "encrypted_b64.json"

    private_path = tmp_path / "priv.pem"
    public_path = tmp_path / "pub.pem"

    with caplog.at_level(logging.WARNING, logger="dreamstone"):
        runner.invoke(app, [
            "genkey",
            "--private-path", str(private_path),
            "--public-path", str(public_path),
        ])

    logs_clean = "\n".join(remove_ansi_escape(r.getMessage()) for r in caplog.records)
    logs_clean = remove_rich_markup(logs_clean)
    match = re.search(r"A strong password was generated: ([\w\-]+)", logs_clean)
    password = match.group(1).strip() if match else None
    assert password is not None, "password not generated on log"

    result_encrypt = runner.invoke(app, [
        "encrypt",
        "--input-data", b64_input,
        "--base64",
        "--public-key-file", str(public_path),
        "--output-file", str(encrypted_file),
    ])
    assert result_encrypt.exit_code == 0
    assert encrypted_file.exists()

    result_decrypt = runner.invoke(app, [
        "decrypt",
        str(encrypted_file),
        "--private-key-file", str(private_path),
        "--password", password,
    ])
    assert result_decrypt.exit_code == 0
    assert plaintext in result_decrypt.stdout

def test_encrypt_fails_without_input(tmp_path, caplog):
    encrypted_file = tmp_path / "should_not_exist.json"

    with caplog.at_level(logging.ERROR, logger="dreamstone"):
        result = runner.invoke(app, [
            "encrypt",
            "--output-file", str(encrypted_file),
        ])

    assert result.exit_code != 0
    assert not encrypted_file.exists()
    logs_clean = "\n".join(remove_ansi_escape(r.getMessage()) for r in caplog.records)
    logs_clean = remove_rich_markup(logs_clean)
    assert "You must provide either --input-file or --input-data" in logs_clean


def test_encrypt_fails_with_both_input_file_and_data(tmp_path, caplog):
    input_file = tmp_path / "input.txt"
    input_file.write_text("text")
    encrypted_file = tmp_path / "fail.json"

    with caplog.at_level(logging.ERROR, logger="dreamstone"):
        result = runner.invoke(app, [
            "encrypt",
            "--input-file", str(input_file),
            "--input-data", "dGVzdGU=",
            "--output-file", str(encrypted_file),
        ])

    assert result.exit_code != 0
    assert not encrypted_file.exists()
    logs_clean = "\n".join(remove_ansi_escape(r.getMessage()) for r in caplog.records)
    logs_clean = remove_rich_markup(logs_clean)
    assert "You must provide only one of --input-file or --input-data" in logs_clean


def test_decrypt_writes_to_output_file(tmp_path, caplog):
    plaintext = "save on file"
    encrypted_file = tmp_path / "encrypted.json"
    decrypted_file = tmp_path / "decrypted.txt"
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"

    with caplog.at_level(logging.WARNING, logger="dreamstone"):
        runner.invoke(app, [
            "genkey", "--private-path", str(priv), "--public-path", str(pub)
        ])

    logs_clean = "\n".join(remove_ansi_escape(r.getMessage()) for r in caplog.records)
    logs_clean = remove_rich_markup(logs_clean)
    password = re.search(r"A strong password was generated: ([\w\-]+)", logs_clean).group(1).strip()

    runner.invoke(app, [
        "encrypt",
        "--input-data", plaintext,
        "--public-key-file", str(pub),
        "--output-file", str(encrypted_file),
    ])

    result = runner.invoke(app, [
        "decrypt",
        str(encrypted_file),
        "--private-key-file", str(priv),
        "--password", password,
        "--output-file", str(decrypted_file),
    ])

    assert result.exit_code == 0
    assert decrypted_file.read_text() == plaintext

def test_encrypt_with_generated_key_and_custom_paths(tmp_path, caplog):
    plaintext = "content with generated keys"
    encrypted_file = tmp_path / "encrypted.json"
    priv = tmp_path / "my_private.pem"
    pub = tmp_path / "my_public.pem"

    result = runner.invoke(app, [
        "encrypt",
        "--input-data", plaintext,
        "--output-file", str(encrypted_file),
        "--private-key-path", str(priv),
        "--public-key-path", str(pub),
        "--key-output-dir", str(tmp_path),
    ], catch_exceptions=False)

    assert result.exit_code == 0
    assert encrypted_file.exists()
    assert priv.exists()
    assert pub.exists()

def test_decrypt_fails_with_wrong_password(tmp_path, caplog):
    plaintext = "wrong password"
    encrypted_file = tmp_path / "encrypted.json"
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"

    with caplog.at_level(logging.WARNING, logger="dreamstone"):
        runner.invoke(app, [
            "genkey", "--private-path", str(priv), "--public-path", str(pub)
        ])

    runner.invoke(app, [
        "encrypt",
        "--input-data", plaintext,
        "--public-key-file", str(pub),
        "--output-file", str(encrypted_file),
    ])

    result = runner.invoke(app, [
        "decrypt",
        str(encrypted_file),
        "--private-key-file", str(priv),
        "--password", "senha_incorreta",
    ])

    assert result.exit_code != 0
    assert "Password was not given" not in result.stdout

def test_decrypt_requires_password_when_key_is_encrypted(tmp_path):
    plaintext = "secret with password required"
    encrypted_file = tmp_path / "encrypted.json"
    private_path = tmp_path / "priv.pem"
    public_path = tmp_path / "pub.pem"
    password = "SecureSecret!"

    runner.invoke(app, [
        "genkey",
        "--private-path", str(private_path),
        "--public-path", str(public_path),
        "--password", password
    ])

    runner.invoke(app, [
        "encrypt",
        "--input-data", plaintext,
        "--public-key-file", str(public_path),
        "--output-file", str(encrypted_file)
    ])

    result = runner.invoke(app, [
        "decrypt",
        str(encrypted_file),
        "--private-key-file", str(private_path),
    ])

    assert result.exit_code != 0
    assert "Password was not given" not in result.stdout

def test_encrypt_fails_with_invalid_base64_input(tmp_path, caplog):
    encrypted_file = tmp_path / "fail.json"

    with caplog.at_level(logging.ERROR, logger="dreamstone"):
        result = runner.invoke(app, [
            "encrypt",
            "--input-data", "###INVALID###BASE64==",
            "--base64",
            "--output-file", str(encrypted_file),
        ])

    logs_clean = "\n".join(remove_ansi_escape(r.getMessage()) for r in caplog.records)
    logs_clean = remove_rich_markup(logs_clean)

    assert result.exit_code != 0
    assert "Invalid input" in logs_clean
    assert not encrypted_file.exists()

def test_encrypted_payload_json_structure(tmp_path):
    plaintext = "structured content"
    encrypted_file = tmp_path / "estruturado.json"

    result = runner.invoke(app, [
        "encrypt",
        "--input-data", plaintext,
        "--output-file", str(encrypted_file),
        "--key-output-dir", str(tmp_path)
    ])

    assert result.exit_code == 0
    assert encrypted_file.exists()

    with open(encrypted_file, "r") as f:
        payload = json.load(f)

    assert "encrypted_key" in payload
    assert "nonce" in payload
    assert "ciphertext" in payload

def test_generated_password_has_minimum_length(tmp_path, caplog):
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"

    with caplog.at_level(logging.WARNING, logger="dreamstone"):
        runner.invoke(app, [
            "genkey",
            "--private-path", str(priv),
            "--public-path", str(pub),
        ])

    logs_clean = "\n".join(remove_ansi_escape(r.getMessage()) for r in caplog.records)
    logs_clean = remove_rich_markup(logs_clean)
    match = re.search(r"A strong password was generated: ([\w\-]+)", logs_clean)
    assert match, "password not generated on log"
    password = match.group(1).strip()
    assert len(password) >= 20, "password too short"

def test_encrypt_respects_log_level(tmp_path, caplog):
    encrypted_file = tmp_path / "silent.json"
    result = runner.invoke(app, [
        "encrypt",
        "--input-data", "dados",
        "--output-file", str(encrypted_file),
        "--log-level", "ERROR",
        "--key-output-dir", str(tmp_path)
    ])
    assert result.exit_code == 0
    assert encrypted_file.exists()
    assert not caplog.records, "No logs should be captured with ERROR level without errors"

@pytest.mark.parametrize("use_base64", [True, False])
def test_encrypt_decrypt_parametrized(tmp_path, use_base64):
    plaintext = "parameterized 123"
    encrypted = tmp_path / "out.json"
    decrypted = tmp_path / "dec.txt"
    priv = tmp_path / "a.pem"
    pub = tmp_path / "b.pem"

    password = "senha123"
    runner.invoke(app, ["genkey", "--private-path", str(priv), "--public-path", str(pub), "--password", password])

    args = [
        "encrypt",
        "--input-data", plaintext if not use_base64 else base64.b64encode(plaintext.encode()).decode(),
        "--output-file", str(encrypted),
        "--public-key-file", str(pub),
    ]
    if use_base64:
        args.append("--base64")

    result = runner.invoke(app, args)
    assert result.exit_code == 0

    result = runner.invoke(app, [
        "decrypt", str(encrypted),
        "--private-key-file", str(priv),
        "--password", password,
        "--output-file", str(decrypted)
    ])
    assert result.exit_code == 0
    assert decrypted.read_text() == plaintext

def test_decrypt_with_corrupted_private_key(tmp_path):
    plaintext = "corrupted test"
    encrypted_file = tmp_path / "enc.json"
    decrypted_file = tmp_path / "dec.txt"
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"

    runner.invoke(app, [
        "genkey", "--private-path", str(priv), "--public-path", str(pub), "--password", "abc123"
    ])

    runner.invoke(app, [
        "encrypt", "--input-data", plaintext,
        "--public-key-file", str(pub),
        "--output-file", str(encrypted_file)
    ])

    priv.write_text("isso não é uma chave")

    result = runner.invoke(app, [
        "decrypt", str(encrypted_file),
        "--private-key-file", str(priv),
        "--password", "abc123",
        "--output-file", str(decrypted_file)
    ])

    assert result.exit_code != 0
    assert not decrypted_file.exists()

def test_help_outputs():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Usage" in result.stdout
    assert "encrypt" in result.stdout
    assert "decrypt" in result.stdout
    assert "genkey" in result.stdout
