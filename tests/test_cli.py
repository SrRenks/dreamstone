import pytest
import re
import base64
import logging
from typer.testing import CliRunner
from dreamstone.cli.main import app
import os
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

def extract_generated_password(output: str) -> str:
    match = re.search(r"Generated password.*?:\s*([^\s]+)", output)
    return match.group(1).strip() if match else None

def test_genkey_creates_files_and_warns_password(tmp_path):
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"

    result = runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub), "--overwrite"])
    assert result.exit_code == 0
    assert priv.exists()
    assert pub.exists()
    assert extract_generated_password(result.output)

def test_genkey_with_custom_password(tmp_path):
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    password = "MyStrongPass123!"

    result = runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub), "--password", password, "--overwrite"])
    assert result.exit_code == 0
    assert priv.exists()
    assert pub.exists()
    assert "Generated password" not in result.output

def test_genkey_password_path(tmp_path):
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    pw_file = tmp_path / "password.txt"

    result = runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub), "--password-path", str(pw_file), "--overwrite"])
    assert result.exit_code == 0
    assert pw_file.exists()
    content = pw_file.read_text().strip()
    assert content != ""

def test_encrypt_and_decrypt_string(tmp_path):
    plaintext = "Hello World!"
    enc_file = tmp_path / "enc.json"
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"

    runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub), "--overwrite"])
    password = extract_generated_password(runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub), "--overwrite"]).output)
    password = password or "dummy"

    runner.invoke(app, ["encrypt", plaintext, "--out", str(enc_file), "--public-key", str(pub)])
    result = runner.invoke(app, ["decrypt", str(enc_file), "--private-key", str(priv), "--password", password])
    assert result.exit_code == 0
    assert plaintext in result.stdout

def test_encrypt_and_decrypt_file(tmp_path):
    content = "File input test"
    input_file = tmp_path / "input.txt"
    input_file.write_text(content)
    enc_file = tmp_path / "enc.json"
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"

    runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub), "--overwrite"])
    password = extract_generated_password(runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub), "--overwrite"]).output)

    runner.invoke(app, ["encrypt", str(input_file), "--out", str(enc_file), "--public-key", str(pub)])
    result = runner.invoke(app, ["decrypt", str(enc_file), "--private-key", str(priv), "--password", password])
    assert result.exit_code == 0
    assert content in result.stdout

def test_encrypt_and_decrypt_base64(tmp_path):
    plaintext = "Base64 test"
    b64_input = base64.b64encode(plaintext.encode()).decode()
    enc_file = tmp_path / "enc.json"
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"

    runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub), "--overwrite"])
    password = extract_generated_password(runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub), "--overwrite"]).output)

    runner.invoke(app, ["encrypt", b64_input, "--base64", "--out", str(enc_file), "--public-key", str(pub)])
    result = runner.invoke(app, ["decrypt", str(enc_file), "--private-key", str(priv), "--password", password])
    assert result.exit_code == 0
    assert plaintext in result.stdout

def test_encrypt_fails_without_input(tmp_path, caplog):
    enc_file = tmp_path / "fail.json"
    with caplog.at_level(logging.ERROR, logger="dreamstone"):
        result = runner.invoke(app, ["encrypt", "--out", str(enc_file)])

    result = runner.invoke(app, ["encrypt", "--out", str(enc_file)])
    assert result.exit_code != 0
    assert "Missing argument 'INPUT" in result.stderr

def test_decrypt_writes_to_file(tmp_path):
    plaintext = "Output file test"
    enc_file = tmp_path / "enc.json"
    dec_file = tmp_path / "dec.txt"
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"

    runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub), "--overwrite"])
    password = extract_generated_password(runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub), "--overwrite"]).output)

    runner.invoke(app, ["encrypt", plaintext, "--out", str(enc_file), "--public-key", str(pub)])
    result = runner.invoke(app, ["decrypt", str(enc_file), "--private-key", str(priv), "--password", password, "--out", str(dec_file)])
    assert result.exit_code == 0
    assert dec_file.read_text() == plaintext

def test_encrypt_generates_keys_with_hash_naming(tmp_path):
    plaintext = "hash test"
    enc_file = tmp_path / "enc.json"

    priv_dir = tmp_path / "private"
    pub_dir = tmp_path / "public"
    priv_dir.mkdir(parents=True, exist_ok=True)
    pub_dir.mkdir(parents=True, exist_ok=True)

    runner.invoke(
        app,
        [
            "encrypt",
            plaintext,
            "--out", str(enc_file),
            "--private-key", str(priv_dir),
            "--public-key", str(pub_dir),
        ]
    )

    priv_files = list(priv_dir.glob("private_*.pem"))
    pub_files = list(pub_dir.glob("public_*.pem"))

    assert len(priv_files) == 1
    assert len(pub_files) == 1

def test_encrypt_invalid_public_key(tmp_path):
    plaintext = "invalid key test"
    enc_file = tmp_path / "fail.json"
    invalid_pub = tmp_path / "invalid.pem"
    invalid_pub.write_text("not a key")

    result = runner.invoke(app, ["encrypt", plaintext, "--out", str(enc_file), "--public-key", str(invalid_pub)])
    assert result.exit_code != 0
    assert not enc_file.exists()

def test_help_outputs():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Usage" in result.stdout
    assert "encrypt" in result.stdout
    assert "decrypt" in result.stdout
    assert "genkey" in result.stdout

def test_genkey_overwrite_existing(tmp_path):
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    priv.write_text("old data")
    pub.write_text("old data")

    result = runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub), "--overwrite"])
    assert result.exit_code == 0
    assert priv.read_text() != "old data"
    assert pub.read_text() != "old data"

def test_genkey_no_show_password(tmp_path):
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"

    result = runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub), "--no-show-password"])
    assert result.exit_code == 0
    assert "Generated password" not in result.output

def test_encrypt_nonexistent_file(tmp_path):
    enc_file = tmp_path / "enc.json"
    missing_file = tmp_path / "missing.txt"

    result = runner.invoke(app, ["encrypt", str(missing_file), "--out", str(enc_file)])
    assert result.exit_code == 1

def test_encrypt_invalid_base64(tmp_path):
    enc_file = tmp_path / "enc.json"
    result = runner.invoke(app, ["encrypt", "invalid_base64$$$", "--out", str(enc_file), "--base64"])
    assert result.exit_code != 0

def test_encrypt_multiple_same_input(tmp_path):
    text = "repeat test"
    enc_file1 = tmp_path / "enc1.json"
    enc_file2 = tmp_path / "enc2.json"

    runner.invoke(app, ["encrypt", text, "--out", str(enc_file1)])
    runner.invoke(app, ["encrypt", text, "--out", str(enc_file2)])

    assert enc_file1.read_text() != enc_file2.read_text()

def test_decrypt_wrong_key(tmp_path):
    enc_file = tmp_path / "enc.json"
    dec_file = tmp_path / "dec.txt"
    priv1 = tmp_path / "priv1.pem"
    pub1 = tmp_path / "pub1.pem"
    priv2 = tmp_path / "priv2.pem"
    pub2 = tmp_path / "pub2.pem"

    runner.invoke(app, ["genkey", "--private-key", str(priv1), "--public-key", str(pub1)])
    runner.invoke(app, ["genkey", "--private-key", str(priv2), "--public-key", str(pub2)])

    runner.invoke(app, ["encrypt", "secret", "--out", str(enc_file), "--public-key", str(pub1)])
    result = runner.invoke(app, ["decrypt", str(enc_file), "--private-key", str(priv2)])
    assert result.exit_code != 0

def test_decrypt_invalid_password(tmp_path):
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    enc_file = tmp_path / "enc.json"
    pw_file = tmp_path / "wrong_pw.txt"

    runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub)])
    runner.invoke(app, ["encrypt", "secret", "--out", str(enc_file), "--public-key", str(pub)])

    pw_file.write_text("incorrectpassword")
    result = runner.invoke(app, ["decrypt", str(enc_file), "--private-key", str(priv), "--password-path", str(pw_file)])
    assert result.exit_code != 0

@pytest.fixture
def keypair(tmp_path):
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub)])
    password = extract_generated_password(runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub)]).output)
    return priv, pub, password

def test_encrypt_decrypt_empty_string(tmp_path):
    enc_file = tmp_path / "enc.json"
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"

    runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub), "--overwrite"])
    password = extract_generated_password(
        runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub), "--overwrite"]).output
    )

    empty_file = tmp_path / "empty.txt"
    empty_file.write_text("")

    runner.invoke(app, ["encrypt", str(empty_file), "--out", str(enc_file), "--public-key", str(pub)])
    result = runner.invoke(app, ["decrypt", str(enc_file), "--private-key", str(priv), "--password", password])

    assert result.exit_code == 0
    assert result.stdout.strip() == ""

def test_decrypt_with_directory_instead_of_file(tmp_path):
    enc_dir = tmp_path / "enc_dir"
    enc_dir.mkdir()

    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub), "--overwrite"])

    result = runner.invoke(
        app,
        ["decrypt", str(enc_dir), "--private-key", str(priv)]
    )
    assert result.exit_code != 0
    assert "is a directory" in result.output

def test_encrypt_decrypt_unicode_string(tmp_path):

    plaintext = "Hello 🌍✨🚀"
    enc_file = tmp_path / "enc.json"
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"

    runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub), "--overwrite"])
    password = extract_generated_password(runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub), "--overwrite"]).output)

    runner.invoke(app, ["encrypt", plaintext, "--out", str(enc_file), "--public-key", str(pub)])
    result = runner.invoke(app, ["decrypt", str(enc_file), "--private-key", str(priv), "--password", password])
    assert result.exit_code == 0
    assert plaintext in result.stdout

def test_decrypt_corrupted_json(tmp_path):
    corrupted_file = tmp_path / "corrupt.json"
    corrupted_file.write_text("{ this is not valid json }")
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"

    runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub), "--overwrite"])
    password = extract_generated_password(
        runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub), "--overwrite"]).output
    )

    result = runner.invoke(
        app, ["decrypt", str(corrupted_file), "--private-key", str(priv), "--password", password]
    )

    assert result.exit_code != 0
    assert isinstance(result.exception, json.JSONDecodeError)

def test_encrypt_large_binary_file(tmp_path):
    large_file = tmp_path / "large.bin"
    large_file.write_bytes(os.urandom(1024 * 1024))
    enc_file = tmp_path / "enc.json"
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"

    runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub), "--overwrite"])
    password = extract_generated_password(
        runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub), "--overwrite"]).output
    )

    runner.invoke(app, ["encrypt", str(large_file), "--out", str(enc_file), "--public-key", str(pub)])
    result = runner.invoke(app, ["decrypt", str(enc_file), "--private-key", str(priv), "--password", password])
    assert result.exit_code == 0
    assert enc_file.exists()

def test_genkey_overwrite_behavior(tmp_path):
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"

    priv.write_text("old_private")
    pub.write_text("old_public")

    result = runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub)])
    assert result.exit_code == 0

    assert priv.read_text() == "old_private"
    assert pub.read_text() == "old_public"

    priv1 = tmp_path / "priv_1.pem"
    pub1 = tmp_path / "pub_1.pem"
    assert priv1.exists()
    assert pub1.exists()
    assert priv1.read_text() != "old_private"
    assert pub1.read_text() != "old_public"

    result = runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub), "--overwrite"])
    assert result.exit_code == 0

    assert priv.read_text() != "old_private"
    assert pub.read_text() != "old_public"

def test_encrypt_with_directory_instead_of_file(tmp_path):
    enc_file = tmp_path / "enc.json"
    dir_input = tmp_path / "input_dir"
    dir_input.mkdir()

    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub), "--overwrite"])

    result = runner.invoke(app, ["encrypt", str(dir_input), "--out", str(enc_file), "--public-key", str(pub)])
    assert result.exit_code != 0
    assert not enc_file.exists()

def test_genkey_password_path_creates_directory(tmp_path):
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    nested_dir = tmp_path / "nested" / "dir"
    pw_file = nested_dir / "password.txt"

    assert not nested_dir.exists()

    result = runner.invoke(app, ["genkey", "--private-key", str(priv), "--public-key", str(pub),
                                 "--password-path", str(pw_file), "--overwrite"])
    assert result.exit_code == 0
    assert nested_dir.exists()

    assert pw_file.exists()
    content = pw_file.read_text().strip()
    assert content != ""