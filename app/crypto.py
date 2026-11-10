import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.errors import StartupError


def load_or_create_key(path: Path) -> bytes:
    if path.is_dir():
        raise StartupError(f"SECRET_PATH is a directory: {path}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise StartupError(
            f"Could not create the directory for SECRET_PATH {path}: {exc.strerror}"
        ) from exc
    if not os.access(path.parent, os.W_OK | os.X_OK):
        raise StartupError(f"SECRET_PATH directory is not writable: {path.parent}")
    if path.exists():
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise StartupError(f"Could not read SECRET_PATH {path}: {exc.strerror}") from exc
        if len(data) != 32:
            raise StartupError(f"SECRET_PATH {path} must be 32 bytes.")
        try:
            os.chmod(path, 0o600)
        except OSError as exc:
            raise StartupError(
                f"Could not set permissions on SECRET_PATH {path}: {exc.strerror}"
            ) from exc
        return data
    data = secrets.token_bytes(32)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        raise StartupError(f"Could not create SECRET_PATH {path}: {exc.strerror}") from exc
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    return data


def encrypt(key: bytes, plaintext: str):
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce, ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> str:
    raw = AESGCM(key).decrypt(nonce, ciphertext, None)
    return raw.decode("utf-8")
