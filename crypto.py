import os
import secrets
from pathlib import Path


_KEY_FILE = Path(os.getenv("DATA_DIR", "./data")) / ".encryption_key"


def _get_or_create_key() -> bytes:
    if _KEY_FILE.exists():
        return bytes.fromhex(_KEY_FILE.read_text().strip())
    key = secrets.token_hex(32)
    _KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    _KEY_FILE.write_text(key)
    os.chmod(_KEY_FILE, 0o600)
    return bytes.fromhex(key)


_KEY = _get_or_create_key()


def encrypt(plaintext: str) -> str:
    if not plaintext:
        return ""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import base64 as _b64
    nonce = secrets.token_bytes(12)
    ct = AESGCM(_KEY).encrypt(nonce, plaintext.encode(), None)
    return _b64.b64encode(nonce + ct).decode()


def decrypt(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import base64 as _b64
    raw = _b64.b64decode(ciphertext)
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(_KEY).decrypt(nonce, ct, None).decode()
