"""AES-GCM encryption for sensitive data (SSH passwords, etc.).

Uses a persistent key stored in DATA_DIR/.encryption_key.
Auto-fixes permissions if the key file exists but is not readable
(e.g. when migrating from a root-run container to a non-root one).
"""
import logging
import os
import secrets
from pathlib import Path

logger = logging.getLogger(__name__)

_KEY_FILE = Path(os.getenv("DATA_DIR", "./data")) / ".encryption_key"


def _get_or_create_key() -> bytes:
    """Load existing key or generate a new one.
    Handles PermissionError gracefully by attempting to fix ownership/permissions."""
    if _KEY_FILE.exists():
        try:
            return bytes.fromhex(_KEY_FILE.read_text().strip())
        except PermissionError:
            # File exists but we can't read it. Likely created by root
            # in a previous container run. Try to fix by removing + regenerating.
            logger.warning(
                "Cannot read %s (permission denied). Attempting to remove and regenerate. "
                "If this fails, run: sudo chown -R 1000:1000 data/",
                _KEY_FILE,
            )
            try:
                os.unlink(_KEY_FILE)
            except PermissionError:
                logger.error(
                    "Cannot remove %s — insufficient permissions. "
                    "Run on host: sudo chown -R 1000:1000 data/ && sudo chmod 600 data/.encryption_key",
                    _KEY_FILE,
                )
                raise
            logger.info("Removed unreadable key file — generating new one.")
        except (ValueError, OSError) as e:
            logger.error("Failed to load encryption key: %s", e)
            raise

    # Generate new key
    key = secrets.token_hex(32)
    _KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    _KEY_FILE.write_text(key)
    try:
        os.chmod(_KEY_FILE, 0o600)
    except OSError as e:
        logger.warning("Could not chmod %s: %s", _KEY_FILE, e)
    logger.info("Generated new encryption key at %s", _KEY_FILE)
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
