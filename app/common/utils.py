# common/utils.py

import hashlib
import base64
import time

def sha256(data: bytes) -> bytes:
    """Computes SHA-256 digest (32 bytes)."""
    return hashlib.sha256(data).digest()

def sha256_hex(data: bytes) -> str:
    """Computes SHA-256 digest and returns the hex string (64 chars)."""
    return hashlib.sha256(data).hexdigest()

def b64_encode(data: bytes) -> str:
    """Base64 encodes bytes for transmission."""
    return base64.b64encode(data).decode('utf-8')

def b64_decode(data: str) -> bytes:
    """Base64 decodes a string into bytes."""
    return base64.b64decode(data)

def now_ms() -> int:
    """Returns current time in milliseconds for nonces/timestamps."""
    return int(time.time() * 1000)