import base64
import hashlib
import hmac
import struct
import time
from typing import Optional


def _decode_secret(secret: str) -> bytes:
    secret = secret.strip().replace(" ", "").upper()
    padding = "=" * ((8 - len(secret) % 8) % 8)
    try:
        return base64.b32decode(secret + padding, casefold=True)
    except Exception:
        return secret.encode("utf-8")


def generate_totp(
    secret: str,
    period: int = 30,
    digits: int = 6,
    for_time: Optional[float] = None,
) -> str:
    if for_time is None:
        for_time = time.time()
    counter = int(for_time) // period
    key = _decode_secret(secret)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10**digits)).zfill(digits)


def totp_seconds_remaining(period: int = 30, for_time: Optional[float] = None) -> int:
    if for_time is None:
        for_time = time.time()
    return period - int(for_time) % period - 1
