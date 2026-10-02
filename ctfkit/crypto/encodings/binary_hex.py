"""
ctfkit.crypto.encodings.binary_hex
Binary bitstring and flexible hexadecimal decoding routines.
"""

from __future__ import annotations
import binascii
from typing import Optional


def decode_binary_str(data: bytes | str) -> Optional[bytes]:
    """
    Decodes bitstrings such as '01001000 01100001' or '0100100001100001' into bytes.
    """
    try:
        text = data.decode("ascii") if isinstance(data, bytes) else data
        clean = "".join(text.split())
        if not clean or any(c not in "01" for c in clean):
            return None
        if len(clean) % 8 != 0:
            return None
        byte_vals = [int(clean[i : i + 8], 2) for i in range(0, len(clean), 8)]
        return bytes(byte_vals)
    except Exception:
        return None


def decode_hex_stream(data: bytes | str) -> Optional[bytes]:
    """
    Decodes raw hexadecimal string, tolerating whitespace, newlines, and optional '0x' prefixes.
    """
    try:
        text = data.decode("ascii") if isinstance(data, bytes) else data
        clean = "".join(text.split()).replace("0x", "").replace("0X", "")
        if not clean or len(clean) % 2 != 0:
            return None
        return binascii.unhexlify(clean)
    except Exception:
        return None
