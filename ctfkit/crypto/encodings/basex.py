"""
ctfkit.crypto.encodings.basex
Standard and esoteric Base encoding and decoding routines with automatic padding restoration.
"""

from __future__ import annotations
import base64
from typing import Optional

# Base58 Bitcoin alphabet
B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def decode_base64(data: bytes | str) -> Optional[bytes]:
    """Decodes standard Base64, adding missing '=' padding if necessary."""
    try:
        raw = data.encode("ascii") if isinstance(data, str) else data
        clean = b"".join(raw.split())
        # Restore padding
        missing_padding = len(clean) % 4
        if missing_padding != 0:
            clean += b"=" * (4 - missing_padding)
        return base64.b64decode(clean, validate=True)
    except Exception:
        return None


def decode_base32(data: bytes | str) -> Optional[bytes]:
    """Decodes Base32 with automatic padding restoration."""
    try:
        raw = data.encode("ascii") if isinstance(data, str) else data
        clean = b"".join(raw.split()).upper()
        missing_padding = len(clean) % 8
        if missing_padding != 0:
            clean += b"=" * (8 - missing_padding)
        return base64.b32decode(clean)
    except Exception:
        return None


def decode_base16(data: bytes | str) -> Optional[bytes]:
    """Decodes Base16 (Hex)."""
    try:
        raw = data.encode("ascii") if isinstance(data, str) else data
        clean = b"".join(raw.split())
        if len(clean) % 2 != 0:
            return None
        return base64.b16decode(clean.upper())
    except Exception:
        return None


def decode_base85(data: bytes | str) -> Optional[bytes]:
    """Decodes standard RFC 1924 Base85."""
    try:
        raw = data.encode("ascii") if isinstance(data, str) else data
        clean = b"".join(raw.split())
        return base64.b85decode(clean)
    except Exception:
        return None


def decode_ascii85(data: bytes | str) -> Optional[bytes]:
    """Decodes Adobe / ZeroMQ Ascii85."""
    try:
        raw = data.encode("ascii") if isinstance(data, str) else data
        clean = b"".join(raw.split())
        return base64.a85decode(clean)
    except Exception:
        return None


def decode_base58(data: bytes | str) -> Optional[bytes]:
    """Decodes Base58 (Bitcoin alphabet)."""
    try:
        raw = data.encode("ascii") if isinstance(data, str) else data
        clean = b"".join(raw.split())
        num = 0
        for b in clean:
            idx = B58_ALPHABET.find(bytes([b]))
            if idx == -1:
                return None
            num = num * 58 + idx

        # Convert to bytes
        res = []
        while num > 0:
            res.append(num & 0xFF)
            num >>= 8
        res.reverse()

        # Leading zeroes preserved as '1'
        pad_len = 0
        for b in clean:
            if b == ord(b'1'):
                pad_len += 1
            else:
                break
        return b"\x00" * pad_len + bytes(res)
    except Exception:
        return None
