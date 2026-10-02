"""
ctfkit.crypto.aes.aes_helper
Unified AES primitives wrapper supporting ECB, CBC, CTR, GCM modes and PKCS#7 padding.
"""

from __future__ import annotations
from typing import Optional, Tuple
from Crypto.Cipher import AES


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = 16) -> Optional[bytes]:
    if not data or len(data) % block_size != 0:
        return None
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        return None
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        return None
    return data[:-pad_len]


class AESHelper:
    """Convenience decryptor and encryptor for standard AES challenge modes."""

    @staticmethod
    def decrypt_ecb(ciphertext: bytes, key: bytes, unpad: bool = True) -> Optional[bytes]:
        try:
            cipher = AES.new(key, AES.MODE_ECB)
            pt = cipher.decrypt(ciphertext)
            return pkcs7_unpad(pt) if unpad else pt
        except Exception:
            return None

    @staticmethod
    def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes, unpad: bool = True) -> Optional[bytes]:
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            pt = cipher.decrypt(ciphertext)
            return pkcs7_unpad(pt) if unpad else pt
        except Exception:
            return None

    @staticmethod
    def decrypt_ctr(ciphertext: bytes, key: bytes, nonce: bytes) -> Optional[bytes]:
        try:
            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
            return cipher.decrypt(ciphertext)
        except Exception:
            return None

    @staticmethod
    def decrypt_gcm(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes, aad: bytes = b"") -> Optional[bytes]:
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            if aad:
                cipher.update(aad)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except Exception:
            return None
