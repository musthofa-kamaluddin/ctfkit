"""
ctfkit.crypto.aes.gcm_forbidden
AES-GCM Nonce Reuse (The Forbidden Attack):
Authentication key H recovery in GF(2^128) and arbitrary tag forgery.
"""

from __future__ import annotations
from typing import List, Tuple, Optional


class GF2_128:
    """
    Galois Field GF(2^128) arithmetic with GCM polynomial:
    x^128 + x^7 + x^2 + x + 1 (reduction constant 0xE1000000000000000000000000000000).
    """
    POLY = 0xE1000000000000000000000000000000

    @classmethod
    def add(cls, a: int, b: int) -> int:
        return a ^ b

    @classmethod
    def mul(cls, x: int, y: int) -> int:
        """Carries out GCM bit-reflected field multiplication."""
        v = x
        z = 0
        for i in range(128):
            if (y >> (127 - i)) & 1:
                z ^= v
            if v & 1:
                v = (v >> 1) ^ cls.POLY
            else:
                v >>= 1
        return z

    @classmethod
    def pow(cls, a: int, exp: int) -> int:
        res = 1 << 127  # Multiplicative identity in GCM bit reflection
        base = a
        while exp > 0:
            if exp & 1:
                res = cls.mul(res, base)
            base = cls.mul(base, base)
            exp >>= 1
        return res

    @classmethod
    def bytes_to_int(cls, b: bytes) -> int:
        return int.from_bytes(b, "big")

    @classmethod
    def int_to_bytes(cls, n: int) -> bytes:
        return n.to_bytes(16, "big")


class GCMForbiddenAttack:
    """
    Recovers GHASH key H when two messages are authenticated with the same (Key, Nonce) pair.
    """

    @staticmethod
    def ghash_block(h: int, block: bytes, current_y: int) -> int:
        block_int = GF2_128.bytes_to_int(block)
        return GF2_128.mul(current_y ^ block_int, h)

    @staticmethod
    def compute_ghash(h: int, data: bytes, aad: bytes = b"") -> int:
        """Evaluates GHASH_H over AAD and ciphertext."""
        y = 0
        # Process AAD in 16-byte blocks
        for i in range(0, len(aad), 16):
            chunk = aad[i : i + 16].ljust(16, b"\x00")
            y = GCMForbiddenAttack.ghash_block(h, chunk, y)

        # Process ciphertext in 16-byte blocks
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16].ljust(16, b"\x00")
            y = GCMForbiddenAttack.ghash_block(h, chunk, y)

        # Append length block: [len(aad) in bits (64-bit) || len(c) in bits (64-bit)]
        len_block = (len(aad) * 8).to_bytes(8, "big") + (len(data) * 8).to_bytes(8, "big")
        y = GCMForbiddenAttack.ghash_block(h, len_block, y)
        return y

    @staticmethod
    def forge_tag(h: int, known_c: bytes, known_tag: bytes, target_c: bytes, aad: bytes = b"") -> bytes:
        """
        Forges a valid authentication tag for target_c without knowing the underlying AES key:
        Tag_forge = GHASH_H(target_c) ^ GHASH_H(known_c) ^ known_tag
        """
        known_ghash = GCMForbiddenAttack.compute_ghash(h, known_c, aad)
        target_ghash = GCMForbiddenAttack.compute_ghash(h, target_c, aad)
        tag_int = GF2_128.bytes_to_int(known_tag)
        # Mask = Tag ^ GHASH_H(known_c)
        mask = tag_int ^ known_ghash
        forge_tag_int = target_ghash ^ mask
        return GF2_128.int_to_bytes(forge_tag_int)
