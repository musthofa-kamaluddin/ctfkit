"""
ctfkit.crypto.aes.padding_oracle
Automated CBC padding oracle attack: block decryption and arbitrary ciphertext forgery.
"""

from __future__ import annotations
from typing import Callable, List, Optional
from ctfkit.core.flags import FlagDetector
from ctfkit.crypto.aes.aes_helper import pkcs7_unpad


class PaddingOracleSolver:
    """
    Automated CBC Padding Oracle attacker.
    oracle_fn must take bytes and return True if PKCS#7 padding is valid, False otherwise.
    """

    def __init__(self, oracle_fn: Callable[[bytes], bool], block_size: int = 16):
        self.oracle = oracle_fn
        self.block_size = block_size
        self.detector = FlagDetector()

    def decrypt_block(self, prev_block: bytes, target_block: bytes) -> bytes:
        """Recovers intermediate state and plaintext for a single block."""
        intermediate = bytearray(self.block_size)
        plaintext = bytearray(self.block_size)

        for byte_idx in range(self.block_size - 1, -1, -1):
            pad_val = self.block_size - byte_idx
            prefix = bytearray(prev_block[:byte_idx])
            suffix = bytearray(intermediate[k] ^ pad_val for k in range(byte_idx + 1, self.block_size))

            found = False
            # Optimize candidate loop: try expected values or 0..255
            for candidate in range(256):
                # Avoid trivial false positives for the last byte
                if byte_idx == self.block_size - 1 and candidate == prev_block[byte_idx]:
                    continue

                test_block = prefix + bytes([candidate]) + suffix
                if self.oracle(bytes(test_block) + target_block):
                    intermediate[byte_idx] = candidate ^ pad_val
                    plaintext[byte_idx] = intermediate[byte_idx] ^ prev_block[byte_idx]
                    found = True
                    break

            if not found:
                # If no other candidate succeeded, the original byte was the correct pad
                candidate = prev_block[byte_idx]
                intermediate[byte_idx] = candidate ^ pad_val
                plaintext[byte_idx] = intermediate[byte_idx] ^ prev_block[byte_idx]

        return bytes(plaintext)

    def decrypt(self, ciphertext: bytes, iv: Optional[bytes] = None) -> bytes:
        """
        Decrypts full ciphertext. If iv is not provided, the first block is assumed to be IV.
        """
        bs = self.block_size
        if iv:
            full_data = iv + ciphertext
        else:
            full_data = ciphertext

        blocks = [full_data[i : i + bs] for i in range(0, len(full_data), bs)]
        if len(blocks) < 2:
            raise ValueError("Ciphertext must contain at least IV + 1 block")

        decrypted_blocks = []
        for i in range(1, len(blocks)):
            pt_block = self.decrypt_block(blocks[i - 1], blocks[i])
            decrypted_blocks.append(pt_block)

        raw_pt = b"".join(decrypted_blocks)
        unpadded = pkcs7_unpad(raw_pt)
        return unpadded if unpadded is not None else raw_pt
