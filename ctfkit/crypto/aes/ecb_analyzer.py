"""
ctfkit.crypto.aes.ecb_analyzer
ECB block collision detection and automated byte-at-a-time ECB decryption engine.
"""

from __future__ import annotations
from typing import Callable, Tuple, Optional, Dict
from ctfkit.core.flags import FlagDetector


def detect_ecb_mode(ciphertext: bytes, block_size: int = 16) -> Tuple[bool, int]:
    """
    Detects ECB mode by checking for repeated blocks of size block_size.
    Returns (is_ecb, duplicate_block_count).
    """
    if len(ciphertext) < block_size * 2:
        return False, 0

    blocks = [ciphertext[i : i + block_size] for i in range(0, len(ciphertext), block_size)]
    unique_blocks = set(blocks)
    duplicates = len(blocks) - len(unique_blocks)
    return duplicates > 0, duplicates


class ECBByteAtATimeSolver:
    """
    Recovers secret appended to user input:
    Oracle(P) = AES-ECB(P || SECRET, Key)
    """

    def __init__(self, oracle: Callable[[bytes], bytes], block_size: int = 16):
        self.oracle = oracle
        self.block_size = block_size
        self.detector = FlagDetector()

    def find_target_length(self) -> int:
        """Determines secret length by measuring padding increments."""
        base_len = len(self.oracle(b""))
        pad = 0
        while True:
            pad += 1
            cur_len = len(self.oracle(b"A" * pad))
            if cur_len > base_len:
                return base_len - pad

    def solve(self, max_bytes: Optional[int] = None) -> bytes:
        """
        Recovers secret byte-by-byte using prefix alignment and 256-dictionary lookup.
        """
        target_len = max_bytes or self.find_target_length()
        recovered = bytearray()

        for i in range(target_len):
            block_idx = i // self.block_size
            pad_len = self.block_size - 1 - (i % self.block_size)
            padding = b"A" * pad_len

            # Target output block
            target_output = self.oracle(padding)
            target_block = target_output[block_idx * self.block_size : (block_idx + 1) * self.block_size]

            # Build dictionary for all 256 byte possibilities
            found_byte = None
            known_context = bytes(padding + recovered)

            for candidate in range(256):
                probe = known_context[-(self.block_size - 1):] + bytes([candidate])
                probe_output = self.oracle(probe)
                probe_block = probe_output[:self.block_size]

                if probe_block == target_block:
                    found_byte = candidate
                    break

            if found_byte is not None:
                recovered.append(found_byte)
                # Check for early termination if flag recovered
                if self.detector.contains_flag(bytes(recovered)):
                    break
            else:
                break

        return bytes(recovered)
