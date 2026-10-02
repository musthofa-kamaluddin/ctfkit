"""
ctfkit.crypto.xor.crib_drag
Automated and interactive crib-dragging engine for multi-stream XOR and keystream reuse.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Tuple, Optional
from ctfkit.core.statistics import quadgram_score, printable_ascii_ratio
from ctfkit.core.flags import FlagDetector, KnownPlaintextOracle


@dataclass
class CribDragMatch:
    position: int
    crib: bytes
    counterpart: bytes
    score: float
    is_printable: bool


class CribDragger:
    """
    Automated crib dragger for two or more ciphertexts sharing a one-time keystream.
    """

    def __init__(self, oracle: Optional[KnownPlaintextOracle] = None):
        self.oracle = oracle or KnownPlaintextOracle()
        self.flag_detector = FlagDetector()

    def xor_bytes(self, a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    def drag(self, c1: bytes, c2: bytes, crib: bytes) -> List[CribDragMatch]:
        """
        Drags a known crib across all valid offsets of (c1 ^ c2).
        Returns ranked matches based on counterpart English plausibility.
        """
        diff = self.xor_bytes(c1, c2)
        crib_len = len(crib)
        matches: List[CribDragMatch] = []

        if len(diff) < crib_len:
            return []

        for pos in range(len(diff) - crib_len + 1):
            diff_slice = diff[pos : pos + crib_len]
            counterpart = self.xor_bytes(diff_slice, crib)

            p_ratio = printable_ascii_ratio(counterpart)
            if p_ratio < 0.70:
                continue

            q_score = quadgram_score(counterpart)
            score = (p_ratio * 40.0) + (q_score * 10.0)

            matches.append(CribDragMatch(
                position=pos,
                crib=crib,
                counterpart=counterpart,
                score=score,
                is_printable=p_ratio > 0.95
            ))

        matches.sort(key=lambda m: m.score, reverse=True)
        return matches

    def auto_solve_with_known_prefix(
        self,
        ciphertexts: List[bytes],
        seed_crib: Optional[bytes] = None
    ) -> Tuple[bytes, List[bytes]]:
        """
        Given multiple ciphertexts sharing a keystream, seeds with known flag prefix
        at position 0, recovers the initial keystream slice, and cascades across all targets.
        """
        if not ciphertexts:
            return b"", []

        crib = seed_crib or self.oracle.prefix_bytes
        min_len = min(len(c) for c in ciphertexts)
        keystream = bytearray(min_len)
        crib_slice_len = min(min_len, len(crib))

        # Anchor crib at position 0 on the first ciphertext
        # (or test which ciphertext generates high quadgram score when paired with crib)
        best_c_idx = 0
        best_keystream_candidate = bytes(ciphertexts[0][i] ^ crib[i] for i in range(crib_slice_len))

        # Apply recovered keystream slice to all ciphertexts
        decrypted_slices = []
        for c in ciphertexts:
            decrypted_slices.append(
                bytes(c[i] ^ best_keystream_candidate[i] for i in range(crib_slice_len))
            )

        return best_keystream_candidate, decrypted_slices
