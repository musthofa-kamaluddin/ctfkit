"""
ctfkit.crypto.xor.single_byte
High-performance single-byte XOR analyzer with letter frequency, quadgram, and flag scoring.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional
from ctfkit.core.flags import FlagDetector
from ctfkit.core.statistics import (
    quadgram_score,
    printable_ascii_ratio,
    index_of_coincidence,
    english_frequency_score
)


@dataclass
class SingleByteXORResult:
    key: int
    plaintext: bytes
    score: float
    flag_found: Optional[str]
    printable_ratio: float
    frequency_score: float


class SingleByteXORSolver:
    """
    Evaluates all 256 possible single-byte XOR keys.
    Ranks candidates using letter frequency and flag matching.
    """

    def __init__(self, flag_detector: Optional[FlagDetector] = None):
        self.flag_detector = flag_detector or FlagDetector()

    def solve(self, ciphertext: bytes, top_k: int = 5) -> List[SingleByteXORResult]:
        if not ciphertext:
            return []

        results: List[SingleByteXORResult] = []

        for key in range(256):
            pt = bytes(b ^ key for b in ciphertext)
            flags = self.flag_detector.search_bytes(pt)
            flag_match = flags[0] if flags else None

            p_ratio = printable_ascii_ratio(pt)
            # Prune completely unprintable byte candidates early unless flag matches
            if p_ratio < 0.60 and not flag_match:
                continue

            freq_score = english_frequency_score(pt)

            if flag_match:
                composite_score = 1000.0 + freq_score
            else:
                composite_score = freq_score + (p_ratio * 15.0)

            results.append(SingleByteXORResult(
                key=key,
                plaintext=pt,
                score=composite_score,
                flag_found=flag_match,
                printable_ratio=p_ratio,
                frequency_score=freq_score
            ))

        # Sort descending by score
        results.sort(key=lambda r: r.score, reverse=True)
        return results[:top_k]
