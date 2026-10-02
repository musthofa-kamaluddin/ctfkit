"""
ctfkit.crypto.classical.transposition
Transposition cipher cryptanalysis: Rail Fence solver across variable rail depths.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional
from ctfkit.core.flags import FlagDetector
from ctfkit.core.statistics import quadgram_score


@dataclass
class RailFenceResult:
    rails: int
    plaintext: str
    score: float
    flag_found: Optional[str]


class RailFenceSolver:
    """
    Evaluates Rail Fence zig-zag transposition for rail counts from 2 to max_rails.
    """

    def __init__(self, detector: Optional[FlagDetector] = None):
        self.detector = detector or FlagDetector()

    def decrypt(self, ciphertext: str, rails: int) -> str:
        n = len(ciphertext)
        if rails <= 1 or rails >= n:
            return ciphertext

        # Mark zig-zag trajectory
        rail_pattern = []
        rail = 0
        direction = 1
        for _ in range(n):
            rail_pattern.append(rail)
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1
            rail += direction

        # Count how many characters belong to each rail
        rail_lengths = [rail_pattern.count(r) for r in range(rails)]

        # Slice ciphertext into each rail's characters
        rail_strings = []
        idx = 0
        for length in rail_lengths:
            rail_strings.append(list(ciphertext[idx : idx + length]))
            idx += length

        # Reconstruct plaintext following original zig-zag sequence
        plaintext = []
        for r in rail_pattern:
            plaintext.append(rail_strings[r].pop(0))

        return "".join(plaintext)

    def solve(self, ciphertext: str | bytes, max_rails: int = 25, top_k: int = 3) -> List[RailFenceResult]:
        text = ciphertext.decode("utf-8", errors="ignore") if isinstance(ciphertext, bytes) else ciphertext
        if len(text) < 4:
            return []

        results: List[RailFenceResult] = []

        for r in range(2, min(max_rails + 1, len(text))):
            pt = self.decrypt(text, r)
            flags = self.detector.search_string(pt)
            flag_match = flags[0] if flags else None

            q_score = quadgram_score(pt)
            score = q_score * 10.0
            if flag_match:
                score += 5000.0

            results.append(RailFenceResult(
                rails=r,
                plaintext=pt,
                score=score,
                flag_found=flag_match
            ))

        results.sort(key=lambda x: x.score, reverse=True)
        return results[:top_k]
