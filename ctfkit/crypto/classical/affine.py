"""
ctfkit.crypto.classical.affine
Affine and Atbash cipher solvers. Decryption: D(y) = a^(-1) * (y - b) mod 26.
"""

from __future__ import annotations
import math
from dataclasses import dataclass
from typing import List, Optional
from ctfkit.core.flags import FlagDetector
from ctfkit.core.statistics import quadgram_score, english_frequency_score

COPRIME_26 = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]


@dataclass
class AffineResult:
    a: int
    b: int
    plaintext: str
    score: float
    flag_found: Optional[str]


class AffineSolver:
    """
    Evaluates all 312 possible Affine key pairs (a, b) and Atbash.
    """

    def __init__(self, detector: Optional[FlagDetector] = None):
        self.detector = detector or FlagDetector()

    def decrypt(self, text: str, a: int, b: int) -> str:
        a_inv = pow(a, -1, 26)
        res = []
        for c in text:
            if 'a' <= c <= 'z':
                y = ord(c) - ord('a')
                res.append(chr(((a_inv * (y - b)) % 26) + ord('a')))
            elif 'A' <= c <= 'Z':
                y = ord(c) - ord('A')
                res.append(chr(((a_inv * (y - b)) % 26) + ord('A')))
            else:
                res.append(c)
        return "".join(res)

    def solve_atbash(self, text: str) -> AffineResult:
        """Atbash is equivalent to Affine cipher with a=25, b=25."""
        pt = self.decrypt(text, a=25, b=25)
        flags = self.detector.search_string(pt)
        q_score = quadgram_score(pt)
        return AffineResult(
            a=25,
            b=25,
            plaintext=pt,
            score=q_score * 10.0 + (5000.0 if flags else 0.0),
            flag_found=flags[0] if flags else None
        )

    def solve(self, ciphertext: str | bytes, top_k: int = 3) -> List[AffineResult]:
        text = ciphertext.decode("utf-8", errors="ignore") if isinstance(ciphertext, bytes) else ciphertext
        if not text:
            return []

        results: List[AffineResult] = []

        for a in COPRIME_26:
            for b in range(26):
                pt = self.decrypt(text, a, b)
                flags = self.detector.search_string(pt)
                flag_match = flags[0] if flags else None

                q_score = quadgram_score(pt)
                f_score = english_frequency_score(pt.encode("utf-8", errors="ignore"))
                score = f_score + (q_score * 5.0)
                if flag_match:
                    score += 5000.0

                results.append(AffineResult(
                    a=a,
                    b=b,
                    plaintext=pt,
                    score=score,
                    flag_found=flag_match
                ))

        results.sort(key=lambda r: r.score, reverse=True)
        return results[:top_k]
