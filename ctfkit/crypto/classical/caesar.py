"""
ctfkit.crypto.classical.caesar
Automated Caesar / ROT-N / ROT13 cryptanalysis.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional
from ctfkit.core.flags import FlagDetector
from ctfkit.core.statistics import quadgram_score, english_frequency_score


@dataclass
class CaesarResult:
    shift: int
    plaintext: str
    score: float
    flag_found: Optional[str]


class CaesarSolver:
    """
    Evaluates all 25 Caesar shifts across alphabet letters (preserving case and non-alpha).
    """

    def __init__(self, detector: Optional[FlagDetector] = None):
        self.detector = detector or FlagDetector()

    def shift_text(self, text: str, shift: int) -> str:
        res = []
        for c in text:
            if 'a' <= c <= 'z':
                res.append(chr((ord(c) - ord('a') - shift) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                res.append(chr((ord(c) - ord('A') - shift) % 26 + ord('A')))
            else:
                res.append(c)
        return "".join(res)

    def solve(self, ciphertext: str | bytes, top_k: int = 3) -> List[CaesarResult]:
        text = ciphertext.decode("utf-8", errors="ignore") if isinstance(ciphertext, bytes) else ciphertext
        if not text:
            return []

        results: List[CaesarResult] = []

        for shift in range(1, 26):
            pt = self.shift_text(text, shift)
            flags = self.detector.search_string(pt)
            flag_match = flags[0] if flags else None

            q_score = quadgram_score(pt)
            f_score = english_frequency_score(pt.encode("utf-8", errors="ignore"))

            score = f_score + (q_score * 5.0)
            if flag_match:
                score += 5000.0

            results.append(CaesarResult(
                shift=shift,
                plaintext=pt,
                score=score,
                flag_found=flag_match
            ))

        results.sort(key=lambda r: r.score, reverse=True)
        return results[:top_k]
