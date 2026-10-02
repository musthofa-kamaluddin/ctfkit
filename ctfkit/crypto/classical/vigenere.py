"""
ctfkit.crypto.classical.vigenere
Vigenere cipher solver using Index of Coincidence, beam search frequency analysis,
and known-prefix key derivation.
"""

from __future__ import annotations
import itertools
from dataclasses import dataclass
from typing import List, Tuple, Optional
from ctfkit.core.flags import FlagDetector, KnownPlaintextOracle
from ctfkit.core.statistics import (
    index_of_coincidence,
    quadgram_score,
    ENGLISH_LETTER_FREQUENCIES
)


@dataclass
class VigenereResult:
    key: str
    key_length: int
    plaintext: str
    score: float
    flag_found: Optional[str]


class VigenereSolver:
    """
    Automated Vigenere cryptanalysis.
    """

    def __init__(
        self,
        detector: Optional[FlagDetector] = None,
        oracle: Optional[KnownPlaintextOracle] = None
    ):
        self.detector = detector or FlagDetector()
        self.oracle = oracle or KnownPlaintextOracle()

    def estimate_key_lengths(self, alpha_text: str, max_len: int = 30) -> List[Tuple[int, float]]:
        """Estimates key lengths by comparing average slice IoC to English (0.067)."""
        scores: List[Tuple[int, float]] = []
        n = len(alpha_text)

        for klen in range(2, min(max_len + 1, n // 3)):
            slice_iocs = []
            for i in range(klen):
                col = alpha_text[i::klen]
                slice_iocs.append(index_of_coincidence(col))
            avg_ioc = sum(slice_iocs) / len(slice_iocs)
            diff = abs(avg_ioc - 0.067)
            scores.append((klen, diff))

        scores.sort(key=lambda x: x[1])
        return scores

    def get_top_column_shifts(self, column: str, top_k: int = 2) -> List[str]:
        """Finds top K candidate shifts for a single column using Chi-squared correlation."""
        n = len(column)
        if n == 0:
            return ['A']

        shift_scores: List[Tuple[int, float]] = []

        for shift in range(26):
            chi = 0.0
            dec = [chr((ord(c) - ord('A') - shift) % 26 + ord('A')) for c in column]
            counts = {chr(k + 65): dec.count(chr(k + 65)) for k in range(26)}

            for letter, exp_pct in ENGLISH_LETTER_FREQUENCIES.items():
                expected = (exp_pct / 100.0) * n
                observed = counts.get(letter, 0)
                chi += ((observed - expected) ** 2) / expected

            shift_scores.append((shift, chi))

        shift_scores.sort(key=lambda x: x[1])
        return [chr(s + ord('A')) for s, _ in shift_scores[:top_k]]

    def decrypt(self, text: str, key: str) -> str:
        key_upper = key.upper()
        klen = len(key_upper)
        res = []
        ki = 0

        for c in text:
            if 'a' <= c <= 'z':
                shift = ord(key_upper[ki % klen]) - ord('A')
                res.append(chr((ord(c) - ord('a') - shift) % 26 + ord('a')))
                ki += 1
            elif 'A' <= c <= 'Z':
                shift = ord(key_upper[ki % klen]) - ord('A')
                res.append(chr((ord(c) - ord('A') - shift) % 26 + ord('A')))
                ki += 1
            else:
                res.append(c)

        return "".join(res)

    def solve(self, ciphertext: str | bytes, candidate_lengths: Optional[List[int]] = None) -> List[VigenereResult]:
        text = ciphertext.decode("utf-8", errors="ignore") if isinstance(ciphertext, bytes) else ciphertext
        alpha_text = "".join(c.upper() for c in text if c.isalpha())
        if len(alpha_text) < 10:
            return []

        if not candidate_lengths:
            ranked_lens = self.estimate_key_lengths(alpha_text)
            candidate_lengths = [klen for klen, _ in ranked_lens[:4]]

        results: List[VigenereResult] = []

        # Strategy 1: Known-prefix key derivation
        alpha_pfx = "".join(c.upper() for c in self.oracle.prefix_str if c.isalpha())
        for klen in candidate_lengths:
            if klen <= len(alpha_pfx):
                key_chars = [
                    chr((ord(alpha_text[i]) - ord(alpha_pfx[i])) % 26 + ord('A'))
                    for i in range(klen)
                ]
                key_candidate = "".join(key_chars)
                pt = self.decrypt(text, key_candidate)
                flags = self.detector.search_string(pt)
                if flags:
                    results.append(VigenereResult(
                        key=key_candidate,
                        key_length=klen,
                        plaintext=pt,
                        score=9999.0,
                        flag_found=flags[0]
                    ))

        # Strategy 2: Multi-candidate column beam search
        for klen in candidate_lengths:
            col_candidates = [self.get_top_column_shifts(alpha_text[i::klen], top_k=2) for i in range(klen)]
            
            # Bound combinations to at most 64 to ensure instant execution
            if (2 ** klen) <= 64:
                all_key_tuples = list(itertools.product(*col_candidates))
            else:
                # Just take the top 1 per column if key length is large
                all_key_tuples = [tuple(c[0] for c in col_candidates)]

            for ktup in all_key_tuples:
                key_candidate = "".join(ktup)
                pt = self.decrypt(text, key_candidate)
                flags = self.detector.search_string(pt)
                flag_match = flags[0] if flags else None

                q_score = quadgram_score(pt)
                score = q_score * 10.0
                if flag_match:
                    score += 5000.0

                results.append(VigenereResult(
                    key=key_candidate,
                    key_length=klen,
                    plaintext=pt,
                    score=score,
                    flag_found=flag_match
                ))

        results.sort(key=lambda r: r.score, reverse=True)
        # Deduplicate results by key
        seen_keys = set()
        unique_results = []
        for r in results:
            if r.key not in seen_keys:
                seen_keys.add(r.key)
                unique_results.append(r)

        return unique_results[:5]
