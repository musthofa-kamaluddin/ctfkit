"""
ctfkit.crypto.xor.multi_byte
Repeating-key XOR cryptanalysis using normalized Hamming distance and block transposition.
"""

from __future__ import annotations
import itertools
from dataclasses import dataclass
from typing import List, Tuple, Optional
from ctfkit.core.flags import FlagDetector
from ctfkit.core.statistics import quadgram_score, printable_ascii_ratio
from ctfkit.crypto.xor.single_byte import SingleByteXORSolver


def hamming_distance(b1: bytes, b2: bytes) -> int:
    """Computes bitwise Hamming distance between two equal-length byte sequences."""
    return sum(bin(x ^ y).count("1") for x, y in zip(b1, b2))


@dataclass
class RepeatingKeyXORResult:
    key: bytes
    key_length: int
    plaintext: bytes
    score: float
    flag_found: Optional[str]


class RepeatingKeyXORSolver:
    """
    Automated Repeating-Key XOR cryptanalysis.
    Identifies key length via normalized edit distance and transposes blocks.
    """

    def __init__(self, flag_detector: Optional[FlagDetector] = None):
        self.flag_detector = flag_detector or FlagDetector()
        self.single_byte_solver = SingleByteXORSolver(self.flag_detector)

    def estimate_key_lengths(
        self,
        ciphertext: bytes,
        min_len: int = 2,
        max_len: int = 64,
        top_n: int = 6
    ) -> List[Tuple[int, float]]:
        """
        Calculates normalized Hamming distances across multiple block pairs
        to estimate the top N most likely key lengths.
        """
        scores: List[Tuple[int, float]] = []

        for klen in range(min_len, min(max_len + 1, len(ciphertext) // 2)):
            # Sample up to 4 consecutive blocks
            num_blocks = min(4, len(ciphertext) // klen)
            if num_blocks < 2:
                continue

            blocks = [ciphertext[i * klen : (i + 1) * klen] for i in range(num_blocks)]
            pairs = list(itertools.combinations(blocks, 2))
            
            distances = [hamming_distance(b1, b2) / klen for b1, b2 in pairs]
            avg_dist = sum(distances) / len(distances)
            scores.append((klen, avg_dist))

        # Sort ascending: lower normalized distance indicates higher probability of correct key length
        scores.sort(key=lambda x: x[1])
        return scores[:top_n]

    def solve(
        self,
        ciphertext: bytes,
        min_len: int = 2,
        max_len: int = 64,
        candidate_lengths: Optional[List[int]] = None
    ) -> List[RepeatingKeyXORResult]:
        if len(ciphertext) < min_len * 2:
            return []

        if not candidate_lengths:
            ranked_lens = self.estimate_key_lengths(ciphertext, min_len, max_len)
            candidate_lengths = [klen for klen, _ in ranked_lens]

        results: List[RepeatingKeyXORResult] = []

        for klen in candidate_lengths:
            key_bytes = bytearray(klen)

            # Transpose: collect every klen-th byte
            for i in range(klen):
                transposed_block = bytes(ciphertext[j] for j in range(i, len(ciphertext), klen))
                candidates = self.single_byte_solver.solve(transposed_block, top_k=1)
                if candidates:
                    key_bytes[i] = candidates[0].key
                else:
                    key_bytes[i] = 0

            recovered_key = bytes(key_bytes)
            # Decrypt full payload
            plaintext = bytes(
                ciphertext[i] ^ recovered_key[i % klen]
                for i in range(len(ciphertext))
            )

            flags = self.flag_detector.search_bytes(plaintext)
            flag_match = flags[0] if flags else None

            # Score the full reconstructed plaintext with quadgrams and printable ratio
            full_quad = quadgram_score(plaintext)
            full_p_ratio = printable_ascii_ratio(plaintext)
            final_score = (full_p_ratio * 50.0) + (full_quad * 10.0)
            if flag_match:
                final_score += 5000.0

            results.append(RepeatingKeyXORResult(
                key=recovered_key,
                key_length=klen,
                plaintext=plaintext,
                score=final_score,
                flag_found=flag_match
            ))

        results.sort(key=lambda r: r.score, reverse=True)
        return results
