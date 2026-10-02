"""
ctfkit.crypto.xor.known_plaintext
Exploits known flag headers (e.g., HackToday26{) to derive XOR keys and reconstruct plaintexts.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, List
from ctfkit.core.flags import KnownPlaintextOracle, FlagDetector


@dataclass
class KnownPlaintextXORResult:
    key_candidate: bytes
    assumed_key_length: int
    plaintext: bytes
    confidence: float
    flag_found: Optional[str]


class KnownPlaintextXORSolver:
    """
    Drives XOR key derivation by anchoring on known plaintext headers.
    """

    def __init__(
        self,
        oracle: Optional[KnownPlaintextOracle] = None,
        detector: Optional[FlagDetector] = None
    ):
        self.oracle = oracle or KnownPlaintextOracle()
        self.detector = detector or FlagDetector()

    def solve(
        self,
        ciphertext: bytes,
        custom_known: Optional[bytes] = None,
        max_period: int = 32
    ) -> List[KnownPlaintextXORResult]:
        """
        Derives keystream from known prefix and searches for periodic key repetitions.
        """
        prefix = custom_known or self.oracle.prefix_bytes
        if not ciphertext or not prefix:
            return []

        limit = min(len(ciphertext), len(prefix))
        keystream_prefix = bytes(ciphertext[i] ^ prefix[i] for i in range(limit))

        results: List[KnownPlaintextXORResult] = []

        # Case 1: Key length L <= limit (Key repeats fully within the known window)
        for period in range(1, limit + 1):
            candidate_key = keystream_prefix[:period]
            # Verify if this period consistently matches the rest of keystream_prefix
            consistent = True
            for i in range(period, limit):
                if keystream_prefix[i] != candidate_key[i % period]:
                    consistent = False
                    break

            if consistent:
                # Decrypt full ciphertext with this repeating key
                pt = bytes(ciphertext[i] ^ candidate_key[i % period] for i in range(len(ciphertext)))
                flags = self.detector.search_bytes(pt)
                flag_match = flags[0] if flags else None

                results.append(KnownPlaintextXORResult(
                    key_candidate=candidate_key,
                    assumed_key_length=period,
                    plaintext=pt,
                    confidence=1.0 if flag_match else 0.85,
                    flag_found=flag_match
                ))

        # Case 2: Partial key when period > limit
        # Decrypt as much as possible using keystream_prefix
        partial_pt = bytes(ciphertext[i] ^ keystream_prefix[i] for i in range(limit))
        flags = self.detector.search_bytes(partial_pt)
        results.append(KnownPlaintextXORResult(
            key_candidate=keystream_prefix,
            assumed_key_length=len(keystream_prefix),
            plaintext=partial_pt,
            confidence=0.5,
            flag_found=flags[0] if flags else None
        ))

        results.sort(key=lambda r: (r.flag_found is not None, r.confidence), reverse=True)
        return results
