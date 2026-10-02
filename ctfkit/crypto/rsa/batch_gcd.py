"""
ctfkit.crypto.rsa.batch_gcd
Batch GCD cryptanalysis across lists of RSA moduli.
"""

from __future__ import annotations
import math
from typing import List, Dict, Tuple, Optional


def batch_gcd(moduli: List[int]) -> Dict[int, Tuple[int, int]]:
    """
    Computes pairwise GCDs to identify shared prime factors across RSA public keys.
    Returns a dictionary mapping factored modulus -> (p, q).
    """
    factored: Dict[int, Tuple[int, int]] = {}
    k = len(moduli)

    for i in range(k):
        for j in range(i + 1, k):
            n1, n2 = moduli[i], moduli[j]
            if n1 == n2:
                continue
            g = math.gcd(n1, n2)
            if 1 < g < n1:
                factored[n1] = (g, n1 // g)
            if 1 < g < n2:
                factored[n2] = (g, n2 // g)

    return factored
