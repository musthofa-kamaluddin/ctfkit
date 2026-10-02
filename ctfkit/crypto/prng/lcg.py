"""
ctfkit.crypto.prng.lcg
Linear Congruential Generator (LCG) parameter recovery and state prediction:
X_{n+1} = (a * X_n + c) mod m
"""

from __future__ import annotations
import math
from typing import List, Tuple, Optional


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean Algorithm returning (gcd, x, y) such that a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = egcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def modinv(a: int, m: int) -> Optional[int]:
    """Modular multiplicative inverse: a^(-1) mod m."""
    gcd, x, _ = egcd(a % m, m)
    if gcd != 1:
        return None
    return (x % m + m) % m


class LCGRecovery:
    """
    Recovers LCG parameters (a, c, m) from sequence observations.
    """

    @staticmethod
    def recover_modulus(states: List[int]) -> Optional[int]:
        """
        Recovers unknown modulus m from at least 6 consecutive full states
        using differences t_n = s_{n+1} - s_n and determinant relation:
        t_{n+2} * t_n - t_{n+1}^2 = 0 (mod m).
        """
        if len(states) < 6:
            return None

        diffs = [states[i + 1] - states[i] for i in range(len(states) - 1)]
        multiples = []
        for i in range(len(diffs) - 2):
            val = abs(diffs[i + 2] * diffs[i] - diffs[i + 1] ** 2)
            if val != 0:
                multiples.append(val)

        if not multiples:
            return None

        m = multiples[0]
        for val in multiples[1:]:
            m = math.gcd(m, val)
        return m if m > 1 else None

    @staticmethod
    def recover_params(states: List[int], modulus: Optional[int] = None) -> Optional[Tuple[int, int, int]]:
        """
        Recovers (a, c, m) from sequence.
        """
        if len(states) < 3:
            return None

        m = modulus or LCGRecovery.recover_modulus(states)
        if not m:
            return None

        s0, s1, s2 = states[0], states[1], states[2]
        delta0 = (s1 - s0) % m
        delta1 = (s2 - s1) % m

        inv_delta0 = modinv(delta0, m)
        if inv_delta0 is None:
            return None

        a = (delta1 * inv_delta0) % m
        c = (s1 - a * s0) % m
        return a, c, m
