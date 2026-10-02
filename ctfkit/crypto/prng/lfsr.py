"""
ctfkit.crypto.prng.lfsr
Linear Feedback Shift Register (LFSR) cryptanalysis using Berlekamp-Massey algorithm over GF(2).
"""

from __future__ import annotations
from typing import List, Tuple


def berlekamp_massey(sequence: List[int]) -> Tuple[List[int], int]:
    """
    Computes the minimal connection polynomial C(x) and linear complexity L
    for a binary sequence over GF(2).
    
    Returns:
        (connection_polynomial_coefficients, linear_complexity)
    """
    n = len(sequence)
    c = [1]  # Connection polynomial C(x)
    b = [1]  # Previous polynomial B(x)
    l = 0    # Linear complexity
    m = 1    # Number of steps since last discrepancy

    for i in range(n):
        # Calculate discrepancy d = s_i ^ sum_{j=1}^l c_j * s_{i-j} (mod 2)
        d = sequence[i]
        for j in range(1, len(c)):
            d ^= (c[j] & sequence[i - j])

        if d == 1:
            # T(x) = C(x)
            t = list(c)
            # C(x) = C(x) ^ (x^m * B(x))
            shifted_b = [0] * m + b
            max_len = max(len(c), len(shifted_b))
            c = [(c[k] if k < len(c) else 0) ^ (shifted_b[k] if k < len(shifted_b) else 0) for k in range(max_len)]

            if 2 * l <= i:
                l = i + 1 - l
                b = t
                m = 1
            else:
                m += 1
        else:
            m += 1

    return c, l


class LFSRSimulator:
    """Simulates an LFSR forward to predict keystreams from state and polynomial."""

    def __init__(self, polynomial: List[int], initial_state: List[int]):
        self.poly = polynomial  # e.g., [1, c1, c2, ..., cL]
        self.state = list(initial_state)
        self.degree = len(self.state)

    def next_bit(self) -> int:
        out = self.state[0]
        # Feedback bit = sum_{i=1}^degree poly[i] * state[degree - i] mod 2
        feedback = 0
        for i in range(1, len(self.poly)):
            if i <= len(self.state):
                feedback ^= (self.poly[i] & self.state[-i])
        self.state = self.state[1:] + [feedback]
        return out
