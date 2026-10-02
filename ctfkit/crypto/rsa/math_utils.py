"""
ctfkit.crypto.rsa.math_utils
High-precision integer and modular arithmetic utilities for RSA cryptanalysis.
"""

from __future__ import annotations
import math
from typing import Tuple, List, Optional, Generator


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean Algorithm: returns (g, x, y) such that a*x + b*y = g = gcd(a, b)."""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = egcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y


def modinv(a: int, m: int) -> Optional[int]:
    """Computes modular multiplicative inverse: a^(-1) mod m."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        return None
    return (x % m + m) % m


def isqrt(n: int) -> int:
    """Exact integer square root."""
    return math.isqrt(n)


def iroot(n: int, k: int) -> Tuple[int, bool]:
    """
    Computes floor(n^(1/k)) and a boolean indicating if root is exact (r^k == n).
    Uses high-speed integer binary search.
    """
    if n < 0:
        raise ValueError("Cannot compute root of negative integer")
    if n == 0:
        return 0, True
    if k == 1:
        return n, True
    if k == 2:
        r = math.isqrt(n)
        return r, r * r == n

    # Binary search for exact k-th root
    low = 1
    high = 1 << ((n.bit_length() + k - 1) // k)
    while low <= high:
        mid = (low + high) // 2
        p = pow(mid, k)
        if p == n:
            return mid, True
        elif p < n:
            low = mid + 1
        else:
            high = mid - 1

    return high, pow(high, k) == n


def crt(remainders: List[int], moduli: List[int]) -> Tuple[int, int]:
    """
    Chinese Remainder Theorem for pairwise coprime moduli.
    Returns (x, M) where x == remainders[i] (mod moduli[i]) and M = prod(moduli).
    """
    if len(remainders) != len(moduli) or not remainders:
        raise ValueError("Invalid parameters for Chinese Remainder Theorem")

    m_total = 1
    for m in moduli:
        m_total *= m

    result = 0
    for r, m in zip(remainders, moduli):
        m_i = m_total // m
        inv = modinv(m_i, m)
        if inv is None:
            raise ValueError(f"Moduli are not pairwise coprime: gcd({m_i}, {m}) != 1")
        result = (result + r * m_i * inv) % m_total

    return result, m_total


def continued_fractions(numerator: int, denominator: int) -> Generator[int, None, None]:
    """Yields continued fraction quotient sequence [a0, a1, a2, ...] of numerator/denominator."""
    while denominator != 0:
        q = numerator // denominator
        yield q
        numerator, denominator = denominator, numerator - q * denominator


def convergents(quotients: List[int]) -> Generator[Tuple[int, int], None, None]:
    """
    Yields (p_k, q_k) convergents from continued fraction quotients.
    p_0 = q0, q_0 = 1
    p_1 = q0*q1 + 1, q_1 = q1
    p_k = qk * p_{k-1} + p_{k-2}
    """
    p_prev, p_curr = 0, 1
    q_prev, q_curr = 1, 0

    for q in quotients:
        p_next = q * p_curr + p_prev
        q_next = q * q_curr + q_prev
        yield p_next, q_next
        p_prev, p_curr = p_curr, p_next
        q_prev, q_curr = q_curr, q_next
