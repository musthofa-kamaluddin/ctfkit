"""
ctfkit.crypto.rsa.attacks
High-performance RSA attacks: Small e, Wiener, Fermat, Common Modulus, Hastad, Pollard p-1.
"""

from __future__ import annotations
import math
from dataclasses import dataclass
from typing import Optional, Tuple, List
from ctfkit.core.artifacts import RSAParameters
from ctfkit.core.flags import FlagDetector
from ctfkit.crypto.rsa.math_utils import (
    iroot,
    isqrt,
    egcd,
    modinv,
    crt,
    continued_fractions,
    convergents
)


@dataclass
class RSAResult:
    attack_name: str
    plaintext_int: int
    plaintext_bytes: bytes
    p: Optional[int] = None
    q: Optional[int] = None
    d: Optional[int] = None
    flag_found: Optional[str] = None


def int_to_bytes(n: int) -> bytes:
    """Converts a big integer to byte stream."""
    if n <= 0:
        return b""
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder="big")


def small_e_attack(n: int, e: int, c: int, max_k: int = 50000) -> Optional[int]:
    """
    Direct e-th root attack when m^e < n, or small k attack when m^e = c + k*n.
    """
    # Direct root check
    root, exact = iroot(c, e)
    if exact:
        return root

    # Small k iteration
    for k in range(1, max_k):
        target = c + k * n
        root, exact = iroot(target, e)
        if exact:
            return root

    return None


def fermat_factorization(n: int, max_iterations: int = 2000000) -> Optional[Tuple[int, int]]:
    """
    Fermat's Factorization Method: factors n when p and q are close:
    n = a^2 - b^2 = (a - b)(a + b)
    """
    a = isqrt(n)
    if a * a < n:
        a += 1

    for _ in range(max_iterations):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            p = a - b
            q = a + b
            if p > 1 and q > 1 and p * q == n:
                return p, q
        a += 1

    return None


def wiener_attack(n: int, e: int) -> Optional[Tuple[int, int, int]]:
    """
    Wiener's Attack using continued fractions: recovers small d < (1/3) * n^(1/4).
    Returns (d, p, q) if successful.
    """
    fracs = list(continued_fractions(e, n))
    for k, d in convergents(fracs):
        if k == 0 or d % 2 == 0:
            continue

        # phi = (e * d - 1) // k
        ed_sub_1 = e * d - 1
        if ed_sub_1 % k != 0:
            continue

        phi = ed_sub_1 // k
        # Roots of x^2 - (n - phi + 1)*x + n = 0 are p and q
        s = n - phi + 1
        discriminant = s * s - 4 * n
        if discriminant >= 0:
            root_disc = isqrt(discriminant)
            if root_disc * root_disc == discriminant:
                p = (s + root_disc) // 2
                q = (s - root_disc) // 2
                if p > 1 and q > 1 and p * q == n:
                    return d, p, q

    return None


def common_modulus_attack(c1: int, c2: int, e1: int, e2: int, n: int) -> Optional[int]:
    """
    Common Modulus Attack: two ciphertexts c1, c2 encrypted under same n with gcd(e1, e2) == 1.
    Finds r, s such that r*e1 + s*e2 = 1 => m = c1^r * c2^s (mod n).
    """
    g, r, s = egcd(e1, e2)
    if g != 1:
        return None

    if r < 0:
        c1_inv = modinv(c1, n)
        if c1_inv is None:
            return None
        c1_term = pow(c1_inv, -r, n)
    else:
        c1_term = pow(c1, r, n)

    if s < 0:
        c2_inv = modinv(c2, n)
        if c2_inv is None:
            return None
        c2_term = pow(c2_inv, -s, n)
    else:
        c2_term = pow(c2, s, n)

    m = (c1_term * c2_term) % n
    return m


def hastad_broadcast_attack(ciphertexts: List[int], moduli: List[int], e: int) -> Optional[int]:
    """
    Hastad's Broadcast Attack: same message encrypted with small exponent e across >= e distinct moduli.
    """
    if len(ciphertexts) < e or len(moduli) < e:
        return None

    c_slice = ciphertexts[:e]
    n_slice = moduli[:e]

    try:
        c_crt, _ = crt(c_slice, n_slice)
        m, exact = iroot(c_crt, e)
        if exact:
            return m
    except Exception:
        pass

    return None


def pollard_p_minus_1(n: int, b1: int = 100000) -> Optional[Tuple[int, int]]:
    """
    Pollard's p-1 algorithm for when p-1 is B1-smooth.
    """
    a = 2
    for j in range(2, b1):
        a = pow(a, j, n)
        d = math.gcd(a - 1, n)
        if 1 < d < n:
            return d, n // d
    return None


class RSAAutomatedTriage:
    """
    Autonomous RSA attack execution engine.
    Sequences instant checks before heavier computations.
    """

    def __init__(self, detector: Optional[FlagDetector] = None):
        self.detector = detector or FlagDetector()

    def audit(self, params: RSAParameters) -> Optional[RSAResult]:
        if not params.is_solvable_direct():
            return None

        n, e, c = params.n, params.e, params.c  # type: ignore

        # 1. Direct / Small e attack
        if e in (3, 5, 7, 17, 65537):
            m_root = small_e_attack(n, e, c, max_k=50000 if e <= 5 else 1000)
            if m_root:
                pt_bytes = int_to_bytes(m_root)
                flags = self.detector.search_bytes(pt_bytes)
                return RSAResult(
                    attack_name="Small e integer root",
                    plaintext_int=m_root,
                    plaintext_bytes=pt_bytes,
                    flag_found=flags[0] if flags else None
                )

        # 2. Wiener Attack (Small d)
        wiener_res = wiener_attack(n, e)
        if wiener_res:
            d, p, q = wiener_res
            m = pow(c, d, n)
            pt_bytes = int_to_bytes(m)
            flags = self.detector.search_bytes(pt_bytes)
            return RSAResult(
                attack_name="Wiener continued fractions (small d)",
                plaintext_int=m,
                plaintext_bytes=pt_bytes,
                p=p,
                q=q,
                d=d,
                flag_found=flags[0] if flags else None
            )

        # 3. Fermat Factorization (Close p, q)
        fermat_res = fermat_factorization(n, max_iterations=500000)
        if fermat_res:
            p, q = fermat_res
            phi = (p - 1) * (q - 1)
            d = modinv(e, phi)
            if d:
                m = pow(c, d, n)
                pt_bytes = int_to_bytes(m)
                flags = self.detector.search_bytes(pt_bytes)
                return RSAResult(
                    attack_name="Fermat factorization (close primes)",
                    plaintext_int=m,
                    plaintext_bytes=pt_bytes,
                    p=p,
                    q=q,
                    d=d,
                    flag_found=flags[0] if flags else None
                )

        # 4. Pollard's p - 1
        pollard_res = pollard_p_minus_1(n, b1=50000)
        if pollard_res:
            p, q = pollard_res
            phi = (p - 1) * (q - 1)
            d = modinv(e, phi)
            if d:
                m = pow(c, d, n)
                pt_bytes = int_to_bytes(m)
                flags = self.detector.search_bytes(pt_bytes)
                return RSAResult(
                    attack_name="Pollard p-1 smooth factor",
                    plaintext_int=m,
                    plaintext_bytes=pt_bytes,
                    p=p,
                    q=q,
                    d=d,
                    flag_found=flags[0] if flags else None
                )

        return None
