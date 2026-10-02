"""
ctfkit.crypto.rsa.franklin_reiter
Franklin-Reiter Related Message Attack on two linear ciphertexts under same RSA modulus.
"""

from __future__ import annotations
from typing import List, Optional
from ctfkit.crypto.rsa.math_utils import modinv
from ctfkit.crypto.rsa.attacks import int_to_bytes


def poly_divmod(dividend: List[int], divisor: List[int], n: int) -> Tuple[List[int], List[int]]:
    """Polynomial division over Z_n. Coefficients stored [c0, c1, ..., c_deg]."""
    # Strip leading zero coefficients
    while len(dividend) > 1 and dividend[-1] == 0:
        dividend.pop()
    while len(divisor) > 1 and divisor[-1] == 0:
        divisor.pop()

    deg_div = len(divisor) - 1
    lead_inv = modinv(divisor[-1], n)
    if lead_inv is None:
        raise ValueError("Cannot invert leading coefficient in Z_n")

    rem = list(dividend)
    quot = [0] * max(1, len(dividend) - deg_div)

    while len(rem) - 1 >= deg_div and any(rem):
        cur_deg = len(rem) - 1
        factor = (rem[-1] * lead_inv) % n
        shift = cur_deg - deg_div
        quot[shift] = factor

        for i in range(len(divisor)):
            rem[i + shift] = (rem[i + shift] - factor * divisor[i]) % n

        while len(rem) > 1 and rem[-1] == 0:
            rem.pop()

    return quot, rem


def poly_gcd(f: List[int], g: List[int], n: int) -> List[int]:
    """Euclidean algorithm for monic polynomial GCD in Z_n[x]."""
    while any(g) and len(g) > 1:
        _, rem = poly_divmod(f, g, n)
        f, g = g, rem

    # Make monic
    lead_inv = modinv(f[-1], n)
    if lead_inv:
        f = [(c * lead_inv) % n for c in f]
    return f


def franklin_reiter_attack(
    c1: int,
    c2: int,
    e: int,
    n: int,
    a: int = 1,
    b: int = 0
) -> Optional[bytes]:
    """
    Recovers m1 when c1 = m1^e and c2 = (a*m1 + b)^e (mod n).
    Specialized for small e (e.g. e=3).
    """
    if e != 3:
        return None

    # f1(x) = x^3 - c1 => [-c1, 0, 0, 1]
    f1 = [(-c1) % n, 0, 0, 1]

    # f2(x) = (a*x + b)^3 - c2 = a^3*x^3 + 3*a^2*b*x^2 + 3*a*b^2*x + (b^3 - c2)
    f2 = [
        (pow(b, 3, n) - c2) % n,
        (3 * a * pow(b, 2, n)) % n,
        (3 * pow(a, 2, n) * b) % n,
        pow(a, 3, n) % n
    ]

    try:
        gcd_res = poly_gcd(f1, f2, n)
        # Monic linear gcd: [ -m1, 1 ] => gcd_res[0] = -m1
        if len(gcd_res) == 2 and gcd_res[1] == 1:
            m1 = (-gcd_res[0]) % n
            return int_to_bytes(m1)
    except Exception:
        pass

    return None
