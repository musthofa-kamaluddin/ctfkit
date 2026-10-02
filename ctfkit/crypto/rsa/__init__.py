"""
ctfkit.crypto.rsa
RSA cryptanalysis and automated attack suite:
Small e, Wiener, Fermat, Common Modulus, Hastad, Coppersmith, Franklin-Reiter, Batch GCD.
"""

from ctfkit.crypto.rsa.math_utils import egcd, modinv, iroot, isqrt, crt
from ctfkit.crypto.rsa.attacks import (
    RSAResult,
    RSAAutomatedTriage,
    small_e_attack,
    wiener_attack,
    fermat_factorization,
    common_modulus_attack,
    hastad_broadcast_attack,
    pollard_p_minus_1,
    int_to_bytes
)
from ctfkit.crypto.rsa.coppersmith import CoppersmithSolver
from ctfkit.crypto.rsa.franklin_reiter import franklin_reiter_attack
from ctfkit.crypto.rsa.batch_gcd import batch_gcd

__all__ = [
    "egcd",
    "modinv",
    "iroot",
    "isqrt",
    "crt",
    "RSAResult",
    "RSAAutomatedTriage",
    "small_e_attack",
    "wiener_attack",
    "fermat_factorization",
    "common_modulus_attack",
    "hastad_broadcast_attack",
    "pollard_p_minus_1",
    "int_to_bytes",
    "CoppersmithSolver",
    "franklin_reiter_attack",
    "batch_gcd",
]
