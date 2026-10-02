"""
Unit tests for ctfkit.crypto.rsa attacks and number theory utilities.
"""

import unittest
from ctfkit.core.artifacts import RSAParameters
from ctfkit.crypto.rsa.math_utils import iroot, crt, modinv
from ctfkit.crypto.rsa.attacks import (
    RSAAutomatedTriage,
    small_e_attack,
    wiener_attack,
    fermat_factorization,
    common_modulus_attack,
    hastad_broadcast_attack,
    int_to_bytes
)
from ctfkit.crypto.rsa.batch_gcd import batch_gcd
from ctfkit.crypto.rsa.franklin_reiter import franklin_reiter_attack


class TestRSAAttacks(unittest.TestCase):

    def test_small_e_and_automated_triage(self):
        # m = "HackToday26{small_e_win}"
        msg = b"HackToday26{small_e_win}"
        m = int.from_bytes(msg, "big")
        e = 3
        c = pow(m, e)
        # Large modulus so c < n
        n = 1 << 1024

        triage = RSAAutomatedTriage()
        res = triage.audit(RSAParameters(n=n, e=e, c=c))
        self.assertIsNotNone(res)
        self.assertEqual(res.plaintext_bytes, msg)
        self.assertIn("HackToday26{small_e_win}", res.flag_found)

    def test_wiener_attack(self):
        # Generate known small d test case
        # p, q = small primes for fast test
        p = 100000000000031
        q = 100000100000041
        n = p * q
        phi = (p - 1) * (q - 1)
        d = 1013  # d < (1/3) * n^(1/4)
        e = modinv(d, phi)

        msg = b"HT26{d}"
        m = int.from_bytes(msg, "big")
        c = pow(m, e, n)

        triage = RSAAutomatedTriage()
        res = triage.audit(RSAParameters(n=n, e=e, c=c))
        self.assertIsNotNone(res)
        self.assertEqual(res.plaintext_bytes, msg)
        self.assertEqual(res.d, d)

    def test_fermat_factorization(self):
        # p and q very close
        p = 1000000000000037
        q = 1000000000000091
        n = p * q
        e = 65537
        phi = (p - 1) * (q - 1)
        d = modinv(e, phi)

        msg = b"HT26{close}"
        m = int.from_bytes(msg, "big")
        c = pow(m, e, n)

        triage = RSAAutomatedTriage()
        res = triage.audit(RSAParameters(n=n, e=e, c=c))
        self.assertIsNotNone(res)
        self.assertEqual(res.plaintext_bytes, msg)
        self.assertEqual(res.p, min(p, q))
        self.assertEqual(res.q, max(p, q))

    def test_common_modulus(self):
        p = 104729
        q = 104743
        n = p * q
        e1 = 17
        e2 = 65537
        m = 133742
        c1 = pow(m, e1, n)
        c2 = pow(m, e2, n)

        recovered_m = common_modulus_attack(c1, c2, e1, e2, n)
        self.assertEqual(recovered_m, m)

    def test_hastad_broadcast(self):
        # 3 moduli for e = 3
        moduli = [104729 * 104743, 104759 * 104761, 104773 * 104779]
        e = 3
        m = 133742
        ciphertexts = [pow(m, e, n) for n in moduli]

        recovered_m = hastad_broadcast_attack(ciphertexts, moduli, e)
        self.assertEqual(recovered_m, m)

    def test_batch_gcd(self):
        p = 104729
        q1 = 104743
        q2 = 104759
        n1 = p * q1
        n2 = p * q2

        factored = batch_gcd([n1, n2, 99999999])
        self.assertIn(n1, factored)
        self.assertIn(n2, factored)
        self.assertEqual(factored[n1][0], p)
        self.assertEqual(factored[n2][0], p)

    def test_franklin_reiter(self):
        p = 104729
        q = 104743
        n = p * q
        e = 3
        m1 = 12345
        m2 = (m1 + 42) % n
        c1 = pow(m1, e, n)
        c2 = pow(m2, e, n)

        rec_bytes = franklin_reiter_attack(c1, c2, e, n, a=1, b=42)
        self.assertIsNotNone(rec_bytes)
        self.assertEqual(int.from_bytes(rec_bytes, "big"), m1)


if __name__ == "__main__":
    unittest.main()
