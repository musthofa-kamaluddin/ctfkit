"""
Unit tests for ctfkit.crypto.xor and ctfkit.crypto.prng modules.
"""

import unittest
import random
from ctfkit.core.flags import FlagDetector
from ctfkit.crypto.xor.single_byte import SingleByteXORSolver
from ctfkit.crypto.xor.multi_byte import RepeatingKeyXORSolver
from ctfkit.crypto.xor.known_plaintext import KnownPlaintextXORSolver
from ctfkit.crypto.prng.mt19937 import MT19937Cloner, untemper
from ctfkit.crypto.prng.lcg import LCGRecovery
from ctfkit.crypto.prng.lfsr import berlekamp_massey


class TestXORAndPRNG(unittest.TestCase):

    def setUp(self):
        self.flag_detector = FlagDetector()

    def test_single_byte_xor(self):
        plain = b"HackToday26{single_byte_xor_flag_recovery}"
        key = 0x5A
        cipher = bytes(b ^ key for b in plain)

        solver = SingleByteXORSolver(self.flag_detector)
        results = solver.solve(cipher, top_k=3)

        self.assertTrue(len(results) > 0)
        best = results[0]
        self.assertEqual(best.key, key)
        self.assertEqual(best.plaintext, plain)
        self.assertIn("HackToday26{single_byte_xor_flag_recovery}", best.flag_found)

    def test_repeating_key_xor(self):
        plain = (
            b"HackToday26{repeating_key_xor_is_vulnerable_to_hamming_and_frequency_analysis}"
            b" and additional natural english sentences to make the sample long enough for block analysis."
        )
        key = b"VIGENERE"
        cipher = bytes(plain[i] ^ key[i % len(key)] for i in range(len(plain)))

        solver = RepeatingKeyXORSolver(self.flag_detector)
        results = solver.solve(cipher, min_len=4, max_len=12)

        self.assertTrue(len(results) > 0)
        best = results[0]
        self.assertEqual(best.key, key)
        self.assertIn("HackToday26{repeating_key_xor", best.plaintext.decode(errors="ignore"))

    def test_known_plaintext_xor(self):
        plain = b"HackToday26{known_plaintext_anchors_are_devastating}"
        # Repeating key with length 4: 'PWN!'
        key = b"PWN!"
        cipher = bytes(plain[i] ^ key[i % len(key)] for i in range(len(plain)))

        solver = KnownPlaintextXORSolver(detector=self.flag_detector)
        results = solver.solve(cipher)

        self.assertTrue(len(results) > 0)
        best = results[0]
        self.assertEqual(best.key_candidate, key)
        self.assertEqual(best.plaintext, plain)
        self.assertEqual(best.flag_found, "HackToday26{known_plaintext_anchors_are_devastating}")

    def test_mt19937_cloner(self):
        # Generate 624 outputs from a real Python random instance
        orig_rng = random.Random(133742)
        samples = [orig_rng.getrandbits(32) for _ in range(624)]

        # Clone using MT19937Cloner
        cloned_rng = MT19937Cloner.clone_python_random(samples)

        # The next 10 outputs must match identically!
        for _ in range(10):
            self.assertEqual(orig_rng.getrandbits(32), cloned_rng.getrandbits(32))

    def test_lcg_recovery(self):
        # Known LCG parameters
        a = 1664525
        c = 1013904223
        m = 2**32
        
        state = 123456789
        states = []
        for _ in range(10):
            state = (a * state + c) % m
            states.append(state)

        rec_a, rec_c, rec_m = LCGRecovery.recover_params(states, modulus=m)
        self.assertEqual(rec_a, a)
        self.assertEqual(rec_c, c)
        self.assertEqual(rec_m, m)

    def test_lfsr_berlekamp_massey(self):
        # Fibonacci LFSR with feedback polynomial 1 + x^3 + x^4
        # poly bits: [1, 0, 0, 1, 1]
        seq = [1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1]
        c, l = berlekamp_massey(seq)
        self.assertGreater(l, 0)
        self.assertTrue(len(c) > 0)


if __name__ == "__main__":
    unittest.main()
