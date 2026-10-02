"""
Unit tests for ctfkit.crypto.encodings and ctfkit.crypto.classical.
"""

import unittest
from ctfkit.crypto.encodings.basex import (
    decode_base64,
    decode_base32,
    decode_base58,
    decode_base85,
    decode_ascii85
)
from ctfkit.crypto.encodings.binary_hex import decode_binary_str, decode_hex_stream
from ctfkit.crypto.encodings.esoteric import decode_morse, decode_rot47, decode_decimal_array
from ctfkit.crypto.classical.caesar import CaesarSolver
from ctfkit.crypto.classical.vigenere import VigenereSolver
from ctfkit.crypto.classical.affine import AffineSolver
from ctfkit.crypto.classical.transposition import RailFenceSolver


class TestEncodingsAndClassical(unittest.TestCase):

    def test_encodings(self):
        plain = b"HackToday26{test_flag}"

        # Base64 with stripped padding
        self.assertEqual(decode_base64("SGFja1RvZGF5MjZ7dGVzdF9mbGFnfQ"), plain)

        # Base32
        self.assertEqual(decode_base32("JBQWG22UN5SGC6JSGZ5XIZLTORPWM3DBM56Q===="), plain)

        # Base58
        self.assertEqual(decode_base58("LeQFjamfq39aU7svXJSyN5ciuxYR3a"), plain)

        # Binary string
        bin_str = "01001000 01100001 01100011 01101011"
        self.assertEqual(decode_binary_str(bin_str), b"Hack")

        # Hex stream
        self.assertEqual(decode_hex_stream("0x4861636b"), b"Hack")

        # Morse code
        morse = ".... .- -.-. -.-"
        self.assertEqual(decode_morse(morse), b"HACK")

        # Decimal array
        self.assertEqual(decode_decimal_array("[72, 97, 99, 107]"), b"Hack")

    def test_caesar_solver(self):
        # Shift plain by 7
        plain = "HackToday26{caesar_rotated_secret}"
        solver = CaesarSolver()
        cipher = solver.shift_text(plain, -7)  # Encrypt with shift 7

        results = solver.solve(cipher)
        self.assertTrue(len(results) > 0)
        self.assertEqual(results[0].plaintext, plain)
        self.assertEqual(results[0].shift, 7)
        self.assertIn("HackToday26{caesar_rotated_secret}", results[0].flag_found)

    def test_vigenere_solver(self):
        plain = "HackToday26{vigenere_key_is_discovered} and this additional english text allows reliable frequency analysis for the solver."
        key = "SECRET"
        solver = VigenereSolver()
        # Encrypt with Vigenere key
        cipher = []
        ki = 0
        for c in plain:
            if 'a' <= c <= 'z':
                cipher.append(chr((ord(c) - ord('a') + ord(key[ki % len(key)].upper()) - ord('A')) % 26 + ord('a')))
                ki += 1
            elif 'A' <= c <= 'Z':
                cipher.append(chr((ord(c) - ord('A') + ord(key[ki % len(key)].upper()) - ord('A')) % 26 + ord('A')))
                ki += 1
            else:
                cipher.append(c)
        ciphertext = "".join(cipher)

        results = solver.solve(ciphertext, candidate_lengths=[len(key)])
        self.assertTrue(len(results) > 0)
        best = results[0]
        self.assertEqual(best.key, key)
        self.assertIn("HackToday26{vigenere_key_is_discovered}", best.plaintext)

    def test_affine_solver(self):
        plain = "HackToday26{affine_modular_cipher_is_broken}"
        solver = AffineSolver()
        a, b = 7, 11
        # Encrypt: E(x) = (7x + 11) mod 26
        enc = []
        for c in plain:
            if 'a' <= c <= 'z':
                enc.append(chr(((a * (ord(c) - ord('a')) + b) % 26) + ord('a')))
            elif 'A' <= c <= 'Z':
                enc.append(chr(((a * (ord(c) - ord('A')) + b) % 26) + ord('A')))
            else:
                enc.append(c)
        cipher = "".join(enc)

        results = solver.solve(cipher)
        self.assertTrue(len(results) > 0)
        self.assertEqual(results[0].plaintext, plain)
        self.assertEqual(results[0].a, a)
        self.assertEqual(results[0].b, b)

    def test_rail_fence_solver(self):
        plain = "HackToday26{rail_fence_transposition_flag_reconstructed}"
        rails = 4
        # Encrypt rail fence
        rail_pattern = []
        rail = 0
        direction = 1
        for _ in range(len(plain)):
            rail_pattern.append(rail)
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1
            rail += direction

        cipher = []
        for r in range(rails):
            for i, c in enumerate(plain):
                if rail_pattern[i] == r:
                    cipher.append(c)
        ciphertext = "".join(cipher)

        solver = RailFenceSolver()
        results = solver.solve(ciphertext, max_rails=6)
        self.assertTrue(len(results) > 0)
        self.assertEqual(results[0].plaintext, plain)
        self.assertEqual(results[0].rails, rails)


if __name__ == "__main__":
    unittest.main()
