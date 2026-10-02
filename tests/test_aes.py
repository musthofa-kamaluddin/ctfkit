"""
Unit tests for ctfkit.crypto.aes modules: ECB, CBC Padding Oracle, and GCM Forbidden Attack.
"""

import unittest
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from ctfkit.crypto.aes.aes_helper import pkcs7_pad, pkcs7_unpad
from ctfkit.crypto.aes.ecb_analyzer import detect_ecb_mode, ECBByteAtATimeSolver
from ctfkit.crypto.aes.padding_oracle import PaddingOracleSolver
from ctfkit.crypto.aes.gcm_forbidden import GCMForbiddenAttack, GF2_128


class TestAESAttacks(unittest.TestCase):

    def setUp(self):
        self.key = get_random_bytes(16)

    def test_ecb_duplicate_detection(self):
        # Plaintext with 3 identical blocks
        plain = b"A" * 48
        cipher = AES.new(self.key, AES.MODE_ECB).encrypt(plain)
        is_ecb, dups = detect_ecb_mode(cipher)
        self.assertTrue(is_ecb)
        self.assertEqual(dups, 2)

    def test_ecb_byte_at_a_time(self):
        secret = b"HackToday26{ecb_win}"

        def ecb_oracle(user_input: bytes) -> bytes:
            cipher = AES.new(self.key, AES.MODE_ECB)
            return cipher.encrypt(pkcs7_pad(user_input + secret))

        solver = ECBByteAtATimeSolver(ecb_oracle)
        recovered = solver.solve()
        self.assertIn(secret, recovered)

    def test_padding_oracle_attack(self):
        secret = b"HackToday26{oracle_cbc_pwn}"
        iv = get_random_bytes(16)
        padded = pkcs7_pad(secret)
        ciphertext = AES.new(self.key, AES.MODE_CBC, iv=iv).encrypt(padded)

        # Build oracle callback
        def cbc_oracle(data: bytes) -> bool:
            test_iv = data[:16]
            test_ct = data[16:]
            pt = AES.new(self.key, AES.MODE_CBC, iv=test_iv).decrypt(test_ct)
            return pkcs7_unpad(pt) is not None

        solver = PaddingOracleSolver(cbc_oracle)
        recovered = solver.decrypt(ciphertext, iv=iv)
        self.assertEqual(recovered, secret)

    def test_gcm_tag_forgery(self):
        # Derive true H key
        zero_block = b"\x00" * 16
        h_bytes = AES.new(self.key, AES.MODE_ECB).encrypt(zero_block)
        h_int = GF2_128.bytes_to_int(h_bytes)

        nonce = get_random_bytes(12)
        cipher1 = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        msg1 = b"Hello World"
        c1 = cipher1.encrypt(msg1)
        tag1 = cipher1.digest()

        # Forge tag for msg2 without key
        target_msg = b"HackToday26{gcm_forged}"
        # Keystream is known for first len(msg1) bytes, but for tag forgery we test known ciphertexts
        c2 = bytes(b ^ 0x01 for b in c1)
        forged_tag = GCMForbiddenAttack.forge_tag(h_int, c1, tag1, c2)

        # Verify with real AES-GCM decryptor
        verifier = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        # Should not raise exception
        try:
            verifier.decrypt_and_verify(c2, forged_tag)
            verified = True
        except ValueError:
            verified = False
        self.assertTrue(verified)


if __name__ == "__main__":
    unittest.main()
