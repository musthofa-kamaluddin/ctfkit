"""
Unit tests for ctfkit.core modules: config, flags, statistics, artifacts.
"""

import unittest
from ctfkit.core.config import Config
from ctfkit.core.flags import FlagDetector, KnownPlaintextOracle
from ctfkit.core.statistics import (
    shannon_entropy,
    index_of_coincidence,
    chi_squared_fit,
    quadgram_score,
    printable_ascii_ratio,
    detect_charset_profile
)
from ctfkit.core.artifacts import (
    CryptoArtifact,
    TransformationStep,
    RSAParameters,
    compute_sha256
)


class TestCoreModules(unittest.TestCase):

    def test_config_and_dynamic_flags(self):
        cfg = Config()
        self.assertEqual(cfg.competition.flag_prefix, "HackToday26{")
        
        # Test dynamic re-configuration
        cfg.set_flag_prefix("CustomCTF{")
        self.assertEqual(cfg.competition.flag_prefix, "CustomCTF{")
        self.assertIn("CustomCTF\\{", cfg.competition.flag_regex)

    def test_flag_detector(self):
        detector = FlagDetector()
        test_str = "Logs leaked secret: HackToday26{sup3r_s3cr3t_fl4g_2026} in memory dump"
        matches = detector.search_string(test_str)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0], "HackToday26{sup3r_s3cr3t_fl4g_2026}")

        # Test byte search
        test_bytes = b"\x00\xffHackToday26{byt3_fl4g_t3st}\x00\x01"
        byte_matches = detector.search_bytes(test_bytes)
        self.assertIn("HackToday26{byt3_fl4g_t3st}", byte_matches)
        self.assertTrue(detector.contains_flag(test_bytes))

    def test_known_plaintext_oracle(self):
        oracle = KnownPlaintextOracle()
        self.assertEqual(oracle.prefix_str, "HackToday26{")
        self.assertEqual(oracle.prefix_bytes, b"HackToday26{")
        self.assertEqual(oracle.prefix_len, 12)

        # Test XOR keystream derivation from known prefix
        # Plaintext = "HackToday26{"
        # Key = b"KEY123456789"
        key = b"KEY123456789"
        plain = b"HackToday26{"
        cipher = bytes(p ^ k for p, k in zip(plain, key))
        recovered_key, mask = oracle.derive_xor_keystream(cipher)
        self.assertEqual(recovered_key, key)

    def test_statistical_heuristics(self):
        # Entropy
        null_bytes = b"\x00" * 100
        self.assertAlmostEqual(shannon_entropy(null_bytes), 0.0)

        english_sample = b"Cryptography is the practice and study of techniques for secure communication in the presence of adversarial third parties. Classical ciphers rely on substitution and transposition to obscure plaintext messages."
        h_eng = shannon_entropy(english_sample)
        self.assertGreater(h_eng, 3.5)
        self.assertLess(h_eng, 5.0)

        # IoC for English
        ioc_eng = index_of_coincidence(english_sample)
        self.assertGreater(ioc_eng, 0.055)  # Natural English is high IoC (~0.065)

        # Printable ratio
        self.assertEqual(printable_ascii_ratio(english_sample), 1.0)
        self.assertLess(printable_ascii_ratio(b"\x00\x01\x02\x03"), 0.1)

        # Quadgrams
        score_eng = quadgram_score("THISISAVALIDENGLISHTEXTTHATSHOULDRANKHIGH")
        score_rand = quadgram_score("XQZKJBWPMVFRTYLHNCBDGSJKLMOPTRWXZ")
        self.assertGreater(score_eng, score_rand)

    def test_charset_detector(self):
        hex_data = b"4861636b546f646179"
        profile = detect_charset_profile(hex_data)
        self.assertTrue(profile["is_hex"])

        b64_data = b"SGFja1RvZGF5MjZ7dGVzdH0="
        profile_b64 = detect_charset_profile(b64_data)
        self.assertTrue(profile_b64["is_base64"])

    def test_artifacts_and_rsa_params(self):
        artifact = CryptoArtifact(payload=b"test payload")
        self.assertEqual(artifact.payload_hash, compute_sha256(b"test payload"))
        self.assertEqual(artifact.size, 12)

        # RSA params from hex dictionary
        params = RSAParameters.from_dict({
            "n": "0x10001",
            "e": 65537,
            "c": "12345"
        })
        self.assertEqual(params.n, 65537)
        self.assertEqual(params.e, 65537)
        self.assertEqual(params.c, 12345)
        self.assertTrue(params.is_solvable_direct())


if __name__ == "__main__":
    unittest.main()
