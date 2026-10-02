"""
ctfkit.crypto.aes
Advanced AES cryptanalysis:
ECB duplicate analysis & byte-at-a-time decryption, CBC padding oracle solver,
and GCM Forbidden Attack tag forger.
"""

from ctfkit.crypto.aes.aes_helper import AESHelper, pkcs7_pad, pkcs7_unpad
from ctfkit.crypto.aes.ecb_analyzer import detect_ecb_mode, ECBByteAtATimeSolver
from ctfkit.crypto.aes.padding_oracle import PaddingOracleSolver
from ctfkit.crypto.aes.gcm_forbidden import GF2_128, GCMForbiddenAttack

__all__ = [
    "AESHelper",
    "pkcs7_pad",
    "pkcs7_unpad",
    "detect_ecb_mode",
    "ECBByteAtATimeSolver",
    "PaddingOracleSolver",
    "GF2_128",
    "GCMForbiddenAttack",
]
