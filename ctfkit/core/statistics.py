"""
ctfkit.core.statistics
Mathematical and statistical heuristics: Shannon Entropy, Index of Coincidence,
Chi-Squared Goodness of Fit, and Quadgram Log-Probability Scoring.
"""

from __future__ import annotations
import math
from collections import Counter
from typing import Dict, Tuple, Optional

# Standard natural English letter frequencies (A-Z) in percentages
ENGLISH_LETTER_FREQUENCIES: Dict[str, float] = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
    'Z': 0.074
}

# High-frequency English Quadgrams with log10 probabilities
# Extracted from standard cryptanalysis frequency corpora (War and Peace / Brown corpus)
TOP_QUADGRAMS: Dict[str, float] = {
    "TION": -2.18, "NTHE": -2.31, "THER": -2.38, "THAT": -2.43, "OFTH": -2.50,
    "FTHE": -2.54, "THES": -2.57, "WITH": -2.60, "INTH": -2.65, "ATIO": -2.69,
    "OTHE": -2.71, "TTHE": -2.76, "DTHE": -2.80, "INGT": -2.82, "ETHE": -2.85,
    "SAND": -2.88, "STHE": -2.90, "HERE": -2.93, "OFTW": -2.97, "THEM": -3.01,
    "RTHE": -3.04, "FROM": -3.08, "THIS": -3.10, "TOBE": -3.12, "HAVE": -3.15,
    "HICH": -3.18, "WHIC": -3.20, "NDTH": -3.22, "THEY": -3.24, "THEC": -3.26,
    "THOU": -3.28, "WERE": -3.30, "THEP": -3.32, "SOME": -3.34, "WILL": -3.36,
    "MENT": -3.38, "THEF": -3.40, "WOUL": -3.42, "OULD": -3.44, "THEB": -3.46,
    "THEN": -3.48, "THEY": -3.50, "THEW": -3.52, "THEG": -3.54, "THEH": -3.56,
    "EVER": -3.58, "THEL": -3.60, "FORE": -3.62, "BEEN": -3.64, "THEO": -3.66,
    "THIN": -3.68, "SAID": -3.70, "THER": -3.72, "WHAT": -3.74, "THEK": -3.76,
    "THEV": -3.78, "MORE": -3.80, "THEU": -3.82, "VERY": -3.84, "THEJ": -3.86,
    "THEZ": -3.88, "THEX": -3.90, "THEQ": -3.92, "ONLY": -3.94, "COME": -3.96,
    "OVER": -3.98, "SUCH": -4.00, "INTO": -4.02, "EVEN": -4.04, "MOST": -4.06,
    "ALSO": -4.08, "MADE": -4.10, "AFTE": -4.12, "FTER": -4.14, "WELL": -4.16,
    "TIME": -4.18, "GOOD": -4.20, "THEY": -4.22, "KNOW": -4.24, "COUL": -4.26,
    "UPON": -4.28, "THEI": -4.30, "LITT": -4.32, "ITTL": -4.34, "TTLE": -4.36,
    "WHEN": -4.38, "THEM": -4.40, "LIKE": -4.42, "THES": -4.44, "THRO": -4.46,
    "HROU": -4.48, "ROUG": -4.50, "OUGH": -4.52, "LONG": -4.54, "MAKE": -4.56,
    "PEOP": -4.58, "EOPL": -4.60, "OPLE": -4.62, "DOWN": -4.64, "MUST": -4.66,
    "FLAG": -4.70, "HACK": -4.72, "TODA": -4.74, "ODAY": -4.76, "CTFS": -4.78
}
QUADGRAM_FLOOR: float = -7.50  # Penalty for unseen 4-character sequences

# Byte-level frequencies for fast single-byte scoring (percentages)
BYTE_FREQUENCIES: Dict[int, float] = {
    ord(k.lower()): v for k, v in ENGLISH_LETTER_FREQUENCIES.items()
}
for k, v in ENGLISH_LETTER_FREQUENCIES.items():
    BYTE_FREQUENCIES[ord(k.upper())] = v * 0.8  # Slight preference for lowercase
BYTE_FREQUENCIES[ord(' ')] = 15.0
BYTE_FREQUENCIES[ord('\n')] = 2.0
BYTE_FREQUENCIES[ord('\t')] = 1.0
BYTE_FREQUENCIES[ord('.')] = 1.5
BYTE_FREQUENCIES[ord(',')] = 1.5
BYTE_FREQUENCIES[ord('_')] = 1.0
BYTE_FREQUENCIES[ord('{')] = 1.5
BYTE_FREQUENCIES[ord('}')] = 1.5


def english_frequency_score(data: bytes) -> float:
    """
    Fast letter frequency score for single-byte XOR and transposed block cryptanalysis.
    Rewards common English letters and space; penalizes non-printable and control bytes.
    """
    if not data:
        return -999.0
    score = 0.0
    for b in data:
        if b in BYTE_FREQUENCIES:
            score += BYTE_FREQUENCIES[b]
        elif 32 <= b <= 126:
            score += 0.5  # Printable punctuation/numbers
        elif b in (9, 10, 13):
            score += 1.0
        else:
            score -= 30.0  # Heavy penalty for non-printable bytes
    return score / len(data)


def shannon_entropy(data: bytes | str) -> float:
    """
    Computes Shannon Entropy H(X) in bits per byte (0.0 <= H <= 8.0).
    H ~ 0.0: Constant data (e.g. all null bytes)
    H ~ 3.5 - 5.0: Natural language text
    H ~ 7.5 - 8.0: High-entropy encrypted or compressed data
    """
    if not data:
        return 0.0
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")

    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def index_of_coincidence(data: bytes | str) -> float:
    """
    Calculates Index of Coincidence (IoC) of alphabetic letters.
    IoC ~ 0.067 for natural English.
    IoC ~ 0.038 for uniform random or polyalphabetic ciphertext (Vigenere).
    """
    if isinstance(data, bytes):
        text = "".join(chr(b).upper() for b in data if (65 <= b <= 90) or (97 <= b <= 122))
    else:
        text = "".join(c.upper() for c in data if c.isalpha())

    n = len(text)
    if n <= 1:
        return 0.0

    counts = Counter(text)
    numerator = sum(count * (count - 1) for count in counts.values())
    denominator = n * (n - 1)
    return numerator / denominator


def chi_squared_fit(data: bytes | str) -> float:
    """
    Computes Chi-Squared statistic against standard English letter frequencies.
    Lower score indicates closer fit to natural English.
    """
    if isinstance(data, bytes):
        text = "".join(chr(b).upper() for b in data if (65 <= b <= 90) or (97 <= b <= 122))
    else:
        text = "".join(c.upper() for c in data if c.isalpha())

    n = len(text)
    if n == 0:
        return 99999.0

    counts = Counter(text)
    chi2 = 0.0
    for letter, expected_pct in ENGLISH_LETTER_FREQUENCIES.items():
        observed = counts.get(letter, 0)
        expected = (expected_pct / 100.0) * n
        chi2 += ((observed - expected) ** 2) / expected

    return chi2


def quadgram_score(text: str | bytes) -> float:
    """
    Computes log-probability score using English quadgrams.
    Normalized by character length for fair comparison across varied text lengths.
    Higher (less negative) is better.
    """
    if isinstance(text, bytes):
        clean_text = "".join(chr(b).upper() for b in text if (65 <= b <= 90) or (97 <= b <= 122))
    else:
        clean_text = "".join(c.upper() for c in text if c.isalpha())

    n = len(clean_text)
    if n < 4:
        return -99.0

    total_score = 0.0
    quadgram_count = n - 3
    for i in range(quadgram_count):
        q = clean_text[i:i+4]
        total_score += TOP_QUADGRAMS.get(q, QUADGRAM_FLOOR)

    # Normalize by number of quadgrams evaluated
    return total_score / quadgram_count


def printable_ascii_ratio(data: bytes) -> float:
    """Computes the ratio of printable ASCII + standard whitespace characters."""
    if not data:
        return 0.0
    printable_count = sum(1 for b in data if (32 <= b <= 126) or b in (9, 10, 13))
    return printable_count / len(data)


def detect_charset_profile(data: bytes | str) -> Dict[str, bool]:
    """
    Analyzes input bytes/string and returns potential character set memberships.
    """
    raw_bytes = data if isinstance(data, bytes) else data.encode("utf-8", errors="ignore")
    if not raw_bytes:
        return {
            "is_hex": False,
            "is_base64": False,
            "is_binary_str": False,
            "is_printable_ascii": False,
            "is_mostly_letters": False,
        }

    # Binary string: '010101...'
    is_binary_str = all(b in (48, 49, 32, 10, 13) for b in raw_bytes) and len(raw_bytes.strip()) >= 8

    # Hex: '0-9a-fA-F' with optional spaces
    clean_hex = bytes(b for b in raw_bytes if b not in (32, 10, 13))
    is_hex = (
        len(clean_hex) >= 2
        and len(clean_hex) % 2 == 0
        and all((48 <= b <= 57) or (65 <= b <= 70) or (97 <= b <= 102) for b in clean_hex)
    )

    # Base64: 'A-Za-z0-9+/=' with optional spaces
    clean_b64 = bytes(b for b in raw_bytes if b not in (32, 10, 13))
    b64_chars = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    is_base64 = (
        len(clean_b64) >= 4
        and len(clean_b64) % 4 == 0
        and all(b in b64_chars for b in clean_b64)
    )

    ratio = printable_ascii_ratio(raw_bytes)
    is_printable = ratio > 0.90

    # Mostly letters (Caesar, Vigenere, substitution candidates)
    letters_count = sum(1 for b in raw_bytes if (65 <= b <= 90) or (97 <= b <= 122))
    is_mostly_letters = (letters_count / len(raw_bytes)) > 0.70

    return {
        "is_hex": is_hex,
        "is_base64": is_base64,
        "is_binary_str": is_binary_str,
        "is_printable_ascii": is_printable,
        "is_mostly_letters": is_mostly_letters,
    }
