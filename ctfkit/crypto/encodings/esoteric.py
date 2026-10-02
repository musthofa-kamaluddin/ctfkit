"""
ctfkit.crypto.encodings.esoteric
Morse code, URL encoding, ROT47, and Decimal/ASCII arrays.
"""

from __future__ import annotations
import urllib.parse
from typing import Optional, Dict

MORSE_CODE_DICT: Dict[str, str] = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
    '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
    '----.': '9', '.-.-.-': '.', '--..--': ',', '..--..': '?', '-..-.': '/',
    '-....-': '-', '-.--.': '(', '-.--.-': ')', '---...': ':', '-.-.-.': ';',
    '-...-': '=', '.-.-.': '+', '.----.': "'", '.-..-.': '"', '.--.-.': '@'
}


def decode_morse(data: bytes | str) -> Optional[bytes]:
    """Decodes Morse code string (words separated by '/' or '   ', letters by ' ')."""
    try:
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        clean = text.strip()
        if not clean or any(c not in ".-/ \n\t" for c in clean):
            return None

        # Normalize word separators
        clean = clean.replace("   ", " / ")
        words = clean.split("/")
        decoded_words = []
        for w in words:
            letters = w.strip().split()
            decoded_letters = []
            for l in letters:
                if l in MORSE_CODE_DICT:
                    decoded_letters.append(MORSE_CODE_DICT[l])
                else:
                    return None
            if decoded_letters:
                decoded_words.append("".join(decoded_letters))

        if not decoded_words:
            return None
        return " ".join(decoded_words).encode("utf-8")
    except Exception:
        return None


def decode_url(data: bytes | str) -> Optional[bytes]:
    """Decodes URL-encoded string."""
    try:
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        if "%" not in text:
            return None
        decoded = urllib.parse.unquote(text)
        return decoded.encode("utf-8")
    except Exception:
        return None


def decode_rot47(data: bytes | str) -> Optional[bytes]:
    """Applies ROT47 to printable ASCII (33-126)."""
    try:
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        res = []
        for c in text:
            code = ord(c)
            if 33 <= code <= 126:
                res.append(chr(33 + ((code - 33 + 47) % 94)))
            else:
                res.append(c)
        return "".join(res).encode("utf-8")
    except Exception:
        return None


def decode_decimal_array(data: bytes | str) -> Optional[bytes]:
    """
    Decodes decimal arrays like '72 97 99 107' or '[72, 97, 99, 107]' into bytes.
    """
    try:
        text = data.decode("ascii") if isinstance(data, bytes) else data
        clean = text.strip().strip("[](){}")
        parts = [p.strip() for p in clean.replace(",", " ").split() if p.strip()]
        if len(parts) < 2:
            return None
        nums = [int(p) for p in parts]
        if all(0 <= n <= 255 for n in nums):
            return bytes(nums)
        return None
    except Exception:
        return None
