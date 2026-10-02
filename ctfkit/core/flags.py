"""
ctfkit.core.flags
Flag detection engine and Known-Plaintext Oracle for weaponizing known format headers.
"""

from __future__ import annotations
import re
from typing import List, Optional, Tuple, Set
from ctfkit.core.config import Config, get_config


class FlagDetector:
    """
    High-performance, ReDoS-resistant flag search engine.
    Supports dynamic pattern reconfiguration and byte-stream scanning.
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or get_config()
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        flags = 0 if self.config.competition.case_sensitive else re.IGNORECASE
        pattern = self.config.competition.flag_regex
        self._regex = re.compile(pattern, flags)

        # Precompiled byte regex
        byte_pattern = pattern.encode("ascii", errors="ignore")
        self._byte_regex = re.compile(byte_pattern, flags)

        # Fallback broad CTF regex for serendipitous discoveries
        broad_pattern = r"(?:flag|FLAG|CTF|ctf|HTB|HackToday26)\{[a-zA-Z0-9_\-\+\!@#\$\%]+?\}"
        self._broad_regex = re.compile(broad_pattern, re.IGNORECASE)
        self._broad_byte_regex = re.compile(broad_pattern.encode("ascii"), re.IGNORECASE)

    def update_pattern(self, new_prefix: Optional[str] = None, new_regex: Optional[str] = None) -> None:
        """Dynamically reconfigures search patterns at runtime."""
        if new_prefix:
            self.config.set_flag_prefix(new_prefix)
        if new_regex:
            self.config.competition.flag_regex = new_regex
        self._compile_patterns()

    def search_string(self, text: str) -> List[str]:
        """Searches string for target flags, returning all unique matches."""
        if not text:
            return []
        matches: Set[str] = set()

        # Primary targeted regex
        for m in self._regex.finditer(text):
            matches.add(m.group(0))

        # Secondary broad regex
        for m in self._broad_regex.finditer(text):
            matches.add(m.group(0))

        return list(matches)

    def search_bytes(self, data: bytes) -> List[str]:
        """Scans raw byte streams for flags without requiring full UTF-8 decoding."""
        if not data:
            return []
        matches: Set[str] = set()

        # Direct byte search
        for m in self._byte_regex.finditer(data):
            try:
                matches.add(m.group(0).decode("utf-8", errors="replace"))
            except Exception:
                pass

        for m in self._broad_byte_regex.finditer(data):
            try:
                matches.add(m.group(0).decode("utf-8", errors="replace"))
            except Exception:
                pass

        # Also attempt decode with ignore/replace to catch any edge cases
        try:
            decoded = data.decode("utf-8", errors="ignore")
            for m in self.search_string(decoded):
                matches.add(m)
        except Exception:
            pass

        return list(matches)

    def contains_flag(self, data: str | bytes) -> bool:
        """Fast boolean test to immediately exit search loops."""
        if isinstance(data, str):
            return bool(self._regex.search(data) or self._broad_regex.search(data))
        elif isinstance(data, bytes):
            return bool(self._byte_regex.search(data) or self._broad_byte_regex.search(data))
        return False


class KnownPlaintextOracle:
    """
    Extracts and formats known plaintext fragments (e.g. 'HackToday26{')
    for injection into XOR crib-draggers, Coppersmith polynomials, and CBC attacks.
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or get_config()

    @property
    def prefix_str(self) -> str:
        return self.config.known_plaintext.default_prefix

    @property
    def prefix_bytes(self) -> bytes:
        return self.prefix_str.encode("utf-8")

    @property
    def suffix_str(self) -> str:
        return self.config.known_plaintext.default_suffix

    @property
    def suffix_bytes(self) -> bytes:
        return self.suffix_str.encode("utf-8")

    @property
    def prefix_len(self) -> int:
        return len(self.prefix_bytes)

    def get_prefix_int(self) -> int:
        """Returns prefix encoded as big-endian integer (for RSA Coppersmith roots)."""
        return int.from_bytes(self.prefix_bytes, byteorder="big")

    def derive_xor_keystream(self, ciphertext: bytes) -> Tuple[bytes, bytes]:
        """
        Derives known initial keystream bytes using K[0..L] = C[0..L] ^ Prefix[0..L].
        Returns (recovered_keystream_prefix, mask).
        """
        pfx = self.prefix_bytes
        limit = min(len(ciphertext), len(pfx))
        if limit == 0:
            return b"", b""
        keystream = bytes(ciphertext[i] ^ pfx[i] for i in range(limit))
        return keystream, pfx[:limit]
