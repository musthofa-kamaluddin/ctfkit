"""
ctfkit.crypto.encodings
Unified codec registry and heuristic applicability dispatch.
"""

from typing import Callable, Optional, Dict, List
from ctfkit.crypto.encodings.basex import (
    decode_base64,
    decode_base32,
    decode_base16,
    decode_base85,
    decode_ascii85,
    decode_base58
)
from ctfkit.crypto.encodings.binary_hex import decode_binary_str, decode_hex_stream
from ctfkit.crypto.encodings.esoteric import (
    decode_morse,
    decode_url,
    decode_rot47,
    decode_decimal_array
)

# Registry mapping codec_name -> decoding function
CODEC_REGISTRY: Dict[str, Callable[[bytes | str], Optional[bytes]]] = {
    "hex": decode_hex_stream,
    "base64": decode_base64,
    "base32": decode_base32,
    "base85": decode_base85,
    "ascii85": decode_ascii85,
    "base58": decode_base58,
    "binary_str": decode_binary_str,
    "decimal_array": decode_decimal_array,
    "url": decode_url,
    "rot47": decode_rot47,
    "morse": decode_morse,
}


def get_available_codecs() -> List[str]:
    return list(CODEC_REGISTRY.keys())
