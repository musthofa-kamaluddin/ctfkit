"""
ctfkit.core.artifacts
Core data contracts, artifact definitions, transformation tracking, and RSA parameter models.
"""

from __future__ import annotations
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any


def compute_sha256(data: bytes | str) -> str:
    """Computes hexadecimal SHA-256 digest of input."""
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class TransformationStep:
    """
    Immutable representation of an atomic transformation operation.
    Enables DAG path reconstruction and provenance auditing.
    """
    codec_name: str
    input_hash: str
    output_hash: str
    depth: int
    parameters: Dict[str, Any] = field(default_factory=dict)

    def describe(self) -> str:
        param_str = f" ({self.parameters})" if self.parameters else ""
        return f"[{self.depth}] {self.codec_name}{param_str}"


@dataclass
class CryptoArtifact:
    """
    Encapsulates a payload state produced at any stage of analysis.
    """
    payload: bytes
    payload_hash: str = field(init=False)
    size: int = field(init=False)
    entropy: float = 0.0
    ioc: float = 0.0
    printable_ratio: float = 0.0
    quadgram_score: float = -99.0
    confidence_score: float = 0.0
    flag_found: Optional[str] = None
    history: List[TransformationStep] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)

    def __post_init__(self) -> None:
        self.payload_hash = compute_sha256(self.payload)
        self.size = len(self.payload)


@dataclass
class RSAParameters:
    """
    Encapsulates extracted or parsed RSA challenge parameters.
    Provides normalization for hex/decimal/text representations.
    """
    n: Optional[int] = None
    e: Optional[int] = None
    c: Optional[int] = None
    d: Optional[int] = None
    p: Optional[int] = None
    q: Optional[int] = None
    dp: Optional[int] = None
    dq: Optional[int] = None
    qinv: Optional[int] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RSAParameters:
        """Parses parameter dictionary normalizing string numbers, hex, and ints."""
        params: Dict[str, Optional[int]] = {}
        for key in ["n", "e", "c", "d", "p", "q", "dp", "dq", "qinv"]:
            val = data.get(key)
            if val is not None:
                if isinstance(val, int):
                    params[key] = val
                elif isinstance(val, str):
                    val_clean = val.strip()
                    if val_clean.startswith("0x") or val_clean.startswith("0X"):
                        params[key] = int(val_clean, 16)
                    else:
                        params[key] = int(val_clean)
                else:
                    params[key] = int(val)
            else:
                params[key] = None
        return cls(**params)

    def is_solvable_direct(self) -> bool:
        """Checks if minimal required fields exist for standard attacks."""
        return self.n is not None and self.e is not None and self.c is not None


@dataclass
class AnalysisResult:
    """
    Standardized result contract returned by any solver or pipeline.
    """
    input_identifier: str
    success: bool
    flags_recovered: List[str] = field(default_factory=list)
    winning_path: List[TransformationStep] = field(default_factory=list)
    artifacts: List[CryptoArtifact] = field(default_factory=list)
    execution_time_seconds: float = 0.0
    notes: List[str] = field(default_factory=list)
