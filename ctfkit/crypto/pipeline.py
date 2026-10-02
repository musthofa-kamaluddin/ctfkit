"""
ctfkit.crypto.pipeline
Recursive Beam Search Transformation Engine:
Explores decoding DAG, scores branches, prunes dead ends, and recovers flags.
"""

from __future__ import annotations
import zlib
import gzip
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from ctfkit.core.config import Config, get_config
from ctfkit.core.flags import FlagDetector
from ctfkit.core.artifacts import (
    TransformationStep,
    compute_sha256
)
from ctfkit.core.statistics import (
    printable_ascii_ratio,
    quadgram_score,
    index_of_coincidence,
    detect_charset_profile
)
from ctfkit.crypto.encodings import CODEC_REGISTRY
from ctfkit.crypto.xor.single_byte import SingleByteXORSolver
from ctfkit.crypto.classical.caesar import CaesarSolver


@dataclass
class PipelineNode:
    """Represents a state node in the beam search transformation tree."""
    payload: bytes
    payload_hash: str
    depth: int
    score: float
    history: List[TransformationStep] = field(default_factory=list)
    flag_found: Optional[str] = None


class RecursiveDecodePipeline:
    """
    Automated multi-layer recursive decoding pipeline using scored beam search.
    Guarantees termination via depth ceiling and global hash de-duplication.
    """

    def __init__(
        self,
        config: Optional[Config] = None,
        detector: Optional[FlagDetector] = None,
        max_depth: Optional[int] = None,
        beam_width: Optional[int] = None
    ):
        self.config = config or get_config()
        self.detector = detector or FlagDetector(self.config)
        self.max_depth = max_depth or self.config.crypto.max_recursive_depth
        self.beam_width = beam_width or self.config.crypto.beam_width
        self.single_xor_solver = SingleByteXORSolver(self.detector)
        self.caesar_solver = CaesarSolver(self.detector)

    def evaluate_node(self, payload: bytes) -> Tuple[float, Optional[str]]:
        """
        Evaluates node plausibility and checks for target flag match.
        Returns (score, flag_match).
        """
        flags = self.detector.search_bytes(payload)
        flag_match = flags[0] if flags else None

        if flag_match:
            return 100000.0, flag_match

        p_ratio = printable_ascii_ratio(payload)
        q_score = quadgram_score(payload)
        ioc = index_of_coincidence(payload)
        prof = detect_charset_profile(payload)

        # Baseline score: English plausibility
        score = (p_ratio * 40.0) + (q_score * 5.0) + (ioc * 60.0)

        # Structural encoding bonuses so valid intermediate encodings stay in beam
        if prof["is_hex"]:
            score += 50.0
        if prof["is_base64"]:
            score += 50.0
        if len(payload) >= 2 and (payload[:2] == b"\x1f\x8b" or payload[0] == 0x78):
            score += 75.0

        return score, None

    def generate_transformations(self, node: PipelineNode) -> List[Tuple[str, bytes, Dict]]:
        """
        Generates candidate successor states from applicable codecs.
        """
        candidates: List[Tuple[str, bytes, Dict]] = []
        payload = node.payload
        profile = detect_charset_profile(payload)

        # 1. Structural decompression checks (magic bytes take top precedence)
        # Gzip: 1f 8b
        if len(payload) >= 2 and payload[:2] == b"\x1f\x8b":
            try:
                decomp = gzip.decompress(payload)
                if decomp and decomp != payload:
                    candidates.append(("gzip_decompress", decomp, {}))
            except Exception:
                pass

        # Zlib: 78 9c or 78 01 or 78 da
        if len(payload) >= 2 and payload[0] == 0x78:
            try:
                decomp = zlib.decompress(payload)
                if decomp and decomp != payload:
                    candidates.append(("zlib_decompress", decomp, {}))
            except Exception:
                pass

        # 2. Structural encodings
        if profile["is_hex"]:
            res = CODEC_REGISTRY["hex"](payload)
            if res and res != payload:
                candidates.append(("hex_decode", res, {}))

        if profile["is_base64"]:
            res = CODEC_REGISTRY["base64"](payload)
            if res and res != payload:
                candidates.append(("base64_decode", res, {}))

        if profile["is_binary_str"]:
            res = CODEC_REGISTRY["binary_str"](payload)
            if res and res != payload:
                candidates.append(("binary_str_decode", res, {}))

        # 3. Text-based classical ciphers (Caesar / ROT) if mostly letters
        if profile["is_mostly_letters"] and len(payload) < 2048:
            rot13_res = self.caesar_solver.shift_text(payload.decode("utf-8", errors="ignore"), 13).encode("utf-8")
            if rot13_res != payload:
                candidates.append(("rot13", rot13_res, {"shift": 13}))

        # 4. Single-byte XOR: Only when not an obvious hex/base64 string or compressed archive
        is_compressed = len(payload) >= 2 and (payload[:2] == b"\x1f\x8b" or payload[0] == 0x78)
        if not profile["is_hex"] and not is_compressed and len(payload) <= 1024:
            xor_candidates = self.single_xor_solver.solve(payload, top_k=2)
            for xc in xor_candidates:
                if xc.key != 0 and xc.plaintext != payload:
                    candidates.append((f"xor_0x{xc.key:02x}", xc.plaintext, {"key": xc.key}))

        # 5. URL decode if '%' present
        if b"%" in payload:
            res = CODEC_REGISTRY["url"](payload)
            if res and res != payload:
                candidates.append(("url_decode", res, {}))

        return candidates

    def run(self, initial_data: bytes | str) -> Optional[PipelineNode]:
        """
        Executes beam search across the transformation state space.
        Returns winning PipelineNode containing complete transformation history.
        """
        raw_bytes = initial_data if isinstance(initial_data, bytes) else initial_data.encode("utf-8")
        if not raw_bytes:
            return None

        init_hash = compute_sha256(raw_bytes)
        init_score, flag_found = self.evaluate_node(raw_bytes)

        root = PipelineNode(
            payload=raw_bytes,
            payload_hash=init_hash,
            depth=0,
            score=init_score,
            history=[],
            flag_found=flag_found
        )

        if flag_found:
            return root

        visited_hashes: Set[str] = {init_hash}
        current_beam: List[PipelineNode] = [root]

        for depth in range(1, self.max_depth + 1):
            next_generation: List[PipelineNode] = []

            for node in current_beam:
                transforms = self.generate_transformations(node)

                for name, new_payload, params in transforms:
                    new_hash = compute_sha256(new_payload)
                    if new_hash in visited_hashes:
                        continue
                    visited_hashes.add(new_hash)

                    score, flag = self.evaluate_node(new_payload)
                    step = TransformationStep(
                        codec_name=name,
                        input_hash=node.payload_hash,
                        output_hash=new_hash,
                        depth=depth,
                        parameters=params
                    )
                    child_node = PipelineNode(
                        payload=new_payload,
                        payload_hash=new_hash,
                        depth=depth,
                        score=score,
                        history=node.history + [step],
                        flag_found=flag
                    )

                    # Immediate exit on flag recovery
                    if flag:
                        return child_node

                    next_generation.append(child_node)

            if not next_generation:
                break

            # Beam pruning: keep top K candidates
            next_generation.sort(key=lambda n: n.score, reverse=True)
            current_beam = next_generation[:self.beam_width]

        current_beam.sort(key=lambda n: n.score, reverse=True)
        return current_beam[0] if current_beam else None
