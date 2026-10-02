"""
ctfkit.crypto.rsa.coppersmith
Coppersmith Stereotyped Message attack with Sage bridge and offline integer polynomial solver.
"""

from __future__ import annotations
import shutil
import subprocess
import json
import tempfile
from pathlib import Path
from typing import Optional
from ctfkit.core.flags import KnownPlaintextOracle, FlagDetector
from ctfkit.crypto.rsa.attacks import int_to_bytes
from ctfkit.crypto.rsa.math_utils import iroot


class CoppersmithSolver:
    """
    Solves stereotyped message problems: m = prefix || x where x < 2^(8*unknown_bytes).
    Uses binary search integer polynomial solver or headless SageMath bridge.
    """

    def __init__(
        self,
        oracle: Optional[KnownPlaintextOracle] = None,
        detector: Optional[FlagDetector] = None
    ):
        self.oracle = oracle or KnownPlaintextOracle()
        self.detector = detector or FlagDetector()

    def solve_stereotyped(
        self,
        n: int,
        e: int,
        c: int,
        known_prefix: Optional[bytes] = None,
        unknown_bytes: int = 16
    ) -> Optional[bytes]:
        prefix = known_prefix or self.oracle.prefix_bytes
        k_shift = unknown_bytes * 8
        prefix_int = int.from_bytes(prefix, "big") << k_shift

        # Case 1: If c < n or m^e < n, solve directly via integer binary search
        # f(x) = (prefix_int + x)^e - c = 0
        if e <= 5:
            low = 0
            high = (1 << k_shift) - 1
            while low <= high:
                mid = (low + high) // 2
                m_candidate = prefix_int + mid
                c_candidate = pow(m_candidate, e)
                if c_candidate == c:
                    return int_to_bytes(m_candidate)
                elif c_candidate < c:
                    low = mid + 1
                else:
                    high = mid - 1

        # Case 2: Headless SageMath bridge if available
        sage_bin = shutil.which("sage")
        if sage_bin:
            sage_script = f"""
import json
n = {n}
e = {e}
c = {c}
k_shift = {k_shift}
prefix_int = {prefix_int}

ZmodN = Zmod(n)
P.<x> = PolynomialRing(ZmodN)
f = (prefix_int + x)^e - c
f = f.monic()
roots = f.small_roots(X=2^k_shift, beta=1.0)
if roots:
    print(json.dumps({{"root": int(roots[0])}}))
else:
    print(json.dumps({{"root": None}}))
"""
            try:
                with tempfile.NamedTemporaryFile("w", suffix=".sage", delete=False) as tf:
                    tf.write(sage_script)
                    temp_path = tf.name

                res = subprocess.run(
                    [sage_bin, temp_path],
                    capture_output=True,
                    text=True,
                    timeout=20
                )
                Path(temp_path).unlink(missing_ok=True)
                for line in res.stdout.splitlines():
                    if "root" in line:
                        data = json.loads(line)
                        if data.get("root") is not None:
                            root_val = int(data["root"])
                            m_val = prefix_int + root_val
                            return int_to_bytes(m_val)
            except Exception:
                pass

        return None
