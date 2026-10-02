"""
ctfkit.crypto.prng.mt19937
Mersenne Twister (MT19937) untempering, state reconstruction, and Python `random` cloning.
"""

from __future__ import annotations
import random
from typing import List, Tuple


def untemper(z: int) -> int:
    """
    Inverts the MT19937 tempering transform to recover internal state word y from output z.
    Tempering operations:
      1. y1 = y ^ (y >> 11)
      2. y2 = y1 ^ ((y1 << 7) & 0x9D2C5680)
      3. y3 = y2 ^ ((y2 << 15) & 0xEFC60000)
      4. z  = y3 ^ (y3 >> 18)
    """
    # Step 4 inverse: z = y3 ^ (y3 >> 18)
    # Since shift is 18 (> 16), the top 18 bits of y3 are untouched in z.
    y3 = z ^ (z >> 18)

    # Step 3 inverse: y3 = y2 ^ ((y2 << 15) & 0xEFC60000)
    # Shift is 15 bits, so bottom 15 bits are untouched.
    y2 = y3 ^ ((y3 << 15) & 0xEFC60000)

    # Step 2 inverse: y2 = y1 ^ ((y1 << 7) & 0x9D2C5680)
    # Shift is 7 bits with mask. Reconstructed iteratively 7 bits at a time.
    y1 = y2
    for _ in range(4):
        y1 = y2 ^ ((y1 << 7) & 0x9D2C5680)

    # Step 1 inverse: y1 = y ^ (y >> 11)
    # Shift is 11 bits. Reconstructed iteratively.
    y = y1
    for _ in range(2):
        y = y1 ^ (y >> 11)

    return y & 0xFFFFFFFF


class MT19937Cloner:
    """
    Reconstructs internal state from 624 32-bit observations and clones Python's `random`.
    """

    @staticmethod
    def clone_python_random(outputs_624: List[int]) -> random.Random:
        """
        Given 624 consecutive 32-bit outputs from random.getrandbits(32),
        returns a cloned random.Random instance synchronized to emit identical subsequent numbers.
        """
        if len(outputs_624) < 624:
            raise ValueError(f"Need exactly 624 32-bit outputs to clone MT19937, got {len(outputs_624)}")

        internal_state = [untemper(z) for z in outputs_624[:624]]
        # Python's random state tuple format: (version=3, (624 uint32s, index=624), gauss=None)
        cloned_rng = random.Random()
        state_tuple = (3, tuple(internal_state + [624]), None)
        cloned_rng.setstate(state_tuple)
        return cloned_rng
