"""
Unit tests for ctfkit.crypto.pipeline: Recursive Beam Search Decoder.
"""

import unittest
import zlib
import base64
from ctfkit.crypto.pipeline import RecursiveDecodePipeline
from ctfkit.crypto.classical.caesar import CaesarSolver


class TestRecursivePipeline(unittest.TestCase):

    def test_multi_layer_recursive_decoding(self):
        flag = "HackToday26{recursive_dag_pipeline_success}"
        
        # Layer 1: ROT13
        caesar = CaesarSolver()
        layer1 = caesar.shift_text(flag, 13).encode("utf-8")
        
        # Layer 2: Zlib compression
        layer2 = zlib.compress(layer1)
        
        # Layer 3: Base64
        layer3 = base64.b64encode(layer2)
        
        # Layer 4: Hex
        layer4 = layer3.hex()

        # Run pipeline on raw outermost hex string
        pipeline = RecursiveDecodePipeline(max_depth=6, beam_width=4)
        node = pipeline.run(layer4)

        self.assertIsNotNone(node)
        self.assertEqual(node.flag_found, flag)
        self.assertEqual(node.payload.decode("utf-8"), flag)
        self.assertEqual(len(node.history), 4)

        # Verify exact transformation pathway
        steps = [s.codec_name for s in node.history]
        self.assertEqual(steps[0], "hex_decode")
        self.assertEqual(steps[1], "base64_decode")
        self.assertEqual(steps[2], "zlib_decompress")
        self.assertEqual(steps[3], "rot13")


if __name__ == "__main__":
    unittest.main()
