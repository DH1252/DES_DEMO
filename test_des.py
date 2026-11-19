import unittest

from des import trace_block


class DESTests(unittest.TestCase):
    def test_known_answer_vectors_in_both_directions(self):
        for block, key, expected in (
            (0x0123456789ABCDEF, 0x133457799BBCDFF1, 0x85E813540F0AB405),
            (0, 0, 0x8CA64DE9C1B123A7),
            (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x7359B2163E4EDC58),
        ):
            with self.subTest(block=block, key=key):
                self.assertEqual(trace_block(block, key).output, expected)
                self.assertEqual(trace_block(expected, key, decrypt=True).output, block)

    def test_intermediate_values_of_example(self):
        trace = trace_block(0x0123456789ABCDEF, 0x133457799BBCDFF1)
        self.assertEqual(trace.after_ip, 0xCC00CCFFF0AAF0AA)
        self.assertEqual(trace.key_after_pc1, 0xF0CCAAF556678F)
        self.assertEqual(len(trace.rounds), 16)
        first = trace.rounds[0]
        self.assertEqual((first.left_in, first.right_in), (0xCC00CCFF, 0xF0AAF0AA))
        self.assertEqual(first.subkey, 0x1B02EFFC7072)
        self.assertEqual((first.key_left, first.key_right), (0xE19955F, 0xAACCF1E))
        self.assertEqual(first.expanded, 0x7A15557A1555)
        self.assertEqual(first.mixed, 0x6117BA866527)
        self.assertEqual(first.substituted, 0x5C82B597)
        self.assertEqual(first.permuted, 0x234AA9BB)
        self.assertEqual((first.left_out, first.right_out), (0xF0AAF0AA, 0xEF4A6544))
        self.assertEqual(trace.before_fp, 0x0A4CD99543423234)

    def test_decryption_reverses_round_keys(self):
        key = 0x133457799BBCDFF1
        encrypt = trace_block(0x0123456789ABCDEF, key)
        decrypt = trace_block(encrypt.output, key, decrypt=True)
        self.assertEqual([r.key_index for r in decrypt.rounds], list(range(16, 0, -1)))
        self.assertEqual([r.subkey for r in decrypt.rounds], [r.subkey for r in reversed(encrypt.rounds)])
        self.assertEqual([(r.key_left, r.key_right) for r in decrypt.rounds],
                         [(r.key_left, r.key_right) for r in reversed(encrypt.rounds)])

    def test_key_parity_is_ignored(self):
        block, key = 0x0123456789ABCDEF, 0x133457799BBCDFF1
        self.assertEqual(trace_block(block, key), trace_block(block, key ^ 0x0101010101010101))

    def test_block_and_key_bounds(self):
        for block, key in ((-1, 0), (0, -1), (1 << 64, 0), (0, 1 << 64)):
            with self.subTest(block=block, key=key), self.assertRaises(ValueError):
                trace_block(block, key)


if __name__ == "__main__":
    unittest.main()
