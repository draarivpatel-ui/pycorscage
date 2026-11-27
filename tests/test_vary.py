"""Cache-safe Vary merging tests."""

from __future__ import annotations

import unittest

from pycorscage import merge_vary

from _support import add_matrix_tests


MERGE_CASES = [
    (None, None, ""),
    ("", "", ""),
    ("Origin", None, "Origin"),
    (None, "Origin", "Origin"),
    ("Accept-Encoding", "Origin", "Accept-Encoding, Origin"),
    ("Accept-Encoding, origin", "Origin", "Accept-Encoding, origin"),
    ("origin", "Origin", "origin"),
    ("Origin,Accept-Encoding", ["Accept-Encoding", "Origin"], "Origin, Accept-Encoding"),
    (" Accept-Encoding , Origin ", "accept-encoding", "Accept-Encoding, Origin"),
    (["Accept-Encoding", "Origin"], "Access-Control-Request-Method", "Accept-Encoding, Origin, Access-Control-Request-Method"),
    (["Accept-Encoding,Origin"], ["origin", "X-One"], "Accept-Encoding, Origin, X-One"),
    ("*", "Origin", "*"),
    ("Origin", "*", "*"),
    ("*, Origin", "Accept-Encoding", "*"),
    (["*"], ["Origin"], "*"),
    ("bad header", "Origin", "Origin"),
    ("bad\x00header", "Origin", "Origin"),
    ("valid-token", "bad header, Origin", "valid-token, Origin"),
    ("", "   ", ""),
    (None, ["", "  ", "Origin"], "Origin"),
    (123, "Origin", "Origin"),
    ([123, None, "Origin"], "origin", "Origin"),
    ("x-a,,x-b", "x-c", "x-a, x-b, x-c"),
    ("\tOrigin\t", "origin", "Origin"),
    ("O", "o, O, o", "O"),
    ("access-control-request-method", "Access-Control-Request-Method", "access-control-request-method"),
]


class TestMergeVary(unittest.TestCase):
    def check_merge(self, case):
        existing, added, expected = case
        self.assertEqual(merge_vary(existing, added), expected)

    def test_input_list_not_mutated(self):
        existing = ["Accept-Encoding"]
        added = ["Origin"]
        merge_vary(existing, added)
        self.assertEqual(existing, ["Accept-Encoding"])
        self.assertEqual(added, ["Origin"])

    def test_star_in_any_position_dominates(self):
        self.assertEqual(merge_vary("Origin, * , Accept-Encoding", "X-One"), "*")

    def test_invalid_iterable_is_ignored(self):
        self.assertEqual(merge_vary(123, 456), "")

    def test_added_tuple_supported(self):
        self.assertEqual(merge_vary(None, ("Origin", "Access-Control-Request-Method")), "Origin, Access-Control-Request-Method")


add_matrix_tests(TestMergeVary, "merge", MERGE_CASES, TestMergeVary.check_merge)


if __name__ == "__main__":
    unittest.main()
