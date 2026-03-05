from __future__ import annotations

import unittest

from hunterops.intelligence import detect_sensitive, http_diff_score, jaccard


class IntelligenceTests(unittest.TestCase):
    def test_detect_sensitive(self) -> None:
        text = "token='AAAAAAAAAAAAAAAAAAAA' and AKIAABCDEFGHIJKLMNOP and eyJabc.def.ghi"
        hits = detect_sensitive(text)
        self.assertTrue(len(hits) >= 2)

    def test_http_diff(self) -> None:
        b = {"status": 200, "length": 100, "json_keys": ["a", "b"]}
        c = {"status": 403, "length": 210, "json_keys": ["a", "c"]}
        diff = http_diff_score(b, c)
        self.assertGreaterEqual(diff["anomaly_score"], 70)

    def test_jaccard(self) -> None:
        self.assertAlmostEqual(jaccard({"a", "b"}, {"a", "b"}), 1.0)
        self.assertLess(jaccard({"a"}, {"b"}), 0.5)


if __name__ == "__main__":
    unittest.main()

