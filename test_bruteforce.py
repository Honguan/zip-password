import unittest

from password_gui.bruteforce import (
    DEFAULT_CATEGORIES,
    build_charset,
    candidate_count,
    estimate_seconds,
    format_duration,
    john_charset_expression,
    parse_hashcat_benchmark,
)
from password_gui.config import AppConfig


class BruteForceTests(unittest.TestCase):
    def test_single_and_multiple_categories_form_an_exact_union(self):
        digits = build_charset(["digits"])
        combined = build_charset(["digits", "english"])
        self.assertEqual(digits, b"0123456789")
        self.assertIn(ord("0"), combined)
        self.assertIn(ord("a"), combined)
        self.assertIn(ord("Z"), combined)
        self.assertEqual(len(combined), len(set(combined)))

    def test_default_includes_all_categories(self):
        charset = build_charset(DEFAULT_CATEGORIES)
        self.assertIn(ord("1"), charset)
        self.assertIn(ord("A"), charset)
        self.assertIn("é".encode("cp1252")[0], charset)
        self.assertIn(ord("!"), charset)
        self.assertIn(ord(" "), charset)
        printable = bytes(
            value for value in range(32, 256)
            if _decodes_to_printable_cp1252(value)
        )
        self.assertEqual(set(charset), set(printable))

    def test_arbitrary_mixed_ascii_placement_is_covered(self):
        charset = build_charset(["digits", "english"])
        for candidate in (b"12t4n6", b"abc123", b"1a2B3c"):
            self.assertTrue(all(value in charset for value in candidate))
        self.assertEqual(john_charset_expression(["digits", "english"]), "?d?l?u")

    def test_deselected_categories_are_excluded(self):
        charset = build_charset(["digits"])
        self.assertNotIn(ord("a"), charset)
        self.assertNotIn(ord("!"), charset)

    def test_candidate_count_covers_only_selected_range(self):
        self.assertEqual(candidate_count(10, 4, 6), 10**4 + 10**5 + 10**6)
        with self.assertRaises(ValueError):
            candidate_count(10, 7, 6)

    def test_eta_uses_candidate_count_or_reports_unavailable(self):
        self.assertIsNone(estimate_seconds(1_000, None))
        self.assertEqual(estimate_seconds(1_000, 100), (5, 10))
        self.assertEqual(format_duration(120), "2.0 分鐘")
        self.assertEqual(format_duration(101 * 365.25 * 86400), ">100 年")
        self.assertEqual(
            parse_hashcat_benchmark("warning\n1:0:2430:8501:87.95:9528719259\n", "0"),
            9_528_719_259,
        )

    def test_selection_and_range_round_trip_through_config(self):
        config = AppConfig.from_mapping({
            "brute_force_categories": ["digits", "english"],
            "brute_force_min_length": 6,
            "brute_force_max_length": 6,
        }, AppConfig())
        restored = AppConfig.from_mapping(config.to_mapping(), AppConfig())
        self.assertEqual(restored.brute_force_categories, ("digits", "english"))
        self.assertEqual((restored.brute_force_min_length, restored.brute_force_max_length), (6, 6))


def _decodes_to_printable_cp1252(value):
    try:
        return bytes([value]).decode("cp1252").isprintable()
    except UnicodeDecodeError:
        return False


if __name__ == "__main__":
    unittest.main()
