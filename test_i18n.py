import unittest

from password_gui.config import AppConfig
from password_gui.i18n import DEFAULT_LANGUAGE, normalize_language, source_text, translate


class LocalizationTests(unittest.TestCase):
    def test_default_and_invalid_language_use_traditional_chinese(self):
        self.assertEqual(AppConfig().language, DEFAULT_LANGUAGE)
        self.assertEqual(normalize_language("unknown"), DEFAULT_LANGUAGE)

    def test_switches_both_directions(self):
        self.assertEqual(translate("開始分析", "en"), "Start analysis")
        self.assertEqual(translate("開始分析", "zh-TW"), "開始分析")

    def test_external_output_is_unchanged(self):
        output = "hashcat: 123456:secret / C:\\目錄\\hash.txt"
        self.assertEqual(translate(output, "en"), output)

    def test_display_label_maps_back_to_stable_source(self):
        sources = {"自動": object(), "純暴力": object()}
        self.assertEqual(source_text("Brute force", sources), "純暴力")

    def test_config_round_trip_and_invalid_fallback(self):
        defaults = AppConfig()
        self.assertEqual(AppConfig.from_mapping({"language": "en"}, defaults).language, "en")
        self.assertEqual(AppConfig.from_mapping({"language": "xx"}, defaults).language, DEFAULT_LANGUAGE)


if __name__ == "__main__":
    unittest.main()
