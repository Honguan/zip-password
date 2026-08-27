import password_gui.app as APP
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import Mock, patch


class Value:
    def __init__(self):
        self.value = ""

    def set(self, value):
        self.value = value


class ConfigLoadingTests(TestCase):
    def load(self, content):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / "password_gui_config.json"
        path.write_text(content, encoding="utf-8")
        defaults = APP.AppConfig(output_dir=Path("default"))
        patches = (
            patch.object(APP, "CONFIG_PATH", path),
            patch.object(APP, "config_search_paths", return_value=[path]),
            patch.object(APP, "default_config", return_value=defaults),
            patch.object(APP, "find_tool_paths", return_value={}),
        )
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        return path, APP.load_config()

    def test_malformed_json_uses_defaults_without_overwriting_source(self):
        original = '{"output_dir": "custom", broken}'
        path, (config, error, source) = self.load(original)

        self.assertEqual(config.output_dir, Path("default"))
        self.assertIn("JSON", error)
        self.assertEqual(source, path)
        self.assertEqual(path.read_text(encoding="utf-8"), original)

    def test_non_object_json_uses_defaults_without_overwriting_source(self):
        original = '["not", "an", "object"]'
        path, (config, error, source) = self.load(original)

        self.assertEqual(config.output_dir, Path("default"))
        self.assertIn("不是 JSON object", error)
        self.assertEqual(source, path)
        self.assertEqual(path.read_text(encoding="utf-8"), original)

    def test_valid_config_loads_without_error(self):
        path, (config, error, source) = self.load(
            '{"output_dir": "custom", "attack_strategy": "MASK", "unknown": "ignored"}'
        )

        self.assertEqual(config.output_dir, Path("custom"))
        self.assertEqual(config.attack_strategy, APP.AttackStrategy.MASK)
        self.assertNotIn("unknown", config.to_mapping())
        self.assertEqual(error, "")
        self.assertEqual(source, path)

    def test_only_explicit_save_can_replace_config_after_load_error(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.config_data = APP.AppConfig(output_dir=Path("default"))
        gui.config_load_error = "invalid JSON"

        with patch.object(APP, "save_config") as save:
            gui._save_config()
            save.assert_not_called()
            gui._save_config(explicit=True)

        save.assert_called_once_with(gui.config_data)
        self.assertEqual(gui.config_load_error, "")

    def test_legacy_boolean_migrates_and_saves_as_json_boolean(self):
        path, (config, error, _source) = self.load('{"auto_follow_order": "0"}')

        self.assertEqual(error, "")
        self.assertEqual(config.attack_strategy, APP.AttackStrategy.AUTO)
        with patch.object(APP, "CONFIG_PATH", path):
            APP.save_config(config)
        saved = APP.read_config_file(path)
        self.assertEqual(saved["attack_strategy"], "AUTO")
        self.assertNotIn("auto_follow_order", saved)

    def test_malformed_typed_value_reports_error_without_overwriting(self):
        original = '{"output_dir": ["invalid"]}'
        path, (config, error, _source) = self.load(original)

        self.assertEqual(config.output_dir, Path("default"))
        self.assertIn("必須是路徑字串", error)
        self.assertEqual(path.read_text(encoding="utf-8"), original)

    def test_load_error_is_shown_to_the_user(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.config_load_error = "JSONDecodeError: invalid"
        gui.quick_status = Value()
        gui.set_status = Mock()

        with patch.object(APP.messagebox, "showwarning") as warning:
            gui._show_config_load_error()

        self.assertIn("使用預設設定", gui.quick_status.value)
        warning.assert_called_once()

    def test_tool_detection_keeps_load_error_visible(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.config_load_error = "invalid JSON"
        gui.quick_status = Value()
        gui._save_config = Mock()
        gui.refresh_converters = Mock()
        gui.sync_config_to_ui = Mock()

        gui.apply_detected_tools_to_ui()

        self.assertIn("設定載入失敗", gui.quick_status.value)


if __name__ == "__main__":
    main()
