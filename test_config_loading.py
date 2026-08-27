import importlib.machinery
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import Mock, patch


APP = importlib.machinery.SourceFileLoader(
    "password_tools_gui_config", str(Path(__file__).with_name("PasswordToolsGUI.pyw"))
).load_module()


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
        defaults = {"path": "default", "enabled": "1"}
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
        original = '{"path": "custom", broken}'
        path, (config, error) = self.load(original)

        self.assertEqual(config, {"path": "default", "enabled": "1"})
        self.assertIn("JSON", error)
        self.assertEqual(path.read_text(encoding="utf-8"), original)

    def test_non_object_json_uses_defaults_without_overwriting_source(self):
        original = '["not", "an", "object"]'
        path, (config, error) = self.load(original)

        self.assertEqual(config, {"path": "default", "enabled": "1"})
        self.assertIn("不是 JSON object", error)
        self.assertEqual(path.read_text(encoding="utf-8"), original)

    def test_valid_config_loads_without_error(self):
        _path, (config, error) = self.load('{"path": "custom", "unknown": "ignored"}')

        self.assertEqual(config, {"path": "custom", "enabled": "1"})
        self.assertEqual(error, "")

    def test_only_explicit_save_can_replace_config_after_load_error(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.config_data = {"path": "default"}
        gui.config_load_error = "invalid JSON"

        with patch.object(APP, "save_config") as save:
            gui._save_config()
            save.assert_not_called()
            gui._save_config(explicit=True)

        save.assert_called_once_with(gui.config_data)
        self.assertEqual(gui.config_load_error, "")

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
