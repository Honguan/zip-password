import importlib.machinery
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch


APP = importlib.machinery.SourceFileLoader(
    "password_tools_gui_config_search", str(Path(__file__).with_name("PasswordToolsGUI.pyw"))
).load_module()


class ConfigSearchTests(TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app_dir = Path(self.temp.name) / "app"
        self.cwd = Path(self.temp.name) / "other"
        self.app_dir.mkdir()
        self.cwd.mkdir()
        self.config_path = self.app_dir / "password_gui_config.json"
        for item in (
            patch.object(APP, "APP_DIR", self.app_dir),
            patch.object(APP, "CONFIG_PATH", self.config_path),
            patch.object(APP, "default_config", return_value={"output_dir": "default"}),
            patch.object(APP, "find_tool_paths", return_value={}),
        ):
            item.start()
            self.addCleanup(item.stop)

    def test_generic_configs_in_cwd_are_ignored(self):
        (self.cwd / "config.json").write_text('{"output_dir": "wrong"}', encoding="utf-8")
        (self.cwd / "settings.json").write_text('{"output_dir": "wrong"}', encoding="utf-8")

        with patch.object(APP.Path, "cwd", return_value=self.cwd):
            config, error, source = APP.load_config()

        self.assertEqual(config["output_dir"], "default")
        self.assertEqual(error, "")
        self.assertIsNone(source)
        self.assertFalse(self.config_path.exists())

    def test_primary_config_is_loaded(self):
        self.config_path.write_text('{"output_dir": "primary"}', encoding="utf-8")

        config, error, source = APP.load_config()

        self.assertEqual(config["output_dir"], "primary")
        self.assertEqual(error, "")
        self.assertEqual(source, self.config_path)

    def test_app_specific_legacy_config_is_migrated_with_source(self):
        legacy = self.app_dir / APP.LEGACY_CONFIG_NAMES[0]
        legacy.write_text('{"output_dir": "legacy"}', encoding="utf-8")

        config, error, source = APP.load_config()

        self.assertEqual(config["output_dir"], "legacy")
        self.assertEqual(error, "")
        self.assertEqual(source, legacy)
        self.assertEqual(APP.read_config_file(self.config_path)["output_dir"], "legacy")


if __name__ == "__main__":
    main()
