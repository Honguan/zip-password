from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import Mock, patch

import password_gui.app as APP


class RuntimePathTests(TestCase):
    def test_fresh_defaults_use_ascii_application_directories(self):
        self.assertEqual(APP.TOOLS_DIR.name, "PasswordToolsGUI_tools")
        self.assertEqual(APP.RESULTS_DIR.name, "PasswordToolsGUI_output")
        APP.TOOLS_DIR.name.encode("ascii")
        APP.RESULTS_DIR.name.encode("ascii")
        with TemporaryDirectory() as temp:
            root = Path(temp)
            tools = root / APP.TOOLS_DIR.name
            results = root / APP.RESULTS_DIR.name
            with (
                patch.object(APP, "TOOLS_DIR", tools),
                patch.object(APP, "DOWNLOADS_DIR", tools / "downloads"),
                patch.object(APP, "TOOL_TMP_DIR", tools / "tmp"),
                patch.object(APP, "WORDLISTS_DIR", tools / "wordlists"),
                patch.object(APP, "RESULTS_DIR", results),
            ):
                APP.ensure_tool_dirs()

            self.assertTrue(tools.is_dir())
            self.assertTrue(results.is_dir())
            self.assertFalse((root / "密碼工具GUI_tools").exists())
            self.assertFalse((root / "密碼工具GUI_輸出").exists())

    def test_legacy_tools_and_results_are_migrated_once(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            legacy_tools = root / "密碼工具GUI_tools"
            legacy_results = root / "密碼工具GUI_輸出"
            tools = root / "PasswordToolsGUI_tools"
            results = root / "PasswordToolsGUI_output"
            (legacy_tools / "hashcat").mkdir(parents=True)
            (legacy_tools / "hashcat" / "hashcat.exe").write_bytes(b"tool")
            (legacy_tools / "JohnRipper" / "run").mkdir(parents=True)
            (legacy_tools / "JohnRipper" / "run" / "john.exe").write_bytes(b"tool")
            legacy_results.mkdir()
            (legacy_results / "previous.txt").write_text("result", encoding="utf-8")

            with (
                patch.object(APP, "LEGACY_TOOLS_DIR", legacy_tools),
                patch.object(APP, "LEGACY_RESULTS_DIR", legacy_results),
                patch.object(APP, "TOOLS_DIR", tools),
                patch.object(APP, "RESULTS_DIR", results),
            ):
                self.assertTrue(APP.migrate_legacy_runtime_dirs())
                self.assertFalse(APP.migrate_legacy_runtime_dirs())

            self.assertEqual((tools / "hashcat" / "hashcat.exe").read_bytes(), b"tool")
            self.assertEqual(APP.find_hashcat_under(tools / "hashcat"), str(tools / "hashcat" / "hashcat.exe"))
            self.assertEqual(APP.find_john_under(tools / "JohnRipper")[0], str(tools / "JohnRipper" / "run" / "john.exe"))
            self.assertEqual((results / "previous.txt").read_text(encoding="utf-8"), "result")
            self.assertFalse(legacy_tools.exists())
            self.assertFalse(legacy_results.exists())

    def test_migration_conflict_keeps_legacy_data_intact(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            legacy = root / "密碼工具GUI_tools"
            current = root / "PasswordToolsGUI_tools"
            legacy.mkdir()
            current.mkdir()
            (legacy / "wordlist.txt").write_text("legacy", encoding="utf-8")
            (current / "wordlist.txt").write_text("current", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "同時存在"):
                APP.migrate_legacy_directory(legacy, current)

            self.assertEqual((legacy / "wordlist.txt").read_text(encoding="utf-8"), "legacy")
            self.assertEqual((current / "wordlist.txt").read_text(encoding="utf-8"), "current")

    def test_empty_ascii_destination_does_not_block_migration(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            legacy = root / "密碼工具GUI_輸出"
            current = root / "PasswordToolsGUI_output"
            legacy.mkdir()
            current.mkdir()
            (legacy / "result.txt").write_text("preserved", encoding="utf-8")

            self.assertTrue(APP.migrate_legacy_directory(legacy, current))

            self.assertEqual((current / "result.txt").read_text(encoding="utf-8"), "preserved")

    def test_second_directory_failure_rolls_back_first_migration(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            legacy_tools = root / "密碼工具GUI_tools"
            legacy_results = root / "密碼工具GUI_輸出"
            tools = root / "PasswordToolsGUI_tools"
            results = root / "PasswordToolsGUI_output"
            legacy_tools.mkdir()
            legacy_results.mkdir()
            original_migrate = APP.migrate_legacy_directory

            def migrate(legacy, current):
                if legacy == legacy_results:
                    raise RuntimeError("模擬第二個目錄失敗")
                return original_migrate(legacy, current)

            with (
                patch.object(APP, "LEGACY_TOOLS_DIR", legacy_tools),
                patch.object(APP, "LEGACY_RESULTS_DIR", legacy_results),
                patch.object(APP, "TOOLS_DIR", tools),
                patch.object(APP, "RESULTS_DIR", results),
                patch.object(APP, "migrate_legacy_directory", side_effect=migrate),
                self.assertRaisesRegex(RuntimeError, "第二個目錄失敗"),
            ):
                APP.migrate_legacy_runtime_dirs()

            self.assertTrue(legacy_tools.is_dir())
            self.assertTrue(legacy_results.is_dir())
            self.assertFalse(tools.exists())
            self.assertFalse(results.exists())

    def test_loaded_config_rewrites_only_migrated_application_paths(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            legacy_tools = root / "密碼工具GUI_tools"
            legacy_results = root / "密碼工具GUI_輸出"
            tools = root / "PasswordToolsGUI_tools"
            results = root / "PasswordToolsGUI_output"
            tools.mkdir()
            results.mkdir()
            config_path = root / "password_gui_config.json"
            custom_node = root / "使用者工具" / "node.exe"
            config_path.write_text(
                "{\n"
                f'  "hashcat_path": "{(legacy_tools / "hashcat/hashcat.exe").as_posix()}",\n'
                f'  "default_wordlist": "{(legacy_tools / "wordlists/常用.txt").as_posix()}",\n'
                f'  "output_dir": "{legacy_results.as_posix()}",\n'
                f'  "node_path": "{custom_node.as_posix()}"\n'
                "}",
                encoding="utf-8",
            )

            with (
                patch.object(APP, "CONFIG_PATH", config_path),
                patch.object(APP, "config_search_paths", return_value=[config_path]),
                patch.object(APP, "LEGACY_TOOLS_DIR", legacy_tools),
                patch.object(APP, "LEGACY_RESULTS_DIR", legacy_results),
                patch.object(APP, "TOOLS_DIR", tools),
                patch.object(APP, "RESULTS_DIR", results),
                patch.object(APP, "default_config", return_value=APP.AppConfig(output_dir=results)),
                patch.object(APP, "find_tool_paths", return_value={}),
            ):
                config, error, source = APP.load_config()

            self.assertEqual(error, "")
            self.assertEqual(source, config_path)
            self.assertEqual(config.hashcat_path, tools / "hashcat" / "hashcat.exe")
            self.assertEqual(config.default_wordlist, tools / "wordlists" / "常用.txt")
            self.assertEqual(config.output_dir, results)
            self.assertEqual(config.node_path, custom_node)
            saved = APP.read_config_file(config_path)
            self.assertEqual(Path(saved["output_dir"]), results)
            self.assertEqual(Path(saved["node_path"]), custom_node)

    def test_missing_legacy_directory_still_upgrades_stored_default(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            legacy_tools = root / "密碼工具GUI_tools"
            legacy_results = root / "密碼工具GUI_輸出"
            tools = root / "PasswordToolsGUI_tools"
            results = root / "PasswordToolsGUI_output"
            config = APP.AppConfig(
                output_dir=legacy_results,
                default_wordlist=legacy_tools / "wordlists" / "common.txt",
            )

            with (
                patch.object(APP, "LEGACY_TOOLS_DIR", legacy_tools),
                patch.object(APP, "LEGACY_RESULTS_DIR", legacy_results),
                patch.object(APP, "TOOLS_DIR", tools),
                patch.object(APP, "RESULTS_DIR", results),
            ):
                self.assertTrue(APP.upgrade_config_runtime_paths(config))

            self.assertEqual(config.output_dir, results)
            self.assertEqual(config.default_wordlist, tools / "wordlists" / "common.txt")

    def test_failed_migration_blocks_automatic_tool_download(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.runtime_migration_error = "新舊目錄衝突"
        gui._startup_tools_checked = False
        with patch.object(gui, "ensure_tools_async") as ensure:
            gui.ensure_tools_on_startup()

        ensure.assert_not_called()

        gui.enqueue_status = Mock()
        gui.ensure_tools_async()
        gui.enqueue_status.assert_called_once_with("執行資料夾需要手動處理")

        gui.job_controller = Mock()
        gui._ensure_tools_worker = Mock()
        gui.enqueue_log = Mock()
        gui._fail_auto_job = Mock()
        gui._auto_workflow(Path("C:/來源/測試.zip"), "", {})
        gui._ensure_tools_worker.assert_not_called()
        self.assertIsInstance(gui._fail_auto_job.call_args.args[0], APP.MissingToolError)


if __name__ == "__main__":
    main()
