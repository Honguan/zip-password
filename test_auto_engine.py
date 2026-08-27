import importlib.machinery
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import Mock, patch


APP = importlib.machinery.SourceFileLoader(
    "password_tools_gui_engine", str(Path(__file__).with_name("PasswordToolsGUI.pyw"))
).load_module()


class Value:
    def __init__(self, value=""):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class AutoEngineTests(TestCase):
    def test_custom_output_directory_is_used_by_auto_and_extract_paths(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            output_dir = root / "custom-output"
            source = root / "sample.zip"
            source.touch()
            gui = object.__new__(APP.PasswordToolGUI)
            gui.config_data = {"output_dir": str(output_dir)}
            gui.extract_input = Value(str(source))
            gui.extract_target = Value("hashcat")
            gui.extract_output = Value()

            paths = gui._auto_output_paths(source)
            gui.suggest_extract_output()
            with patch.object(APP.os, "startfile") as startfile:
                gui.open_output_folder()

        result_dir = next(iter(paths.values())).parent
        self.assertEqual(result_dir.parent, output_dir)
        self.assertTrue(all(path.parent == result_dir for path in paths.values()))
        self.assertEqual(Path(gui.extract_output.get()).parent, result_dir)
        startfile.assert_called_once_with(str(output_dir))

    def test_rar5_uses_john_before_hashcat(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            hashcat = root / "hashcat.exe"
            john = root / "john.exe"
            source = root / "sample.rar"
            cracked = root / "sample_cracked.txt"
            hashcat.touch()
            john.touch()
            source.write_bytes(b"changed archive content")
            cracked.write_text("password-from-previous-content\n", encoding="utf-8")
            paths = {
                "john_hash": root / "john.hash",
                "hashcat_hash": root / "hashcat.hash",
                "cracked": cracked,
            }
            gui = object.__new__(APP.PasswordToolGUI)
            gui.config_data = {"hashcat_path": str(hashcat), "john_path": str(john)}
            gui._ensure_tools_worker = Mock()
            gui._auto_output_paths = Mock(return_value=paths)
            gui.convert_file_to_hash_text = Mock(return_value="hash")
            gui.build_auto_attack_stages = Mock(return_value=[])
            gui.start_auto_stages = Mock()
            gui.after = Mock(side_effect=AssertionError("worker called Tk after"))
            gui.enqueue_ui = Mock()
            gui.enqueue_log = Mock()
            gui.enqueue_status = Mock()
            settings = {
                "auto_download": True,
                "converter": "rar2john.exe",
                "safe_copy": True,
                "expand_wordlist": False,
                "hashcat_mask": "",
                "john_mask": "",
            }

            with patch.object(APP, "prepare_hash_output", return_value="hash"), patch.object(
                APP, "detect_hashcat_mode", return_value=Mock(status="detected", mode="13000 - RAR5")
            ):
                gui._auto_workflow(source, "wordlist.txt", settings)

        self.assertEqual(gui.build_auto_attack_stages.call_args.args[2], "john")
        gui.convert_file_to_hash_text.assert_called_once_with(source, "rar2john.exe", True)
        self.assertFalse(cracked.exists())
        gui.after.assert_not_called()
        gui.enqueue_ui.call_args.args[0]()
        gui.start_auto_stages.assert_called_once_with([], 0)

    def test_unknown_pdf_mode_explicitly_falls_back_to_john(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            hashcat = root / "hashcat.exe"
            john = root / "john.exe"
            source = root / "sample.pdf"
            hashcat.touch()
            john.touch()
            source.touch()
            paths = {
                "john_hash": root / "john.hash",
                "hashcat_hash": root / "hashcat.hash",
                "cracked": root / "cracked.txt",
            }
            gui = object.__new__(APP.PasswordToolGUI)
            gui.config_data = {"hashcat_path": str(hashcat), "john_path": str(john)}
            gui._ensure_tools_worker = Mock()
            gui._auto_output_paths = Mock(return_value=paths)
            gui.read_hash_text = Mock(return_value="$pdf$9*9*256*unknown")
            gui.build_auto_attack_stages = Mock(return_value=[])
            gui.enqueue_ui = Mock()
            gui.enqueue_log = Mock()
            gui.enqueue_status = Mock()
            settings = {
                "auto_download": True,
                "converter": "",
                "safe_copy": True,
                "expand_wordlist": False,
                "hashcat_mask": "",
                "john_mask": "",
            }

            gui._auto_workflow(source, "wordlist.txt", settings)

        self.assertEqual(gui.build_auto_attack_stages.call_args.args[2], "john")
        self.assertTrue(any("無法安全判定 PDF" in call.args[0] for call in gui.enqueue_log.call_args_list))

    def test_ambiguous_raw_hash_requests_mode_instead_of_reporting_missing_tools(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            hashcat = root / "hashcat.exe"
            source = root / "sample.hash"
            hashcat.touch()
            source.touch()
            paths = {
                "john_hash": root / "john.hash",
                "hashcat_hash": root / "hashcat.hash",
                "cracked": root / "cracked.txt",
            }
            gui = object.__new__(APP.PasswordToolGUI)
            gui.config_data = {"hashcat_path": str(hashcat), "john_path": ""}
            gui.quick_status = Value("自動流程執行中。")
            gui._ensure_tools_worker = Mock()
            gui._auto_output_paths = Mock(return_value=paths)
            gui.read_hash_text = Mock(return_value="8846f7eaee8fb117ad06bdd830b7586c")
            gui.build_auto_attack_stages = Mock()
            gui.enqueue_ui = Mock()
            gui.enqueue_log = Mock()
            gui.enqueue_status = Mock()
            settings = {
                "auto_download": True,
                "converter": "",
                "safe_copy": True,
                "expand_wordlist": False,
                "hashcat_mask": "",
                "john_mask": "",
            }

            gui._auto_workflow(source, "wordlist.txt", settings)

        gui.build_auto_attack_stages.assert_not_called()
        self.assertIn("無法唯一判定", gui.enqueue_status.call_args.args[0])
        gui.enqueue_ui.call_args.args[0]()
        self.assertIn("選擇 Hashcat 模式", gui.quick_status.get())


if __name__ == "__main__":
    main()
