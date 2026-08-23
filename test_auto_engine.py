import importlib.machinery
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import Mock, patch


APP = importlib.machinery.SourceFileLoader(
    "password_tools_gui_engine", str(Path(__file__).with_name("PasswordToolsGUI.pyw"))
).load_module()


class AutoEngineTests(TestCase):
    def test_rar5_uses_john_before_hashcat(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            hashcat = root / "hashcat.exe"
            john = root / "john.exe"
            hashcat.touch()
            john.touch()
            paths = {"john_hash": root / "john.hash", "hashcat_hash": root / "hashcat.hash"}
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
                APP, "detect_hashcat_mode", return_value="13000 - RAR5"
            ):
                gui._auto_workflow(root / "sample.rar", "wordlist.txt", settings)

        self.assertEqual(gui.build_auto_attack_stages.call_args.args[2], "john")
        gui.convert_file_to_hash_text.assert_called_once_with(root / "sample.rar", "rar2john.exe", True)
        gui.after.assert_not_called()
        gui.enqueue_ui.call_args.args[0]()
        gui.start_auto_stages.assert_called_once_with([], 0)


if __name__ == "__main__":
    main()
