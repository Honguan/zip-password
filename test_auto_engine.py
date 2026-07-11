import importlib.machinery
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import Mock


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
            gui.converter_for_input = Mock(return_value="rar2john.exe")
            gui.convert_file_to_hash_text = Mock(return_value="hash")
            gui.prepare_hash_output = Mock(return_value="hash")
            gui.detect_hashcat_mode = Mock(return_value="13000 - RAR5")
            gui.build_auto_attack_stages = Mock(return_value=[])
            gui.start_auto_stages = Mock()
            gui.after = lambda _delay, callback: callback()
            gui.enqueue_log = Mock()
            gui.enqueue_status = Mock()

            gui._auto_workflow(root / "sample.rar", "wordlist.txt")

        self.assertEqual(gui.build_auto_attack_stages.call_args.args[2], "john")


if __name__ == "__main__":
    main()
