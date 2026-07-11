import importlib.machinery
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import Mock, patch


APP = importlib.machinery.SourceFileLoader(
    "password_tools_gui_setup", str(Path(__file__).with_name("PasswordToolsGUI.pyw"))
).load_module()


class Value:
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value


class FirstRunSetupTests(TestCase):
    def make_gui(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.config_data = {}
        gui.quick_auto_download = Value(True)
        gui.enqueue_log = Mock()
        gui.enqueue_status = Mock()
        gui.apply_detected_tools_to_ui = Mock()
        gui.after = lambda _delay, callback: callback()
        gui.download_hashcat = Mock(return_value="hashcat.exe")
        gui.download_john = Mock(return_value=("john.exe", "john-run"))
        return gui

    def test_missing_tools_are_downloaded_on_first_run(self):
        gui = self.make_gui()
        missing = {key: "" for key in ("hashcat_path", "john_path", "john_run_dir")}

        with patch.object(APP, "ensure_tool_dirs"), patch.object(APP, "find_tool_paths", return_value=missing):
            gui._ensure_tools_worker()

        gui.download_hashcat.assert_called_once_with()
        gui.download_john.assert_called_once_with()
        self.assertEqual(gui.config_data["hashcat_path"], "hashcat.exe")
        self.assertEqual(gui.config_data["john_path"], "john.exe")
        self.assertEqual(gui.config_data["john_run_dir"], "john-run")

    def test_existing_tools_are_reused_without_download(self):
        gui = self.make_gui()
        installed = {"hashcat_path": "hashcat.exe", "john_path": "john.exe", "john_run_dir": "john-run"}

        with patch.object(APP, "ensure_tool_dirs"), patch.object(APP, "find_tool_paths", return_value=installed):
            gui._ensure_tools_worker()

        gui.download_hashcat.assert_not_called()
        gui.download_john.assert_not_called()
        self.assertEqual(gui.config_data, installed)


if __name__ == "__main__":
    main()
