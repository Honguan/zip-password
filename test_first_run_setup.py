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
        gui._tools_setup_lock = APP.threading.Lock()
        gui.quick_auto_download = Value(True)
        gui.enqueue_log = Mock()
        gui.enqueue_status = Mock()
        gui.enqueue_ui = Mock()
        gui.apply_detected_tools_to_ui = Mock()
        gui.download_hashcat = Mock(return_value="hashcat.exe")
        gui.download_john = Mock(return_value=("john.exe", "john-run"))
        return gui

    def test_missing_tools_are_downloaded_on_first_run(self):
        gui = self.make_gui()
        gui.config_data = {
            "hashcat_path": "missing-hashcat.exe",
            "john_path": "missing-john.exe",
            "john_run_dir": "missing-run",
        }
        missing = {key: "" for key in ("hashcat_path", "john_path", "john_run_dir")}

        with patch.object(APP, "ensure_tool_dirs"), patch.object(APP, "find_tool_paths", return_value=missing):
            gui._ensure_tools_worker()

        gui.download_hashcat.assert_called_once_with()
        gui.download_john.assert_called_once_with()
        self.assertEqual(gui.config_data["hashcat_path"], "hashcat.exe")
        self.assertEqual(gui.config_data["john_path"], "john.exe")
        self.assertEqual(gui.config_data["john_run_dir"], "john-run")

    def test_missing_tools_are_cleared_when_download_is_disabled(self):
        gui = self.make_gui()
        gui.config_data = {
            "hashcat_path": "missing-hashcat.exe",
            "john_path": "missing-john.exe",
            "john_run_dir": "missing-run",
        }
        missing = {key: "" for key in ("hashcat_path", "john_path", "john_run_dir")}

        with patch.object(APP, "ensure_tool_dirs"), patch.object(APP, "find_tool_paths", return_value=missing):
            gui._ensure_tools_worker(auto_download=False)

        self.assertEqual(gui.config_data, missing)
        gui.enqueue_ui.assert_not_called()
        gui.enqueue_status.assert_called_with("工具環境需要手動處理")

    def test_invalid_john_path_does_not_preserve_its_run_directory(self):
        with patch.object(APP, "existing_exe", return_value=""), patch.object(
            APP, "find_in_env", return_value=""
        ), patch.object(APP.shutil, "which", return_value=None), patch.object(
            APP, "find_hashcat_under", return_value=""
        ), patch.object(APP, "find_john_under", return_value=("", "")):
            detected = APP.find_tool_paths({"john_path": "missing.exe", "john_run_dir": "missing-run"})

        self.assertEqual(detected["john_path"], "")
        self.assertEqual(detected["john_run_dir"], "")

    def test_existing_tools_are_reused_without_download(self):
        gui = self.make_gui()
        installed = {"hashcat_path": "hashcat.exe", "john_path": "john.exe", "john_run_dir": "john-run"}

        with patch.object(APP, "ensure_tool_dirs"), patch.object(APP, "find_tool_paths", return_value=installed):
            gui._ensure_tools_worker()

        gui.download_hashcat.assert_not_called()
        gui.download_john.assert_not_called()
        self.assertEqual(gui.config_data, installed)

    def test_repeated_async_setup_is_ignored_until_the_worker_finishes(self):
        gui = self.make_gui()
        thread = Mock()

        with patch.object(APP.threading, "Thread", return_value=thread) as thread_class:
            gui.ensure_tools_async()
            gui.ensure_tools_async()

        thread_class.assert_called_once_with(target=gui._ensure_tools_worker, args=(True, True), daemon=True)
        thread.start.assert_called_once_with()
        gui.enqueue_status.assert_called_with("工具環境檢查已在執行")
        gui._tools_setup_lock.release()

    def test_setup_can_run_again_after_completion(self):
        gui = self.make_gui()
        installed = {"hashcat_path": "hashcat.exe", "john_path": "john.exe", "john_run_dir": "john-run"}

        with patch.object(APP, "ensure_tool_dirs"), patch.object(APP, "find_tool_paths", return_value=installed) as find_paths:
            gui._ensure_tools_worker()
            gui._ensure_tools_worker()

        self.assertEqual(find_paths.call_count, 2)

    def test_setup_can_retry_after_failure(self):
        gui = self.make_gui()
        installed = {"hashcat_path": "hashcat.exe", "john_path": "john.exe", "john_run_dir": "john-run"}

        with patch.object(APP, "ensure_tool_dirs"), patch.object(APP, "find_tool_paths", side_effect=[RuntimeError("failed"), installed]):
            gui._ensure_tools_worker()
            gui._ensure_tools_worker()

        self.assertEqual(gui.config_data, installed)

    def test_setup_worker_uses_snapshotted_download_setting(self):
        gui = self.make_gui()
        gui.quick_auto_download = Mock()
        gui.quick_auto_download.get.side_effect = AssertionError("worker touched Tk")
        installed = {"hashcat_path": "hashcat.exe", "john_path": "john.exe", "john_run_dir": "john-run"}

        with patch.object(APP, "ensure_tool_dirs"), patch.object(APP, "find_tool_paths", return_value=installed):
            gui._ensure_tools_worker(auto_download=False)

        gui.quick_auto_download.get.assert_not_called()
        gui.enqueue_ui.assert_called_once_with(gui.apply_detected_tools_to_ui)
        gui.enqueue_status.assert_called_with("工具環境已就緒")


if __name__ == "__main__":
    main()
