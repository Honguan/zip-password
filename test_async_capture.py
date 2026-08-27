from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import Mock, patch

import password_gui.app as APP


class DeferredThread:
    def __init__(self, target, daemon):
        self.target = target
        self.daemon = daemon

    def start(self):
        pass

    def is_alive(self):
        return False


class AsyncCaptureTests(TestCase):
    def make_gui(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.runner = Mock()
        gui.capture_thread = None
        gui.enqueue_ui = Mock()
        gui.conversion_cancel = APP.threading.Event()
        return gui

    def test_show_callback_schedules_capture_and_continues_only_after_ui_result(self):
        with TemporaryDirectory() as temp:
            gui = self.make_gui()
            gui.config_data = APP.AppConfig(hashcat_path=Path("hashcat.exe"))
            gui.quick_status = Mock()
            gui.log = Mock()
            gui.set_cracked_passwords = Mock()
            gui.runner.capture.return_value = APP.subprocess.CompletedProcess([], 0, b"secret\n", b"")
            complete = Mock()

            with patch.object(APP.threading, "Thread", DeferredThread):
                gui.finalize_auto_cracked(
                    "hashcat", Path("hash.txt"), "0 - MD5", Path(temp) / "cracked.txt", complete
                )

            gui.runner.capture.assert_not_called()
            complete.assert_not_called()
            gui.capture_thread.target()
            complete.assert_not_called()
            gui.enqueue_ui.call_args.args[0]()
            complete.assert_called_once_with()

    def test_load_formats_callback_does_not_wait_for_john(self):
        gui = self.make_gui()
        gui.config_data = APP.AppConfig(john_run_dir=Path("run"))
        gui.john_common_args = Mock(return_value=["john.exe"])

        with patch.object(APP.threading, "Thread", DeferredThread):
            gui.load_john_formats()

        gui.runner.capture.assert_not_called()
        self.assertIsNotNone(gui.capture_thread)

    def test_health_check_callback_does_not_wait_for_tools(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            hashcat = root / "hashcat.exe"
            john = root / "john.exe"
            hashcat.touch()
            john.touch()
            gui = self.make_gui()
            gui.config_data = APP.AppConfig(hashcat_path=hashcat, john_path=john)
            gui.apply_settings = Mock()
            gui.notebook = Mock()
            gui.output_tab = object()
            gui.log = Mock()

            with patch.object(APP, "find_tool_paths", return_value={}), patch.object(
                APP.threading, "Thread", DeferredThread
            ):
                gui.health_check()

        gui.runner.capture.assert_not_called()
        self.assertIsNotNone(gui.capture_thread)

    def test_worker_error_is_delivered_through_ui_queue(self):
        gui = self.make_gui()
        on_error = Mock()

        gui._start_capture_task(
            Mock(side_effect=TimeoutError("slow tool")), Mock(), on_error
        )
        gui.capture_thread.join()

        on_error.assert_not_called()
        gui.enqueue_ui.call_args.args[0]()
        on_error.assert_called_once()


if __name__ == "__main__":
    main()
