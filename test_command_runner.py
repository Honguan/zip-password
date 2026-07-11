import importlib.machinery
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import Mock, patch


APP = importlib.machinery.SourceFileLoader(
    "password_tools_gui_runner", str(Path(__file__).with_name("PasswordToolsGUI.pyw"))
).load_module()


class CommandRunnerTests(TestCase):
    def test_elapsed_seconds_tracks_running_and_completed_work(self):
        runner = APP.CommandRunner(Mock())
        runner.started_at = 100.0

        with patch.object(APP.time, "monotonic", return_value=165.0):
            self.assertEqual(runner.elapsed_seconds(), 65.0)

        runner.started_at = None
        runner.last_elapsed = 65.0
        self.assertEqual(runner.elapsed_seconds(), 65.0)

    def test_format_elapsed_uses_hours_when_needed(self):
        self.assertEqual(APP.format_elapsed(65), "01:05")
        self.assertEqual(APP.format_elapsed(3661), "01:01:01")

    def test_stop_terminates_running_process_and_logs_request(self):
        app = Mock()
        runner = APP.CommandRunner(app)
        process = Mock()
        process.poll.return_value = None
        runner.process = process

        runner.stop()

        process.terminate.assert_called_once_with()
        app.log.assert_called_once_with("\n[控制] 已要求停止目前工作\n")

    def test_dashboard_shows_runner_elapsed_time(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.runner = Mock()
        gui.runner.elapsed_seconds.return_value = 65.0
        gui.output_elapsed_var = Mock()

        gui.update_elapsed()

        gui.output_elapsed_var.set.assert_called_once_with("01:05")


if __name__ == "__main__":
    main()
