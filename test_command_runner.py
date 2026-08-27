import importlib.machinery
from pathlib import Path
from tempfile import TemporaryDirectory
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

    def test_reader_passes_cancellation_to_finish_callback(self):
        app = Mock()
        app.enqueue_ui.side_effect = lambda callback: callback()
        runner = APP.CommandRunner(app)
        process = Mock()
        process.stdout.readline.return_value = b""
        process.wait.return_value = -15
        callback = Mock()
        runner.process = process
        runner.on_finish = callback
        runner.cancel_requested = True
        runner.job_lock.acquire()

        runner._reader(process, "hashcat")

        callback.assert_called_once_with(-15, True)
        app.enqueue_status.assert_called_once_with("hashcat 已停止")
        self.assertEqual(runner.last_result.exit_code, -15)
        self.assertTrue(runner.last_result.cancelled)
        self.assertIsNone(runner.last_result.error)

    def test_capture_returns_converter_output_and_releases_the_job(self):
        app = Mock()
        runner = APP.CommandRunner(app)
        process = Mock(returncode=0)
        process.communicate.return_value = (b"hash", b"warning")

        with patch.object(APP.subprocess, "Popen", return_value=process):
            result = runner.capture("convert", ["converter.exe"])

        self.assertEqual((result.stdout, result.stderr), (b"hash", b"warning"))
        self.assertEqual(runner.last_result.exit_code, 0)
        self.assertFalse(runner.last_result.cancelled)
        self.assertIsNone(runner.last_result.error)
        self.assertTrue(runner.job_lock.acquire(blocking=False))
        runner.job_lock.release()

    def test_capture_rejects_a_second_job(self):
        runner = APP.CommandRunner(Mock())
        runner.job_lock.acquire()

        with self.assertRaisesRegex(RuntimeError, "已有工作"):
            runner.capture("convert", ["converter.exe"])

        runner.job_lock.release()

    def test_start_reports_launch_exception_and_releases_job(self):
        app = Mock()
        runner = APP.CommandRunner(app)

        with (
            patch.object(APP.subprocess, "Popen", side_effect=FileNotFoundError("missing.exe")),
            patch.object(APP.messagebox, "showerror"),
        ):
            started = runner.start("hashcat", ["missing.exe"])

        self.assertFalse(started)
        self.assertIn("FileNotFoundError: missing.exe", app.log.call_args.args[0])
        self.assertIsInstance(runner.last_result.error, FileNotFoundError)
        self.assertTrue(runner.job_lock.acquire(blocking=False))
        runner.job_lock.release()

    def test_stopping_capture_terminates_it_and_reports_stopped(self):
        app = Mock()
        runner = APP.CommandRunner(app)
        process = Mock(returncode=-15)
        process.poll.return_value = None

        def communicate():
            runner.stop()
            return b"", b""

        process.communicate.side_effect = communicate
        with patch.object(APP.subprocess, "Popen", return_value=process):
            with self.assertRaises(InterruptedError):
                runner.capture("convert", ["converter.exe"])

        process.terminate.assert_called_once_with()
        app.enqueue_status.assert_called_with("convert 已停止")
        self.assertEqual(runner.last_result.exit_code, -15)
        self.assertTrue(runner.last_result.cancelled)
        self.assertIsInstance(runner.last_result.error, InterruptedError)

    def test_stop_marks_a_converter_worker_cancelled_before_launch(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.runner = Mock()
        gui.runner.running.return_value = False
        gui.extract_thread = Mock()
        gui.extract_thread.is_alive.return_value = True
        gui.auto_thread = None
        gui.conversion_cancel = APP.threading.Event()
        gui.log = Mock()

        gui.stop_current_work()

        self.assertTrue(gui.conversion_cancel.is_set())
        gui.runner.stop.assert_not_called()

    def test_extract_rejects_a_second_converter_worker(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.extract_input = Mock()
        gui.extract_input.get.return_value = __file__
        gui.extract_output = Mock()
        gui.extract_output.get.return_value = "output.hash"
        gui.converter_for_input = Mock(return_value="zip2john.exe")
        gui.runner = Mock()
        gui.runner.running.return_value = False
        gui.extract_thread = Mock()
        gui.extract_thread.is_alive.return_value = True
        gui.auto_thread = None

        with patch.object(APP.messagebox, "showwarning") as warning:
            gui.start_extract()

        warning.assert_called_once()

    def test_close_stops_and_waits_for_the_active_process(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.runner = Mock()
        gui.runner.running.return_value = True
        gui.extract_thread = None
        gui.auto_thread = None
        gui.conversion_cancel = APP.threading.Event()
        gui.destroy = Mock()

        with patch.object(APP.messagebox, "askyesno", return_value=True):
            gui._on_close()

        gui.runner.stop.assert_called_once_with()
        gui.runner.wait.assert_called_once_with()
        gui.destroy.assert_called_once_with()

    def test_close_waits_for_a_converter_worker_before_destroying(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.runner = Mock()
        gui.runner.running.return_value = False
        gui.extract_thread = Mock()
        gui.extract_thread.is_alive.return_value = True
        gui.auto_thread = None
        gui.conversion_cancel = APP.threading.Event()
        gui.log = Mock()
        gui.destroy = Mock()

        with patch.object(APP.messagebox, "askyesno", return_value=True):
            gui._on_close()

        gui.extract_thread.join.assert_called_once_with()
        gui.destroy.assert_called_once_with()

    def test_close_cancels_and_waits_for_auto_workflow(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.runner = Mock()
        gui.runner.running.return_value = False
        gui.extract_thread = None
        gui.auto_thread = Mock()
        gui.auto_thread.is_alive.return_value = True
        gui.conversion_cancel = APP.threading.Event()
        gui.log = Mock()
        gui.destroy = Mock()

        with patch.object(APP.messagebox, "askyesno", return_value=True):
            gui._on_close()

        self.assertTrue(gui.conversion_cancel.is_set())
        gui.auto_thread.join.assert_called_once_with()
        gui.destroy.assert_called_once_with()

    def test_extract_worker_uses_snapshot_and_queues_ui_update(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            src = root / "input.zip"
            src.touch()
            out = root / "output.hash"
            gui = object.__new__(APP.PasswordToolGUI)
            gui.config_data = APP.AppConfig()
            gui.conversion_cancel = APP.threading.Event()
            gui.converter_command = Mock(return_value=["zip2john.exe", str(src)])
            gui.runner = Mock()
            gui.runner.capture.return_value = APP.subprocess.CompletedProcess([], 0, b"hash", b"")
            gui.enqueue_log = Mock()
            gui.enqueue_status = Mock()
            gui.enqueue_ui = Mock()
            gui.apply_extracted_hash = Mock()
            gui.extract_safe_copy = Mock()
            gui.extract_safe_copy.get.side_effect = AssertionError("worker touched Tk")
            settings = {"safe_copy": False, "target": "john", "fill_hashcat": True, "fill_john": False}

            with patch.object(APP, "prepare_hash_output", return_value="hash\n"):
                gui._extract_worker(src, out, "zip2john.exe", settings)

            self.assertEqual(out.read_text(encoding="utf-8"), "hash\n")
            gui.extract_safe_copy.get.assert_not_called()
            gui.enqueue_ui.call_args.args[0]()
            gui.apply_extracted_hash.assert_called_once_with(out, settings)

    def test_dashboard_shows_runner_elapsed_time(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.runner = Mock()
        gui.runner.elapsed_seconds.return_value = 65.0
        gui.output_elapsed_var = Mock()

        gui.update_elapsed()

        gui.output_elapsed_var.set.assert_called_once_with("01:05")


if __name__ == "__main__":
    main()
