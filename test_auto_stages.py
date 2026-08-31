import password_gui.app as APP
from password_gui.job import ErrorCategory
from contextlib import nullcontext
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import Mock, patch



class Value:
    def __init__(self):
        self.value = ""

    def set(self, value):
        self.value = value


class AutoStagesTests(TestCase):
    def make_gui(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.quick_status = Value()
        gui.start_auto_command = Mock()
        gui.job_controller = APP.JobController()
        return gui

    def make_finalize_gui(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.config_data = APP.AppConfig(hashcat_path=Path("hashcat.exe"), john_path=Path("john.exe"))
        gui.quick_status = Value()
        gui.log = Mock()
        gui.set_cracked_passwords = Mock()
        gui.runner = Mock()
        gui.capture_thread = None
        gui.enqueue_ui = Mock()
        gui.conversion_cancel = APP.threading.Event()
        return gui

    def complete_capture(self, gui):
        gui.capture_thread.join()
        gui.enqueue_ui.call_args.args[0]()

    def make_start_gui(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.quick_status = Value()
        gui.output_job_var = Value()
        gui.output_status_var = Value()
        gui.output_mode_var = Value()
        gui.output_file_var = Value()
        gui.refresh_output_overview = Mock()
        gui.describe_auto_attack_plan = Mock(return_value="plan")
        gui.log = Mock()
        gui.runner = Mock()
        return gui

    def stages(self, cracked, engine="hashcat"):
        return [
            APP.JobStage(
                id="dictionary", display_name=f"{engine} 字典", engine=engine,
                attack_type="dict", command=(engine,), session_log=Path("session.log"),
                hash_file=Path("hash.txt"), mode_label="0 - MD5", cracked_file=cracked,
            ),
            APP.JobStage(
                id="mask", display_name=f"{engine} 硬破解", engine=engine,
                attack_type="mask", command=(engine, "-a", "3"), session_log=Path("session.log"),
                hash_file=Path("hash.txt"), mode_label="0 - MD5", cracked_file=cracked,
            ),
        ]

    def start_stages(self, gui, stages):
        gui.job_controller.start(APP.JobContext(source_file="input.zip", stages=stages))
        gui.job_controller.run()
        gui.start_auto_stages()

    def test_continues_to_next_stage_when_no_password_was_written(self):
        with TemporaryDirectory() as temp:
            gui = self.make_gui()
            stages = self.stages(Path(temp) / "cracked.txt")

            self.start_stages(gui, stages)
            callback = gui.start_auto_command.call_args.kwargs["on_finish"]
            callback(0, False)

        self.assertEqual(gui.start_auto_command.call_count, 2)

    def test_stops_stages_after_password_is_written(self):
        with TemporaryDirectory() as temp:
            cracked = Path(temp) / "cracked.txt"
            cracked.write_text("1234\n", encoding="utf-8")
            gui = self.make_gui()

            self.start_stages(gui, self.stages(cracked))
            callback = gui.start_auto_command.call_args.kwargs["on_finish"]
            callback(0, False)

        self.assertEqual(gui.start_auto_command.call_count, 1)
        self.assertEqual(gui.job_controller.state, APP.JobState.SUCCEEDED)

    def test_nonzero_exit_does_not_start_the_next_stage(self):
        with TemporaryDirectory() as temp:
            gui = self.make_gui()
            self.start_stages(gui, self.stages(Path(temp) / "cracked.txt"))

            callback = gui.start_auto_command.call_args.kwargs["on_finish"]
            callback(2, False)

        self.assertEqual(gui.start_auto_command.call_count, 1)
        self.assertEqual(gui.job_controller.state, APP.JobState.FAILED)

    def test_hashcat_exhausted_continues_to_next_stage(self):
        with TemporaryDirectory() as temp:
            gui = self.make_gui()
            self.start_stages(gui, self.stages(Path(temp) / "cracked.txt"))

            callback = gui.start_auto_command.call_args.kwargs["on_finish"]
            callback(1, False)

        self.assertEqual(gui.start_auto_command.call_count, 2)

    def test_john_exit_one_does_not_use_hashcat_exhausted_rule(self):
        with TemporaryDirectory() as temp:
            gui = self.make_gui()
            stages = self.stages(Path(temp) / "cracked.txt", engine="john")
            self.start_stages(gui, stages)

            callback = gui.start_auto_command.call_args.kwargs["on_finish"]
            callback(1, False)

        self.assertEqual(gui.start_auto_command.call_count, 1)
        self.assertEqual(gui.job_controller.state, APP.JobState.FAILED)

    def test_cancelled_stage_does_not_start_the_next_stage(self):
        with TemporaryDirectory() as temp:
            gui = self.make_gui()
            self.start_stages(gui, self.stages(Path(temp) / "cracked.txt"))

            callback = gui.start_auto_command.call_args.kwargs["on_finish"]
            callback(-15, True)

        self.assertEqual(gui.start_auto_command.call_count, 1)
        self.assertEqual(gui.job_controller.state, APP.JobState.CANCELLED)

    def test_attack_plan_uses_precomputed_dictionary_count(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.output_candidate_var = Value()
        gui.output_length_var = Value()

        with patch.object(APP, "count_text_lines", side_effect=AssertionError("counted on UI thread")):
            plan = gui.describe_auto_attack_plan(
                "hashcat 字典", ["hashcat", "-a", "0", "hash.txt", "large.txt"], None,
                Path("session.log"), "hashcat", Path("hash.txt"), "0 - MD5", Path("cracked.txt"),
                "100,000 筆",
            )

        self.assertEqual(gui.output_candidate_var.value, "")
        self.assertIn("候選規模：100,000 筆", plan)

    def test_launch_failure_updates_auto_stage_status(self):
        with TemporaryDirectory() as temp:
            gui = self.make_gui()
            gui.start_auto_command.return_value = False
            self.start_stages(gui, self.stages(Path(temp) / "cracked.txt"))

        self.assertEqual(gui.job_controller.state, APP.JobState.FAILED)
        self.assertEqual(gui.job_controller.snapshot.error_category, ErrorCategory.ENGINE_LAUNCH)

    def test_large_dictionary_count_can_be_cancelled(self):
        cancel = APP.threading.Event()
        source = Mock()

        def lines():
            yield b"first\n"
            cancel.set()
            yield b"second\n"

        source.open.return_value = nullcontext(lines())

        with self.assertRaisesRegex(InterruptedError, "統計已停止"):
            APP.count_text_lines(source, cancel=cancel)

    def test_large_temporary_dictionary_is_counted(self):
        with TemporaryDirectory() as temp:
            wordlist = Path(temp) / "large.txt"
            wordlist.write_text("candidate\n" * 100_000, encoding="utf-8")

            result = APP.count_text_lines(wordlist)

        self.assertEqual(result, "100,000 筆")

    def test_failed_show_does_not_modify_cracked_result(self):
        for engine in ("hashcat", "john"):
            with self.subTest(engine=engine), TemporaryDirectory() as temp:
                cracked = Path(temp) / "cracked.txt"
                cracked.write_text("existing\n", encoding="utf-8")
                gui = self.make_finalize_gui()
                result = Mock(returncode=2, stdout=b"", stderr=b"fatal: fake-password\n")
                complete = Mock()

                gui.runner.capture.return_value = result
                gui.finalize_auto_cracked(engine, Path("hash.txt"), "0 - MD5", cracked, complete)
                self.complete_capture(gui)

                self.assertEqual(cracked.read_text(encoding="utf-8"), "existing\n")
                error = complete.call_args.args[0]
                self.assertIsInstance(error, APP.EngineRuntimeError)

    def test_successful_show_never_parses_stderr(self):
        with TemporaryDirectory() as temp:
            cracked = Path(temp) / "cracked.txt"
            gui = self.make_finalize_gui()
            result = Mock(returncode=0, stdout=b"", stderr=b"warning: fake-password\n")
            complete = Mock()

            gui.runner.capture.return_value = result
            gui.finalize_auto_cracked("hashcat", Path("hash.txt"), "0 - MD5", cracked, complete)
            self.complete_capture(gui)

            self.assertFalse(cracked.exists())
            complete.assert_called_once_with(None)
            self.assertIn("warning: fake-password", gui.log.call_args_list[0].args[0])

    def test_successful_show_parses_stdout(self):
        with TemporaryDirectory() as temp:
            cracked = Path(temp) / "cracked.txt"
            gui = self.make_finalize_gui()
            result = Mock(returncode=0, stdout=b"secret\n", stderr=b"")
            complete = Mock()

            gui.runner.capture.return_value = result
            gui.finalize_auto_cracked("hashcat", Path("hash.txt"), "0 - MD5", cracked, complete)
            self.complete_capture(gui)

            self.assertEqual(cracked.read_text(encoding="utf-8"), "secret\n")
            complete.assert_called_once_with(None)
            command = gui.runner.capture.call_args.args[1]
            self.assertIn("--outfile-format", command)
            self.assertIn("2", command)

    def test_hashcat_show_does_not_merge_truncated_password(self):
        with TemporaryDirectory() as temp:
            cracked = Path(temp) / "cracked.txt"
            cracked.write_text("abc:def\n", encoding="utf-8")
            gui = self.make_finalize_gui()
            result = Mock(returncode=0, stdout=b"abc:def\n", stderr=b"")
            complete = Mock()

            gui.runner.capture.return_value = result
            gui.finalize_auto_cracked("hashcat", Path("hash.txt"), "0 - MD5", cracked, complete)
            self.complete_capture(gui)

            self.assertEqual(cracked.read_text(encoding="utf-8"), "abc:def\n")
            complete.assert_called_once_with(None)

    def test_stage_completion_waits_for_show_finalization(self):
        gui = self.make_start_gui()
        gui.runner.start.return_value = True
        gui.finalize_auto_cracked = Mock()
        complete = Mock()

        self.assertTrue(gui.start_auto_command(
            "mask 6", ["hashcat", "-a", "3", "hash.txt", "?d?d?d?d?d?d"], None,
            Path("session.log"), "hashcat", Path("hash.txt"), "0 - MD5",
            Path("cracked.txt"), on_finish=complete,
        ))
        gui.runner.start.call_args.kwargs["on_finish"](0, False)

        complete.assert_not_called()
        gui.finalize_auto_cracked.call_args.args[-1](None)
        complete.assert_called_once_with(0, False, None)


if __name__ == "__main__":
    main()
