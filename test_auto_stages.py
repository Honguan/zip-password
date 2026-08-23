import importlib.machinery
from contextlib import nullcontext
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import Mock, patch


APP = importlib.machinery.SourceFileLoader(
    "password_tools_gui_stages", str(Path(__file__).with_name("PasswordToolsGUI.pyw"))
).load_module()


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
        return gui

    def stages(self, cracked):
        return [
            {
                "name": "hashcat 字典",
                "cmd": ["hashcat"],
                "cwd": None,
                "session_log": Path("session.log"),
                "engine": "hashcat",
                "hash_file": Path("hash.txt"),
                "mode_label": "0 - MD5",
                "cracked": cracked,
            },
            {
                "name": "hashcat 硬破解",
                "cmd": ["hashcat", "-a", "3"],
                "cwd": None,
                "session_log": Path("session.log"),
                "engine": "hashcat",
                "hash_file": Path("hash.txt"),
                "mode_label": "0 - MD5",
                "cracked": cracked,
            },
        ]

    def test_continues_to_next_stage_when_no_password_was_written(self):
        with TemporaryDirectory() as temp:
            gui = self.make_gui()
            stages = self.stages(Path(temp) / "cracked.txt")

            gui.start_auto_stages(stages, 0)
            callback = gui.start_auto_command.call_args.kwargs["on_finish"]
            callback(0, False)

        self.assertEqual(gui.start_auto_command.call_count, 2)

    def test_stops_stages_after_password_is_written(self):
        with TemporaryDirectory() as temp:
            cracked = Path(temp) / "cracked.txt"
            cracked.write_text("1234\n", encoding="utf-8")
            gui = self.make_gui()

            gui.start_auto_stages(self.stages(cracked), 0)
            callback = gui.start_auto_command.call_args.kwargs["on_finish"]
            callback(0, False)

        self.assertEqual(gui.start_auto_command.call_count, 1)
        self.assertIn("找到密碼", gui.quick_status.value)

    def test_nonzero_exit_does_not_start_the_next_stage(self):
        with TemporaryDirectory() as temp:
            gui = self.make_gui()
            gui.start_auto_stages(self.stages(Path(temp) / "cracked.txt"), 0)

            callback = gui.start_auto_command.call_args.kwargs["on_finish"]
            callback(2, False)

        self.assertEqual(gui.start_auto_command.call_count, 1)
        self.assertIn("失敗", gui.quick_status.value)

    def test_cancelled_stage_does_not_start_the_next_stage(self):
        with TemporaryDirectory() as temp:
            gui = self.make_gui()
            gui.start_auto_stages(self.stages(Path(temp) / "cracked.txt"), 0)

            callback = gui.start_auto_command.call_args.kwargs["on_finish"]
            callback(-15, True)

        self.assertEqual(gui.start_auto_command.call_count, 1)
        self.assertIn("停止", gui.quick_status.value)

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

        self.assertEqual(gui.output_candidate_var.value, "100,000 筆")
        self.assertIn("候選規模：100,000 筆", plan)

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


if __name__ == "__main__":
    main()
