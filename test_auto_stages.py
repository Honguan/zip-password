import importlib.machinery
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import Mock


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
            callback(0)

        self.assertEqual(gui.start_auto_command.call_count, 2)

    def test_stops_stages_after_password_is_written(self):
        with TemporaryDirectory() as temp:
            cracked = Path(temp) / "cracked.txt"
            cracked.write_text("1234\n", encoding="utf-8")
            gui = self.make_gui()

            gui.start_auto_stages(self.stages(cracked), 0)
            callback = gui.start_auto_command.call_args.kwargs["on_finish"]
            callback(0)

        self.assertEqual(gui.start_auto_command.call_count, 1)
        self.assertIn("找到密碼", gui.quick_status.value)


if __name__ == "__main__":
    main()
