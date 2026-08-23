import importlib.machinery
import queue
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock


APP = importlib.machinery.SourceFileLoader(
    "password_tools_gui_output", str(Path(__file__).with_name("PasswordToolsGUI.pyw"))
).load_module()


class OutputLimitTests(TestCase):
    def test_each_ui_tick_processes_a_bounded_log_batch(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.log_queue = queue.Queue()
        gui.status_queue = queue.Queue()
        gui.ui_queue = queue.Queue()
        gui.log = Mock()
        gui.set_status = Mock()
        gui.update_elapsed = Mock()
        gui.after = Mock()
        for index in range(APP.UI_QUEUE_ITEMS_PER_TICK + 10):
            gui.log_queue.put(str(index))

        gui._drain_queues()

        self.assertEqual(gui.log.call_count, APP.UI_QUEUE_ITEMS_PER_TICK)
        self.assertEqual(gui.log_queue.qsize(), 10)
        gui.after.assert_called_once_with(80, gui._drain_queues)

    def test_full_ui_queue_discards_the_oldest_message(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.log_queue = queue.Queue(maxsize=2)
        gui.log_queue.put("old")
        gui.log_queue.put("middle")

        gui.enqueue_log("new")

        self.assertEqual([gui.log_queue.get(), gui.log_queue.get()], ["middle", "new"])

    def test_ui_log_evicts_lines_over_the_limit(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.update_output_dashboard = Mock()
        gui.output = Mock()
        gui.output.index.return_value = f"{APP.UI_LOG_MAX_LINES + 10}.0"

        gui.log("message")

        gui.output.delete.assert_called_once_with("1.0", "11.0")

    def test_session_log_is_buffered_and_flushed_completely(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "session.log"
            runner = APP.CommandRunner(Mock())
            runner.log_path = path

            runner._append_session_log("first\n")
            self.assertFalse(path.exists())
            runner._append_session_log("second\n", flush=True)

            self.assertEqual(path.read_text(encoding="utf-8"), "first\nsecond\n")
