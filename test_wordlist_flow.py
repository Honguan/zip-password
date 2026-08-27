import importlib.machinery
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import Mock, patch


APP = importlib.machinery.SourceFileLoader(
    "password_tools_gui_wordlist", str(Path(__file__).with_name("PasswordToolsGUI.pyw"))
).load_module()


class Value:
    def __init__(self, value=""):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class WordlistFlowTests(TestCase):
    def make_gui(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.config_data = {"hashcat_path": "hashcat.exe"}
        gui.collect_dictionary_sources = Mock(return_value=[Path("source.txt")])
        gui.prepare_library_wordlist = Mock(return_value="merged.txt")
        gui.prepare_auto_wordlist = Mock(
            side_effect=lambda source, _dest, expand: "expanded.txt" if expand else source
        )
        gui.prepare_combo_wordlist = Mock(return_value="")
        gui.enqueue_status = Mock()
        gui.conversion_cancel = APP.threading.Event()
        return gui

    def paths(self):
        return {key: Path(f"{key}.txt") for key in (
            "john_hash", "hashcat_hash", "cracked", "mask", "session", "library_wordlist",
            "expanded_wordlist", "combo_seed", "combo_key_wordlist", "combo_wordlist",
        )}

    def test_default_order_expands_the_merged_dictionary_when_enabled(self):
        gui = self.make_gui()
        settings = {"expand_wordlist": True, "hashcat_mask": "", "john_mask": ""}

        with patch.object(APP, "build_auto_hashcat_command", return_value=["hashcat.exe"]) as builder, patch.object(
            Path, "write_text"
        ):
            stages = gui.build_auto_attack_stages(
                Path("input.zip"), self.paths(), "hashcat", Path("hash.txt"), "0 - MD5", "", settings
            )

        gui.prepare_auto_wordlist.assert_called_once_with(
            "merged.txt", Path("expanded_wordlist.txt"), True
        )
        self.assertEqual(stages[0]["stage_name"], "階段1 字典庫破解")
        self.assertIn("expanded.txt", builder.call_args_list[0].args)

    def test_default_order_keeps_the_merged_dictionary_when_disabled(self):
        gui = self.make_gui()
        settings = {"expand_wordlist": False, "hashcat_mask": "", "john_mask": ""}

        with patch.object(APP, "build_auto_hashcat_command", return_value=["hashcat.exe"]) as builder, patch.object(
            Path, "write_text"
        ):
            gui.build_auto_attack_stages(
                Path("input.zip"), self.paths(), "hashcat", Path("hash.txt"), "0 - MD5", "", settings
            )

        gui.prepare_auto_wordlist.assert_called_once_with(
            "merged.txt", Path("expanded_wordlist.txt"), False
        )
        self.assertIn("merged.txt", builder.call_args_list[0].args)

    def test_duplicate_wordlist_download_starts_one_worker(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.common_wordlist = Value(APP.COMMON_WORDLISTS[0][0])
        gui.quick_status = Value()
        gui.common_wordlist_download_button = Mock()
        gui._wordlist_download_lock = APP.threading.Lock()

        with patch.object(APP.threading, "Thread") as thread:
            gui.download_selected_wordlist()
            gui.download_selected_wordlist()

        thread.assert_called_once()
        thread.return_value.start.assert_called_once_with()
        gui.common_wordlist_download_button.state.assert_called_once_with(["disabled"])
        self.assertIn("下載中", gui.quick_status.get())

    def test_wordlist_download_releases_single_flight_after_success_or_failure(self):
        for error in (None, RuntimeError("download failed")):
            with self.subTest(error=bool(error)), TemporaryDirectory() as temp:
                gui = object.__new__(APP.PasswordToolGUI)
                gui._wordlist_download_lock = APP.threading.Lock()
                gui._wordlist_download_lock.acquire()
                gui.common_wordlist_download_button = Mock()
                gui.quick_status = Value("正在下載")
                gui.enqueue_status = Mock()
                gui.enqueue_log = Mock()
                gui.enqueue_ui = Mock()
                gui.apply_downloaded_wordlist = Mock()
                download = Mock(side_effect=error)

                with (
                    patch.object(APP, "WORDLISTS_DIR", Path(temp)),
                    patch.object(APP, "ensure_tool_dirs"),
                    patch.object(APP, "download_file", download),
                ):
                    gui._download_wordlist_worker(APP.COMMON_WORDLISTS[0])

                for call in gui.enqueue_ui.call_args_list:
                    call.args[0]()

                self.assertTrue(gui._wordlist_download_lock.acquire(blocking=False))
                gui._wordlist_download_lock.release()
                gui.common_wordlist_download_button.state.assert_called_with(["!disabled"])
                if error:
                    self.assertIn("下載失敗", gui.quick_status.get())
                gui.common_wordlist = Value(APP.COMMON_WORDLISTS[0][0])
                with patch.object(APP.threading, "Thread") as thread:
                    gui.download_selected_wordlist()
                thread.return_value.start.assert_called_once_with()

if __name__ == "__main__":
    main()
