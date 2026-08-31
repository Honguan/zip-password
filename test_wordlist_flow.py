import password_gui.app as APP
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import Mock, patch


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
        gui.config_data = APP.AppConfig(hashcat_path=Path("hashcat.exe"))
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
            "charset", "expanded_wordlist", "combo_seed", "combo_key_wordlist", "combo_wordlist",
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
        self.assertEqual(stages[0].display_name, "hashcat 字典破解")
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

    def test_strategy_builds_explicit_stage_plan(self):
        expected = {
            APP.AttackStrategy.AUTO: ["字典破解", "提示詞破解", "遮罩破解"],
            APP.AttackStrategy.DICTIONARY: ["字典破解"],
            APP.AttackStrategy.HINTS: ["提示詞破解"],
            APP.AttackStrategy.MASK: ["遮罩破解"],
        }
        settings = {"expand_wordlist": False, "hashcat_mask": "?d?d", "john_mask": ""}
        for strategy, stage_names in expected.items():
            with self.subTest(strategy=strategy):
                gui = self.make_gui()
                gui.config_data.attack_strategy = strategy
                gui.config_data.combo_key = "hint"
                gui.prepare_combo_wordlist.return_value = "hints.txt"
                with patch.object(APP, "build_auto_hashcat_command", return_value=["hashcat.exe"]), patch.object(
                    Path, "write_text"
                ):
                    stages = gui.build_auto_attack_stages(
                        Path("input.zip"), self.paths(), "hashcat", Path("hash.txt"), "0 - MD5", "source.txt", settings
                    )

                self.assertEqual(
                    [stage.display_name.removeprefix("hashcat ") for stage in stages],
                    stage_names,
                )

    def test_default_hashcat_masks_are_ordered_independent_stages(self):
        gui = self.make_gui()
        gui.config_data.attack_strategy = APP.AttackStrategy.MASK

        stages = gui.build_auto_attack_stages(
            Path("input.zip"), self.paths(), "hashcat", Path("hash.txt"), "0 - MD5", "",
            {"expand_wordlist": False, "hashcat_mask": APP.HASHCAT_DEFAULT_MASK, "john_mask": ""},
        )

        masks = [stage.command[-1] for stage in stages]
        self.assertEqual(masks, APP.AUTO_MASKS)
        self.assertEqual(
            [mask for mask in masks if set(mask) <= {"?", "d"}],
            ["?d" * length for length in range(4, 9)],
        )
        self.assertLess(masks.index("?d?d?d?d?d?d"), masks.index("?d?d?d?d?d?d?d"))
        six_digit = stages[masks.index("?d?d?d?d?d?d")]
        self.assertIn("6 位", six_digit.display_name)
        self.assertEqual(six_digit.command[-3:-1], ("3", "hashcat_hash.txt"))

    def test_selected_categories_use_one_charset_at_every_position(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            paths = {key: root / path.name for key, path in self.paths().items()}
            gui = self.make_gui()
            gui.config_data.attack_strategy = APP.AttackStrategy.MASK

            stages = gui.build_auto_attack_stages(
                Path("input.zip"), paths, "hashcat", paths["hashcat_hash"], "0 - MD5", "",
                {
                    "expand_wordlist": False,
                    "hashcat_mask": APP.HASHCAT_DEFAULT_MASK,
                    "john_mask": "",
                    "brute_force_categories": ("digits", "english"),
                    "brute_force_min_length": 6,
                    "brute_force_max_length": 6,
                },
            )

            self.assertEqual(len(stages), 1)
            self.assertEqual(stages[0].command[-1], "?1" * 6)
            self.assertEqual(stages[0].command[-3], str(paths["charset"]))
            self.assertEqual(paths["charset"].read_bytes(), APP.build_charset(["digits", "english"]))
            self.assertEqual(stages[0].candidate_count, 62**6)
            self.assertIn("6 位", stages[0].display_name)

    def test_source_strategies_reject_missing_candidates(self):
        settings = {"expand_wordlist": False, "hashcat_mask": "", "john_mask": ""}
        for strategy, message in (
            (APP.AttackStrategy.DICTIONARY, "需要明確選擇"),
            (APP.AttackStrategy.HINTS, "需要提示詞"),
        ):
            with self.subTest(strategy=strategy):
                gui = self.make_gui()
                gui.config_data.attack_strategy = strategy
                gui.prepare_library_wordlist.return_value = ""
                with self.assertRaisesRegex(ValueError, message):
                    gui.build_auto_attack_stages(
                        Path("input.zip"), self.paths(), "hashcat", Path("hash.txt"), "0 - MD5", "", settings
                    )

    def test_hints_strategy_rejects_an_empty_candidate_file(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            empty = root / "empty.txt"
            empty.write_text("\n", encoding="utf-8")
            paths = {key: root / f"{key}.txt" for key in self.paths()}
            gui = self.make_gui()
            gui.config_data.attack_strategy = APP.AttackStrategy.HINTS
            gui.config_data.combo_wordlist = empty
            gui.prepare_combo_wordlist = APP.PasswordToolGUI.prepare_combo_wordlist.__get__(gui)

            with self.assertRaisesRegex(ValueError, "需要提示詞"):
                gui.build_auto_attack_stages(
                    Path("input.zip"), paths, "hashcat", Path("hash.txt"), "0 - MD5", "",
                    {"expand_wordlist": False, "hashcat_mask": "", "john_mask": ""},
                )

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
                gui.mark_downloaded_wordlist_available = Mock()
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

    def test_unselected_downloaded_wordlists_are_not_attack_sources(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            selected = root / "selected.txt"
            selected.write_text("selected\n", encoding="utf-8")
            (root / "historical.txt").write_text("historical\n", encoding="utf-8")
            gui = object.__new__(APP.PasswordToolGUI)
            gui.config_data = APP.AppConfig(default_wordlist=root / "historical.txt")

            with patch.object(APP, "WORDLISTS_DIR", root), patch.object(
                APP.Path, "rglob", side_effect=AssertionError("implicit scan is not allowed")
            ) as rglob:
                empty = gui.collect_dictionary_sources("")
                sources = gui.collect_dictionary_sources(str(selected))

        self.assertEqual(empty, [])
        self.assertEqual(sources, [selected])
        rglob.assert_not_called()

    def test_download_does_not_select_wordlist_until_explicit_use(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.quick_status = Value()
        gui.quick_wordlist = Value("current.txt")

        gui.mark_downloaded_wordlist_available(Path("downloaded.txt"), "Common")

        self.assertEqual(gui.quick_wordlist.get(), "current.txt")
        self.assertIn("才會套用", gui.quick_status.get())

    def test_explicit_common_wordlist_selection_updates_current_job(self):
        with TemporaryDirectory() as temp:
            item = APP.COMMON_WORDLISTS[0]
            path = Path(temp) / item[1]
            path.touch()
            gui = object.__new__(APP.PasswordToolGUI)
            gui.common_wordlist = Value(item[0])
            gui.quick_wordlist = Value()
            gui.hashcat_wordlist = Value()
            gui.john_wordlist = Value()
            gui.quick_status = Value()

            with patch.object(APP, "WORDLISTS_DIR", Path(temp)):
                gui.use_selected_common_wordlist()

        self.assertEqual(gui.quick_wordlist.get(), str(path))
        self.assertEqual(gui.hashcat_wordlist.get(), str(path))
        self.assertEqual(gui.john_wordlist.get(), str(path))

    def test_attack_plan_log_lists_every_selected_source(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            sources = [root / "one.txt", root / "two.txt"]
            for source in sources:
                source.write_text(source.stem + "\n", encoding="utf-8")
            gui = object.__new__(APP.PasswordToolGUI)
            gui.enqueue_log = Mock()

            gui.prepare_library_wordlist(sources, root / "merged.txt")

        log = "".join(call.args[0] for call in gui.enqueue_log.call_args_list)
        self.assertIn(str(sources[0]), log)
        self.assertIn(str(sources[1]), log)

    def test_required_source_failure_stops_library_preparation(self):
        with TemporaryDirectory() as temp:
            gui = object.__new__(APP.PasswordToolGUI)
            gui.enqueue_log = Mock()
            missing = Path(temp) / "missing-required.txt"

            with self.assertRaisesRegex(RuntimeError, "無法讀取指定字典"):
                gui.prepare_library_wordlist([missing], Path(temp) / "unused.txt")

        self.assertIn(str(missing), gui.enqueue_log.call_args.args[0])

    def test_optional_source_failure_is_logged_and_successful_source_continues(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            loaded = root / "loaded.txt"
            missing = root / "missing.txt"
            loaded.write_text("candidate\n", encoding="utf-8")
            gui = object.__new__(APP.PasswordToolGUI)
            gui.enqueue_log = Mock()

            result = gui.prepare_library_wordlist(
                [loaded, missing], root / "merged.txt", optional_sources={missing}
            )

        self.assertTrue(result)
        log = "".join(call.args[0] for call in gui.enqueue_log.call_args_list)
        self.assertIn("選用", log)
        self.assertIn(str(missing), log)

if __name__ == "__main__":
    main()
