import importlib.machinery
from contextlib import nullcontext
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import Mock, patch


APP = importlib.machinery.SourceFileLoader(
    "password_tools_gui_streaming", str(Path(__file__).with_name("PasswordToolsGUI.pyw"))
).load_module()


class WordlistStreamingTests(TestCase):
    def test_empty_dictionary_creates_empty_output(self):
        with TemporaryDirectory() as temp:
            source = Path(temp) / "empty.txt"
            dest = Path(temp) / "expanded.txt"
            source.touch()

            count = APP.build_expanded_wordlist(source, dest)

            self.assertEqual(count, 0)
            self.assertEqual(dest.read_text(encoding="utf-8"), "")

    def test_limit_stops_only_derived_candidates(self):
        source = Mock()

        def lines():
            yield b"Alpha\n"
            yield b"final-secret\n"

        source.open.return_value = nullcontext(lines())
        with TemporaryDirectory() as temp:
            dest = Path(temp) / "expanded.txt"
            count = APP.build_expanded_wordlist(source, dest, limit=2)
            candidates = dest.read_text(encoding="utf-8").splitlines()

        self.assertEqual(count, 4)
        self.assertIn("Alpha", candidates)
        self.assertIn("final-secret", candidates)

    def test_large_dictionary_is_not_read_into_one_buffer(self):
        with TemporaryDirectory() as temp:
            source = Path(temp) / "large.txt"
            dest = Path(temp) / "expanded.txt"
            source.write_text("".join(f"candidate-{index}\n" for index in range(100_000)), encoding="utf-8")

            with patch.object(Path, "read_bytes", side_effect=AssertionError("full-file read")), patch.object(
                Path, "read_text", side_effect=AssertionError("full-file read")
            ):
                count = APP.build_expanded_wordlist(source, dest, limit=100)

            self.assertGreaterEqual(count, 100_000)
            with dest.open(encoding="utf-8") as output:
                self.assertIn("candidate-99999", (line.strip() for line in output))

    def test_merged_sources_keep_later_original_candidates(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            first = root / "first.txt"
            second = root / "second.txt"
            merged = root / "merged.txt"
            expanded = root / "expanded.txt"
            first.write_text("Alpha\n", encoding="utf-8")
            second.write_text("later-password\n", encoding="utf-8")
            result = APP.merge_wordlist_files([first, second], merged)
            self.assertEqual(result.loaded_sources, (first, second))
            self.assertEqual(result.failed_sources, ())
            self.assertFalse(result.truncated_by_limit)

            APP.build_expanded_wordlist(merged, expanded, limit=1)

            candidates = expanded.read_text(encoding="utf-8").splitlines()
            self.assertIn("Alpha", candidates)
            self.assertIn("later-password", candidates)

    def test_merge_limit_and_io_failure_have_distinct_results(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.txt"
            missing = root / "missing.txt"
            source.write_text("one\ntwo\n", encoding="utf-8")

            truncated = APP.merge_wordlist_files([source], root / "truncated.txt", limit=1)
            failed = APP.merge_wordlist_files([missing], root / "failed.txt")

        self.assertTrue(truncated.truncated_by_limit)
        self.assertEqual(truncated.failed_sources, ())
        self.assertFalse(failed.truncated_by_limit)
        self.assertEqual(failed.failed_sources[0].source, missing)

    def test_expansion_stops_when_cancelled(self):
        source = Mock()
        cancel = APP.threading.Event()

        def lines():
            yield b"Alpha\n"
            cancel.set()
            yield b"Beta\n"

        source.open.return_value = nullcontext(lines())
        with TemporaryDirectory() as temp:
            dest = Path(temp) / "expanded.txt"
            APP.build_expanded_wordlist(source, dest, cancel=cancel)
            candidates = dest.read_text(encoding="utf-8").splitlines()

        self.assertIn("Alpha", candidates)
        self.assertNotIn("Beta", candidates)

    def test_many_tokens_have_bounded_expansion_without_character_splitting(self):
        with TemporaryDirectory() as temp:
            source = Path(temp) / "tokens.txt"
            dest = Path(temp) / "expanded.txt"
            source.write_text(" ".join(f"Alpha{index}" for index in range(120)), encoding="utf-8")

            count = APP.build_expanded_wordlist(source, dest)
            candidates = dest.read_text(encoding="utf-8").splitlines()

        self.assertLess(count, 1_000)
        self.assertIn("Alpha0", candidates)
        self.assertIn("alpha0", candidates)
        self.assertNotIn("A", candidates)


if __name__ == "__main__":
    main()
