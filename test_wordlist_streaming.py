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

    def test_limit_stops_the_source_iterator_immediately(self):
        source = Mock()

        def lines():
            yield b"Alpha\n"
            raise AssertionError("read past expansion limit")

        source.open.return_value = nullcontext(lines())
        with TemporaryDirectory() as temp:
            count = APP.build_expanded_wordlist(source, Path(temp) / "expanded.txt", limit=2)

        self.assertEqual(count, 2)

    def test_large_dictionary_is_not_read_into_one_buffer(self):
        with TemporaryDirectory() as temp:
            source = Path(temp) / "large.txt"
            dest = Path(temp) / "expanded.txt"
            source.write_text("".join(f"candidate-{index}\n" for index in range(100_000)), encoding="utf-8")

            with patch.object(Path, "read_bytes", side_effect=AssertionError("full-file read")), patch.object(
                Path, "read_text", side_effect=AssertionError("full-file read")
            ):
                count = APP.build_expanded_wordlist(source, dest, limit=100)

        self.assertEqual(count, 100)

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
