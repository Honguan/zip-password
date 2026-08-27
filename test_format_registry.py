import password_gui.app as APP
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main

import password_logic as logic



class Value:
    def __init__(self, value="自動偵測"):
        self.value = value

    def get(self):
        return self.value


class FormatRegistryTests(TestCase):
    def test_every_extension_has_one_converter_or_raw_hash_handler(self):
        extensions = [extension for spec in logic.FORMAT_REGISTRY for extension in spec.extensions]

        self.assertEqual(len(extensions), len(set(extensions)))
        for spec in logic.FORMAT_REGISTRY:
            with self.subTest(format=spec.name):
                self.assertTrue(spec.converter or spec.detector)
                for extension in spec.extensions:
                    self.assertIs(logic.format_for_extension(extension), spec)
                    self.assertIn(f"*{extension}", logic.supported_file_pattern())

    def test_converter_runtime_and_hashcat_modes_come_from_registry(self):
        for spec in logic.FORMAT_REGISTRY:
            if spec.converter:
                self.assertEqual(logic.converter_runtime(spec.converter), spec.runtime)
        self.assertEqual(APP.HASHCAT_MODES, logic.hashcat_mode_labels())

    def test_specialized_format_detection_keeps_format_capabilities(self):
        examples = {
            "$zip2$*0*3*hash": ("ZIP", "13600 - WinZip"),
            "$rar5$16$hash": ("RAR", "13000 - RAR5"),
            "$pdf$9*9*256*unknown": ("PDF", ""),
        }
        for hash_text, expected in examples.items():
            with self.subTest(hash_text=hash_text):
                result = logic.detect_hashcat_mode(hash_text)
                self.assertEqual((result.format_name, result.mode), expected)

    def test_gui_converter_selection_and_runtime_use_registry(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            converter = root / "office2john.py"
            runtime = root / "python.exe"
            converter.touch()
            runtime.touch()
            gui = object.__new__(APP.PasswordToolGUI)
            gui.extract_converter = Value()
            gui.config_data = APP.AppConfig(john_run_dir=root, python_path=runtime)

            selected = gui.converter_for_input(Path("document.docx"))
            command = gui.converter_command(selected, Path("document.docx"))

        self.assertEqual(selected, "office2john.py")
        self.assertEqual(command, [str(runtime), str(converter), "document.docx"])


if __name__ == "__main__":
    main()
