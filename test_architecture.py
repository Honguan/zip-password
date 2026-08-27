from pathlib import Path
from unittest import TestCase, main


class ArchitectureTests(TestCase):
    def test_entrypoint_only_starts_the_application(self):
        source = Path("PasswordToolsGUI.pyw").read_text(encoding="utf-8")

        self.assertIn("from password_gui.app import main", source)
        self.assertNotIn("tkinter", source)
        self.assertNotIn("subprocess", source)

    def test_service_modules_do_not_import_tk(self):
        for name in ("config", "output_parser", "runner", "tools", "wordlists", "workflow"):
            with self.subTest(module=name):
                source = (Path("password_gui") / f"{name}.py").read_text(encoding="utf-8")
                self.assertNotIn("tkinter", source)


if __name__ == "__main__":
    main()
