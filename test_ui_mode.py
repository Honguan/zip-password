import importlib.machinery
from pathlib import Path
import unittest


APP = importlib.machinery.SourceFileLoader(
    "password_tools_gui", str(Path(__file__).with_name("PasswordToolsGUI.pyw"))
).load_module()


class FakeNotebook:
    def __init__(self):
        self.states = {}

    def tab(self, tab, **kwargs):
        self.states[tab] = kwargs["state"]


class FakeButton:
    def __init__(self):
        self.text = ""

    def configure(self, **kwargs):
        self.text = kwargs["text"]


class FakeFrame:
    def __init__(self):
        self.visible = True

    def grid(self):
        self.visible = True

    def grid_remove(self):
        self.visible = False


class UiModeTests(unittest.TestCase):
    def test_tools_directory_is_not_an_editable_setting(self):
        self.assertNotIn("tools_dir", APP.default_config())

    def test_advanced_tabs_are_hidden_by_default_and_can_be_shown(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.notebook = FakeNotebook()
        gui.advanced_toggle = FakeButton()
        gui.launcher = FakeFrame()
        gui._advanced_tabs = ("extract", "hashcat", "john", "settings")

        gui.set_advanced_visible(False)

        self.assertEqual(gui.notebook.states, {tab: "hidden" for tab in gui._advanced_tabs})
        self.assertEqual(gui.advanced_toggle.text, "顯示進階工具")
        self.assertTrue(gui.launcher.visible)

        gui.set_advanced_visible(True)

        self.assertEqual(gui.notebook.states, {tab: "normal" for tab in gui._advanced_tabs})
        self.assertEqual(gui.advanced_toggle.text, "隱藏進階工具")
        self.assertFalse(gui.launcher.visible)

    def test_optional_candidate_fields_can_be_collapsed(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.candidate_options = FakeFrame()
        gui.candidate_options_toggle = FakeButton()

        gui.set_candidate_options_visible(False)

        self.assertFalse(gui.candidate_options.visible)
        self.assertEqual(gui.candidate_options_toggle.text, "顯示候選選項")

        gui.set_candidate_options_visible(True)

        self.assertTrue(gui.candidate_options.visible)
        self.assertEqual(gui.candidate_options_toggle.text, "收起候選選項")


if __name__ == "__main__":
    unittest.main()
