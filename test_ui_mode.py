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
        self.assertFalse(hasattr(APP.default_config(), "tools_dir"))

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
        self.assertTrue(gui.launcher.visible)

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

    def test_minimum_window_keeps_primary_sections_visible(self):
        gui = APP.PasswordToolGUI()
        try:
            gui.geometry("1100x720")
            gui.update()
            visible_launcher_children = [child for child in gui.launcher.winfo_children() if child.winfo_ismapped()]

            self.assertLessEqual(
                max(child.winfo_y() + child.winfo_height() for child in visible_launcher_children),
                gui.launcher.winfo_height(),
            )
            self.assertTrue(all(child.winfo_ismapped() for child in gui.output_tab.winfo_children()))

            gui.set_advanced_visible(True)
            gui.update()
            self.assertTrue(gui.launcher.winfo_ismapped())
            for tab in gui._advanced_tabs:
                gui.notebook.select(tab)
                gui.update()
                self.assertLessEqual(tab.winfo_reqwidth(), tab.winfo_width())

            gui.set_advanced_visible(False)
            gui.update()
            self.assertTrue(gui.launcher.winfo_ismapped())
        finally:
            gui.destroy()


if __name__ == "__main__":
    unittest.main()
