import importlib.machinery
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import Mock


APP = importlib.machinery.SourceFileLoader(
    "password_tools_gui_wordlist", str(Path(__file__).with_name("PasswordToolsGUI.pyw"))
).load_module()


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
        gui.build_auto_hashcat_command = Mock(return_value=["hashcat.exe"])
        return gui

    def paths(self):
        return {key: Path(f"{key}.txt") for key in (
            "john_hash", "hashcat_hash", "cracked", "mask", "session", "library_wordlist",
            "expanded_wordlist", "combo_seed", "combo_key_wordlist", "combo_wordlist",
        )}

    def test_default_order_expands_the_merged_dictionary_when_enabled(self):
        gui = self.make_gui()
        settings = {"expand_wordlist": True, "hashcat_mask": "", "john_mask": ""}

        stages = gui.build_auto_attack_stages(
            Path("input.zip"), self.paths(), "hashcat", Path("hash.txt"), "0 - MD5", "", settings
        )

        gui.prepare_auto_wordlist.assert_called_once_with(
            "merged.txt", Path("expanded_wordlist.txt"), True
        )
        self.assertEqual(stages[0]["stage_name"], "階段1 字典庫破解")
        self.assertIn("expanded.txt", gui.build_auto_hashcat_command.call_args_list[0].args)

    def test_default_order_keeps_the_merged_dictionary_when_disabled(self):
        gui = self.make_gui()
        settings = {"expand_wordlist": False, "hashcat_mask": "", "john_mask": ""}

        gui.build_auto_attack_stages(
            Path("input.zip"), self.paths(), "hashcat", Path("hash.txt"), "0 - MD5", "", settings
        )

        gui.prepare_auto_wordlist.assert_called_once_with(
            "merged.txt", Path("expanded_wordlist.txt"), False
        )
        self.assertIn("merged.txt", gui.build_auto_hashcat_command.call_args_list[0].args)

if __name__ == "__main__":
    main()
