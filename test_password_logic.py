from pathlib import Path
from unittest import TestCase, main

import password_logic as logic


class PasswordLogicTests(TestCase):
    def test_config_values_merge_without_unknown_keys(self):
        self.assertEqual(
            logic.merge_config({"enabled": "1", "path": "default"}, {"enabled": "0", "extra": "ignored"}),
            {"enabled": "0", "path": "default"},
        )
        self.assertFalse(logic.config_bool("off"))

    def test_auto_hashcat_command_preserves_dictionary_arguments(self):
        command = logic.build_auto_hashcat_command(
            "hashcat.exe", Path("hash.txt"), "0", "words.txt", Path("cracked.txt"),
            Path("auto.hcmask"), Path("sample.zip"), "", "dict",
        )

        self.assertEqual(
            command,
            [
                "hashcat.exe", "-m", "0", "--session", "auto_sample_dict", "--status",
                "--status-timer", "10", "--outfile", "cracked.txt", "--outfile-format", "2",
                "-a", "0", "hash.txt", "words.txt",
            ],
        )

    def test_auto_john_command_preserves_default_mask_arguments(self):
        command = logic.build_auto_john_command(
            "john.exe", Path("hash.txt"), "", Path("sample.zip"), logic.JOHN_DEFAULT_MASK
        )

        self.assertEqual(
            command,
            [
                "john.exe", "--session=auto_sample", "--mask=?d?d?d?d?d?d?d?d",
                "--min-length=4", "hash.txt",
            ],
        )

    def test_hash_output_and_mode_parsing_need_no_gui(self):
        text = "archive.zip:$rar5$16$hash:metadata\n"

        self.assertEqual(logic.prepare_hash_output(text, "hashcat"), "$rar5$16$hash:metadata\n")
        modes = {
            "$zip2$*0*3*hash": "13600 - WinZip",
            "$pkzip2$*1*2*hash": "17200 - PKZIP",
            "$rar5$16$hash": "13000 - RAR5",
            "$rar3$*0*hash": "12500 - RAR3-hp",
            "$7z$0$19$hash": "11600 - 7-Zip",
            "$office$*2007*hash": "9400 - MS Office 2007",
            "$office$*2010*hash": "9500 - MS Office 2010",
            "$office$*2013*hash": "9600 - MS Office 2013",
            "$pdf$2*3*hash": "10500 - PDF 1.4-1.6",
        }
        for hash_text, expected in modes.items():
            with self.subTest(hash_text=hash_text):
                self.assertEqual(logic.detect_hashcat_mode(hash_text), expected)
        self.assertEqual(logic.extract_passwords_from_show("archive.zip:secret\n0 passwords cracked\n"), ["secret"])

    def test_hashcat_zip_output_discards_john_metadata_only(self):
        text = (
            "archive.zip:$zip2$*0*3*hash$/zip2$:archive.zip:folder/file.txt\n"
            "archive.zip:$pkzip2$*1*2*hash$/pkzip2$:archive.zip:folder/file.txt\n"
            "archive.zip:$rar5$16$hash:metadata\n"
            "$office$*2013*hash:metadata\n"
        )

        self.assertEqual(
            logic.prepare_hash_output(text, "hashcat"),
            "$zip2$*0*3*hash$/zip2$\n"
            "$pkzip2$*1*2*hash$/pkzip2$\n"
            "$rar5$16$hash:metadata\n"
            "$office$*2013*hash:metadata\n",
        )


if __name__ == "__main__":
    main()
