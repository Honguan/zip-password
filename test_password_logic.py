from pathlib import Path
from unittest import TestCase, main

import password_logic as logic


class PasswordLogicTests(TestCase):
    def test_commands_preserve_unicode_input_and_custom_output_paths(self):
        tool_path = "C:/使用者工具/hashcat.exe"
        hash_path = Path("C:/測試資料/雜湊.txt")
        wordlist = "C:/使用者字典/常用.txt"
        output = Path("D:/自訂輸出/結果.txt")

        command = logic.build_auto_hashcat_command(
            tool_path, hash_path, "0", wordlist, output,
            Path("auto.hcmask"), Path("C:/來源/壓縮包.zip"), "", "dict",
        )

        self.assertEqual(command[0], tool_path)
        self.assertIn(str(hash_path), command)
        self.assertIn(wordlist, command)
        self.assertIn(str(output), command)

    def test_auto_hashcat_command_preserves_dictionary_arguments(self):
        source = Path("sample.zip")
        command = logic.build_auto_hashcat_command(
            "hashcat.exe", Path("hash.txt"), "0", "words.txt", Path("cracked.txt"),
            Path("auto.hcmask"), source, "", "dict",
        )

        self.assertEqual(
            command,
            [
                "hashcat.exe", "-m", "0", "--session", f"auto_{logic.source_identity(source)}_dict", "--status",
                "--status-timer", "10", "--outfile", "cracked.txt", "--outfile-format", "2",
                "-a", "0", "hash.txt", "words.txt",
            ],
        )

    def test_auto_john_command_preserves_default_mask_arguments(self):
        source = Path("sample.zip")
        command = logic.build_auto_john_command(
            "john.exe", Path("hash.txt"), "", source, logic.JOHN_DEFAULT_MASK
        )

        self.assertEqual(
            command,
            [
                "john.exe", f"--session=auto_{logic.source_identity(source)}", "--mask=?d?d?d?d?d?d?d?d",
                "--min-length=4", "hash.txt",
            ],
        )

    def test_auto_john_command_uses_selected_charset_and_exact_length(self):
        command = logic.build_auto_john_command(
            "john.exe", Path("hash.txt"), "", Path("sample.zip"), logic.JOHN_DEFAULT_MASK,
            "mask-6", "?d?l?u", 6,
        )

        self.assertIn("-1=?d?l?u", command)
        self.assertIn("--encoding=cp1252", command)
        self.assertIn("--mask=?1", command)
        self.assertIn("--min-length=6", command)
        self.assertIn("--max-length=6", command)

    def test_hash_output_and_mode_parsing_need_no_gui(self):
        text = "archive.rar:$rar5$16$11111111111111111111111111111111$15$22222222222222222222222222222222$8$3333333333333333:archive.rar\n"

        self.assertEqual(
            logic.prepare_hash_output(text, "hashcat"),
            "$rar5$16$11111111111111111111111111111111$15$22222222222222222222222222222222$8$3333333333333333\n",
        )
        modes = {
            "$zip2$*0*3*hash": "13600 - WinZip",
            "$pkzip2$*1*2*hash": "17200 - PKZIP",
            "$rar5$16$hash": "13000 - RAR5",
            "$rar3$*0*hash": "12500 - RAR3-hp",
            "$7z$0$19$hash": "11600 - 7-Zip",
            "$office$*2007*hash": "9400 - MS Office 2007",
            "$office$*2010*hash": "9500 - MS Office 2010",
            "$office$*2013*hash": "9600 - MS Office 2013",
        }
        for hash_text, expected in modes.items():
            with self.subTest(hash_text=hash_text):
                result = logic.detect_hashcat_mode(hash_text)
                self.assertEqual((result.status, result.mode), ("detected", expected))
        self.assertEqual(
            logic.extract_passwords_from_show("hash:secret\n0 passwords cracked\n", "hashcat"),
            ["secret"],
        )

    def test_same_basename_uses_distinct_bounded_tool_sessions(self):
        with self.subTest(engine="hashcat"):
            first = logic.build_auto_hashcat_command(
                "hashcat.exe", Path("hash.txt"), "0", "words.txt", Path("cracked.txt"),
                Path("auto.hcmask"), Path("C:/A/backup.zip"), "", "dict",
            )[4]
            second = logic.build_auto_hashcat_command(
                "hashcat.exe", Path("hash.txt"), "0", "words.txt", Path("cracked.txt"),
                Path("auto.hcmask"), Path("D:/B/backup.zip"), "", "dict",
            )[4]
            brute = logic.build_auto_hashcat_command(
                "hashcat.exe", Path("hash.txt"), "0", "", Path("cracked.txt"),
                Path("auto.hcmask"), Path("C:/A/backup.zip"), "", "brute",
            )[4]
            long_name = logic.build_auto_hashcat_command(
                "hashcat.exe", Path("hash.txt"), "0", "words.txt", Path("cracked.txt"),
                Path("auto.hcmask"), Path("C:/A") / ("a" * 100 + ".zip"), "", "dict",
            )[4]
        with self.subTest(engine="john"):
            john_first = logic.build_auto_john_command(
                "john.exe", Path("hash.txt"), "", Path("C:/A/backup.zip"), logic.JOHN_DEFAULT_MASK, "dict"
            )[1].removeprefix("--session=")
            john_second = logic.build_auto_john_command(
                "john.exe", Path("hash.txt"), "", Path("D:/B/backup.zip"), logic.JOHN_DEFAULT_MASK, "dict"
            )[1].removeprefix("--session=")

        for session in (first, second, brute, long_name, john_first, john_second):
            self.assertRegex(session, r"^[A-Za-z0-9_.-]{1,60}$")
        self.assertTrue(all(session.endswith("_dict") for session in (first, second, long_name, john_first, john_second)))
        self.assertTrue(brute.endswith("_brute"))
        self.assertNotEqual(first, second)
        self.assertNotEqual(first, brute)
        self.assertNotEqual(john_first, john_second)

    def test_pdf_modes_use_version_revision_and_key_length(self):
        examples = {
            "$pdf$1*2*40*-1*0*16*01221086741440841668371056103222*32*27c3fecef6d46a78eb61b8b4dbc690f5f8a2912bbb9afc842c12d79481568b74*32*0000000000000000000000000000000000000000000000000000000000000000": "10400 - PDF 1.1-1.3",
            "$pdf$2*3*128*-4*1*16*62888255846156252261477183186121*32*6879919b1afd520bd3b7dbcc0868a0a500000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000": "10500 - PDF 1.4-1.6",
            "$pdf$1*3*40*-4*1*16*5e1f73575e1f73575e1f73575e1f7357*32*c0be424bef466277092f2a1ba0fbe506ebabe5c01db100dedc0ffeebabe5c01d*32*0ff1cedeadce110ff1cedeadce110ff1cedeadce110ff1cedeadce11babebabe": "10510 - PDF 1.3-1.6 RC4-40",
            "$pdf$5*5*256*-1028*1*16*28562274676426582441147358074521": "10600 - PDF 1.7 Level 3",
            "$pdf$5*6*256*-1028*1*16*62137640825124540503886403748430": "10700 - PDF 1.7 Level 8",
            "$pdf$2*3*128*-3904*1*16*631ed33746e50fba5caf56bcc39e09c6*32*5f9d0e4f0b39835dace0d306c40cd6b700000000000000000000000000000000*32*842103b0a0dc886db9223b94afe2d7cd63389079b61986a4fcf70095ad630c24*known-user-pass": "25400 - PDF 1.4-1.6 user/owner",
        }

        for hash_text, expected in examples.items():
            with self.subTest(hash_text=hash_text[:20]):
                result = logic.detect_hashcat_mode(hash_text)
                self.assertEqual((result.status, result.mode), ("detected", expected))

        self.assertEqual(logic.detect_hashcat_mode("$pdf$9*9*256*unknown").status, "unsupported")

    def test_raw_hash_detection_reports_ambiguity(self):
        md5 = logic.detect_hashcat_mode("5d41402abc4b2a76b9719d911017c592")
        ntlm = logic.detect_hashcat_mode("8846f7eaee8fb117ad06bdd830b7586c")
        sha1 = logic.detect_hashcat_mode("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
        sha256 = logic.detect_hashcat_mode("a" * 64)
        sha512 = logic.detect_hashcat_mode("b" * 128)

        for result in (md5, ntlm):
            self.assertEqual(result.status, "ambiguous")
            self.assertEqual(result.mode, "")
            self.assertIn("0 - MD5", result.candidates)
            self.assertIn("1000 - NTLM", result.candidates)
        self.assertEqual((sha1.status, sha1.mode), ("detected", "100 - SHA1"))
        self.assertEqual(sha256.status, "ambiguous")
        self.assertIn("1400 - SHA2-256", sha256.candidates)
        self.assertEqual(sha512.status, "ambiguous")
        self.assertIn("1700 - SHA2-512", sha512.candidates)

    def test_john_password_parsing_preserves_password_fields(self):
        shown = (
            "alice:p@ ss:wo$rd:1000:1000:Alice:/home/alice:/bin/bash\n"
            "archive.zip:plain:with colon\n"
            "2 password hashes cracked, 0 left\n"
        )

        self.assertEqual(
            logic.extract_passwords_from_show(shown, "john"),
            ["p@ ss:wo$rd", "plain:with colon"],
        )

    def test_hashcat_plaintext_only_output_preserves_passwords(self):
        shown = "abc:def\none::two\n 密碼 值 \n$HEX[e9]\n$HEX[e5af86e7a2bc]\n"

        self.assertEqual(
            logic.extract_passwords_from_show(shown, "hashcat", plaintext_only=True),
            ["abc:def", "one::two", " 密碼 值 ", "é", "密碼"],
        )

    def test_hashcat_zip_output_discards_john_metadata_only(self):
        text = (
            "archive.zip:$zip2$*0*3*hash$/zip2$:archive.zip:folder/file.txt\n"
            "archive.zip:$pkzip2$*1*2*hash$/pkzip2$:archive.zip:folder/file.txt\n"
            "archive.rar:$rar5$16$hash:metadata\n"
            "$office$*2013*hash:metadata\n"
        )

        self.assertEqual(
            logic.prepare_hash_output(text, "hashcat"),
            "$zip2$*0*3*hash$/zip2$\n"
            "$pkzip2$*1*2*hash$/pkzip2$\n"
            "$rar5$16$hash\n"
            "$office$*2013*hash:metadata\n",
        )


if __name__ == "__main__":
    main()
