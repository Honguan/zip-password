import hashlib
import password_gui.app as APP
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import Mock, patch


class Response:
    def __init__(self, chunks, total, url=APP.HASHCAT_ARCHIVE_URL):
        self.chunks = iter(chunks)
        self.headers = {"Content-Length": str(total)}
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def geturl(self):
        return self.url

    def read(self, _size):
        return next(self.chunks, b"")


class DownloadSecurityTests(TestCase):
    def test_non_official_download_source_is_rejected_before_request(self):
        with TemporaryDirectory() as temp, patch.object(APP.urllib.request, "urlopen") as urlopen:
            with self.assertRaisesRegex(APP.SetupError, "非官方"):
                APP.download_file(
                    "https://github.com.evil.example/tool.7z", Path(temp) / "tool.7z",
                    expected_sha256="0" * 64, allowed_hosts=APP.OFFICIAL_DOWNLOAD_HOSTS,
                )

        urlopen.assert_not_called()

    def test_checksum_mismatch_removes_partial_file(self):
        with TemporaryDirectory() as temp:
            dest = Path(temp) / "tool.7z"
            response = Response([b"tampered", b""], len(b"tampered"))
            with patch.object(APP.urllib.request, "urlopen", return_value=response):
                with self.assertRaisesRegex(APP.SetupError, "SHA-256"):
                    APP.download_file(
                        APP.HASHCAT_ARCHIVE_URL, dest, expected_sha256="0" * 64,
                        allowed_hosts=APP.OFFICIAL_DOWNLOAD_HOSTS,
                    )

            self.assertFalse(dest.exists())
            self.assertFalse(dest.with_suffix(".7z.part").exists())

    def test_redirect_to_non_official_source_is_rejected(self):
        with TemporaryDirectory() as temp:
            dest = Path(temp) / "tool.7z"
            response = Response([], 0, "https://downloads.evil.example/tool.7z")
            with patch.object(APP.urllib.request, "urlopen", return_value=response):
                with self.assertRaisesRegex(APP.SetupError, "非官方"):
                    APP.download_file(
                        APP.HASHCAT_ARCHIVE_URL, dest, expected_sha256="0" * 64,
                        allowed_hosts=APP.OFFICIAL_DOWNLOAD_HOSTS,
                    )

            self.assertFalse(dest.exists())

    def test_incomplete_download_is_not_promoted(self):
        with TemporaryDirectory() as temp:
            dest = Path(temp) / "tool.7z"
            response = Response([b"partial", b""], 100)
            with patch.object(APP.urllib.request, "urlopen", return_value=response):
                with self.assertRaisesRegex(APP.SetupError, "下載不完整"):
                    APP.download_file(
                        APP.HASHCAT_ARCHIVE_URL, dest, expected_sha256="0" * 64,
                        allowed_hosts=APP.OFFICIAL_DOWNLOAD_HOSTS,
                    )

            self.assertFalse(dest.exists())
            self.assertFalse(dest.with_suffix(".7z.part").exists())

    def test_verified_official_download_is_promoted(self):
        content = b"verified archive"
        expected = hashlib.sha256(content).hexdigest()
        with TemporaryDirectory() as temp:
            dest = Path(temp) / "tool.7z"
            response = Response(
                [content, b""], len(content),
                "https://release-assets.githubusercontent.com/github-production-release-asset/tool.7z",
            )
            with patch.object(APP.urllib.request, "urlopen", return_value=response):
                APP.download_file(
                    APP.HASHCAT_ARCHIVE_URL, dest, expected_sha256=expected,
                    allowed_hosts=APP.OFFICIAL_DOWNLOAD_HOSTS,
                )

            self.assertEqual(dest.read_bytes(), content)

    def test_failed_extraction_preserves_existing_tool_directory(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            tools = root / "tools"
            target = tools / "hashcat"
            target.mkdir(parents=True)
            existing = target / "hashcat.exe"
            existing.write_bytes(b"existing")
            (tools / "tmp").mkdir()
            gui = object.__new__(APP.PasswordToolGUI)
            gui.enqueue_log = Mock()

            def partial_extract(_archive, staged, _log):
                staged.mkdir(parents=True)
                (staged / "partial.bin").write_bytes(b"partial")
                raise RuntimeError("extract failed")

            with patch.object(APP, "TOOLS_DIR", tools), patch.object(APP, "DOWNLOADS_DIR", root), patch.object(
                APP, "TOOL_TMP_DIR", tools / "tmp"
            ), patch.object(APP, "download_file"), patch.object(APP, "extract_archive", side_effect=partial_extract):
                with self.assertRaisesRegex(RuntimeError, "extract failed"):
                    gui.download_hashcat()

            self.assertEqual(existing.read_bytes(), b"existing")


if __name__ == "__main__":
    main()
