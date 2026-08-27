import password_gui.app as APP
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch

from password_gui import tools


class ToolDiscoveryTests(TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.exe = self.root / "tool.exe"
        self.exe.touch()

    def test_environment_can_point_to_executable(self):
        with patch.dict(os.environ, {"TOOL_PATH": str(self.exe)}):
            self.assertEqual(APP.find_in_env("TOOL_PATH", "tool.exe"), str(self.exe))

    def test_environment_can_point_to_executable_directory(self):
        with patch.dict(os.environ, {"TOOL_PATH": str(self.root)}):
            self.assertEqual(APP.find_in_env("TOOL_PATH", "tool.exe"), str(self.exe))

    def test_unrelated_directory_returns_without_recursive_search(self):
        unrelated = self.root / "unrelated"
        (unrelated / "deep").mkdir(parents=True)
        (unrelated / "deep" / "tool.exe").touch()

        with patch.dict(os.environ, {"TOOL_PATH": str(unrelated)}), patch.object(
            APP.Path, "rglob", side_effect=AssertionError("recursive search is not allowed")
        ) as rglob:
            result = APP.find_in_env("TOOL_PATH", "tool.exe")

        self.assertEqual(result, "")
        rglob.assert_not_called()

    def test_detection_falls_back_to_path_then_managed_tools(self):
        found = {
            "hashcat.exe": "path/hashcat.exe",
            "python.exe": "path/python.exe",
            "perl.exe": "path/perl.exe",
            "node.exe": "path/node.exe",
        }
        with patch.object(tools, "existing_exe", return_value=""), patch.object(
            tools, "find_in_env", return_value=""
        ), patch.object(tools.shutil, "which", side_effect=lambda name: found.get(name)), patch.object(
            tools, "find_hashcat_under"
        ) as managed_hashcat, patch.object(
            tools, "find_john_under", return_value=("managed/john.exe", "managed/run")
        ):
            detected = APP.find_tool_paths(tools_dir=APP.TOOLS_DIR)

        self.assertEqual(detected["hashcat_path"], "path/hashcat.exe")
        self.assertEqual(detected["john_path"], "managed/john.exe")
        self.assertEqual(detected["python_path"], "path/python.exe")
        self.assertEqual(detected["perl_path"], "path/perl.exe")
        self.assertEqual(detected["node_path"], "path/node.exe")
        managed_hashcat.assert_not_called()


if __name__ == "__main__":
    main()
