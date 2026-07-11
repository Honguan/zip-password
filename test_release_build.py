from pathlib import Path
import unittest


ROOT = Path(__file__).parent


class ReleaseBuildTests(unittest.TestCase):
    def test_spec_uses_relative_font_path(self):
        spec = (ROOT / "build" / "密碼工具GUI.spec").read_text(encoding="utf-8")
        self.assertIn("('..\\\\Iansui-Regular.ttf', '.')", spec)
        self.assertNotIn("C:\\\\Users\\\\", spec)

    def test_release_workflow_builds_and_publishes_tagged_release(self):
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn("tags:", workflow)
        self.assertIn('"v*"', workflow)
        self.assertIn("^v\\d+\\.\\d+\\.\\d+$", workflow)
        self.assertIn("pyinstaller", workflow)
        self.assertIn("python -m unittest", workflow)
        self.assertIn("40MB", workflow)
        self.assertIn("Get-FileHash", workflow)
        self.assertIn("softprops/action-gh-release@v2", workflow)

    def test_release_checklist_covers_required_manual_flows(self):
        checklist = (ROOT / "RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
        for item in ("啟動", "自動安裝", "執行", "停止", "輸出"):
            self.assertIn(item, checklist)


if __name__ == "__main__":
    unittest.main()
