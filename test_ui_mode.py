import password_gui.app as APP
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest


class FakeButton:
    def __init__(self):
        self.text = ""
        self.states = []
        self.visible = False

    def configure(self, **kwargs):
        self.text = kwargs["text"]

    def state(self, values):
        self.states = values

    def pack(self, **_kwargs):
        self.visible = True

    def pack_forget(self):
        self.visible = False

    def winfo_manager(self):
        return "pack" if self.visible else ""


class FakeValue:
    def __init__(self):
        self.value = ""

    def set(self, value):
        self.value = value


class FakeFrame:
    def __init__(self):
        self.visible = True

    def grid(self):
        self.visible = True

    def grid_remove(self):
        self.visible = False


class UiModeTests(unittest.TestCase):
    def destroy_gui(self, gui):
        for after_id in gui.tk.splitlist(gui.tk.call("after", "info")):
            gui.after_cancel(after_id)
        gui.destroy()

    def test_monospace_font_falls_back_without_cascadia(self):
        self.assertEqual(
            APP.select_font_family({"Consolas"}, ("Cascadia Mono", "Consolas"), "TkFixedFont"),
            "Consolas",
        )
        self.assertEqual(
            APP.select_font_family(set(), ("Cascadia Mono", "Consolas"), "TkFixedFont"),
            "TkFixedFont",
        )

    def test_job_render_distinguishes_stopping_from_cancelled(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.quick_status = FakeValue()
        gui.quick_start_button = FakeButton()
        gui.stop_button = FakeButton()

        gui.render_job(APP.JobSnapshot(state=APP.JobState.STOPPING))
        self.assertEqual(gui.quick_status.value, "正在停止工作，請稍候。")
        self.assertEqual(gui.quick_start_button.states, ["disabled"])
        self.assertEqual(gui.stop_button.text, "正在停止…")
        self.assertEqual(gui.stop_button.states, ["disabled"])
        self.assertTrue(gui.stop_button.visible)

        gui.render_job(APP.JobSnapshot(state=APP.JobState.CANCELLED))
        self.assertEqual(gui.quick_status.value, "工作已取消。")
        self.assertEqual(gui.quick_start_button.states, ["!disabled"])
        self.assertEqual(gui.stop_button.text, "停止")
        self.assertFalse(gui.stop_button.visible)

    def test_tools_directory_is_not_an_editable_setting(self):
        self.assertFalse(hasattr(APP.default_config(), "tools_dir"))

    def test_structured_output_snapshot_renders_extended_metrics(self):
        gui = object.__new__(APP.PasswordToolGUI)
        for name in (
            "output_status_var", "output_progress_var", "progress_value", "output_speed_var",
            "output_temp_var", "output_candidate_var", "output_recovered_var", "output_mode_var",
            "output_length_var", "output_queue_var", "output_file_var",
        ):
            setattr(gui, name, FakeValue())

        gui.render_output_snapshot(
            APP.DashboardSnapshot(mode="MD5", password_length="8 位", queue="1/2", output_file="result.txt")
        )

        self.assertEqual(gui.output_mode_var.value, "MD5")
        self.assertEqual(gui.output_length_var.value, "8 位")
        self.assertEqual(gui.output_queue_var.value, "1/2")
        self.assertEqual(gui.output_file_var.value, "result.txt")

    def test_tool_detection_sync_preserves_current_job_inputs(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.setting_vars = {}
        gui.config_data = APP.AppConfig(
            default_wordlist=Path("configured.txt"),
            attack_strategy=APP.AttackStrategy.AUTO,
        )
        gui.quick_wordlist = FakeValue()
        gui.quick_wordlist.value = "current.txt"
        gui.quick_combo_wordlist = FakeValue()
        gui.quick_combo_key = FakeValue()
        gui.candidate_source = FakeValue()
        gui.candidate_source.value = "自訂字典"
        gui.quick_strategy = FakeValue()
        gui.hashcat_wordlist = FakeValue()
        gui.john_wordlist = FakeValue()

        gui.sync_config_to_ui(sync_task_inputs=False)

        self.assertEqual(gui.quick_wordlist.value, "current.txt")
        self.assertEqual(gui.candidate_source.value, "自訂字典")

    def test_advanced_settings_replace_the_main_workspace(self):
        gui = object.__new__(APP.PasswordToolGUI)
        gui.advanced_toggle = FakeButton()
        gui.main_workspace = FakeFrame()
        gui.advanced_panel = FakeFrame()

        gui.set_advanced_visible(False)

        self.assertEqual(gui.advanced_toggle.text, "進階設定")
        self.assertTrue(gui.main_workspace.visible)
        self.assertFalse(gui.advanced_panel.visible)

        gui.set_advanced_visible(True)

        self.assertEqual(gui.advanced_toggle.text, "返回工作")
        self.assertFalse(gui.main_workspace.visible)
        self.assertTrue(gui.advanced_panel.visible)

    def test_target_summary_and_candidate_requirements_gate_start(self):
        with TemporaryDirectory() as temp:
            target = Path(temp) / "sample.zip"
            target.write_bytes(b"zip")
            gui = APP.PasswordToolGUI()
            try:
                gui.quick_input.set(str(target))
                gui.update()
                self.assertIn("sample.zip｜ZIP", gui.target_summary.get())
                self.assertTrue(gui.quick_start_button.instate(["!disabled"]))
                self.assertFalse(any(isinstance(widget, APP.ttk.Combobox) for widget in gui.strategy_card.winfo_children()))

                gui.quick_wordlist.set("")
                gui.candidate_source.set("自訂字典")
                gui.update()
                self.assertEqual(gui.selected_attack_strategy(), APP.AttackStrategy.DICTIONARY)
                self.assertTrue(gui.quick_start_button.instate(["disabled"]))
                self.assertIn("字典", gui.quick_status.get())

                wordlist = Path(temp) / "words.txt"
                wordlist.write_text("secret\n", encoding="utf-8")
                gui.quick_wordlist.set(str(wordlist))
                gui.update()
                self.assertTrue(gui.quick_start_button.instate(["!disabled"]))
            finally:
                self.destroy_gui(gui)

    def test_job_results_and_details_use_distinct_main_views(self):
        gui = APP.PasswordToolGUI()
        try:
            self.assertFalse(gui.details_panel.winfo_ismapped())
            gui.show_job_view()
            gui.set_details_visible(True)
            gui.update()
            self.assertTrue(gui.details_panel.winfo_ismapped())

            stage = APP.JobStage(id="hints", display_name="提示詞組合")
            gui.render_job(
                APP.JobSnapshot(
                    state=APP.JobState.RUNNING,
                    stages=(stage,),
                    total_stages=1,
                )
            )
            gui.update()
            self.assertEqual(gui.output_job_var.get(), "1 / 1  提示詞組合")
            self.assertTrue(gui.stop_button.winfo_ismapped())

            for state, title in (
                (APP.JobState.SUCCEEDED, "已找到密碼"),
                (APP.JobState.EXHAUSTED, "未找到密碼"),
                (APP.JobState.FAILED, "工作失敗"),
            ):
                gui.render_job(APP.JobSnapshot(state=state, error="可讀錯誤"))
                gui.update()
                self.assertEqual(gui.result_title_var.get(), title)
                self.assertTrue(gui.output_tab.winfo_ismapped())
                self.assertFalse(gui.launcher.winfo_ismapped())
        finally:
            self.destroy_gui(gui)

    def test_minimum_window_keeps_primary_sections_visible(self):
        gui = APP.PasswordToolGUI()
        try:
            mono = APP.tkfont.Font(gui, family=gui.mono_font, size=10)
            ui = APP.tkfont.Font(gui, family=gui.ui_font, size=11)
            self.assertEqual(mono.measure("iiii"), mono.measure("WWWW"))
            self.assertGreater(ui.measure("繁體中文"), 0)

            for geometry in ("1100x720", "1366x768"):
                gui.geometry(geometry)
                gui.show_launcher()
                gui.update()
                self.assertTrue(gui.quick_start_button.winfo_ismapped())
                self.assertLessEqual(
                    gui.quick_start_button.winfo_x() + gui.quick_start_button.winfo_width(),
                    gui.launcher.winfo_width(),
                )
                self.assertLessEqual(
                    gui.quick_start_button.winfo_y() + gui.quick_start_button.winfo_height(),
                    gui.launcher.winfo_height(),
                )

            gui.set_advanced_visible(True)
            gui.update()
            self.assertFalse(gui.main_workspace.winfo_ismapped())
            self.assertTrue(gui.advanced_panel.winfo_ismapped())
            for tab in (gui.extract_tab, gui.hashcat_tab, gui.john_tab, gui.settings_tab, gui.help_tab):
                gui.notebook.select(tab)
                gui.update()
                self.assertLessEqual(tab.winfo_reqwidth(), tab.winfo_width())

            gui.set_advanced_visible(False)
            gui.update()
            self.assertTrue(gui.main_workspace.winfo_ismapped())
        finally:
            self.destroy_gui(gui)


if __name__ == "__main__":
    unittest.main()
