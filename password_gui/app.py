# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import queue
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import ctypes
import urllib.parse
from pathlib import Path
from tkinter import filedialog, font as tkfont, messagebox, scrolledtext
import tkinter as tk
from tkinter import ttk

from password_gui.config import (
    AppConfig,
    AttackStrategy,
    load_config_file,
    read_config_file as read_typed_config_file,
    save_config_file,
)
from password_logic import (
    AUTO_MASKS,
    HASHCAT_DEFAULT_MASK,
    JOHN_DEFAULT_MASK,
    build_auto_hashcat_command,
    build_auto_john_command,
    converter_names,
    converter_runtime,
    detect_hashcat_mode,
    extract_passwords_from_show,
    format_for_extension,
    hashcat_mode_labels,
    prepare_hash_output,
    source_identity,
    supported_file_pattern,
    supported_format_summary,
)
from password_gui.runner import (
    CommandRunner,
    JobBusyError,
    ProcessResult,
    clean_output,
    decode_bytes,
    format_elapsed,
    hidden_startup,
    quote_command,
)
from password_gui.tools import (
    SEVENZIP_DOWNLOAD_PAGE,
    SetupError,
    download_file,
    extract_archive,
    existing_exe,
    file_sha256,
    find_hashcat_under,
    find_in_env,
    find_john_under,
    find_tool_paths,
    replace_tool_directory,
    validate_download_url,
)
from password_gui.output_parser import (
    DashboardSnapshot,
    EngineOutputParser,
    apply_event,
    estimate_mask_length,
)
from password_gui.wordlists import (
    WORDLIST_EXPANSION_LIMIT,
    WORDLIST_JOINERS,
    WordlistMergeFailure,
    WordlistMergeResult,
    build_expanded_wordlist,
    case_variants,
    count_text_lines,
    merge_wordlist_files,
    split_candidate_tokens,
)
from password_gui.job import (
    CancelledError,
    ConverterError,
    EngineLaunchError,
    EngineRuntimeError,
    InvalidDictionaryError,
    JobAlreadyRunningError,
    JobContext,
    JobController,
    JobSnapshot,
    JobStage,
    JobState,
    MissingToolError,
    StageResult,
    UnsupportedFormatError,
)
from password_gui.workflow import attack_steps


APP_DIR = (
    Path(sys.executable).resolve().parent
    if getattr(sys, "frozen", False)
    else Path(__file__).resolve().parent.parent
)
TOOLS_DIR = APP_DIR / "密碼工具GUI_tools"
DOWNLOADS_DIR = TOOLS_DIR / "downloads"
TOOL_TMP_DIR = TOOLS_DIR / "tmp"
WORDLISTS_DIR = TOOLS_DIR / "wordlists"
CONFIG_PATH = APP_DIR / "password_gui_config.json"
LEGACY_CONFIG_NAMES = [
    "密碼工具GUI_config.json",
    "密碼工具GUI設定.json",
    "PasswordToolsGUI_config.json",
    "password_tools_gui_config.json",
]
RESULTS_DIR = APP_DIR / "密碼工具GUI_輸出"
BG = "#F3F6FA"
SURFACE = "#FFFFFF"
SURFACE_2 = "#EEF3F8"
TEXT = "#172033"
MUTED = "#667085"
BORDER = "#D7DEE8"
ACCENT = "#2563EB"
ACCENT_DARK = "#1E40AF"
DANGER = "#DC2626"
HASHCAT_DOWNLOAD_PAGE = "https://hashcat.net/hashcat/"
JOHN_RELEASE_PAGE = "https://github.com/openwall/john-packages/releases/latest"
HASHCAT_ARCHIVE_URL = "https://github.com/hashcat/hashcat/releases/download/v7.1.2/hashcat-7.1.2.7z"
HASHCAT_ARCHIVE_SHA256 = "80db0316387794ce9d14ed376da75b8a7742972485b45db790f5f8260307ff98"
JOHN_ARCHIVE_URL = "https://github.com/openwall/john-packages/releases/download/v1.9.1-ce/winX64_1_JtR.7z"
JOHN_ARCHIVE_SHA256 = "8259f751378fd0f81a298e52c1277d9c6b08a0d5eb6ba66c46d5dc25b9de3607"
OFFICIAL_DOWNLOAD_HOSTS = frozenset({"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"})
PERL_DOWNLOAD_PAGE = "https://strawberryperl.com/"
PYTHON_DOWNLOAD_PAGE = "https://www.python.org/downloads/windows/"
NODE_DOWNLOAD_PAGE = "https://nodejs.org/en/download"

COMMON_WORDLISTS = [
    (
        "SecLists 500 worst passwords",
        "500-worst-passwords.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/500-worst-passwords.txt",
    ),
    (
        "SecLists 10k most common",
        "10k-most-common.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
    ),
    (
        "SecLists 100k NCSC",
        "100k-most-used-passwords-NCSC.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt",
    ),
    (
        "SecLists Pwdb top 100k",
        "Pwdb_top-100000.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/Pwdb_top-100000.txt",
    ),
]

ATTACK_STRATEGY_OPTIONS = {
    "AUTO－字典 → 提示詞 → 遮罩": AttackStrategy.AUTO,
    "DICTIONARY－只使用所選字典": AttackStrategy.DICTIONARY,
    "HINTS－只使用提示詞／組合": AttackStrategy.HINTS,
    "MASK－只使用遮罩": AttackStrategy.MASK,
}

CANDIDATE_SOURCE_STRATEGIES = {
    "自動": AttackStrategy.AUTO,
    "常用字典": AttackStrategy.DICTIONARY,
    "自訂字典": AttackStrategy.DICTIONARY,
    "提示詞組合": AttackStrategy.HINTS,
    "純暴力": AttackStrategy.MASK,
}
DEFAULT_CANDIDATE_SOURCES = {
    AttackStrategy.AUTO: "自動",
    AttackStrategy.DICTIONARY: "自訂字典",
    AttackStrategy.HINTS: "提示詞組合",
    AttackStrategy.MASK: "純暴力",
}

UI_QUEUE_LIMIT = 2_000
UI_QUEUE_ITEMS_PER_TICK = 100
UI_LOG_MAX_LINES = 5_000
HASHCAT_MODES = hashcat_mode_labels()

HASHCAT_ATTACKS = [
    "0 - 字典 / Straight",
    "1 - 組合 / Combination",
    "3 - 遮罩 / Brute-force",
    "6 - 字典 + 遮罩",
    "7 - 遮罩 + 字典",
]

JOHN_MODES = [
    "wordlist - 字典",
    "single - Single crack",
    "incremental - Incremental",
    "mask - Mask",
    "none - 只用進階參數",
]


def default_config() -> AppConfig:
    python_path = shutil.which("python") or sys.executable
    if getattr(sys, "frozen", False):
        python_path = shutil.which("python") or ""
    elif python_path.lower().endswith("pythonw.exe"):
        candidate = Path(python_path).with_name("python.exe")
        if candidate.exists():
            python_path = str(candidate)
    config = AppConfig(python_path=Path(python_path) if python_path else None, output_dir=RESULTS_DIR)
    config.update_tool_paths(find_tool_paths(config.tool_paths(), TOOLS_DIR))
    return config


def config_search_paths() -> list[Path]:
    return [CONFIG_PATH, *(APP_DIR / name for name in LEGACY_CONFIG_NAMES)]


def read_config_file(path: Path) -> dict[str, object]:
    return read_typed_config_file(path)


def load_config() -> tuple[AppConfig, str, Path | None]:
    cfg = default_config()
    cfg, error, loaded_path = load_config_file(cfg, config_search_paths())
    if error:
        return cfg, error, loaded_path
    cfg.update_tool_paths(find_tool_paths(cfg.tool_paths(), TOOLS_DIR))
    if loaded_path and loaded_path != CONFIG_PATH:
        try:
            save_config(cfg)
        except Exception:
            pass
    return cfg, "", loaded_path


def save_config(cfg: AppConfig) -> None:
    save_config_file(cfg, CONFIG_PATH)


def ensure_tool_dirs() -> None:
    for path in (TOOLS_DIR, DOWNLOADS_DIR, TOOL_TMP_DIR, WORDLISTS_DIR, RESULTS_DIR, TOOLS_DIR / "hashcat", TOOLS_DIR / "JohnRipper"):
        path.mkdir(parents=True, exist_ok=True)


def safe_stem(text: str) -> str:
    value = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", text).strip(" ._")
    return value[:80] or "output"


def result_dir_for_source(src: Path, output_dir: Path) -> Path:
    out_dir = output_dir / source_identity(src)
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def split_extra_args(text: str) -> list[str]:
    text = text.strip()
    if not text:
        return []
    if os.name == "nt":
        argc = ctypes.c_int()
        command_line_to_argv = ctypes.windll.shell32.CommandLineToArgvW
        command_line_to_argv.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
        command_line_to_argv.restype = ctypes.POINTER(ctypes.c_wchar_p)
        local_free = ctypes.windll.kernel32.LocalFree
        local_free.argtypes = [ctypes.c_void_p]
        local_free.restype = ctypes.c_void_p
        argv = command_line_to_argv(text, ctypes.byref(argc))
        if not argv:
            raise ValueError("進階參數格式錯誤：Windows 解析失敗")
        try:
            return [argv[i] for i in range(argc.value)]
        finally:
            local_free(argv)
    try:
        return shlex.split(text)
    except ValueError as exc:
        raise ValueError(f"進階參數格式錯誤：{exc}") from exc


def first_number(value: str) -> str:
    match = re.match(r"\s*(\d+)", value or "")
    return match.group(1) if match else value.strip()


def select_font_family(
    available: set[str], preferred: tuple[str, ...], fallback: str
) -> str:
    return next((family for family in preferred if family in available), fallback)


def summarize_masks(masks: list[str]) -> str:
    lengths = [estimate_mask_length(mask.strip()) for mask in masks if mask.strip()]
    if not lengths:
        return "-"
    unique = sorted(set(lengths))
    if len(unique) == 1:
        return f"{unique[0]} 位"
    return f"{unique[0]}-{unique[-1]} 位 ({len(unique)} 種長度)"


class PasswordToolGUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        available_fonts = set(tkfont.families(self))
        self.ui_font = select_font_family(
            available_fonts,
            ("Microsoft JhengHei UI", "Microsoft JhengHei", "Segoe UI"),
            str(tkfont.nametofont("TkDefaultFont", self).actual("family")),
        )
        self.mono_font = select_font_family(
            available_fonts,
            ("Cascadia Mono", "Consolas"),
            str(tkfont.nametofont("TkFixedFont", self).actual("family")),
        )
        self.title("密碼工具 GUI")
        self.geometry("1400x900")
        self.minsize(1100, 720)
        self.config_data, self.config_load_error, self.config_load_source = load_config()
        self.log_queue: queue.Queue[str] = queue.Queue(maxsize=UI_QUEUE_LIMIT)
        self.status_queue: queue.Queue[str] = queue.Queue(maxsize=UI_QUEUE_LIMIT)
        self.ui_queue: queue.Queue[object] = queue.Queue()
        self._tools_setup_lock = threading.Lock()
        self._wordlist_download_lock = threading.Lock()
        self.runner = CommandRunner(self, self._notify_runner)
        self.output_parser = EngineOutputParser()
        self.output_snapshot = DashboardSnapshot()
        self.extract_thread: threading.Thread | None = None
        self.auto_thread: threading.Thread | None = None
        self.capture_thread: threading.Thread | None = None
        self.conversion_cancel = threading.Event()
        self.job_controller = JobController(self._on_job_snapshot)
        self.converter_names: list[str] = []
        self.setting_vars: dict[str, tk.StringVar] = {}
        self._build_style()
        self._build_ui()
        if self.config_load_error:
            self.after(0, self._show_config_load_error)
        elif self.config_load_source and self.config_load_source != CONFIG_PATH:
            self.after(0, self._show_config_migration)
        self.refresh_converters()
        self.after(80, self._drain_queues)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(300, self.ensure_tools_on_startup)

    @staticmethod
    def _notify_runner(level: str, title: str, message: str) -> None:
        getattr(messagebox, f"show{level}")(title, message)

    def _build_style(self) -> None:
        self.configure(bg=BG)
        self.option_add("*Font", (self.ui_font, 11))
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(".", font=(self.ui_font, 11), background=BG, foreground=TEXT)
        style.configure("App.TFrame", background=BG)
        style.configure("Shell.TFrame", background=BG)
        style.configure("TopBar.TFrame", background=SURFACE, relief="solid", borderwidth=1)
        style.configure("TopBarInner.TFrame", background=SURFACE)
        style.configure("Panel.TFrame", background=SURFACE, relief="solid", borderwidth=1)
        style.configure("Card.TFrame", background=SURFACE, relief="solid", borderwidth=1)
        style.configure("Soft.TFrame", background=SURFACE_2)
        style.configure("TLabel", padding=(0, 2), background=BG, foreground=TEXT)
        style.configure("Panel.TLabel", background=SURFACE, foreground=TEXT)
        style.configure("Soft.TLabel", background=SURFACE_2, foreground=TEXT)
        style.configure("Card.TLabel", background=SURFACE, foreground=TEXT)
        style.configure("Muted.TLabel", background=SURFACE, foreground=MUTED)
        style.configure("Title.TLabel", background=BG, foreground=TEXT, font=(self.ui_font, 20, "bold"))
        style.configure("PanelTitle.TLabel", background=SURFACE, foreground=TEXT, font=(self.ui_font, 16, "bold"))
        style.configure("Header.TLabel", background=BG, foreground=TEXT, font=(self.ui_font, 14, "bold"))
        style.configure("PanelHeader.TLabel", background=SURFACE, foreground=TEXT, font=(self.ui_font, 13, "bold"))
        style.configure("MetricValue.TLabel", background=SURFACE, foreground=TEXT, font=(self.mono_font, 14, "bold"))
        style.configure("MetricName.TLabel", background=SURFACE, foreground=MUTED, font=(self.ui_font, 10))
        style.configure("Status.TLabel", anchor="w", background=BG, foreground=MUTED)
        style.configure("Pill.TLabel", background="#EAF2FF", foreground=ACCENT_DARK, padding=(10, 4), font=(self.ui_font, 10, "bold"))
        style.configure("TButton", padding=(12, 7), background=SURFACE, foreground=TEXT, bordercolor=BORDER, lightcolor=SURFACE, darkcolor=BORDER)
        style.map("TButton", background=[("active", SURFACE_2), ("pressed", "#E4EAF3")])
        style.configure("Accent.TButton", padding=(14, 8), background=ACCENT, foreground="#FFFFFF", bordercolor=ACCENT, lightcolor=ACCENT, darkcolor=ACCENT_DARK)
        style.map("Accent.TButton", background=[("active", ACCENT_DARK), ("pressed", ACCENT_DARK)], foreground=[("disabled", "#DBEAFE")])
        style.configure("Danger.TButton", padding=(12, 7), background="#FEF2F2", foreground=DANGER, bordercolor="#FECACA")
        style.map("Danger.TButton", background=[("active", "#FEE2E2"), ("pressed", "#FECACA")])
        style.configure("TEntry", fieldbackground=SURFACE, foreground=TEXT, bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER, padding=6)
        style.configure("TCombobox", fieldbackground=SURFACE, foreground=TEXT, bordercolor=BORDER, padding=5)
        style.configure("TCheckbutton", background=BG, foreground=TEXT)
        style.configure("Card.TCheckbutton", background=SURFACE, foreground=TEXT)
        style.configure("TRadiobutton", background=BG, foreground=TEXT)
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background="#E6ECF4", foreground=MUTED, padding=(16, 9), borderwidth=0)
        style.map("TNotebook.Tab", background=[("selected", SURFACE), ("active", "#F8FAFC")], foreground=[("selected", ACCENT), ("active", TEXT)])
        style.configure("Horizontal.TProgressbar", troughcolor=SURFACE_2, background=ACCENT, bordercolor=SURFACE_2, lightcolor=ACCENT, darkcolor=ACCENT)

    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=16, style="Shell.TFrame")
        root.pack(fill="both", expand=True)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(1, weight=1)
        self.status_var = tk.StringVar(value="就緒")

        topbar = ttk.Frame(root, padding=(18, 14), style="TopBar.TFrame")
        topbar.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        topbar.columnconfigure(0, weight=1)
        ttk.Label(topbar, text="密碼工具 GUI", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(topbar, text="選擇目標、候選來源與策略，開始分析", style="Muted.TLabel").grid(row=1, column=0, sticky="w", pady=(4, 0))
        ttk.Label(topbar, textvariable=self.status_var, style="Pill.TLabel").grid(row=0, column=1, rowspan=2, sticky="e", padx=(12, 14))
        top_actions = ttk.Frame(topbar, style="TopBarInner.TFrame")
        top_actions.grid(row=0, column=2, rowspan=2, sticky="e")
        self.advanced_toggle = ttk.Button(top_actions, command=lambda: self.set_advanced_visible(not self._advanced_visible))
        self.advanced_toggle.pack(side="left", padx=(0, 8))
        self.stop_button = ttk.Button(
            top_actions, text="停止", command=self.stop_current_work, style="Danger.TButton"
        )
        self.stop_button.pack(side="left")
        self.stop_button.pack_forget()

        body = ttk.Frame(root, style="Shell.TFrame")
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)

        self.main_workspace = ttk.Frame(body, style="Shell.TFrame")
        self.main_workspace.grid(row=0, column=0, sticky="nsew")
        self.main_workspace.columnconfigure(0, weight=1)
        self.main_workspace.rowconfigure(0, weight=1)

        self.launcher = ttk.Frame(self.main_workspace, padding=(18, 12), style="Panel.TFrame")
        self.launcher.grid(row=0, column=0, sticky="nsew")
        self._build_launcher_panel(self.launcher)

        self.output_tab = ttk.Frame(self.main_workspace, padding=12, style="App.TFrame")
        self.output_tab.grid(row=0, column=0, sticky="nsew")
        self._build_output_tab()
        self.output_tab.grid_remove()

        details_panel = ttk.Frame(body, style="Shell.TFrame")
        details_panel.grid(row=0, column=0, sticky="nsew")
        details_panel.columnconfigure(0, weight=1)
        details_panel.rowconfigure(0, weight=1)
        self.advanced_panel = details_panel
        self.notebook = ttk.Notebook(details_panel)
        self.notebook.grid(row=0, column=0, sticky="nsew")

        self.extract_tab = ttk.Frame(self.notebook, padding=12, style="App.TFrame")
        self.hashcat_tab = ttk.Frame(self.notebook, padding=12, style="App.TFrame")
        self.john_tab = ttk.Frame(self.notebook, padding=12, style="App.TFrame")
        self.settings_tab = ttk.Frame(self.notebook, padding=12, style="App.TFrame")
        self.help_tab = ttk.Frame(self.notebook, padding=12, style="App.TFrame")

        self.notebook.add(self.extract_tab, text="雜湊轉換")
        self.notebook.add(self.hashcat_tab, text="Hashcat")
        self.notebook.add(self.john_tab, text="John")
        self.notebook.add(self.settings_tab, text="設定")
        self.notebook.add(self.help_tab, text="說明")

        self._build_extract_tab()
        self._build_hashcat_tab()
        self._build_john_tab()
        self._build_settings_tab()
        self._build_help_tab()
        self.advanced_panel.grid_remove()
        self.set_advanced_visible(False)

    def set_advanced_visible(self, visible: bool) -> None:
        self._advanced_visible = visible
        if visible:
            self.main_workspace.grid_remove()
            self.advanced_panel.grid()
        else:
            self.advanced_panel.grid_remove()
            self.main_workspace.grid()
        self.advanced_toggle.configure(text="返回工作" if visible else "進階設定")

    def _build_launcher_panel(self, parent: ttk.Frame) -> None:
        self.quick_input = tk.StringVar()
        self.quick_wordlist = tk.StringVar(value=str(self.config_data.default_wordlist or ""))
        self.quick_combo_wordlist = tk.StringVar(value=str(self.config_data.combo_wordlist or ""))
        self.quick_combo_key = tk.StringVar(value=self.config_data.combo_key)
        candidate_source = DEFAULT_CANDIDATE_SOURCES[self.config_data.attack_strategy]
        self.candidate_source = tk.StringVar(value=candidate_source)
        self.common_wordlist = tk.StringVar(value=COMMON_WORDLISTS[1][0])
        self.quick_auto_download = tk.BooleanVar(value=True)
        self.quick_expand_wordlist = tk.BooleanVar(value=True)
        strategy_label = next(label for label, strategy in ATTACK_STRATEGY_OPTIONS.items() if strategy == self.config_data.attack_strategy)
        self.quick_strategy = tk.StringVar(value=strategy_label)
        self.quick_status = tk.StringVar(value="請先選擇目標檔案。")
        self.target_summary = tk.StringVar(value="尚未選擇檔案")
        self.strategy_summary = tk.StringVar()

        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(2, weight=1)
        ttk.Label(parent, text="開始新工作", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            parent, text=f"選擇檔案、候選來源與策略即可開始；支援 {supported_format_summary()}。", style="Muted.TLabel"
        ).grid(row=1, column=0, sticky="w", pady=(4, 12))

        self.task_cards = ttk.Frame(parent, style="Panel.TFrame")
        self.task_cards.grid(row=2, column=0, sticky="nsew")
        self.task_cards.columnconfigure(0, weight=1)

        self.target_card = self._card(self.task_cards, 0, 0, pady=(0, 10))
        self.target_card.columnconfigure(0, weight=1)
        ttk.Label(self.target_card, text="1  目標檔案", style="PanelHeader.TLabel").grid(row=0, column=0, sticky="w")
        file_box = ttk.Frame(self.target_card, style="Card.TFrame")
        file_box.grid(row=1, column=0, sticky="ew", pady=(10, 8))
        file_box.columnconfigure(0, weight=1)
        ttk.Entry(file_box, textvariable=self.quick_input).grid(row=0, column=0, sticky="ew")
        ttk.Button(file_box, text="選擇檔案", command=self._browse_quick_file).grid(row=0, column=1, padx=(8, 0))
        ttk.Label(self.target_card, textvariable=self.target_summary, style="Muted.TLabel").grid(row=2, column=0, sticky="w")

        self.candidate_card = self._card(self.task_cards, 1, 0, pady=(0, 10))
        self.candidate_card.columnconfigure(0, weight=1)
        ttk.Label(self.candidate_card, text="2  候選來源", style="PanelHeader.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Combobox(
            self.candidate_card,
            textvariable=self.candidate_source,
            values=list(CANDIDATE_SOURCE_STRATEGIES),
            state="readonly",
        ).grid(row=1, column=0, sticky="ew", pady=(10, 8))
        self.candidate_fields = ttk.Frame(self.candidate_card, style="Card.TFrame")
        self.candidate_fields.grid(row=2, column=0, sticky="ew")
        self.candidate_fields.columnconfigure(0, weight=1)
        self.candidate_source_frames: dict[str, ttk.Frame] = {}

        auto_frame = ttk.Frame(self.candidate_fields, style="Card.TFrame")
        ttk.Label(auto_frame, text="自動使用字典庫、提示詞與遮罩。", style="Muted.TLabel").grid(sticky="w")
        self.candidate_source_frames["自動"] = auto_frame

        common_frame = ttk.Frame(self.candidate_fields, style="Card.TFrame")
        common_frame.columnconfigure(0, weight=1)
        ttk.Combobox(common_frame, textvariable=self.common_wordlist, values=[item[0] for item in COMMON_WORDLISTS], state="readonly").grid(row=0, column=0, sticky="ew")
        self.common_wordlist_download_button = ttk.Button(common_frame, text="下載", command=self.download_selected_wordlist)
        self.common_wordlist_download_button.grid(row=0, column=1, padx=(8, 0))
        ttk.Button(common_frame, text="套用", command=self.use_selected_common_wordlist).grid(row=0, column=2, padx=(8, 0))
        self.candidate_source_frames["常用字典"] = common_frame

        custom_frame = ttk.Frame(self.candidate_fields, style="Card.TFrame")
        custom_frame.columnconfigure(0, weight=1)
        ttk.Entry(custom_frame, textvariable=self.quick_wordlist).grid(row=0, column=0, sticky="ew")
        ttk.Button(custom_frame, text="瀏覽", command=lambda: self._browse_file(self.quick_wordlist)).grid(row=0, column=1, padx=(8, 0))
        self.candidate_source_frames["自訂字典"] = custom_frame

        hints_frame = ttk.Frame(self.candidate_fields, style="Card.TFrame")
        hints_frame.columnconfigure(0, weight=1)
        combo_box = ttk.Frame(hints_frame, style="Card.TFrame")
        combo_box.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        combo_box.columnconfigure(0, weight=1)
        ttk.Entry(combo_box, textvariable=self.quick_combo_wordlist).grid(row=0, column=0, sticky="ew")
        ttk.Button(combo_box, text="瀏覽", command=lambda: self._browse_file(self.quick_combo_wordlist)).grid(row=0, column=1, padx=(8, 0))
        ttk.Entry(hints_frame, textvariable=self.quick_combo_key).grid(row=1, column=0, sticky="ew")
        self.candidate_source_frames["提示詞組合"] = hints_frame

        brute_frame = ttk.Frame(self.candidate_fields, style="Card.TFrame")
        ttk.Label(brute_frame, text="使用自動遮罩進行純暴力分析。", style="Muted.TLabel").grid(sticky="w")
        self.candidate_source_frames["純暴力"] = brute_frame

        self.strategy_card = self._card(self.task_cards, 2, 0, pady=(0, 10))
        self.strategy_card.columnconfigure(0, weight=1)
        ttk.Label(self.strategy_card, text="3  執行策略摘要", style="PanelHeader.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Combobox(
            self.strategy_card, textvariable=self.quick_strategy, values=list(ATTACK_STRATEGY_OPTIONS), state="readonly"
        ).grid(row=1, column=0, sticky="ew", pady=(10, 6))
        ttk.Label(self.strategy_card, textvariable=self.strategy_summary, style="Muted.TLabel").grid(row=2, column=0, sticky="w", pady=(0, 6))
        ttk.Checkbutton(self.strategy_card, text="建立基本變體與有限組合", variable=self.quick_expand_wordlist, style="Card.TCheckbutton").grid(row=3, column=0, sticky="w")
        ttk.Checkbutton(self.strategy_card, text="自動管理工具環境", variable=self.quick_auto_download, style="Card.TCheckbutton").grid(row=4, column=0, sticky="w", pady=(4, 0))

        self.quick_start_button = ttk.Button(
            parent, text="開始分析", command=self.auto_start_selected, style="Accent.TButton"
        )
        self.quick_start_button.grid(row=3, column=0, sticky="ew", pady=(2, 10))

        status_box = ttk.Frame(parent, padding=(10, 8), style="Soft.TFrame")
        status_box.grid(row=4, column=0, sticky="ew")
        status_box.columnconfigure(0, weight=1)
        ttk.Label(status_box, textvariable=self.quick_status, style="Soft.TLabel").grid(row=0, column=0, sticky="w")

        for variable in (
            self.quick_input,
            self.quick_wordlist,
            self.quick_combo_wordlist,
            self.quick_combo_key,
            self.quick_strategy,
        ):
            variable.trace_add("write", lambda *_: self._refresh_task_summary())
        self.candidate_source.trace_add("write", lambda *_: self._set_candidate_source())
        parent.bind("<Configure>", self._layout_task_cards, add="+")
        self._set_candidate_source()

    def _layout_task_cards(self, event: tk.Event) -> None:
        wide = event.width >= 1250
        if getattr(self, "_task_cards_wide", None) == wide:
            return
        self._task_cards_wide = wide
        for card in (self.target_card, self.candidate_card, self.strategy_card):
            card.grid_forget()
        self.task_cards.columnconfigure(0, weight=1)
        self.task_cards.columnconfigure(1, weight=1 if wide else 0)
        if wide:
            self.target_card.grid(row=0, column=0, sticky="nsew", padx=(0, 5), pady=(0, 10))
            self.candidate_card.grid(row=0, column=1, sticky="nsew", padx=(5, 0), pady=(0, 10))
            self.strategy_card.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(0, 10))
        else:
            self.target_card.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
            self.candidate_card.grid(row=1, column=0, sticky="nsew", pady=(0, 10))
            self.strategy_card.grid(row=2, column=0, sticky="nsew", pady=(0, 10))

    def _set_candidate_source(self) -> None:
        source = self.candidate_source.get()
        for frame in self.candidate_source_frames.values():
            frame.grid_remove()
        self.candidate_source_frames[source].grid(row=0, column=0, sticky="ew")
        strategy = CANDIDATE_SOURCE_STRATEGIES[source]
        label = next(label for label, value in ATTACK_STRATEGY_OPTIONS.items() if value == strategy)
        self.quick_strategy.set(label)
        self._refresh_task_summary()

    def _refresh_task_summary(self, update_status: bool = True) -> None:
        if "quick_start_button" not in self.__dict__:
            return
        path = Path(self.quick_input.get().strip())
        spec = format_for_extension(path.suffix) if path.suffix else None
        if path.is_file():
            size = path.stat().st_size
            size_text = f"{size / 1024 / 1024:.1f} MB" if size >= 1024 * 1024 else f"{max(1, size // 1024)} KB"
            converter = spec.converter if spec and spec.converter else "不需轉換"
            self.target_summary.set(f"{path.name}｜{spec.name if spec else '未知格式'}｜{size_text}｜{converter}")
        else:
            self.target_summary.set("尚未選擇有效檔案")

        strategy = ATTACK_STRATEGY_OPTIONS[self.quick_strategy.get()]
        stages = {
            AttackStrategy.AUTO: "字典庫 → 提示詞擴展 → 暴力遮罩",
            AttackStrategy.DICTIONARY: "字典",
            AttackStrategy.HINTS: "提示詞組合",
            AttackStrategy.MASK: "暴力遮罩",
        }[strategy]
        self.strategy_summary.set(f"引擎：自動｜階段：{stages}｜候選數：執行前計算")

        reason = ""
        source = self.candidate_source.get()
        if not path.is_file():
            reason = "請先選擇有效的目標檔案。"
        elif spec is None:
            reason = "此檔案格式不在支援清單中。"
        elif source in {"常用字典", "自訂字典"} and not Path(self.quick_wordlist.get().strip()).is_file():
            reason = "請先選擇或套用字典。"
        elif source == "提示詞組合" and not (
            self.quick_combo_key.get().strip() or Path(self.quick_combo_wordlist.get().strip()).is_file()
        ):
            reason = "請輸入提示詞或選擇提示詞檔案。"
        self.quick_start_button.state(["disabled"] if reason else ["!disabled"])
        if update_status:
            self.quick_status.set(reason or "條件已完成，可以開始分析。")

    def _browse_quick_file(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("支援檔案", supported_file_pattern()), ("所有檔案", "*.*")])
        if path:
            self.quick_input.set(path)

    def _row(self, parent: ttk.Frame, row: int, label: str, var: tk.StringVar, browse: str | None = None) -> ttk.Entry:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(0, 8), pady=4)
        entry = ttk.Entry(parent, textvariable=var)
        entry.grid(row=row, column=1, sticky="ew", pady=4)
        if browse:
            command = (lambda: self._browse_file(var)) if browse == "file" else (lambda: self._browse_dir(var))
            ttk.Button(parent, text="瀏覽", command=command).grid(row=row, column=2, padx=(8, 0), pady=4)
        return entry

    def _browse_file(self, var: tk.StringVar, filetypes: list[tuple[str, str]] | None = None) -> None:
        path = filedialog.askopenfilename(filetypes=filetypes or [("所有檔案", "*.*")])
        if path:
            var.set(path)

    def _browse_save(self, var: tk.StringVar, defaultextension: str = ".txt") -> None:
        path = filedialog.asksaveasfilename(defaultextension=defaultextension, filetypes=[("文字檔", "*.txt *.hash"), ("所有檔案", "*.*")])
        if path:
            var.set(path)

    def _browse_dir(self, var: tk.StringVar) -> None:
        path = filedialog.askdirectory()
        if path:
            var.set(path)

    def _card(self, parent: ttk.Widget, row: int, column: int, **grid) -> ttk.Frame:
        card = ttk.Frame(parent, padding=16, style="Card.TFrame")
        card.grid(row=row, column=column, sticky=grid.pop("sticky", "nsew"), padx=grid.pop("padx", 0), pady=grid.pop("pady", 0), **grid)
        return card

    def _build_extract_tab(self) -> None:
        self.extract_input = tk.StringVar()
        self.extract_output = tk.StringVar()
        self.extract_converter = tk.StringVar(value="自動偵測")
        self.extract_target = tk.StringVar(value="john")
        self.extract_safe_copy = tk.BooleanVar(value=True)
        self.extract_fill_hashcat = tk.BooleanVar(value=True)
        self.extract_fill_john = tk.BooleanVar(value=True)

        frame = self.extract_tab
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, text="壓縮包 / 加密檔轉雜湊", style="Header.TLabel").grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))
        self._row(frame, 1, "來源檔案", self.extract_input, "file")
        self._row(frame, 2, "輸出雜湊檔", self.extract_output, None)
        ttk.Button(frame, text="另存", command=lambda: self._browse_save(self.extract_output, ".hash")).grid(row=2, column=2, padx=(8, 0))

        ttk.Label(frame, text="轉換器").grid(row=3, column=0, sticky="w", padx=(0, 8), pady=4)
        self.converter_combo = ttk.Combobox(frame, textvariable=self.extract_converter, values=["自動偵測"], state="readonly")
        self.converter_combo.grid(row=3, column=1, sticky="ew", pady=4)
        ttk.Button(frame, text="刷新", command=self.refresh_converters).grid(row=3, column=2, padx=(8, 0), pady=4)

        target_box = ttk.Frame(frame)
        target_box.grid(row=4, column=1, sticky="w", pady=4)
        ttk.Radiobutton(target_box, text="John 格式", value="john", variable=self.extract_target).pack(side="left", padx=(0, 14))
        ttk.Radiobutton(target_box, text="Hashcat 格式（自動移除檔名前綴）", value="hashcat", variable=self.extract_target).pack(side="left")
        ttk.Label(frame, text="輸出格式").grid(row=4, column=0, sticky="w", padx=(0, 8), pady=4)

        checks = ttk.Frame(frame)
        checks.grid(row=5, column=1, sticky="w", pady=4)
        ttk.Checkbutton(checks, text="中文/空白路徑使用安全暫存名", variable=self.extract_safe_copy).grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(checks, text="完成後填入 Hashcat", variable=self.extract_fill_hashcat).grid(row=1, column=0, sticky="w", pady=(4, 0), padx=(0, 14))
        ttk.Checkbutton(checks, text="完成後填入 John", variable=self.extract_fill_john).grid(row=1, column=1, sticky="w", pady=(4, 0))

        buttons = ttk.Frame(frame)
        buttons.grid(row=6, column=0, columnspan=3, sticky="w", pady=(10, 8))
        ttk.Button(buttons, text="開始轉換", command=self.start_extract).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="建議輸出", command=self.suggest_extract_output).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="開啟輸出資料夾", command=self.open_output_folder).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="填入兩套工具", command=self.fill_hash_targets).pack(side="left")

        info = (
            "支援 ZIP/RAR/7Z、Office、PDF、DMG、GPG、KeePass、BitLocker 等 John 轉換器。\n"
            "缺少 hashcat / John 會自動下載；.pl 轉換器仍需要手動安裝 Perl。"
        )
        ttk.Label(frame, text=info, foreground="#555555").grid(row=7, column=0, columnspan=3, sticky="w", pady=(8, 0))

    def _build_hashcat_tab(self) -> None:
        self.hashcat_hash_file = tk.StringVar()
        self.hashcat_mode = tk.StringVar(value=HASHCAT_MODES[0])
        self.hashcat_attack = tk.StringVar(value=HASHCAT_ATTACKS[0])
        self.hashcat_wordlist = tk.StringVar(value=str(self.config_data.default_wordlist or ""))
        self.hashcat_second = tk.StringVar()
        self.hashcat_mask = tk.StringVar(value=HASHCAT_DEFAULT_MASK)
        self.hashcat_rule = tk.StringVar()
        self.hashcat_outfile = tk.StringVar(value="")
        self.hashcat_session = tk.StringVar(value="gui_hashcat")
        self.hashcat_workload = tk.StringVar(value="3")
        self.hashcat_device = tk.StringVar()
        self.hashcat_status_timer = tk.StringVar(value="10")
        self.hashcat_username = tk.BooleanVar(value=False)
        self.hashcat_remove = tk.BooleanVar(value=False)
        self.hashcat_optimized = tk.BooleanVar(value=True)
        self.hashcat_extra = tk.StringVar()

        frame = self.hashcat_tab
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, text="Hashcat 設定", style="Header.TLabel").grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 10))
        self._row(frame, 1, "雜湊檔", self.hashcat_hash_file, "file")
        ttk.Label(frame, text="雜湊模式").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Combobox(frame, textvariable=self.hashcat_mode, values=HASHCAT_MODES).grid(row=2, column=1, sticky="ew", pady=4)
        ttk.Label(frame, text="攻擊模式").grid(row=3, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Combobox(frame, textvariable=self.hashcat_attack, values=HASHCAT_ATTACKS, state="readonly").grid(row=3, column=1, sticky="ew", pady=4)
        self._row(frame, 4, "字典檔", self.hashcat_wordlist, "file")
        self._row(frame, 5, "第二字典/右側參數", self.hashcat_second, "file")
        self._row(frame, 6, "遮罩", self.hashcat_mask, None)

        ttk.Label(frame, text="規則檔").grid(row=7, column=0, sticky="w", padx=(0, 8), pady=4)
        rule_box = ttk.Frame(frame)
        rule_box.grid(row=7, column=1, sticky="ew", pady=4)
        rule_box.columnconfigure(0, weight=1)
        self.rule_combo = ttk.Combobox(rule_box, textvariable=self.hashcat_rule, values=self._rule_files())
        self.rule_combo.grid(row=0, column=0, sticky="ew")
        ttk.Button(rule_box, text="瀏覽", command=lambda: self._browse_file(self.hashcat_rule)).grid(row=0, column=1, padx=(8, 0))

        self._row(frame, 8, "輸出檔", self.hashcat_outfile, None)
        ttk.Button(frame, text="另存", command=lambda: self._browse_save(self.hashcat_outfile, ".txt")).grid(row=8, column=2, padx=(8, 0))

        options = ttk.Frame(frame)
        options.grid(row=9, column=1, sticky="ew", pady=4)
        ttk.Checkbutton(options, text="--username", variable=self.hashcat_username).grid(row=0, column=0, sticky="w", padx=(0, 10))
        ttk.Checkbutton(options, text="--remove", variable=self.hashcat_remove).grid(row=0, column=1, sticky="w", padx=(0, 10))
        ttk.Checkbutton(options, text="-O 最佳化", variable=self.hashcat_optimized).grid(row=0, column=2, sticky="w")
        ttk.Label(options, text="工作量 -w").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(options, textvariable=self.hashcat_workload, width=6).grid(row=2, column=0, sticky="w")
        ttk.Label(options, text="裝置 -d").grid(row=1, column=1, sticky="w", pady=(8, 0))
        ttk.Entry(options, textvariable=self.hashcat_device, width=12).grid(row=2, column=1, sticky="w")
        ttk.Label(options, text="狀態秒數").grid(row=1, column=2, sticky="w", pady=(8, 0))
        ttk.Entry(options, textvariable=self.hashcat_status_timer, width=8).grid(row=2, column=2, sticky="w")

        session_row = ttk.Frame(frame)
        session_row.grid(row=10, column=1, sticky="ew", pady=4)
        ttk.Label(frame, text="Session").grid(row=10, column=0, sticky="w", padx=(0, 8), pady=4)
        session_row.columnconfigure(0, weight=1)
        ttk.Entry(session_row, textvariable=self.hashcat_session).grid(row=0, column=0, sticky="ew")
        ttk.Label(frame, text="進階參數").grid(row=11, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(frame, textvariable=self.hashcat_extra).grid(row=11, column=1, sticky="ew", pady=4)

        buttons = ttk.Frame(frame)
        buttons.grid(row=12, column=1, columnspan=3, sticky="ew", pady=(10, 8))
        for idx, (label, command) in enumerate([
            ("開始 hashcat", self.start_hashcat), ("顯示已破解", self.hashcat_show),
            ("自訂執行", self.hashcat_custom), ("裝置資訊", self.hashcat_devices),
            ("基準測試", self.hashcat_benchmark), ("說明", self.hashcat_help),
        ]):
            row, column = divmod(idx, 3)
            buttons.columnconfigure(column, weight=1)
            ttk.Button(buttons, text=label, command=command).grid(row=row, column=column, sticky="ew", padx=(0 if column == 0 else 8, 0), pady=(0 if row == 0 else 8, 0))

        controls = ttk.Frame(frame)
        controls.grid(row=13, column=1, sticky="ew", pady=4)
        for idx, (label, key) in enumerate([("狀態(s)", "s"), ("暫停(p)", "p"), ("繼續(r)", "r"), ("檢查點(c)", "c"), ("離開(q)", "q")]):
            row, column = divmod(idx, 2)
            controls.columnconfigure(column, weight=1)
            ttk.Button(controls, text=label, command=lambda value=key: self.runner.send_key(value)).grid(row=row, column=column, sticky="ew", padx=(0 if column == 0 else 8, 0), pady=(0 if row == 0 else 8, 0))

        note = "進階參數會原樣加入命令，可使用 hashcat 全部選項；GUI 不顯示任何命令視窗。"
        ttk.Label(frame, text=note, foreground="#555555").grid(row=14, column=0, columnspan=3, sticky="w", pady=(8, 0))

    def _build_john_tab(self) -> None:
        self.john_hash_file = tk.StringVar()
        self.john_format = tk.StringVar()
        self.john_mode = tk.StringVar(value=JOHN_MODES[0])
        self.john_wordlist = tk.StringVar(value=str(self.config_data.default_wordlist or ""))
        self.john_mask = tk.StringVar(value=JOHN_DEFAULT_MASK)
        self.john_rules = tk.StringVar()
        self.john_session = tk.StringVar(value="gui_john")
        self.john_fork = tk.StringVar()
        self.john_extra = tk.StringVar()

        frame = self.john_tab
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, text="John the Ripper 設定", style="Header.TLabel").grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 10))
        self._row(frame, 1, "雜湊檔", self.john_hash_file, "file")
        ttk.Label(frame, text="格式 --format").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=4)
        self.john_format_combo = ttk.Combobox(frame, textvariable=self.john_format, values=[])
        self.john_format_combo.grid(row=2, column=1, sticky="ew", pady=4)
        ttk.Button(frame, text="載入格式", command=self.load_john_formats).grid(row=2, column=2, padx=(8, 0))

        ttk.Label(frame, text="模式").grid(row=3, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Combobox(frame, textvariable=self.john_mode, values=JOHN_MODES, state="readonly").grid(row=3, column=1, sticky="ew", pady=4)
        self._row(frame, 4, "字典檔", self.john_wordlist, "file")
        self._row(frame, 5, "遮罩", self.john_mask, None)
        self._row(frame, 6, "規則 --rules", self.john_rules, None)

        compact = ttk.Frame(frame)
        compact.grid(row=7, column=1, sticky="ew", pady=4)
        compact.columnconfigure(1, weight=1)
        ttk.Label(frame, text="Session / Fork").grid(row=7, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Label(compact, text="Session").grid(row=0, column=0, sticky="w")
        ttk.Entry(compact, textvariable=self.john_session).grid(row=0, column=1, sticky="ew", padx=(6, 0))
        ttk.Label(compact, text="--fork").grid(row=1, column=0, sticky="w", pady=(4, 0))
        ttk.Entry(compact, textvariable=self.john_fork, width=8).grid(row=1, column=1, sticky="w", padx=(6, 0), pady=(4, 0))

        ttk.Label(frame, text="進階參數").grid(row=8, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(frame, textvariable=self.john_extra).grid(row=8, column=1, sticky="ew", pady=4)

        buttons = ttk.Frame(frame)
        buttons.grid(row=9, column=1, columnspan=3, sticky="ew", pady=(10, 8))
        for idx, (label, command) in enumerate([
            ("開始 John", self.start_john), ("顯示已破解", self.john_show),
            ("自訂執行", self.john_custom), ("查狀態", self.john_status),
            ("恢復 Session", self.john_restore), ("測速", self.john_test),
            ("說明", self.john_help),
        ]):
            row, column = divmod(idx, 3)
            buttons.columnconfigure(column, weight=1)
            ttk.Button(buttons, text=label, command=command).grid(row=row, column=column, sticky="ew", padx=(0 if column == 0 else 8, 0), pady=(0 if row == 0 else 8, 0))

        note = "John 也可直接在進階參數使用所有官方選項，例如 --incremental、--external、--subsets。"
        ttk.Label(frame, text=note, foreground="#555555").grid(row=10, column=0, columnspan=3, sticky="w", pady=(8, 0))

    def _build_output_tab(self) -> None:
        frame = self.output_tab
        frame.rowconfigure(3, weight=1)
        frame.columnconfigure(0, weight=1)
        self.output_job_var = tk.StringVar(value="尚未開始")
        self.output_status_var = tk.StringVar(value="就緒")
        self.output_progress_var = tk.StringVar(value="0%")
        self.output_elapsed_var = tk.StringVar(value="-")
        self.output_speed_var = tk.StringVar(value="-")
        self.output_temp_var = tk.StringVar(value="-")
        self.output_recovered_var = tk.StringVar(value="-")
        self.output_length_var = tk.StringVar(value="-")
        self.output_queue_var = tk.StringVar(value="-")
        self.output_candidate_var = tk.StringVar(value="-")
        self.output_mode_var = tk.StringVar(value="-")
        self.output_file_var = tk.StringVar(value="尚未產生輸出")
        self.output_overview_var = tk.StringVar(value="模式：-｜狀態：就緒｜進度：0%｜位數：-｜佇列：-｜候選：-")
        self.result_title_var = tk.StringVar(value="尚未開始")
        self.result_hint_var = tk.StringVar(value="完成後會在這裡顯示結果。")
        self.cracked_display_var = tk.StringVar(value="尚未找到密碼")
        self.last_cracked_file: Path | None = None
        self.progress_value = tk.DoubleVar(value=0)

        header = ttk.Frame(frame, style="App.TFrame")
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="工作狀態", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(header, textvariable=self.output_job_var, style="Status.TLabel").grid(row=1, column=0, sticky="w", pady=(2, 0))
        actions = ttk.Frame(header, style="App.TFrame")
        actions.grid(row=0, column=1, rowspan=2, sticky="e")
        ttk.Button(actions, text="清空記錄", command=self.clear_output_view).pack(side="left", padx=(0, 10))
        ttk.Button(actions, text="開啟輸出資料夾", command=self.open_output_folder).pack(side="left", padx=(0, 10))
        self.details_toggle = ttk.Button(actions, command=lambda: self.set_details_visible(not self._details_visible))
        self.details_toggle.pack(side="left")

        metrics = ttk.Frame(frame, style="App.TFrame")
        metrics.grid(row=1, column=0, sticky="ew", pady=(12, 10))
        metric_items = [
            ("狀態", self.output_status_var),
            ("進度", self.output_progress_var),
            ("耗時", self.output_elapsed_var),
            ("速度", self.output_speed_var),
            ("溫度", self.output_temp_var),
            ("已破解", self.output_recovered_var),
        ]
        for idx, (title, var) in enumerate(metric_items):
            row, col = divmod(idx, 3)
            card = ttk.Frame(metrics, padding=(10, 6), style="Card.TFrame")
            card.grid(row=row, column=col, sticky="nsew", padx=(0 if col == 0 else 8, 0), pady=(0 if row == 0 else 8, 0))
            metrics.columnconfigure(col, weight=1)
            ttk.Label(card, text=title, style="MetricName.TLabel").pack(anchor="w")
            ttk.Label(card, textvariable=var, style="MetricValue.TLabel").pack(anchor="w", pady=(4, 0))

        progress_card = self._card(frame, 2, 0, pady=(0, 10))
        progress_card.columnconfigure(0, weight=1)
        ttk.Label(progress_card, text="破解概覽", style="MetricName.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(progress_card, textvariable=self.output_mode_var, style="Card.TLabel").grid(row=0, column=1, sticky="e")
        ttk.Progressbar(progress_card, variable=self.progress_value, maximum=100).grid(row=1, column=0, columnspan=2, sticky="ew", pady=(10, 8))
        ttk.Label(progress_card, textvariable=self.output_overview_var, style="Card.TLabel").grid(row=2, column=0, columnspan=2, sticky="w")
        ttk.Label(progress_card, textvariable=self.output_file_var, style="Muted.TLabel").grid(row=3, column=0, columnspan=2, sticky="w", pady=(6, 0))

        results = ttk.Frame(frame, style="App.TFrame")
        results.grid(row=3, column=0, sticky="nsew")
        results.rowconfigure(0, weight=1)
        results.columnconfigure(0, weight=1)

        cracked_card = self._card(results, 0, 0)
        cracked_card.rowconfigure(2, weight=1)
        cracked_card.columnconfigure(0, weight=1)
        ttk.Label(cracked_card, textvariable=self.result_title_var, style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(cracked_card, textvariable=self.result_hint_var, style="Muted.TLabel").grid(row=1, column=0, sticky="w", pady=(4, 8))
        cracked_actions = ttk.Frame(cracked_card, style="Card.TFrame")
        cracked_actions.grid(row=0, column=1, rowspan=2, sticky="e", pady=(0, 8))
        self.copy_result_button = ttk.Button(cracked_actions, text="複製密碼", command=self.copy_cracked_passwords)
        self.copy_result_button.pack(side="left", padx=(0, 8))
        self.open_result_button = ttk.Button(cracked_actions, text="開啟結果檔", command=self.open_cracked_file)
        self.open_result_button.pack(side="left", padx=(0, 8))
        self.adjust_strategy_button = ttk.Button(cracked_actions, text="調整策略", command=lambda: self.start_new_job(False))
        self.adjust_strategy_button.pack(side="left", padx=(0, 8))
        self.new_job_button = ttk.Button(cracked_actions, text="開始新工作", command=lambda: self.start_new_job(True))
        self.new_job_button.pack(side="left")
        self.cracked_text = scrolledtext.ScrolledText(
            cracked_card,
            wrap="word",
            width=1,
            height=4,
            font=(self.mono_font, 11),
            background="#F8FAFC",
            foreground=TEXT,
            insertbackground=TEXT,
            relief="flat",
            borderwidth=0,
            padx=12,
            pady=10,
        )
        self.cracked_text.grid(row=2, column=0, columnspan=2, sticky="nsew")
        self.cracked_text.insert("1.0", self.cracked_display_var.get())
        self.cracked_text.configure(state="disabled")

        details = self._card(frame, 4, 0, pady=(10, 0))
        self.details_panel = details
        details.rowconfigure(1, weight=1)
        details.columnconfigure(0, weight=1)
        ttk.Label(details, text="詳細記錄", style="MetricName.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8))
        self.output = scrolledtext.ScrolledText(
            details,
            wrap="word",
            width=1,
            height=7,
            font=(self.mono_font, 10),
            background="#FFFFFF",
            foreground=TEXT,
            insertbackground=TEXT,
            relief="solid",
            borderwidth=1,
            padx=12,
            pady=10,
        )
        self.output.grid(row=1, column=0, sticky="nsew")
        self.set_details_visible(False)

    def set_details_visible(self, visible: bool) -> None:
        self._details_visible = visible
        if visible:
            self.details_panel.grid()
        else:
            self.details_panel.grid_remove()
        self.details_toggle.configure(text="收起詳細記錄" if visible else "顯示詳細記錄")

    def show_job_view(self) -> None:
        launcher = self.__dict__.get("launcher")
        output_tab = self.__dict__.get("output_tab")
        if hasattr(launcher, "grid_remove"):
            launcher.grid_remove()
        if hasattr(output_tab, "grid"):
            output_tab.grid()
        if self.__dict__.get("_advanced_visible"):
            self.set_advanced_visible(False)

    def show_launcher(self) -> None:
        launcher = self.__dict__.get("launcher")
        output_tab = self.__dict__.get("output_tab")
        if hasattr(output_tab, "grid_remove"):
            output_tab.grid_remove()
        if hasattr(launcher, "grid"):
            launcher.grid()
        if self.__dict__.get("_advanced_visible"):
            self.set_advanced_visible(False)
        if "quick_input" in self.__dict__:
            self._refresh_task_summary()

    def start_new_job(self, clear_target: bool) -> None:
        if self.job_controller.state in {
            JobState.SUCCEEDED, JobState.EXHAUSTED, JobState.FAILED, JobState.CANCELLED
        }:
            self.job_controller.reset()
        if clear_target:
            self.quick_input.set("")
        self.show_launcher()

    def _build_settings_tab(self) -> None:
        frame = self.settings_tab
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, text="工具路徑", style="Header.TLabel").grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))
        rows = [
            ("hashcat_path", "hashcat.exe"),
            ("john_path", "john.exe"),
            ("john_run_dir", "John run 目錄"),
            ("python_path", "python.exe"),
            ("perl_path", "perl.exe"),
            ("node_path", "node.exe"),
            ("output_dir", "輸出目錄"),
        ]
        for idx, (key, label) in enumerate(rows, start=1):
            var = tk.StringVar(value=str(getattr(self.config_data, key) or ""))
            self.setting_vars[key] = var
            browse = "dir" if key in {"john_run_dir", "output_dir"} else "file"
            self._row(frame, idx, label, var, browse)
        buttons = ttk.Frame(frame)
        buttons.grid(row=len(rows) + 1, column=1, sticky="ew", pady=(12, 8))
        for idx, (label, command) in enumerate([
            ("儲存設定", self.save_settings), ("自動偵測", self.detect_settings),
            ("健康檢查", self.health_check), ("開啟輸出資料夾", self.open_output_folder),
            ("開啟設定檔", self.open_config_file), ("匯入設定檔", self.import_config_file),
        ]):
            row, column = divmod(idx, 2)
            buttons.columnconfigure(column, weight=1)
            ttk.Button(buttons, text=label, command=command).grid(row=row, column=column, sticky="ew", padx=(0 if column == 0 else 8, 0), pady=(0 if row == 0 else 8, 0))
        ttk.Label(frame, text=f"目前設定檔：{CONFIG_PATH}", foreground="#555555").grid(row=len(rows) + 2, column=0, columnspan=3, sticky="w", pady=(8, 0))
        tip = "Perl 未安裝時，7z2john.pl、pdf2john.pl 等 .pl 轉換器會無法使用；安裝後在此指定路徑即可。"
        ttk.Label(frame, text=tip, foreground="#555555").grid(row=len(rows) + 3, column=0, columnspan=3, sticky="w", pady=(8, 0))

    def _build_help_tab(self) -> None:
        frame = self.help_tab
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        text = scrolledtext.ScrolledText(frame, wrap="word", font=(self.ui_font, 11))
        text.grid(row=0, column=0, sticky="nsew")
        text.insert(
            "1.0",
            (
                "使用流程\n"
                "1. 在「開始新工作」選擇 ZIP/RAR/7Z/Office/PDF 或雜湊檔。\n"
                "2. 工具會自動偵測環境、必要時下載 hashcat / John，並自動開始。\n"
                "3. 密碼、雜湊與記錄會集中在設定的輸出資料夾。\n\n"
                "完整功能\n"
                "Hashcat 與 John 的 GUI 欄位只放常用項目；任何未列出的官方選項請填在「進階參數」。\n"
                "例如 hashcat 可填 --increment --hwmon-temp-abort=90；John 可填 --external、--subsets、--loopback。\n\n"
                "中文壓縮包\n"
                "雜湊轉換預設會把來源複製到 ASCII 暫存檔名，再呼叫轉換器，避免舊工具不支援中文路徑。\n\n"
                "7Z / PDF\n"
                "7z2john.pl、pdf2john.pl 需要 Perl。若系統尚未安裝，請在設定頁指定 perl.exe 後使用。"
            ),
        )
        text.configure(state="disabled")

    def _rule_files(self) -> list[str]:
        hashcat_path = self.config_data.hashcat_path
        rule_dir = hashcat_path.parent / "rules" if hashcat_path else TOOLS_DIR / "hashcat" / "rules"
        if not rule_dir.exists():
            return []
        return [str(path) for path in sorted(rule_dir.rglob("*.rule"))]

    def refresh_converters(self) -> None:
        run_dir = self.config_data.john_run_dir or Path()
        names = [name for name in converter_names() if (run_dir / name).is_file()]
        self.converter_names = names
        values = ["自動偵測"] + names
        if hasattr(self, "converter_combo"):
            self.converter_combo.configure(values=values)
            if self.extract_converter.get() not in values:
                self.extract_converter.set("自動偵測")

    def enqueue_log(self, text: str) -> None:
        self._enqueue_bounded(self.log_queue, text)

    def enqueue_status(self, text: str) -> None:
        self._enqueue_bounded(self.status_queue, text)

    @staticmethod
    def _enqueue_bounded(target: queue.Queue, item) -> None:
        try:
            target.put_nowait(item)
        except queue.Full:
            try:
                target.get_nowait()
            except queue.Empty:
                pass
            try:
                target.put_nowait(item)
            except queue.Full:
                pass

    def enqueue_ui(self, callback) -> None:
        self.ui_queue.put(callback)

    def _drain_queues(self) -> None:
        try:
            for _ in range(UI_QUEUE_ITEMS_PER_TICK):
                self.log(self.log_queue.get_nowait())
        except queue.Empty:
            pass
        try:
            for _ in range(UI_QUEUE_ITEMS_PER_TICK):
                self.set_status(self.status_queue.get_nowait())
        except queue.Empty:
            pass
        try:
            for _ in range(UI_QUEUE_ITEMS_PER_TICK):
                self.ui_queue.get_nowait()()
        except queue.Empty:
            pass
        self.update_elapsed()
        self.after(80, self._drain_queues)

    def log(self, text: str) -> None:
        self.update_output_dashboard(text)
        self.output.insert("end", text)
        lines = int(self.output.index("end-1c").split(".", 1)[0])
        if lines > UI_LOG_MAX_LINES:
            self.output.delete("1.0", f"{lines - UI_LOG_MAX_LINES + 1}.0")
        self.output.see("end")

    def set_status(self, text: str) -> None:
        controller = self.__dict__.get("job_controller")
        if controller and controller.state not in {
            JobState.IDLE, JobState.SUCCEEDED, JobState.EXHAUSTED, JobState.FAILED, JobState.CANCELLED
        }:
            return
        self.status_var.set(text)
        self.refresh_output_overview()

    def _on_job_snapshot(self, snapshot: JobSnapshot) -> None:
        if threading.current_thread() is threading.main_thread():
            self.render_job(snapshot)
        else:
            self.enqueue_ui(lambda snapshot=snapshot: self.render_job(snapshot))

    def render_job(self, snapshot: JobSnapshot) -> None:
        labels = {
            JobState.IDLE: "就緒",
            JobState.PREPARING: "準備中",
            JobState.CHECKING_ENV: "檢查工具環境",
            JobState.CONVERTING: "轉換雜湊",
            JobState.BUILDING_CANDIDATES: "建立候選",
            JobState.RUNNING: "執行中",
            JobState.STOPPING: "正在停止…",
            JobState.SUCCEEDED: "已找到密碼",
            JobState.EXHAUSTED: "未找到密碼",
            JobState.FAILED: "失敗",
            JobState.CANCELLED: "已取消",
        }
        messages = {
            JobState.IDLE: "尚未開始。",
            JobState.PREPARING: "正在準備工作。",
            JobState.CHECKING_ENV: "正在檢查工具環境。",
            JobState.CONVERTING: "正在轉換雜湊。",
            JobState.BUILDING_CANDIDATES: "正在建立候選與攻擊計畫。",
            JobState.RUNNING: "破解工作執行中。",
            JobState.STOPPING: "正在停止工作，請稍候。",
            JobState.SUCCEEDED: "已找到密碼，工作完成。",
            JobState.EXHAUSTED: "所有策略已完成，尚未找到密碼。",
            JobState.FAILED: snapshot.error or "工作失敗，請查看詳細記錄。",
            JobState.CANCELLED: "工作已取消。",
        }
        label = labels[snapshot.state]
        current_stage = snapshot.current_stage
        active = snapshot.state in {
            JobState.PREPARING,
            JobState.CHECKING_ENV,
            JobState.CONVERTING,
            JobState.BUILDING_CANDIDATES,
            JobState.RUNNING,
            JobState.STOPPING,
        }
        if "main_workspace" in self.__dict__ and not self._advanced_visible:
            if snapshot.state == JobState.IDLE:
                self.show_launcher()
            else:
                self.show_job_view()
        if "quick_status" in self.__dict__:
            self.quick_status.set(messages[snapshot.state])
        if "status_var" in self.__dict__:
            self.status_var.set(label)
        if "output_status_var" in self.__dict__:
            self.output_status_var.set(label)
            self.output_job_var.set(
                f"{snapshot.current_stage_index + 1} / {snapshot.total_stages}  {current_stage.display_name}"
                if current_stage
                else Path(snapshot.source_file).name if snapshot.source_file else "尚未開始"
            )
            progress = snapshot.progress
            self.output_progress_var.set(
                f"{progress:.2f}%" if isinstance(progress, (int, float)) else str(progress or "0%")
            )
            self.progress_value.set(float(progress) if isinstance(progress, (int, float)) else 0)
            self.output_elapsed_var.set(format_elapsed(snapshot.elapsed_time))
            self.output_speed_var.set(snapshot.speed or "-")
            self.output_temp_var.set(snapshot.temperature or "-")
            self.output_recovered_var.set(
                snapshot.recovered_count
                or (f"{len(snapshot.recovered_passwords)} 筆" if snapshot.recovered_passwords else "-")
            )
            self.output_candidate_var.set(
                snapshot.current_candidate or snapshot.candidate_count or "-"
            )
            self.output_length_var.set(snapshot.password_length or "-")
            self.output_queue_var.set(snapshot.queue or "-")
            self.output_mode_var.set(snapshot.mode or snapshot.selected_engine or "-")
            paths = dict(snapshot.output_paths)
            self.output_file_var.set(str(paths.get("cracked", "尚未產生輸出")))
            self.refresh_output_overview()
            if snapshot.state == JobState.PREPARING:
                self.last_cracked_file = None
                self.set_cracked_passwords([])
            elif snapshot.state == JobState.SUCCEEDED:
                cracked = Path(paths["cracked"]) if "cracked" in paths else None
                self.set_cracked_passwords(list(snapshot.recovered_passwords), cracked)
            elif snapshot.state == JobState.EXHAUSTED:
                cracked = Path(paths["cracked"]) if "cracked" in paths else None
                self.set_cracked_passwords([], cracked)
            result_text = {
                JobState.SUCCEEDED: ("已找到密碼", "密碼已寫入結果檔，可直接複製或開啟資料夾。"),
                JobState.EXHAUSTED: ("未找到密碼", "所有策略已完成；可調整策略後重新分析。"),
                JobState.FAILED: ("工作失敗", snapshot.error or "請展開詳細記錄查看技術資訊。"),
                JobState.CANCELLED: ("工作已取消", "可調整設定或開始新工作。"),
            }.get(snapshot.state, ("工作執行中", messages[snapshot.state]))
            self.result_title_var.set(result_text[0])
            self.result_hint_var.set(result_text[1])
            terminal = snapshot.state in {
                JobState.SUCCEEDED, JobState.EXHAUSTED, JobState.FAILED, JobState.CANCELLED
            }
            if snapshot.state == JobState.SUCCEEDED:
                self.copy_result_button.pack(side="left", padx=(0, 8))
                self.open_result_button.pack(side="left", padx=(0, 8))
            else:
                self.copy_result_button.pack_forget()
                self.open_result_button.pack_forget()
            if terminal:
                self.new_job_button.pack(side="left")
            else:
                self.new_job_button.pack_forget()
            if snapshot.state in {JobState.EXHAUSTED, JobState.FAILED, JobState.CANCELLED}:
                self.adjust_strategy_button.pack(side="left", padx=(0, 8))
            else:
                self.adjust_strategy_button.pack_forget()
        if "quick_start_button" in self.__dict__:
            if active:
                self.quick_start_button.state(["disabled"])
            elif "quick_input" in self.__dict__:
                self._refresh_task_summary(update_status=snapshot.state == JobState.IDLE)
            else:
                self.quick_start_button.state(["!disabled"])
        if "stop_button" in self.__dict__:
            self.stop_button.configure(text="正在停止…" if snapshot.state == JobState.STOPPING else "停止")
            self.stop_button.state(["!disabled"] if active and snapshot.state != JobState.STOPPING else ["disabled"])
            if active:
                if not self.stop_button.winfo_manager():
                    self.stop_button.pack(side="left")
            else:
                self.stop_button.pack_forget()

    def clear_output_view(self) -> None:
        self.output_snapshot = DashboardSnapshot()
        self.output.delete("1.0", "end")
        self.status_var.set("就緒")
        self.output_job_var.set("尚未開始")
        self.output_status_var.set("就緒")
        self.output_progress_var.set("0%")
        self.output_elapsed_var.set("-")
        self.output_speed_var.set("-")
        self.output_temp_var.set("-")
        self.output_recovered_var.set("-")
        self.output_length_var.set("-")
        self.output_queue_var.set("-")
        self.output_candidate_var.set("-")
        self.output_mode_var.set("-")
        self.output_file_var.set("尚未產生輸出")
        self.output_overview_var.set("模式：-｜狀態：就緒｜進度：0%｜位數：-｜佇列：-｜候選：-")
        self.progress_value.set(0)
        self.last_cracked_file = None
        self.set_cracked_passwords([])

    def set_cracked_passwords(self, passwords: list[str], cracked_file: Path | None = None) -> None:
        if cracked_file:
            self.last_cracked_file = cracked_file
        display = "\n".join(dict.fromkeys([item for item in passwords if item.strip()]))
        if not display:
            display = "尚未找到密碼"
            if hasattr(self, "output_recovered_var"):
                self.output_recovered_var.set("-")
        elif hasattr(self, "output_recovered_var"):
            self.output_recovered_var.set(f"{len(display.splitlines())} 筆")
        if not hasattr(self, "cracked_text"):
            return
        self.cracked_text.configure(state="normal")
        self.cracked_text.delete("1.0", "end")
        self.cracked_text.insert("1.0", display)
        self.cracked_text.configure(state="disabled")
        self.refresh_output_overview()

    def copy_cracked_passwords(self) -> None:
        if not hasattr(self, "cracked_text"):
            return
        text = self.cracked_text.get("1.0", "end").strip()
        if not text or text == "尚未找到密碼":
            messagebox.showinfo("沒有密碼", "目前沒有可複製的破解密碼。")
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.set_status("已複製破解密碼")

    def open_cracked_file(self) -> None:
        if self.last_cracked_file and self.last_cracked_file.exists():
            os.startfile(str(self.last_cracked_file))
            return
        messagebox.showinfo("沒有結果檔", "目前沒有可開啟的破解結果檔。")

    def refresh_output_overview(self) -> None:
        if not hasattr(self, "output_overview_var"):
            return
        self.output_overview_var.set(
            "｜".join(
                [
                    f"模式：{self.output_mode_var.get()}",
                    f"狀態：{self.output_status_var.get()}",
                    f"進度：{self.output_progress_var.get()}",
                    f"耗時：{self.output_elapsed_var.get()}",
                    f"位數：{self.output_length_var.get()}",
                    f"佇列：{self.output_queue_var.get()}",
                    f"候選：{self.output_candidate_var.get()}",
                ]
            )
        )

    def update_elapsed(self) -> None:
        controller = self.__dict__.get("job_controller")
        if controller and controller.state not in {
            JobState.IDLE, JobState.SUCCEEDED, JobState.EXHAUSTED, JobState.FAILED, JobState.CANCELLED
        }:
            self.render_job(controller.snapshot)
        elif hasattr(self, "output_elapsed_var"):
            self.output_elapsed_var.set(format_elapsed(self.runner.elapsed_seconds()))

    def update_output_dashboard(self, text: str) -> None:
        if not hasattr(self, "output_status_var"):
            return
        controller = self.__dict__.get("job_controller")
        job_active = controller is not None and controller.state not in {
            JobState.IDLE, JobState.SUCCEEDED, JobState.EXHAUSTED, JobState.FAILED, JobState.CANCELLED
        }
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if "啟動 " in line and not job_active:
                self.output_job_var.set(line.strip("[]"))
            events = self.output_parser.feed(line)
            for event in events:
                self.output_snapshot = apply_event(self.output_snapshot, event)
            if events:
                if job_active:
                    progress: float | str = (
                        self.output_snapshot.progress_percent
                        if self.output_snapshot.progress_percent
                        else self.output_snapshot.progress
                    )
                    updates: dict[str, object] = dict(
                        progress=progress,
                        speed=self.output_snapshot.speed,
                        temperature=self.output_snapshot.temperature,
                        current_candidate=self.output_snapshot.candidate,
                        recovered_count=self.output_snapshot.recovered,
                    )
                    if self.output_snapshot.mode != "-":
                        updates["mode"] = self.output_snapshot.mode
                    if self.output_snapshot.password_length != "-":
                        updates["password_length"] = self.output_snapshot.password_length
                    if self.output_snapshot.queue != "-":
                        updates["queue"] = self.output_snapshot.queue
                    controller.update(**updates)
                else:
                    self.render_output_snapshot(self.output_snapshot)
        if not job_active:
            self.refresh_output_overview()

    def render_output_snapshot(self, snapshot: DashboardSnapshot) -> None:
        self.output_status_var.set(snapshot.status)
        self.output_progress_var.set(snapshot.progress)
        self.progress_value.set(snapshot.progress_percent)
        self.output_speed_var.set(snapshot.speed)
        self.output_temp_var.set(snapshot.temperature)
        self.output_candidate_var.set(snapshot.candidate)
        self.output_recovered_var.set(snapshot.recovered)
        self.output_mode_var.set(snapshot.mode)
        self.output_length_var.set(snapshot.password_length)
        self.output_queue_var.set(snapshot.queue)
        self.output_file_var.set(snapshot.output_file)

    def short_metric(self, value: str, limit: int) -> str:
        return value if len(value) <= limit else value[: max(0, limit - 1)] + "…"

    def ensure_tools_on_startup(self) -> None:
        if getattr(self, "_startup_tools_checked", False):
            return
        self._startup_tools_checked = True
        self.ensure_tools_async(force_download=False)

    def ensure_tools_async(self, force_download: bool = False) -> None:
        if not self._tools_setup_lock.acquire(blocking=False):
            self.enqueue_status("工具環境檢查已在執行")
            return
        try:
            auto_var = getattr(self, "quick_auto_download", None)
            auto_download = force_download or (bool(auto_var.get()) if auto_var is not None else True)
            thread = threading.Thread(target=self._ensure_tools_worker, args=(auto_download, True), daemon=True)
            thread.start()
        except Exception:
            self._tools_setup_lock.release()
            raise

    def _ensure_tools_worker(self, auto_download: bool = True, lock_acquired: bool = False) -> None:
        if not lock_acquired:
            self._tools_setup_lock.acquire()
        try:
            self.enqueue_status("檢查工具環境中")
            ensure_tool_dirs()
            self.config_data.update_tool_paths(find_tool_paths(self.config_data.tool_paths(), TOOLS_DIR))
            if not self.config_data.hashcat_path and auto_download:
                self.enqueue_log("\n找不到 hashcat，開始自動下載。\n")
                self.config_data.hashcat_path = Path(self.download_hashcat())
            if not self.config_data.john_path and auto_download:
                self.enqueue_log("\n找不到 John the Ripper，開始自動下載。\n")
                john_path, john_run = self.download_john()
                self.config_data.john_path = Path(john_path)
                self.config_data.john_run_dir = Path(john_run)
            if not self.config_data.hashcat_path and not self.config_data.john_path:
                raise SetupError("找不到可用的 hashcat 或 John。", HASHCAT_DOWNLOAD_PAGE)
            self.enqueue_ui(self.apply_detected_tools_to_ui)
            self.enqueue_status("工具環境已就緒")
        except SetupError as exc:
            message = str(exc)
            if exc.url:
                message += f"\n下載網址：{exc.url}"
            self.enqueue_log(f"\n[環境錯誤] {message}\n")
            self.enqueue_status("工具環境需要手動處理")
        except Exception as exc:
            self.enqueue_log(f"\n[環境錯誤] {exc}\n")
            self.enqueue_status("工具環境檢查失敗")
        finally:
            self._tools_setup_lock.release()

    def apply_detected_tools_to_ui(self) -> None:
        self._save_config()
        self.refresh_converters()
        self.sync_config_to_ui(sync_task_inputs=False)
        controller = self.__dict__.get("job_controller")
        if controller and controller.state not in {
            JobState.IDLE, JobState.SUCCEEDED, JobState.EXHAUSTED, JobState.FAILED, JobState.CANCELLED
        }:
            self.render_job(controller.snapshot)
        elif self.config_load_error:
            self.quick_status.set("工具環境已就緒；設定載入失敗，目前使用預設設定。")
        else:
            self._refresh_task_summary()

    def download_hashcat(self) -> str:
        url = HASHCAT_ARCHIVE_URL
        archive_name = Path(urllib.parse.urlparse(url).path).name or "hashcat.7z"
        archive = DOWNLOADS_DIR / archive_name
        self.enqueue_log(f"下載：{url}\n")
        download_file(url, archive, self.enqueue_log, HASHCAT_ARCHIVE_SHA256, OFFICIAL_DOWNLOAD_HOSTS)
        with tempfile.TemporaryDirectory(prefix="hashcat_install_", dir=TOOL_TMP_DIR) as temp:
            staged = Path(temp) / "payload"
            extract_archive(archive, staged, self.enqueue_log)
            path = find_hashcat_under(staged)
            if not path:
                raise SetupError("hashcat 已下載但找不到 hashcat.exe。", HASHCAT_DOWNLOAD_PAGE)
            relative_path = Path(path).relative_to(staged)
            target = TOOLS_DIR / "hashcat"
            replace_tool_directory(staged, target)
        return str(target / relative_path)

    def download_john(self) -> tuple[str, str]:
        url = JOHN_ARCHIVE_URL
        archive_name = Path(urllib.parse.urlparse(url).path).name or "john.7z"
        archive = DOWNLOADS_DIR / archive_name
        self.enqueue_log(f"下載：{url}\n")
        download_file(url, archive, self.enqueue_log, JOHN_ARCHIVE_SHA256, OFFICIAL_DOWNLOAD_HOSTS)
        with tempfile.TemporaryDirectory(prefix="john_install_", dir=TOOL_TMP_DIR) as temp:
            staged = Path(temp) / "payload"
            extract_archive(archive, staged, self.enqueue_log)
            john_path, john_run = find_john_under(staged)
            if not john_path:
                raise SetupError("John 已下載但找不到 john.exe。", JOHN_RELEASE_PAGE)
            john_relative = Path(john_path).relative_to(staged)
            run_relative = Path(john_run).relative_to(staged)
            target = TOOLS_DIR / "JohnRipper"
            replace_tool_directory(staged, target)
        return str(target / john_relative), str(target / run_relative)

    def download_selected_wordlist(self) -> None:
        selected = self.common_wordlist.get()
        item = next((entry for entry in COMMON_WORDLISTS if entry[0] == selected), None)
        if not item:
            messagebox.showerror("字典錯誤", "請選擇要下載的字典。")
            return
        if not self._wordlist_download_lock.acquire(blocking=False):
            self.quick_status.set("常見字典下載中，請稍候。")
            return
        self.common_wordlist_download_button.state(["disabled"])
        self.quick_status.set(f"正在下載字典：{item[0]}")
        try:
            threading.Thread(target=self._download_wordlist_worker, args=(item,), daemon=True).start()
        except Exception:
            self.common_wordlist_download_button.state(["!disabled"])
            self._wordlist_download_lock.release()
            raise

    def _download_wordlist_worker(self, item: tuple[str, str, str]) -> None:
        name, filename, url = item
        try:
            ensure_tool_dirs()
            dest = WORDLISTS_DIR / filename
            self.enqueue_status(f"下載字典：{name}")
            self.enqueue_log(f"\n下載字典：{name}\n{url}\n")
            if not dest.exists():
                download_file(url, dest, self.enqueue_log)
            self.enqueue_ui(lambda: self.mark_downloaded_wordlist_available(dest, name))
            self.enqueue_status("字典已下載")
        except Exception as exc:
            self.enqueue_log(f"\n[字典下載錯誤] {exc}\n")
            self.enqueue_status("字典下載失敗")
            self.enqueue_ui(lambda: self.quick_status.set("字典下載失敗，請查看詳細記錄。"))
        finally:
            self.enqueue_ui(self._finish_wordlist_download)

    def _finish_wordlist_download(self) -> None:
        self.common_wordlist_download_button.state(["!disabled"])
        self._wordlist_download_lock.release()

    def mark_downloaded_wordlist_available(self, path: Path, name: str) -> None:
        self.quick_status.set(f"已下載字典：{name}；按「使用所選常見字典」才會套用。")

    def use_selected_common_wordlist(self) -> None:
        selected = self.common_wordlist.get()
        item = next((item for item in COMMON_WORDLISTS if item[0] == selected), None)
        if not item:
            messagebox.showerror("字典錯誤", "請選擇要使用的字典。")
            return
        path = WORDLISTS_DIR / item[1]
        if not path.is_file():
            messagebox.showerror("字典錯誤", "請先下載所選字典。")
            return
        self.quick_wordlist.set(str(path))
        self.hashcat_wordlist.set(str(path))
        self.john_wordlist.set(str(path))
        self.quick_status.set(f"本次工作使用字典：{item[0]}")

    def sync_config_to_ui(self, sync_task_inputs: bool = True) -> None:
        for key in ("hashcat_path", "john_path", "john_run_dir", "python_path", "perl_path", "node_path", "output_dir"):
            if key in self.setting_vars:
                self.setting_vars[key].set(str(getattr(self.config_data, key) or ""))
        if sync_task_inputs and hasattr(self, "quick_wordlist"):
            self.quick_wordlist.set(str(self.config_data.default_wordlist or ""))
            self.quick_combo_wordlist.set(str(self.config_data.combo_wordlist or ""))
            self.quick_combo_key.set(self.config_data.combo_key)
            self.candidate_source.set(DEFAULT_CANDIDATE_SOURCES[self.config_data.attack_strategy])
            label = next(
                label for label, strategy in ATTACK_STRATEGY_OPTIONS.items()
                if strategy == self.config_data.attack_strategy
            )
            self.quick_strategy.set(label)
        if hasattr(self, "hashcat_wordlist"):
            self.hashcat_wordlist.set(str(self.config_data.default_wordlist or ""))
        if hasattr(self, "john_wordlist"):
            self.john_wordlist.set(str(self.config_data.default_wordlist or ""))

    def _save_config(self, explicit: bool = False) -> bool:
        if self.config_load_error and not explicit:
            return False
        save_config(self.config_data)
        if explicit:
            self.config_load_error = ""
        return True

    def _show_config_load_error(self) -> None:
        summary = "設定載入失敗，目前使用預設設定；原設定檔未修改。"
        self.quick_status.set(summary)
        self.set_status("設定載入失敗，使用預設設定")
        messagebox.showwarning(
            "設定載入失敗",
            f"{summary}\n\n原因：{self.config_load_error}\n\n只有按下「儲存設定」後才會覆寫設定檔。",
        )

    def _show_config_migration(self) -> None:
        summary = f"舊設定已從 {self.config_load_source} 遷移至 {CONFIG_PATH}。"
        self.quick_status.set(summary)
        self.set_status("舊設定遷移完成")
        messagebox.showinfo("設定遷移完成", summary)

    def open_output_folder(self) -> None:
        out_dir = self.config_data.output_dir
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.startfile(str(out_dir))
        except Exception as exc:
            messagebox.showerror("無法開啟資料夾", str(exc))

    def open_config_file(self) -> None:
        try:
            if not CONFIG_PATH.exists():
                self._save_config()
            os.startfile(str(CONFIG_PATH))
        except Exception as exc:
            messagebox.showerror("無法開啟設定檔", str(exc))

    def import_config_file(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("JSON 設定檔", "*.json"), ("所有檔案", "*.*")])
        if not path:
            return
        try:
            data = read_config_file(Path(path))
            self.config_data = AppConfig.from_mapping(data, default_config())
            self._save_config(explicit=True)
            self.sync_config_to_ui()
            self.refresh_converters()
            self.set_status("設定檔已匯入")
            messagebox.showinfo("已匯入", f"設定檔已匯入：{path}")
        except Exception as exc:
            messagebox.showerror("匯入失敗", str(exc))

    def suggest_extract_output(self) -> None:
        src = Path(self.extract_input.get().strip())
        configured_dir = self.config_data.output_dir
        out_dir = result_dir_for_source(src, configured_dir) if src.name else configured_dir
        out_dir.mkdir(parents=True, exist_ok=True)
        stem = src.stem if src.name else "hash"
        suffix = "_hashcat.hash" if self.extract_target.get() == "hashcat" else ".hash"
        self.extract_output.set(str(out_dir / f"{stem}{suffix}"))

    def fill_hash_targets(self) -> None:
        path = self.extract_output.get().strip()
        if not path:
            self.suggest_extract_output()
            path = self.extract_output.get().strip()
        self.hashcat_hash_file.set(path)
        self.john_hash_file.set(path)

    def auto_start_selected(self) -> None:
        src = Path(self.quick_input.get().strip())
        if not src.exists():
            messagebox.showerror("檔案不存在", "請先選擇要破解的檔案。")
            return
        if self.runner.running() or (self.extract_thread and self.extract_thread.is_alive()):
            messagebox.showwarning("已有工作執行中", "請先停止或等待目前工作完成。")
            return
        try:
            if self.job_controller.state in {
                JobState.SUCCEEDED, JobState.EXHAUSTED, JobState.FAILED, JobState.CANCELLED
            }:
                self.job_controller.reset()
            wordlist = self.quick_wordlist.get().strip()
            converter = self.converter_for_input(src)
            self.config_data.default_wordlist = Path(wordlist) if wordlist else None
            self.config_data.combo_wordlist = Path(value) if (value := self.quick_combo_wordlist.get().strip()) else None
            self.config_data.combo_key = self.quick_combo_key.get().strip()
            self.config_data.attack_strategy = ATTACK_STRATEGY_OPTIONS[self.quick_strategy.get()]
            settings = {
                "auto_download": bool(self.quick_auto_download.get()),
                "converter": converter,
                "safe_copy": bool(self.extract_safe_copy.get()),
                "expand_wordlist": bool(self.quick_expand_wordlist.get()),
                "hashcat_mask": self.hashcat_mask.get().strip(),
                "john_mask": self.john_mask.get().strip(),
            }
            paths = self._auto_output_paths(src)
            self.job_controller.start(
                JobContext(
                    source_file=src,
                    detected_type=src.suffix.lower() or "raw-hash",
                    converter=converter or None,
                    output_paths=paths,
                    cancellation_token=self.conversion_cancel,
                )
            )
        except JobAlreadyRunningError:
            messagebox.showwarning("已有工作執行中", "請先停止或等待目前工作完成。")
            return
        except Exception as exc:
            messagebox.showerror("無法開始工作", str(exc))
            return
        self.sync_config_to_ui()
        self._save_config()
        self.show_job_view()
        self.auto_thread = threading.Thread(
            target=self._auto_workflow, args=(src, wordlist, settings), daemon=True
        )
        self.auto_thread.start()

    def _auto_output_paths(self, src: Path) -> dict[str, Path]:
        output_dir = self.config_data.output_dir
        out_dir = result_dir_for_source(src, output_dir)
        base = out_dir / safe_stem(src.stem)
        return {
            "john_hash": base.with_name(base.name + ".hash"),
            "hashcat_hash": base.with_name(base.name + "_hashcat.hash"),
            "cracked": base.with_name(base.name + "_cracked.txt"),
            "session": base.with_name(base.name + "_session.log"),
            "mask": base.with_name(base.name + "_auto.hcmask"),
            "expanded_wordlist": base.with_name(base.name + "_expanded_wordlist.txt"),
            "library_wordlist": base.with_name(base.name + "_library_wordlists.txt"),
            "combo_seed": base.with_name(base.name + "_combo_seed.txt"),
            "combo_key_wordlist": base.with_name(base.name + "_combo_key_wordlist.txt"),
            "combo_wordlist": base.with_name(base.name + "_combo_wordlist.txt"),
        }

    def collect_dictionary_sources(self, manual_wordlist: str) -> list[Path]:
        sources: list[Path] = []
        seen: set[str] = set()

        def add(path_text: str) -> None:
            if not path_text:
                return
            path = Path(path_text)
            if not path.is_file():
                return
            key = str(path.resolve())
            if key not in seen:
                seen.add(key)
                sources.append(path)

        add(manual_wordlist)
        return sources

    def prepare_library_wordlist(
        self, sources: list[Path], dest: Path, optional_sources: set[Path] | None = None
    ) -> str:
        if not sources:
            return ""
        result = merge_wordlist_files(sources, dest, optional_sources=optional_sources)
        for failure in result.failed_sources:
            level = "必要" if failure.required else "選用"
            self.enqueue_log(f"[字典來源錯誤／{level}] {failure.source}：{failure.error}\n")
        required_failures = [failure for failure in result.failed_sources if failure.required]
        if required_failures:
            raise RuntimeError(f"無法讀取指定字典：{required_failures[0].source}（{required_failures[0].error}）")
        if result.written_count <= 0:
            return ""
        self.enqueue_log("\n[階段 1] 字典庫破解\n")
        self.enqueue_log("實際載入來源：\n" + "\n".join(f"- {path}" for path in result.loaded_sources) + "\n")
        limit_status = "（已達上限）" if result.truncated_by_limit else ""
        self.enqueue_log(f"合併字典：{dest}\n候選數：{result.written_count:,} 筆{limit_status}\n")
        return str(dest)

    def prepare_combo_wordlist(self, combo_file: str, combo_key: str, paths: dict[str, Path]) -> str:
        sources: list[Path] = []
        if combo_file:
            path = Path(combo_file)
            if path.is_file():
                sources.append(path)
            else:
                raise FileNotFoundError(f"組合密碼檔不存在：{combo_file}")
        if combo_key.strip():
            paths["combo_seed"].write_text(combo_key.strip() + "\n", encoding="utf-8", newline="\n")
            count = build_expanded_wordlist(
                paths["combo_seed"], paths["combo_key_wordlist"], cancel=self.conversion_cancel
            )
            if count > 0:
                sources.append(paths["combo_key_wordlist"])
                self.enqueue_log(f"\n[階段 2] 已由 Key 生成組合候選：{count:,} 筆\n")
        if not sources:
            return ""
        result = merge_wordlist_files(sources, paths["combo_wordlist"])
        if result.failed_sources:
            failure = result.failed_sources[0]
            self.enqueue_log(f"[字典來源錯誤／必要] {failure.source}：{failure.error}\n")
            raise RuntimeError(f"無法讀取指定字典：{failure.source}（{failure.error}）")
        if result.written_count <= 0:
            return ""
        self.enqueue_log(
            f"\n[階段 2] 組合候選已合併：{paths['combo_wordlist']}\n候選數：{result.written_count:,} 筆\n"
        )
        return str(paths["combo_wordlist"])

    def prepare_auto_wordlist(self, wordlist: str, expanded_path: Path, should_expand: bool) -> str:
        if not wordlist:
            return ""
        source = Path(wordlist)
        if not source.exists():
            raise FileNotFoundError(f"字典檔不存在：{wordlist}")
        if not should_expand:
            return str(source)
        count = build_expanded_wordlist(source, expanded_path, cancel=self.conversion_cancel)
        if count <= 0:
            raise RuntimeError("字典檔沒有可用候選密碼。")
        self.enqueue_log(f"\n已建立組合字典：{expanded_path}\n候選數：{count}\n")
        self.enqueue_status(f"組合字典已建立：{count} 筆")
        return str(expanded_path)

    def build_auto_attack_stages(
        self,
        src: Path,
        paths: dict[str, Path],
        engine: str,
        hash_file: Path,
        mode_label: str,
        manual_wordlist: str,
        settings: dict[str, object],
    ) -> list[JobStage]:
        strategy = self.config_data.attack_strategy
        combo_file = str(self.config_data.combo_wordlist or "")
        combo_key = self.config_data.combo_key.strip()
        dictionary_sources = self.collect_dictionary_sources(manual_wordlist)
        stages: list[JobStage] = []

        def add_stage(stage_name: str, wordlist: str, suffix: str) -> None:
            candidate_count = "-"
            if wordlist:
                self.enqueue_status("正在統計字典候選")
                candidate_count = count_text_lines(Path(wordlist), cancel=self.conversion_cancel)
                self.enqueue_status(f"字典候選統計完成：{candidate_count}")
            if engine == "hashcat":
                configured_mask = str(settings["hashcat_mask"])
                if not wordlist and (not configured_mask or configured_mask == HASHCAT_DEFAULT_MASK):
                    paths["mask"].write_text("\n".join(AUTO_MASKS) + "\n", encoding="utf-8", newline="\n")
                cmd = build_auto_hashcat_command(
                    str(self.config_data.hashcat_path), paths["hashcat_hash"], first_number(mode_label),
                    wordlist, paths["cracked"], paths["mask"], src, configured_mask, suffix,
                )
                cwd = str(self.config_data.hashcat_path.parent)
            else:
                cmd = build_auto_john_command(
                    str(self.config_data.john_path), paths["john_hash"], wordlist, src,
                    str(settings["john_mask"]), suffix,
                )
                cwd = str(self.config_data.john_run_dir) if self.config_data.john_run_dir else None
            stages.append(
                JobStage(
                    id=f"{engine}-{suffix}",
                    display_name=f"{engine} {stage_name}",
                    engine=engine,
                    attack_type=suffix,
                    command=tuple(cmd),
                    cwd=cwd,
                    candidate_count=candidate_count,
                    session_log=paths["session"],
                    hash_file=hash_file,
                    mode_label=mode_label,
                    cracked_file=paths["cracked"],
                )
            )

        library_wordlist = ""
        if strategy in {AttackStrategy.AUTO, AttackStrategy.DICTIONARY}:
            library_wordlist = self.prepare_library_wordlist(dictionary_sources, paths["library_wordlist"])
        combo_wordlist = ""
        if strategy in {AttackStrategy.AUTO, AttackStrategy.HINTS}:
            combo_wordlist = self.prepare_combo_wordlist(combo_file, combo_key, paths)

        for step in attack_steps(
            strategy, has_dictionary=bool(library_wordlist), has_hints=bool(combo_wordlist)
        ):
            if step == "dictionary":
                attack_wordlist = self.prepare_auto_wordlist(
                    library_wordlist, paths["expanded_wordlist"], bool(settings["expand_wordlist"])
                )
                add_stage("字典破解", attack_wordlist, "dict")
            elif step == "hints":
                add_stage("提示詞破解", combo_wordlist, "hints")
            else:
                add_stage("遮罩破解", "", "mask")
        return stages

    def _auto_workflow(self, src: Path, wordlist: str, settings: dict[str, object]) -> None:
        try:
            self.job_controller.transition(JobState.CHECKING_ENV)
            self._ensure_tools_worker(bool(settings["auto_download"]))
            if self.conversion_cancel.is_set():
                raise CancelledError("自動流程已停止")
            paths = self._auto_output_paths(src)

            converter = str(settings["converter"])
            if converter:
                self.job_controller.transition(JobState.CONVERTING)
                try:
                    john_text = self.convert_file_to_hash_text(src, converter, bool(settings["safe_copy"]))
                except InterruptedError:
                    raise
                except Exception as exc:
                    raise ConverterError("雜湊轉換失敗", details=f"{type(exc).__name__}: {exc}") from exc
            else:
                try:
                    john_text = self.read_hash_text(src)
                except Exception as exc:
                    raise UnsupportedFormatError(str(exc), details=f"{type(exc).__name__}: {exc}") from exc

            if not john_text.strip():
                raise UnsupportedFormatError("沒有取得可破解的雜湊。")

            self.job_controller.transition(JobState.BUILDING_CANDIDATES)

            paths["cracked"].unlink(missing_ok=True)
            paths["john_hash"].write_text(prepare_hash_output(john_text, "john"), encoding="utf-8", newline="\n")
            hashcat_text = prepare_hash_output(john_text, "hashcat")
            paths["hashcat_hash"].write_text(hashcat_text, encoding="utf-8", newline="\n")

            detection = detect_hashcat_mode(hashcat_text)
            mode_label = detection.mode
            if detection.status == "ambiguous":
                candidates = "、".join(detection.candidates)
                message = f"雜湊格式無法唯一判定，請在進階工具選擇 Hashcat 模式（候選：{candidates}）。"
                self.enqueue_log(f"\n[自動流程] {message}\n")
                raise UnsupportedFormatError(message)
            if mode_label and self.config_data.hashcat_path and self.config_data.hashcat_path.exists():
                engine = "hashcat"
                stages = self.build_auto_attack_stages(
                    src, paths, engine, paths["hashcat_hash"], mode_label, wordlist, settings
                )
            elif self.config_data.john_path and self.config_data.john_path.exists():
                engine = "john"
                if detection.preferred_engine == "john" and detection.format_name:
                    self.enqueue_log(
                        f"\n[自動流程] 無法安全判定 {detection.format_name} 的 Hashcat 模式，改用 John。\n"
                    )
                stages = self.build_auto_attack_stages(
                    src, paths, engine, paths["john_hash"], "", wordlist, settings
                )
            elif detection.preferred_engine == "john" and detection.format_name:
                raise MissingToolError(
                    f"無法安全判定 {detection.format_name} 的 Hashcat 模式；請設定 John 或在進階工具手動選擇模式。"
                )
            else:
                raise MissingToolError("找不到可用的 hashcat 或 John。", details=HASHCAT_DOWNLOAD_PAGE)
            if self.conversion_cancel.is_set():
                raise CancelledError("自動流程已停止")
            self.enqueue_ui(lambda stages=stages, engine=engine: self._begin_auto_stages(stages, engine))
        except InterruptedError as exc:
            self.enqueue_log(f"\n[自動流程停止] {exc}\n")
            self._cancel_auto_job(CancelledError(str(exc)))
        except CancelledError as exc:
            self.enqueue_log(f"\n[自動流程停止] {exc}\n")
            self._cancel_auto_job(exc)
        except SetupError as exc:
            message = str(exc)
            if exc.url:
                message += f"\n下載網址：{exc.url}"
            self.enqueue_log(f"\n[自動流程錯誤] {message}\n")
            self._fail_auto_job(MissingToolError(str(exc), details=exc.url or None))
        except (MissingToolError, UnsupportedFormatError, ConverterError, InvalidDictionaryError) as exc:
            self.enqueue_log(f"\n[自動流程錯誤] {exc}\n")
            self._fail_auto_job(exc)
        except (FileNotFoundError, ValueError) as exc:
            self.enqueue_log(f"\n[自動流程錯誤] {exc}\n")
            self._fail_auto_job(InvalidDictionaryError(str(exc), details=f"{type(exc).__name__}: {exc}"))
        except Exception as exc:
            self.enqueue_log(f"\n[自動流程錯誤] {exc}\n")
            self._fail_auto_job(EngineRuntimeError(str(exc), details=f"{type(exc).__name__}: {exc}"))

    def _begin_auto_stages(self, stages: list[JobStage], engine: str) -> None:
        if self.job_controller.state == JobState.STOPPING:
            self.job_controller.complete_stage(StageResult.CANCELLED, error=CancelledError("工作已取消"))
            return
        self.job_controller.update(stages=stages, selected_engine=engine)
        self.job_controller.transition(JobState.RUNNING)
        self.start_auto_stages()

    def _fail_auto_job(self, error: Exception) -> None:
        if self.job_controller.state == JobState.STOPPING:
            self._cancel_auto_job(CancelledError(str(error)))
        elif self.job_controller.state not in {
            JobState.SUCCEEDED, JobState.EXHAUSTED, JobState.FAILED, JobState.CANCELLED
        }:
            self.job_controller.fail(error)

    def _cancel_auto_job(self, error: CancelledError) -> None:
        if self.job_controller.state not in {JobState.STOPPING, JobState.CANCELLED}:
            self.job_controller.request_cancel()
        if self.job_controller.state == JobState.STOPPING:
            self.job_controller.complete_stage(StageResult.CANCELLED, error=error)

    def convert_file_to_hash_text(self, src: Path, converter: str, safe_copy: bool) -> str:
        temp: tempfile.TemporaryDirectory[str] | None = None
        try:
            input_for_tool = src
            if safe_copy:
                temp = tempfile.TemporaryDirectory(prefix="ptgui_")
                input_for_tool = self.safe_converter_input(src, Path(temp.name))
            if self.conversion_cancel.is_set():
                raise InterruptedError("雜湊轉換已停止")
            cmd = self.converter_command(converter, input_for_tool)
            self.enqueue_log(f"\n[{time.strftime('%H:%M:%S')}] 自動轉換：{converter}\n")
            proc = self.runner.capture(
                "雜湊轉換", cmd, cwd=str(self.config_data.john_run_dir) if self.config_data.john_run_dir else None
            )
            if self.conversion_cancel.is_set():
                raise InterruptedError("雜湊轉換已停止")
            stderr = clean_output(decode_bytes(proc.stderr))
            if stderr.strip():
                self.enqueue_log(stderr + ("\n" if not stderr.endswith("\n") else ""))
            stdout = clean_output(decode_bytes(proc.stdout))
            if proc.returncode != 0 and not stdout.strip():
                raise RuntimeError(f"轉換器結束代碼 {proc.returncode}")
            return stdout
        finally:
            if temp:
                temp.cleanup()

    def read_hash_text(self, src: Path) -> str:
        text = src.read_text(encoding="utf-8", errors="replace")
        if "$" not in text and ":" not in text and not re.search(r"\b[0-9a-fA-F]{32,}\b", text):
            raise RuntimeError("無法判斷檔案格式；請選擇支援的壓縮包/加密檔或雜湊文字檔。")
        return text

    def describe_auto_attack_plan(
        self, name: str, cmd: list[str], cwd: str | None, session_log: Path, engine: str,
        hash_file: Path, mode_label: str, cracked: Path, candidate_count: str = "-",
    ) -> str:
        attack_mode = "-"
        wordlist = ""
        mask_text = ""
        length_summary = "-"

        if engine == "hashcat":
            attack_code = ""
            if "-a" in cmd:
                idx = cmd.index("-a")
                if idx + 1 < len(cmd):
                    attack_code = cmd[idx + 1]
            attack_mode = {"0": "字典攻擊", "3": "遮罩/組合破解"}.get(attack_code, f"hashcat -a {attack_code or '?'}")
            hash_arg = str(hash_file)
            if hash_arg in cmd:
                idx = cmd.index(hash_arg)
                if attack_code == "0" and idx + 1 < len(cmd):
                    wordlist = cmd[idx + 1]
                elif attack_code == "3" and idx + 1 < len(cmd):
                    mask_text = cmd[idx + 1]
        else:
            attack_mode = "John 字典攻擊" if any(arg.startswith("--wordlist=") for arg in cmd) else "John 遮罩破解"
            for arg in cmd:
                if arg.startswith("--wordlist="):
                    wordlist = arg.split("=", 1)[1]
                elif arg.startswith("--mask="):
                    mask_text = arg.split("=", 1)[1]

        if wordlist:
            length_summary = "依字典候選"
        elif mask_text:
            mask_path = Path(mask_text)
            if mask_path.exists():
                try:
                    masks = [line.strip() for line in mask_path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
                    length_summary = summarize_masks(masks)
                except Exception:
                    length_summary = "遮罩檔"
            else:
                length_summary = f"{estimate_mask_length(mask_text)} 位"

        plan = [
            "",
            "========== 攻擊計畫 ==========",
            f"工作名稱：{name}",
            f"工具：{engine}",
            f"目前狀態：準備啟動",
            f"雜湊模式：{mode_label or '由 John 自動判斷'}",
            f"攻擊方式：{attack_mode}",
            f"破解位數：{length_summary}",
            f"候選規模：{candidate_count}",
            f"雜湊檔：{hash_file}",
            f"字典檔：{wordlist or '未指定'}",
            f"遮罩：{mask_text or '未使用'}",
            f"輸出密碼：{cracked}",
            f"Session 記錄：{session_log}",
            f"工作目錄：{cwd or Path.cwd()}",
            f"完整命令：{quote_command(cmd)}",
            "==============================",
            "",
        ]
        return "\n".join(plan)

    def start_auto_stages(self) -> None:
        if self.job_controller.state == JobState.BUILDING_CANDIDATES:
            self.job_controller.transition(JobState.RUNNING)
        snapshot = self.job_controller.snapshot
        stage = snapshot.current_stage
        if stage is None:
            self.job_controller.complete_stage(StageResult.EXHAUSTED)
            return
        candidate_count = str(stage.candidate_count or "-")
        self.job_controller.update(
            candidate_count=candidate_count,
            mode=stage.mode_label or stage.engine,
            current_candidate="遮罩即時計算" if not stage.candidate_count else None,
        )

        def continue_stages(code: int, cancelled: bool, show_error: Exception | None = None) -> None:
            if cancelled or self.job_controller.state == JobState.STOPPING:
                if self.job_controller.state != JobState.STOPPING:
                    self.job_controller.request_cancel()
                self.job_controller.complete_stage(
                    StageResult.CANCELLED, exit_code=code, error=CancelledError("工作已取消")
                )
                return
            if show_error:
                self.job_controller.complete_stage(StageResult.FAILED, exit_code=code, error=show_error)
                return
            if code != 0 and not (stage.engine == "hashcat" and code == 1):
                self.job_controller.complete_stage(
                    StageResult.FAILED,
                    exit_code=code,
                    error=EngineRuntimeError(
                        f"{stage.display_name} 執行失敗",
                        command=stage.command,
                        exit_code=code,
                    ),
                )
                return
            cracked = stage.cracked_file or Path()
            if cracked.exists() and cracked.read_text(encoding="utf-8", errors="replace").strip():
                passwords = cracked.read_text(encoding="utf-8", errors="replace").splitlines()
                self.job_controller.update(recovered_passwords=passwords, recovered_count=f"{len(passwords)} 筆")
                self.job_controller.complete_stage(StageResult.FOUND, exit_code=code)
                return
            next_snapshot = self.job_controller.complete_stage(StageResult.EXHAUSTED, exit_code=code)
            if next_snapshot.state == JobState.BUILDING_CANDIDATES:
                self.start_auto_stages()

        started = self.start_auto_command(
            stage.display_name,
            list(stage.command),
            str(stage.cwd) if stage.cwd else None,
            stage.session_log or Path("session.log"),
            stage.engine,
            stage.hash_file or Path(),
            stage.mode_label,
            stage.cracked_file or Path(),
            candidate_count=candidate_count,
            on_finish=continue_stages,
        )
        if not started:
            self.job_controller.complete_stage(
                StageResult.FAILED,
                error=EngineLaunchError(
                    f"{stage.display_name} 啟動失敗", command=stage.command
                ),
            )

    def start_auto_command(
        self, name: str, cmd: list[str], cwd: str | None, session_log: Path, engine: str,
        hash_file: Path, mode_label: str, cracked: Path, candidate_count: str = "-", on_finish=None,
    ) -> bool:
        plan = self.describe_auto_attack_plan(
            name, cmd, cwd, session_log, engine, hash_file, mode_label, cracked, candidate_count
        )
        self.log(plan)
        try:
            session_log.parent.mkdir(parents=True, exist_ok=True)
            with session_log.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(plan + "\n")
        except Exception:
            pass
        def finish(code: int, cancelled: bool) -> None:
            if cancelled:
                if on_finish:
                    on_finish(code, True, None)
                return
            self.finalize_auto_cracked(
                engine,
                hash_file,
                mode_label,
                cracked,
                (lambda error: on_finish(code, False, error)) if on_finish else None,
            )

        started = self.runner.start(
            name,
            cmd,
            cwd=cwd,
            log_path=session_log,
            on_finish=finish,
        )
        if not started:
            return False
        return True

    def _start_capture_task(self, operation, on_success, on_error) -> bool:
        capture_thread = self.__dict__.get("capture_thread")
        if capture_thread and capture_thread.is_alive():
            messagebox.showwarning("已有工作執行中", "請先停止或等待目前工作完成。")
            return False
        self.conversion_cancel.clear()

        def worker() -> None:
            try:
                if self.conversion_cancel.is_set():
                    raise InterruptedError("背景擷取工作已停止")
                result = operation()
            except Exception as exc:
                self.enqueue_ui(lambda exc=exc: on_error(exc))
            else:
                self.enqueue_ui(lambda result=result: on_success(result))

        self.capture_thread = threading.Thread(target=worker, daemon=True)
        self.capture_thread.start()
        return True

    def finalize_auto_cracked(
        self,
        engine: str,
        hash_file: Path,
        mode_label: str,
        cracked: Path,
        on_complete=None,
    ) -> None:
        try:
            if engine == "hashcat":
                cmd = [
                    str(self.config_data.hashcat_path), "-m", first_number(mode_label),
                    "--show", "--outfile-format", "2", str(hash_file),
                ]
                cwd = str(self.config_data.hashcat_path.parent)
            else:
                cmd = [str(self.config_data.john_path), "--show", str(hash_file)]
                cwd = str(self.config_data.john_run_dir) if self.config_data.john_run_dir else None
            started = self._start_capture_task(
                lambda: self.runner.capture("讀取破解結果", cmd, cwd=cwd, timeout=60),
                lambda proc: self._apply_auto_cracked_result(engine, cracked, proc, on_complete),
                lambda exc: self._handle_auto_cracked_error(exc, on_complete),
            )
            if not started:
                self._handle_auto_cracked_error(RuntimeError("已有背景擷取工作執行中"), on_complete)
        except Exception as exc:
            self._handle_auto_cracked_error(exc, on_complete)

    def _apply_auto_cracked_result(
        self, engine: str, cracked: Path, proc: subprocess.CompletedProcess[bytes], on_complete=None
    ) -> None:
        result_error: Exception | None = None
        try:
            shown = clean_output(decode_bytes(proc.stdout))
            stderr = clean_output(decode_bytes(proc.stderr))
            if stderr:
                self.log(f"\n[破解結果訊息]\n{stderr}\n")
            if proc.returncode != 0:
                self.log(f"\n[破解結果錯誤] --show 結束代碼 {proc.returncode}\n")
                result_error = EngineRuntimeError(
                    "破解結果讀取失敗", exit_code=proc.returncode, stderr=stderr or None
                )
            else:
                passwords = extract_passwords_from_show(shown, engine, plaintext_only=engine == "hashcat")
                if passwords:
                    existing = cracked.read_text(encoding="utf-8", errors="replace").splitlines() if cracked.exists() else []
                    merged = list(dict.fromkeys([line for line in existing + passwords if line.strip()]))
                    cracked.write_text("\n".join(merged) + "\n", encoding="utf-8", newline="\n")
                    self.log(f"\n已輸出密碼：{cracked}\n")
                elif cracked.exists() and cracked.read_text(encoding="utf-8", errors="replace").strip():
                    self.log(f"\n已輸出密碼：{cracked}\n")
        except Exception as exc:
            result_error = EngineRuntimeError(
                "破解結果處理失敗", details=f"{type(exc).__name__}: {exc}"
            )
            self.log(f"\n[輸出密碼錯誤] {exc}\n")
        finally:
            if on_complete:
                on_complete(result_error)

    def _handle_auto_cracked_error(self, exc: Exception, on_complete=None) -> None:
        self.log(f"\n[輸出密碼錯誤] {exc}\n")
        if on_complete:
            on_complete(
                exc if isinstance(exc, EngineRuntimeError) else EngineRuntimeError(
                    "破解結果讀取失敗", details=f"{type(exc).__name__}: {exc}"
                )
            )

    def converter_for_input(self, input_path: Path) -> str:
        chosen = self.extract_converter.get()
        if chosen and chosen != "自動偵測":
            return chosen
        spec = format_for_extension(input_path.suffix)
        return spec.converter if spec else ""

    def converter_command(self, converter_name: str, input_path: Path) -> list[str]:
        run_dir = self.config_data.john_run_dir or Path()
        converter_path = run_dir / converter_name
        if not converter_path.exists():
            raise FileNotFoundError(f"找不到轉換器：{converter_path}")
        runtime = converter_runtime(converter_name)
        if runtime is None:
            raise ValueError(f"不支援的轉換器：{converter_name}")
        if not runtime:
            return [str(converter_path), str(input_path)]
        runtime_path = getattr(self.config_data, runtime)
        if not runtime_path or not runtime_path.exists():
            if runtime == "python_path":
                raise SetupError("未設定可用的 python.exe，無法執行 .py 轉換器。", PYTHON_DOWNLOAD_PAGE)
            if runtime == "perl_path":
                raise SetupError("未設定可用的 perl.exe，無法執行 .pl 轉換器。", PERL_DOWNLOAD_PAGE)
            if runtime == "node_path":
                raise SetupError("未設定可用的 node.exe，無法執行 .js 轉換器。", NODE_DOWNLOAD_PAGE)
        return [str(runtime_path), str(converter_path), str(input_path)]

    def safe_converter_input(self, original: Path, temp_dir: Path) -> Path:
        safe_name = "input" + original.suffix.lower()
        safe_path = temp_dir / safe_name
        shutil.copy2(original, safe_path)
        return safe_path

    def start_extract(self) -> None:
        src = Path(self.extract_input.get().strip())
        if not src.exists():
            messagebox.showerror("來源不存在", "請選擇要轉換的檔案。")
            return
        if not self.extract_output.get().strip():
            self.suggest_extract_output()
        out_path = Path(self.extract_output.get().strip())
        converter = self.converter_for_input(src)
        if not converter:
            messagebox.showerror("無法偵測轉換器", "請手動選擇 *2john 轉換器。")
            return
        if self.runner.running() or any(
            thread and thread.is_alive() for thread in (self.extract_thread, self.auto_thread)
        ):
            messagebox.showwarning("已有工作執行中", "請先停止或等待目前工作完成。")
            return
        settings = {
            "safe_copy": bool(self.extract_safe_copy.get()),
            "target": self.extract_target.get(),
            "fill_hashcat": bool(self.extract_fill_hashcat.get()),
            "fill_john": bool(self.extract_fill_john.get()),
        }
        self.conversion_cancel.clear()
        self.extract_thread = threading.Thread(
            target=self._extract_worker, args=(src, out_path, converter, settings), daemon=True
        )
        self.extract_thread.start()

    def _extract_worker(
        self, src: Path, out_path: Path, converter: str, settings: dict[str, object]
    ) -> None:
        self.enqueue_status("雜湊轉換中")
        temp: tempfile.TemporaryDirectory[str] | None = None
        try:
            input_for_tool = src
            if bool(settings["safe_copy"]):
                temp = tempfile.TemporaryDirectory(prefix="ptgui_")
                input_for_tool = self.safe_converter_input(src, Path(temp.name))
            if self.conversion_cancel.is_set():
                raise InterruptedError("雜湊轉換已停止")
            cmd = self.converter_command(converter, input_for_tool)
            self.enqueue_log(f"\n[{time.strftime('%H:%M:%S')}] 雜湊轉換：{converter}\n{quote_command(cmd)}\n\n")
            proc = self.runner.capture(
                "雜湊轉換", cmd, cwd=str(self.config_data.john_run_dir) if self.config_data.john_run_dir else None
            )
            if self.conversion_cancel.is_set():
                raise InterruptedError("雜湊轉換已停止")
            stdout = clean_output(decode_bytes(proc.stdout))
            stderr = clean_output(decode_bytes(proc.stderr))
            if stderr.strip():
                self.enqueue_log(stderr + ("\n" if not stderr.endswith("\n") else ""))
            if proc.returncode != 0 and not stdout.strip():
                raise RuntimeError(f"轉換器結束代碼 {proc.returncode}")
            result = prepare_hash_output(stdout, str(settings["target"]))
            if not result.strip():
                raise RuntimeError("沒有取得雜湊輸出，請確認檔案是否加密或轉換器是否支援。")
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(result, encoding="utf-8", newline="\n")
            self.enqueue_log(result + ("\n" if not result.endswith("\n") else ""))
            self.enqueue_log(f"\n已寫入：{out_path}\n")
            self.enqueue_ui(lambda: self.apply_extracted_hash(out_path, settings))
            self.enqueue_status("雜湊轉換完成")
        except InterruptedError as exc:
            self.enqueue_log(f"\n[停止] {exc}\n")
            self.enqueue_status("雜湊轉換已停止")
        except SetupError as exc:
            message = str(exc)
            if exc.url:
                message += f"\n下載網址：{exc.url}"
            self.enqueue_log(f"\n[錯誤] {message}\n")
            self.enqueue_status("雜湊轉換失敗")
        except Exception as exc:
            self.enqueue_log(f"\n[錯誤] {exc}\n")
            self.enqueue_status("雜湊轉換失敗")
        finally:
            if temp:
                temp.cleanup()

    def apply_extracted_hash(self, out_path: Path, settings: dict[str, object]) -> None:
        if settings["fill_hashcat"]:
            self.hashcat_hash_file.set(str(out_path))
        if settings["fill_john"]:
            self.john_hash_file.set(str(out_path))

    def hashcat_common_args(self) -> list[str]:
        self.config_data.update_tool_paths(find_tool_paths(self.config_data.tool_paths(), TOOLS_DIR))
        exe = self.config_data.hashcat_path
        if not exe or not exe.exists():
            raise SetupError("找不到 hashcat.exe，可按「檢查/下載環境」自動下載。", HASHCAT_DOWNLOAD_PAGE)
        return [str(exe)]

    def build_hashcat_command(self, show: bool = False) -> list[str]:
        cmd = self.hashcat_common_args()
        hash_file = self.hashcat_hash_file.get().strip()
        if not hash_file:
            raise ValueError("請指定雜湊檔。")
        mode = first_number(self.hashcat_mode.get())
        attack = first_number(self.hashcat_attack.get())
        if mode:
            cmd += ["-m", mode]
        if not show:
            cmd += ["-a", attack]
        session = self.hashcat_session.get().strip()
        if session:
            cmd += ["--session", session]
        if self.hashcat_username.get():
            cmd.append("--username")
        if self.hashcat_remove.get() and not show:
            cmd.append("--remove")
        if self.hashcat_optimized.get() and not show:
            cmd.append("-O")
        workload = self.hashcat_workload.get().strip()
        if workload and not show:
            cmd += ["-w", workload]
        device = self.hashcat_device.get().strip()
        if device and not show:
            cmd += ["-d", device]
        timer = self.hashcat_status_timer.get().strip()
        if timer and not show:
            cmd += ["--status", "--status-timer", timer]
        outfile = self.hashcat_outfile.get().strip()
        if outfile and not show:
            Path(outfile).parent.mkdir(parents=True, exist_ok=True)
            cmd += ["--outfile", outfile]
        cmd += split_extra_args(self.hashcat_extra.get())
        if show:
            cmd += ["--show", hash_file]
            return cmd
        cmd.append(hash_file)
        wordlist = self.hashcat_wordlist.get().strip()
        second = self.hashcat_second.get().strip()
        mask = self.hashcat_mask.get().strip()
        rule = self.hashcat_rule.get().strip()
        if attack == "0":
            if wordlist:
                cmd.append(wordlist)
            if rule:
                cmd += ["-r", rule]
        elif attack == "1":
            if wordlist:
                cmd.append(wordlist)
            if second:
                cmd.append(second)
        elif attack == "3":
            if mask:
                cmd.append(mask)
        elif attack == "6":
            if wordlist:
                cmd.append(wordlist)
            if mask:
                cmd.append(mask)
            if rule:
                cmd += ["-r", rule]
        elif attack == "7":
            if mask:
                cmd.append(mask)
            if wordlist:
                cmd.append(wordlist)
            if rule:
                cmd += ["-r", rule]
        return cmd

    def start_hashcat(self) -> None:
        try:
            cmd = self.build_hashcat_command()
        except Exception as exc:
            messagebox.showerror("Hashcat 設定錯誤", str(exc))
            return
        self.show_job_view()
        self.runner.start("hashcat", cmd, cwd=str(self.config_data.hashcat_path.parent))

    def hashcat_show(self) -> None:
        try:
            cmd = self.build_hashcat_command(show=True)
        except Exception as exc:
            messagebox.showerror("Hashcat 設定錯誤", str(exc))
            return
        self.show_job_view()
        self.runner.start("hashcat --show", cmd, cwd=str(self.config_data.hashcat_path.parent))

    def hashcat_custom(self) -> None:
        try:
            extra = split_extra_args(self.hashcat_extra.get())
            if not extra:
                raise ValueError("請在進階參數輸入要執行的 hashcat 選項。")
            cmd = self.hashcat_common_args() + extra
        except Exception as exc:
            messagebox.showerror("Hashcat 設定錯誤", str(exc))
            return
        self.show_job_view()
        self.runner.start("hashcat custom", cmd, cwd=str(self.config_data.hashcat_path.parent))

    def hashcat_devices(self) -> None:
        try:
            cmd = self.hashcat_common_args() + ["-I"]
        except Exception as exc:
            messagebox.showerror("Hashcat 設定錯誤", str(exc))
            return
        self.show_job_view()
        self.runner.start("hashcat -I", cmd, cwd=str(self.config_data.hashcat_path.parent))

    def hashcat_benchmark(self) -> None:
        try:
            cmd = self.hashcat_common_args() + ["-b"]
        except Exception as exc:
            messagebox.showerror("Hashcat 設定錯誤", str(exc))
            return
        self.show_job_view()
        self.runner.start("hashcat benchmark", cmd, cwd=str(self.config_data.hashcat_path.parent))

    def hashcat_help(self) -> None:
        try:
            cmd = self.hashcat_common_args() + ["--help"]
        except Exception as exc:
            messagebox.showerror("Hashcat 設定錯誤", str(exc))
            return
        self.show_job_view()
        self.runner.start("hashcat help", cmd, cwd=str(self.config_data.hashcat_path.parent))

    def john_common_args(self) -> list[str]:
        self.config_data.update_tool_paths(find_tool_paths(self.config_data.tool_paths(), TOOLS_DIR))
        exe = self.config_data.john_path
        if not exe or not exe.exists():
            raise SetupError("找不到 john.exe，可按「檢查/下載環境」自動下載。", JOHN_RELEASE_PAGE)
        return [str(exe)]

    def build_john_command(self) -> list[str]:
        cmd = self.john_common_args()
        mode = (self.john_mode.get() or "").split(" ", 1)[0]
        fmt = self.john_format.get().strip()
        if fmt:
            cmd.append(f"--format={fmt}")
        session = self.john_session.get().strip()
        if session:
            cmd.append(f"--session={session}")
        if mode == "wordlist":
            wordlist = self.john_wordlist.get().strip()
            if wordlist:
                cmd.append(f"--wordlist={wordlist}")
            rules = self.john_rules.get().strip()
            if rules:
                cmd.append(f"--rules={rules}")
        elif mode == "single":
            cmd.append("--single")
        elif mode == "incremental":
            cmd.append("--incremental")
        elif mode == "mask":
            mask = self.john_mask.get().strip()
            if mask:
                cmd.append(f"--mask={mask}")
        fork = self.john_fork.get().strip()
        if fork:
            cmd.append(f"--fork={fork}")
        cmd += split_extra_args(self.john_extra.get())
        hash_file = self.john_hash_file.get().strip()
        if not hash_file:
            raise ValueError("請指定雜湊檔。")
        cmd.append(hash_file)
        return cmd

    def start_john(self) -> None:
        try:
            cmd = self.build_john_command()
        except Exception as exc:
            messagebox.showerror("John 設定錯誤", str(exc))
            return
        self.show_job_view()
        self.runner.start("John", cmd, cwd=str(self.config_data.john_run_dir) if self.config_data.john_run_dir else None)

    def john_show(self) -> None:
        try:
            cmd = self.john_common_args()
            fmt = self.john_format.get().strip()
            if fmt:
                cmd.append(f"--format={fmt}")
            cmd += ["--show", self.john_hash_file.get().strip()]
        except Exception as exc:
            messagebox.showerror("John 設定錯誤", str(exc))
            return
        self.show_job_view()
        self.runner.start("John --show", cmd, cwd=str(self.config_data.john_run_dir) if self.config_data.john_run_dir else None)

    def john_custom(self) -> None:
        try:
            extra = split_extra_args(self.john_extra.get())
            if not extra:
                raise ValueError("請在進階參數輸入要執行的 John 選項。")
            cmd = self.john_common_args() + extra
        except Exception as exc:
            messagebox.showerror("John 設定錯誤", str(exc))
            return
        self.show_job_view()
        self.runner.start("John custom", cmd, cwd=str(self.config_data.john_run_dir) if self.config_data.john_run_dir else None)

    def john_status(self) -> None:
        try:
            cmd = self.john_common_args()
            session = self.john_session.get().strip()
            cmd.append(f"--status={session}" if session else "--status")
        except Exception as exc:
            messagebox.showerror("John 設定錯誤", str(exc))
            return
        self.show_job_view()
        self.runner.start("John status", cmd, cwd=str(self.config_data.john_run_dir) if self.config_data.john_run_dir else None)

    def john_restore(self) -> None:
        try:
            cmd = self.john_common_args()
            session = self.john_session.get().strip()
            cmd.append(f"--restore={session}" if session else "--restore")
        except Exception as exc:
            messagebox.showerror("John 設定錯誤", str(exc))
            return
        self.show_job_view()
        self.runner.start("John restore", cmd, cwd=str(self.config_data.john_run_dir) if self.config_data.john_run_dir else None)

    def john_test(self) -> None:
        try:
            cmd = self.john_common_args() + ["--test=5"]
        except Exception as exc:
            messagebox.showerror("John 設定錯誤", str(exc))
            return
        self.show_job_view()
        self.runner.start("John test", cmd, cwd=str(self.config_data.john_run_dir) if self.config_data.john_run_dir else None)

    def john_help(self) -> None:
        try:
            cmd = self.john_common_args() + ["--help"]
        except Exception as exc:
            messagebox.showerror("John 設定錯誤", str(exc))
            return
        self.show_job_view()
        self.runner.start("John help", cmd, cwd=str(self.config_data.john_run_dir) if self.config_data.john_run_dir else None)

    def load_john_formats(self) -> None:
        try:
            cmd = self.john_common_args() + ["--list=formats"]
            cwd = str(self.config_data.john_run_dir) if self.config_data.john_run_dir else None
            self._start_capture_task(
                lambda: self.runner.capture("載入 John formats", cmd, cwd=cwd, timeout=20),
                self._apply_john_formats,
                lambda exc: messagebox.showerror("載入失敗", str(exc)),
            )
        except Exception as exc:
            messagebox.showerror("載入失敗", str(exc))

    def _apply_john_formats(self, proc: subprocess.CompletedProcess[bytes]) -> None:
        text = clean_output(decode_bytes(proc.stdout + proc.stderr))
        values = sorted({part.strip() for part in re.split(r"[,\s]+", text) if part.strip() and not part.startswith("-")})
        self.john_format_combo.configure(values=values)
        self.log("\n已載入 John formats：" + str(len(values)) + "\n")

    def apply_settings(self, persist: bool = False) -> None:
        for key, var in self.setting_vars.items():
            value = var.get().strip()
            setattr(self.config_data, key, Path(value) if value else (RESULTS_DIR if key == "output_dir" else None))
        if hasattr(self, "quick_strategy"):
            self.config_data.attack_strategy = ATTACK_STRATEGY_OPTIONS[self.quick_strategy.get()]
            self.config_data.default_wordlist = Path(value) if (value := self.quick_wordlist.get().strip()) else None
            self.config_data.combo_wordlist = Path(value) if (value := self.quick_combo_wordlist.get().strip()) else None
            self.config_data.combo_key = self.quick_combo_key.get().strip()
        if persist:
            self._save_config(explicit=True)
        self.config_data.output_dir.mkdir(parents=True, exist_ok=True)
        self.refresh_converters()
        self.sync_config_to_ui()

    def save_settings(self) -> None:
        self.apply_settings(persist=True)
        messagebox.showinfo("已儲存", "設定已儲存。")

    def detect_settings(self) -> None:
        detected = default_config()
        for key in ("hashcat_path", "john_path", "john_run_dir", "python_path", "perl_path", "node_path", "output_dir"):
            value = getattr(detected, key)
            current = self.setting_vars.get(key)
            if current and (value or not current.get().strip()):
                current.set(str(value or ""))

    def health_check(self) -> None:
        self.apply_settings()
        self.config_data.update_tool_paths(find_tool_paths(self.config_data.tool_paths(), TOOLS_DIR))
        tests = []
        if self.config_data.hashcat_path and self.config_data.hashcat_path.exists():
            tests.append(("hashcat", [str(self.config_data.hashcat_path), "--version"], str(self.config_data.hashcat_path.parent)))
        else:
            self.log(f"\n[健康檢查] hashcat: 未找到，下載網址 {HASHCAT_DOWNLOAD_PAGE}\n")
        if self.config_data.john_path and self.config_data.john_path.exists():
            tests.append((
                "john", [str(self.config_data.john_path), "--list=build-info"],
                str(self.config_data.john_run_dir) if self.config_data.john_run_dir else None,
            ))
        else:
            self.log(f"\n[健康檢查] john: 未找到，下載網址 {JOHN_RELEASE_PAGE}\n")
        self.show_job_view()
        if tests:
            self._start_capture_task(
                lambda: self._run_health_checks(tests),
                self._apply_health_check_results,
                lambda exc: self.log(f"\n[健康檢查] 已停止：{exc}\n"),
            )
        if not self.config_data.perl_path:
            self.log("[健康檢查] perl: 未設定，.pl 轉換器不可用\n")

    def _run_health_checks(
        self, tests: list[tuple[str, list[str], str | None]]
    ) -> list[tuple[str, subprocess.CompletedProcess[bytes] | None, Exception | None]]:
        results = []
        for name, cmd, cwd in tests:
            if self.conversion_cancel.is_set():
                raise InterruptedError("健康檢查已停止")
            try:
                results.append((name, self.runner.capture(f"健康檢查 {name}", cmd, cwd=cwd, timeout=20), None))
            except InterruptedError:
                raise
            except Exception as exc:
                results.append((name, None, exc))
        return results

    def _apply_health_check_results(
        self, results: list[tuple[str, subprocess.CompletedProcess[bytes] | None, Exception | None]]
    ) -> None:
        for name, proc, error in results:
            if error:
                self.log(f"\n[健康檢查] {name}: 失敗 {error}\n")
                continue
            assert proc is not None
            text = clean_output(decode_bytes(proc.stdout + proc.stderr)).strip()
            first = text.splitlines()[0] if text else f"return {proc.returncode}"
            self.log(f"\n[健康檢查] {name}: {first}\n")

    def stop_current_work(self) -> None:
        controller = self.__dict__.get("job_controller")
        if controller and controller.state in {
            JobState.PREPARING,
            JobState.CHECKING_ENV,
            JobState.CONVERTING,
            JobState.BUILDING_CANDIDATES,
            JobState.RUNNING,
        }:
            controller.request_cancel()
        workers = [
            thread for thread in (
                self.extract_thread,
                self.auto_thread,
                self.__dict__.get("capture_thread"),
            )
            if thread and thread.is_alive()
        ]
        if workers:
            self.conversion_cancel.set()
        if self.runner.running():
            self.runner.stop()
        elif workers:
            self.log("\n[控制] 已要求停止目前工作\n")
        else:
            self.runner.stop()

    def _on_close(self) -> None:
        extract_running = self.extract_thread is not None and self.extract_thread.is_alive()
        auto_running = self.auto_thread is not None and self.auto_thread.is_alive()
        capture_thread = self.__dict__.get("capture_thread")
        capture_running = capture_thread is not None and capture_thread.is_alive()
        if self.runner.running() or extract_running or auto_running or capture_running:
            if not messagebox.askyesno("仍有工作執行中", "關閉前要停止目前工作嗎？"):
                return
            self.stop_current_work()
            if self.runner.running():
                self.runner.wait()
            if extract_running:
                self.extract_thread.join()
            if auto_running:
                self.auto_thread.join()
            if capture_running:
                capture_thread.join()
        self.destroy()


def main() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    app = PasswordToolGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
