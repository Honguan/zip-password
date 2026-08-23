# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import locale
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
import fnmatch
import hashlib
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext
import tkinter as tk
from tkinter import ttk


APP_DIR = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
RESOURCE_DIR = Path(getattr(sys, "_MEIPASS", APP_DIR))
TOOLS_DIR = APP_DIR / "密碼工具GUI_tools"
DOWNLOADS_DIR = TOOLS_DIR / "downloads"
TOOL_TMP_DIR = TOOLS_DIR / "tmp"
WORDLISTS_DIR = TOOLS_DIR / "wordlists"
CONFIG_PATH = APP_DIR / "password_gui_config.json"
LEGACY_CONFIG_NAMES = [
    "password_gui_config.json",
    "密碼工具GUI_config.json",
    "密碼工具GUI設定.json",
    "PasswordToolsGUI_config.json",
    "password_tools_gui_config.json",
    "settings.json",
    "config.json",
]
DEFAULT_OUTPUT_DIR = APP_DIR / "gui_output"
RESULTS_DIR = APP_DIR / "密碼工具GUI_輸出"
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
UI_FONT = "Iansui"
MONO_FONT = UI_FONT
FONT_FILE_NAME = "Iansui-Regular.ttf"
BG = "#F3F6FA"
SURFACE = "#FFFFFF"
SURFACE_2 = "#EEF3F8"
TEXT = "#172033"
MUTED = "#667085"
BORDER = "#D7DEE8"
ACCENT = "#2563EB"
ACCENT_DARK = "#1E40AF"
SUCCESS = "#059669"
WARNING = "#D97706"
DANGER = "#DC2626"
DARK_PANEL = "#101828"
HASHCAT_DOWNLOAD_PAGE = "https://hashcat.net/hashcat/"
JOHN_RELEASE_API = "https://api.github.com/repos/openwall/john-packages/releases/latest"
JOHN_RELEASE_PAGE = "https://github.com/openwall/john-packages/releases/latest"
PERL_DOWNLOAD_PAGE = "https://strawberryperl.com/"
SEVENZIP_DOWNLOAD_PAGE = "https://www.7-zip.org/download.html"
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

AUTO_MASKS = [
    "?d?d?d?d",
    "?d?d?d?d?d",
    "?d?d?d?d?d?d",
    "?d?d?d?d?d?d?d",
    "?d?d?d?d?d?d?d?d",
    "?l?l?l?l",
    "?l?l?l?l?l",
    "?l?l?l?l?l?l",
    "?l?l?l?d?d",
    "?l?l?l?l?d?d",
    "?u?l?l?l?d?d",
]

WORDLIST_JOINERS = ["", " ", ".", "-", "_", "/", "@", "\t"]
WORDLIST_EXPANSION_LIMIT = 500_000
HASHCAT_DEFAULT_MASK = "?a?a?a?a?a?a"
JOHN_DEFAULT_MASK = "?a?a?a?a?a?a"

HASHCAT_PREFIX_MODES = [
    ("$zip2$*", "17200 - PKZIP"),
    ("$rar5$*", "13000 - RAR5"),
    ("$rar3$*", "12500 - RAR3-hp"),
    ("$7z$*", "11600 - 7-Zip"),
    ("$office$*2007*", "9400 - MS Office 2007"),
    ("$office$*2010*", "9500 - MS Office 2010"),
    ("$office$*2013*", "9600 - MS Office 2013"),
    ("$pdf$*", "10500 - PDF 1.4-1.6"),
]

ARCHIVE_CONVERTER_MAP = {
    ".zip": "zip2john.exe",
    ".zipx": "zip2john.exe",
    ".jar": "zip2john.exe",
    ".apk": "zip2john.exe",
    ".epub": "zip2john.exe",
    ".rar": "rar2john.exe",
    ".7z": "7z2john.pl",
    ".pdf": "pdf2john.pl",
    ".doc": "office2john.py",
    ".docx": "office2john.py",
    ".xls": "office2john.py",
    ".xlsx": "office2john.py",
    ".ppt": "office2john.py",
    ".pptx": "office2john.py",
    ".pps": "office2john.py",
    ".ppsx": "office2john.py",
    ".odt": "libreoffice2john.py",
    ".ods": "libreoffice2john.py",
    ".odp": "libreoffice2john.py",
    ".dmg": "dmg2john.exe",
    ".gpg": "gpg2john.exe",
    ".kdbx": "keepass2john.exe",
    ".pfx": "pfx2john.py",
    ".p12": "pfx2john.py",
    ".pem": "pem2john.py",
    ".key": "ssh2john.py",
    ".vhd": "bitlocker2john.exe",
    ".vhdx": "bitlocker2john.exe",
    ".hc": "truecrypt2john.py",
    ".tc": "truecrypt2john.py",
}

HASHCAT_MODES = [
    "0 - MD5",
    "100 - SHA1",
    "1400 - SHA2-256",
    "1700 - SHA2-512",
    "1000 - NTLM",
    "3000 - LM",
    "3200 - bcrypt",
    "5500 - NetNTLMv1",
    "5600 - NetNTLMv2",
    "9400 - MS Office 2007",
    "9500 - MS Office 2010",
    "9600 - MS Office 2013",
    "10500 - PDF 1.4-1.6",
    "10600 - PDF 1.7 Level 3",
    "10700 - PDF 1.7 Level 8",
    "11600 - 7-Zip",
    "12500 - RAR3-hp",
    "13000 - RAR5",
    "13600 - WinZip",
    "17200 - PKZIP",
    "17220 - PKZIP Multi-File",
    "17225 - PKZIP Mixed Multi-File",
    "17230 - PKZIP Mixed",
    "23001 - SecureZIP AES-128",
    "23002 - SecureZIP AES-192",
    "23003 - SecureZIP AES-256",
]

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


def existing_exe(path_text: str) -> str:
    if not path_text:
        return ""
    path = Path(path_text).expanduser()
    if path.is_file():
        return str(path)
    return ""


def find_in_env(env_name: str, exe_name: str) -> str:
    value = os.environ.get(env_name, "").strip().strip('"')
    if not value:
        return ""
    path = Path(value).expanduser()
    if path.is_file():
        return str(path)
    if path.is_dir():
        candidate = path / exe_name
        if candidate.is_file():
            return str(candidate)
        matches = list(path.rglob(exe_name))
        if matches:
            return str(matches[0])
    return ""


def find_hashcat_under(root: Path) -> str:
    candidates = [
        root / "hashcat.exe",
        root / "hashcat" / "hashcat.exe",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    if root.exists():
        matches = sorted(root.rglob("hashcat.exe"), key=lambda p: len(str(p)))
        if matches:
            return str(matches[0])
    return ""


def find_john_under(root: Path) -> tuple[str, str]:
    candidates = [
        root / "john.exe",
        root / "run" / "john.exe",
        root / "JohnRipper" / "run" / "john.exe",
    ]
    for candidate in candidates:
        if candidate.is_file():
            run_dir = candidate.parent if candidate.parent.name.lower() == "run" else candidate.parent
            return str(candidate), str(run_dir)
    if root.exists():
        matches = sorted(root.rglob("john.exe"), key=lambda p: (0 if p.parent.name.lower() == "run" else 1, len(str(p))))
        if matches:
            candidate = matches[0]
            run_dir = candidate.parent if candidate.parent.name.lower() == "run" else candidate.parent
            return str(candidate), str(run_dir)
    return "", ""


def find_tool_paths(saved: dict[str, str] | None = None) -> dict[str, str]:
    saved = saved or {}
    hashcat_path = existing_exe(saved.get("hashcat_path", ""))
    john_path = existing_exe(saved.get("john_path", ""))
    john_run_dir = saved.get("john_run_dir", "")

    if not hashcat_path:
        hashcat_path = find_in_env("HASHCAT_PATH", "hashcat.exe")
    if not john_path:
        john_path = find_in_env("JOHN_PATH", "john.exe")
    if not hashcat_path:
        hashcat_path = shutil.which("hashcat.exe") or shutil.which("hashcat") or ""
    if not john_path:
        john_path = shutil.which("john.exe") or shutil.which("john") or ""
    if not hashcat_path:
        hashcat_path = find_hashcat_under(TOOLS_DIR / "hashcat")
    if not john_path:
        john_path, john_run_dir = find_john_under(TOOLS_DIR / "JohnRipper")
    elif not john_run_dir or not Path(john_run_dir).exists():
        parent = Path(john_path).parent
        john_run_dir = str(parent if parent.name.lower() == "run" else parent)

    python_path = existing_exe(saved.get("python_path", "")) or find_in_env("PYTHON_PATH", "python.exe") or shutil.which("python.exe") or shutil.which("python") or ""
    perl_path = existing_exe(saved.get("perl_path", "")) or find_in_env("PERL_PATH", "perl.exe") or shutil.which("perl.exe") or shutil.which("perl") or ""
    node_path = existing_exe(saved.get("node_path", "")) or find_in_env("NODE_PATH", "node.exe") or shutil.which("node.exe") or shutil.which("node") or ""

    return {
        "hashcat_path": str(hashcat_path),
        "john_path": str(john_path),
        "john_run_dir": str(john_run_dir),
        "python_path": str(python_path),
        "perl_path": str(perl_path),
        "node_path": str(node_path),
    }


def default_config() -> dict[str, str]:
    python_path = shutil.which("python") or sys.executable
    if getattr(sys, "frozen", False):
        python_path = shutil.which("python") or ""
    elif python_path.lower().endswith("pythonw.exe"):
        candidate = Path(python_path).with_name("python.exe")
        if candidate.exists():
            python_path = str(candidate)
    detected = find_tool_paths({"python_path": python_path})
    return {
        "hashcat_path": detected["hashcat_path"],
        "john_path": detected["john_path"],
        "john_run_dir": detected["john_run_dir"],
        "python_path": detected["python_path"] or python_path,
        "perl_path": detected["perl_path"],
        "node_path": detected["node_path"],
        "default_wordlist": "",
        "auto_follow_order": "1",
        "combo_wordlist": "",
        "combo_key": "",
        "output_dir": str(RESULTS_DIR),
        "tools_dir": str(TOOLS_DIR),
    }


def config_search_paths() -> list[Path]:
    roots = [APP_DIR, Path.cwd()]
    if not getattr(sys, "frozen", False):
        roots.append(Path(__file__).resolve().parent)
    paths: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        for name in LEGACY_CONFIG_NAMES:
            path = root / name
            key = str(path.resolve() if path.exists() else path)
            if key not in seen:
                seen.add(key)
                paths.append(path)
    return paths


def read_config_file(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("設定檔格式不是 JSON object")
    return {str(k): str(v) for k, v in data.items()}


def config_bool(value: str | bool | None, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if not text:
        return default
    return text not in {"0", "false", "no", "off", "關", "否", "停用"}


def load_config() -> dict[str, str]:
    cfg = default_config()
    saved: dict[str, str] = {}
    loaded_path = next((path for path in config_search_paths() if path.exists()), None)
    if loaded_path:
        try:
            data = read_config_file(loaded_path)
            saved = data
            for key in cfg:
                if key in data:
                    cfg[key] = str(data[key])
        except Exception:
            pass
    detected = find_tool_paths(saved)
    for key, value in detected.items():
        if value:
            cfg[key] = value
    cfg["tools_dir"] = str(TOOLS_DIR)
    if loaded_path and loaded_path != CONFIG_PATH:
        try:
            save_config(cfg)
        except Exception:
            pass
    return cfg


def save_config(cfg: dict[str, str]) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")


class SetupError(RuntimeError):
    def __init__(self, message: str, url: str = "") -> None:
        super().__init__(message)
        self.url = url


def urlopen_text(url: str, timeout: int = 30) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "PasswordToolsGUI/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        return response.read().decode(charset, errors="replace")


def latest_hashcat_url() -> str:
    html = urlopen_text(HASHCAT_DOWNLOAD_PAGE)
    links = re.findall(r'href=["\']([^"\']*hashcat-[0-9][0-9.]*\.7z)["\']', html, flags=re.I)
    if not links:
        raise SetupError("無法從 hashcat 官方頁面找到 binary 下載連結。", HASHCAT_DOWNLOAD_PAGE)

    def version_key(link: str) -> tuple[int, ...]:
        match = re.search(r"hashcat-([0-9.]+)\.7z", link)
        if not match:
            return (0,)
        return tuple(int(part) for part in match.group(1).split(".") if part.isdigit())

    best = max(links, key=version_key)
    return urllib.parse.urljoin(HASHCAT_DOWNLOAD_PAGE, best)


def latest_john_url() -> str:
    data = json.loads(urlopen_text(JOHN_RELEASE_API))
    assets = data.get("assets", [])
    for asset in assets:
        name = str(asset.get("name", "")).lower()
        if "win" in name and "x64" in name and name.endswith((".7z", ".zip")):
            url = str(asset.get("browser_download_url", ""))
            if url:
                return url
    raise SetupError("無法從 John 最新 release 找到 Windows x64 下載檔。", JOHN_RELEASE_PAGE)


def download_file(url: str, dest: Path, log_cb=None) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    temp = dest.with_suffix(dest.suffix + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": "PasswordToolsGUI/1.0"})
    with urllib.request.urlopen(request, timeout=60) as response, temp.open("wb") as fh:
        total = int(response.headers.get("Content-Length") or "0")
        done = 0
        last_report = 0.0
        while True:
            chunk = response.read(1024 * 512)
            if not chunk:
                break
            fh.write(chunk)
            done += len(chunk)
            now = time.time()
            if log_cb and now - last_report > 1.5:
                if total:
                    log_cb(f"下載中 {dest.name}: {done / total:.0%}\n")
                else:
                    log_cb(f"下載中 {dest.name}: {done // 1048576} MB\n")
                last_report = now
    temp.replace(dest)
    return dest


def extract_archive(archive: Path, dest: Path, log_cb=None) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    if archive.suffix.lower() == ".zip":
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest)
        return
    tar = shutil.which("tar.exe") or shutil.which("tar")
    if not tar:
        raise SetupError("缺少可解壓 .7z 的工具，請安裝 7-Zip 後再重試。", SEVENZIP_DOWNLOAD_PAGE)
    if log_cb:
        log_cb(f"解壓縮 {archive.name}\n")
    creationflags, startupinfo = hidden_startup()
    proc = subprocess.run(
        [tar, "-xf", str(archive), "-C", str(dest)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=creationflags,
        startupinfo=startupinfo,
    )
    if proc.returncode != 0:
        detail = clean_output(decode_bytes(proc.stderr or proc.stdout)).strip()
        raise SetupError(f"解壓縮失敗：{detail or archive.name}", SEVENZIP_DOWNLOAD_PAGE)


def ensure_tool_dirs() -> None:
    for path in (TOOLS_DIR, DOWNLOADS_DIR, TOOL_TMP_DIR, WORDLISTS_DIR, RESULTS_DIR, TOOLS_DIR / "hashcat", TOOLS_DIR / "JohnRipper"):
        path.mkdir(parents=True, exist_ok=True)


def safe_stem(text: str) -> str:
    value = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", text).strip(" ._")
    return value[:80] or "output"


def result_dir_for_source(src: Path) -> Path:
    digest = hashlib.sha1(str(src.resolve() if src.exists() else src).encode("utf-8", errors="ignore")).hexdigest()[:8]
    out_dir = RESULTS_DIR / f"{safe_stem(src.stem)}_{digest}"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def decode_bytes(data: bytes) -> str:
    encodings = ["utf-8", locale.getpreferredencoding(False), "cp950", "big5", "latin-1"]
    for enc in encodings:
        try:
            return data.decode(enc)
        except Exception:
            continue
    return data.decode("utf-8", errors="replace")


def clean_output(text: str) -> str:
    return ANSI_RE.sub("", text.replace("\r\n", "\n").replace("\r", "\n"))


def case_variants(text: str) -> list[str]:
    if not re.search(r"[A-Za-z]", text):
        return [text]
    return list(dict.fromkeys([text, text.lower(), text.upper(), text.title(), text.capitalize()]))


def split_candidate_tokens(text: str) -> list[str]:
    tokens = re.split(r"[\s./\\:_\-?&=@#\[\](){}<>\"'，。！？、；：]+", text)
    return [token for token in tokens if token]


def build_expanded_wordlist(source: Path, dest: Path, limit: int = WORDLIST_EXPANSION_LIMIT) -> int:
    raw = source.read_bytes()
    text = clean_output(decode_bytes(raw))
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    candidates: dict[str, None] = {}

    def add(value: str) -> bool:
        value = value.strip("\r\n")
        if not value or len(value) > 256:
            return len(candidates) >= limit
        candidates.setdefault(value, None)
        return len(candidates) >= limit

    def add_with_case(value: str) -> bool:
        for variant in case_variants(value):
            if add(variant):
                return True
        return False

    line_tokens: list[list[str]] = []
    token_pool: list[str] = []
    token_seen: set[str] = set()

    for line in lines:
        if add_with_case(line):
            break
        compact = re.sub(r"\s+", "", line)
        if compact != line and add_with_case(compact):
            break
        tokens = split_candidate_tokens(line)
        if tokens:
            line_tokens.append(tokens)
        for token in tokens:
            if add_with_case(token):
                break
            key = token.lower()
            if key not in token_seen:
                token_seen.add(key)
                token_pool.append(token)
            for char in token:
                if not char.isspace() and add(char):
                    break
        if len(candidates) >= limit:
            break

    for tokens in line_tokens:
        if len(candidates) >= limit:
            break
        usable = tokens[:8]
        if len(usable) < 2:
            continue
        for joiner in WORDLIST_JOINERS:
            if add(joiner.join(usable)):
                break
            if add(joiner.join(reversed(usable))):
                break
            if len(usable) > 2 and add(joiner.join([usable[0], usable[-1]])):
                break

    pool = token_pool[:120]
    for first in pool:
        if len(candidates) >= limit:
            break
        for second in pool:
            if len(candidates) >= limit:
                break
            if first == second:
                continue
            for joiner in WORDLIST_JOINERS:
                if add(first + joiner + second):
                    break

    small_pool = token_pool[:32]
    for first in small_pool:
        if len(candidates) >= limit:
            break
        for second in small_pool:
            if len(candidates) >= limit:
                break
            if first == second:
                continue
            for third in small_pool:
                if len(candidates) >= limit:
                    break
                if third in {first, second}:
                    continue
                for joiner in WORDLIST_JOINERS:
                    if add(joiner.join([first, second, third])):
                        break

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(candidates.keys()) + ("\n" if candidates else ""), encoding="utf-8", newline="\n")
    return len(candidates)


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


def hidden_startup() -> tuple[int, subprocess.STARTUPINFO | None]:
    if os.name != "nt":
        return 0, None
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    return subprocess.CREATE_NO_WINDOW, startupinfo


def load_private_font() -> None:
    if os.name != "nt":
        return
    for font_path in (RESOURCE_DIR / FONT_FILE_NAME, APP_DIR / FONT_FILE_NAME):
        if not font_path.exists():
            continue
        try:
            ctypes.windll.gdi32.AddFontResourceExW(str(font_path), 0x10, 0)
        except Exception:
            pass
        return


def quote_command(args: list[str]) -> str:
    return " ".join(subprocess.list2cmdline([arg]) for arg in args)


def estimate_mask_length(mask: str) -> int:
    length = 0
    i = 0
    while i < len(mask):
        if mask[i] == "?" and i + 1 < len(mask):
            length += 1
            i += 2
            continue
        length += 1
        i += 1
    return length


def summarize_masks(masks: list[str]) -> str:
    lengths = [estimate_mask_length(mask.strip()) for mask in masks if mask.strip()]
    if not lengths:
        return "-"
    unique = sorted(set(lengths))
    if len(unique) == 1:
        return f"{unique[0]} 位"
    return f"{unique[0]}-{unique[-1]} 位 ({len(unique)} 種長度)"


def count_text_lines(path: Path, limit: int = 5_000_000) -> str:
    try:
        count = 0
        with path.open("rb") as fh:
            for raw in fh:
                if raw.strip():
                    count += 1
                if count >= limit:
                    return f"至少 {limit:,} 筆"
        return f"{count:,} 筆"
    except Exception:
        return "無法統計"


def merge_wordlist_files(sources: list[Path], dest: Path, limit: int = 5_000_000) -> int:
    dest.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with dest.open("w", encoding="utf-8", newline="\n") as out:
        for source in sources:
            try:
                with source.open("rb") as fh:
                    for raw in fh:
                        line = decode_bytes(raw).strip()
                        if not line:
                            continue
                        out.write(line + "\n")
                        count += 1
                        if count >= limit:
                            return count
            except Exception:
                continue
    return count


def format_elapsed(seconds: float | None) -> str:
    if seconds is None:
        return "-"
    total = max(0, int(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02}:{minutes:02}:{seconds:02}" if hours else f"{minutes:02}:{seconds:02}"


class CommandRunner:
    def __init__(self, app: "PasswordToolGUI") -> None:
        self.app = app
        self.process: subprocess.Popen[bytes] | None = None
        self.thread: threading.Thread | None = None
        self.lock = threading.Lock()
        self.job_lock = threading.Lock()
        self.current_name = ""
        self.log_path: Path | None = None
        self.on_finish = None
        self.started_at: float | None = None
        self.last_elapsed: float | None = None
        self.cancel_requested = False

    def running(self) -> bool:
        with self.lock:
            return self.process is not None and self.process.poll() is None

    def start(self, name: str, args: list[str], cwd: str | None = None, log_path: Path | None = None, on_finish=None) -> bool:
        if not self.job_lock.acquire(blocking=False):
            messagebox.showwarning("已有工作執行中", "請先停止或等待目前工作完成。")
            return False
        creationflags, startupinfo = hidden_startup()
        try:
            proc = subprocess.Popen(
                args,
                cwd=cwd or None,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                creationflags=creationflags,
                startupinfo=startupinfo,
            )
        except Exception as exc:
            self.job_lock.release()
            messagebox.showerror("啟動失敗", str(exc))
            return False
        with self.lock:
            self.process = proc
            self.current_name = name
            self.log_path = log_path
            self.on_finish = on_finish
            self.started_at = time.monotonic()
            self.last_elapsed = None
            self.cancel_requested = False
        start_text = (
            f"\n[{time.strftime('%H:%M:%S')}] 啟動 {name}\n"
            f"工作目錄：{cwd or Path.cwd()}\n"
            f"Session 記錄：{log_path or '未指定'}\n"
            f"執行命令：{quote_command(args)}\n"
        )
        session_start_text = start_text + "\n"
        self.app.log(start_text)
        self._append_session_log(session_start_text)
        self.thread = threading.Thread(target=self._reader, args=(proc, name), daemon=True)
        self.thread.start()
        self.app.set_status(f"{name} 執行中")
        return True

    def capture(self, name: str, args: list[str], cwd: str | None = None) -> subprocess.CompletedProcess[bytes]:
        if not self.job_lock.acquire(blocking=False):
            raise RuntimeError("已有工作執行中，請先停止或等待目前工作完成。")
        creationflags, startupinfo = hidden_startup()
        try:
            proc = subprocess.Popen(
                args,
                cwd=cwd or None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=creationflags,
                startupinfo=startupinfo,
            )
        except Exception:
            self.job_lock.release()
            raise
        with self.lock:
            self.process = proc
            self.current_name = name
            self.started_at = time.monotonic()
            self.last_elapsed = None
            self.cancel_requested = False
        self.app.enqueue_status(f"{name} 執行中")
        cancelled = False
        try:
            stdout, stderr = proc.communicate()
            with self.lock:
                cancelled = self.cancel_requested
            if cancelled:
                raise InterruptedError(f"{name} 已停止")
            return subprocess.CompletedProcess(args, proc.returncode, stdout, stderr)
        finally:
            with self.lock:
                if self.process is proc:
                    self.process = None
                    if self.started_at is not None:
                        self.last_elapsed = time.monotonic() - self.started_at
                    self.started_at = None
            self.job_lock.release()
            self.app.enqueue_status(f"{name} {'已停止' if cancelled else '已結束'}")

    def elapsed_seconds(self) -> float | None:
        with self.lock:
            if self.started_at is None:
                return self.last_elapsed
            return time.monotonic() - self.started_at

    def _append_session_log(self, text: str) -> None:
        path = self.log_path
        if not path:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
        except Exception:
            pass

    def _reader(self, proc: subprocess.Popen[bytes], name: str) -> None:
        assert proc.stdout is not None
        while True:
            chunk = proc.stdout.readline()
            if not chunk:
                break
            text = clean_output(decode_bytes(chunk))
            self.app.enqueue_log(text)
            self._append_session_log(text)
        code = proc.wait()
        end_text = f"\n[{time.strftime('%H:%M:%S')}] {name} 結束，代碼 {code}\n"
        self.app.enqueue_log(end_text)
        self._append_session_log(end_text)
        finish_callback = None
        with self.lock:
            if self.process is proc:
                self.process = None
                if self.started_at is not None:
                    self.last_elapsed = time.monotonic() - self.started_at
                self.started_at = None
                finish_callback = self.on_finish
                self.log_path = None
                self.on_finish = None
                cancelled = self.cancel_requested
            else:
                cancelled = False
        self.job_lock.release()
        self.app.enqueue_status(f"{name} {'已停止' if cancelled else '已結束'}")
        if finish_callback:
            self.app.enqueue_ui(lambda: finish_callback(code))

    def send_key(self, key: str) -> None:
        with self.lock:
            proc = self.process
        if not proc or proc.poll() is not None or not proc.stdin:
            messagebox.showinfo("無執行中工作", "目前沒有可控制的工作。")
            return
        try:
            proc.stdin.write(key.encode("ascii", errors="ignore"))
            proc.stdin.flush()
            self.app.log(f"\n[控制] 已送出 {key!r}\n")
        except Exception as exc:
            messagebox.showerror("控制失敗", str(exc))

    def stop(self) -> None:
        with self.lock:
            proc = self.process
            if proc and proc.poll() is None:
                self.cancel_requested = True
        if not proc or proc.poll() is not None:
            messagebox.showinfo("無執行中工作", "目前沒有可停止的工作。")
            return
        try:
            proc.terminate()
            self.app.log("\n[控制] 已要求停止目前工作\n")
        except Exception as exc:
            messagebox.showerror("停止失敗", str(exc))

    def wait(self, timeout: float = 5) -> None:
        with self.lock:
            proc = self.process
        if not proc or proc.poll() is not None:
            return
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


class PasswordToolGUI(tk.Tk):
    def __init__(self) -> None:
        load_private_font()
        super().__init__()
        self.title("密碼工具 GUI")
        self.geometry("1360x860")
        self.minsize(1180, 720)
        self.config_data = load_config()
        try:
            save_config(self.config_data)
        except Exception:
            pass
        self.log_queue: queue.Queue[str] = queue.Queue()
        self.status_queue: queue.Queue[str] = queue.Queue()
        self.ui_queue: queue.Queue[object] = queue.Queue()
        self._tools_setup_lock = threading.Lock()
        self.runner = CommandRunner(self)
        self.extract_thread: threading.Thread | None = None
        self.auto_thread: threading.Thread | None = None
        self.conversion_cancel = threading.Event()
        self.converter_names: list[str] = []
        self.setting_vars: dict[str, tk.StringVar] = {}
        self._build_style()
        self._build_ui()
        self.refresh_converters()
        self.after(80, self._drain_queues)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(300, self.ensure_tools_on_startup)

    def _build_style(self) -> None:
        self.configure(bg=BG)
        self.option_add("*Font", (UI_FONT, 10))
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(".", font=(UI_FONT, 10), background=BG, foreground=TEXT)
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
        style.configure("Title.TLabel", background=BG, foreground=TEXT, font=(UI_FONT, 18, "bold"))
        style.configure("PanelTitle.TLabel", background=SURFACE, foreground=TEXT, font=(UI_FONT, 15, "bold"))
        style.configure("Header.TLabel", background=BG, foreground=TEXT, font=(UI_FONT, 12, "bold"))
        style.configure("MetricValue.TLabel", background=SURFACE, foreground=TEXT, font=(MONO_FONT, 13, "bold"))
        style.configure("MetricName.TLabel", background=SURFACE, foreground=MUTED, font=(UI_FONT, 9))
        style.configure("Status.TLabel", anchor="w", background=BG, foreground=MUTED)
        style.configure("Pill.TLabel", background="#EAF2FF", foreground=ACCENT_DARK, padding=(10, 4), font=(UI_FONT, 9, "bold"))
        style.configure("StatusBar.TFrame", background="#F8FAFC")
        style.configure("StatusBar.TLabel", background="#F8FAFC", foreground=TEXT, font=(UI_FONT, 9))
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
        style.configure("Treeview", background="#FFFFFF", fieldbackground="#FFFFFF", foreground=TEXT, rowheight=30, bordercolor="#E5E7EB", lightcolor="#E5E7EB", darkcolor="#E5E7EB", font=(UI_FONT, 10))
        style.configure("Treeview.Heading", background="#FFFFFF", foreground=TEXT, relief="flat", bordercolor="#E5E7EB", font=(UI_FONT, 10))
        style.map("Treeview", background=[("selected", "#E8F2FF")], foreground=[("selected", TEXT)])

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
        ttk.Label(topbar, text="選檔、自動偵測、破解、集中輸出", style="Muted.TLabel").grid(row=1, column=0, sticky="w", pady=(4, 0))
        ttk.Label(topbar, textvariable=self.status_var, style="Pill.TLabel").grid(row=0, column=1, rowspan=2, sticky="e", padx=(12, 14))
        top_actions = ttk.Frame(topbar, style="TopBarInner.TFrame")
        top_actions.grid(row=0, column=2, rowspan=2, sticky="e")
        ttk.Button(top_actions, text="選擇檔案並開始", command=self.select_and_auto_start, style="Accent.TButton").pack(side="left", padx=(0, 8))
        ttk.Button(top_actions, text="檢查環境", command=lambda: self.ensure_tools_async(force_download=True)).pack(side="left", padx=(0, 8))
        self.advanced_toggle = ttk.Button(top_actions, command=lambda: self.set_advanced_visible(not self._advanced_visible))
        self.advanced_toggle.pack(side="left", padx=(0, 8))
        ttk.Button(top_actions, text="停止", command=self.stop_current_work, style="Danger.TButton").pack(side="left")

        body = ttk.Frame(root, style="Shell.TFrame")
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        launcher = ttk.Frame(body, width=370, padding=16, style="Panel.TFrame")
        launcher.grid(row=0, column=0, sticky="nsw", padx=(0, 14))
        launcher.grid_propagate(False)
        self._build_launcher_panel(launcher)

        workspace = ttk.Frame(body, style="Shell.TFrame")
        workspace.grid(row=0, column=1, sticky="nsew")
        workspace.columnconfigure(0, weight=1)
        workspace.rowconfigure(1, weight=1)

        jobs_panel = ttk.Frame(workspace, padding=12, style="Panel.TFrame")
        jobs_panel.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        jobs_panel.columnconfigure(0, weight=1)
        jobs_panel.rowconfigure(1, weight=1)
        jobs_head = ttk.Frame(jobs_panel, style="Panel.TFrame")
        jobs_head.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        jobs_head.columnconfigure(0, weight=1)
        ttk.Label(jobs_head, text="工作佇列", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Button(jobs_head, text="清空記錄", command=self.clear_output_view).grid(row=0, column=1, padx=(8, 0))
        ttk.Button(jobs_head, text="開啟輸出資料夾", command=self.open_output_folder).grid(row=0, column=2, padx=(8, 0))
        self.jobs_tree = ttk.Treeview(
            jobs_panel,
            columns=("size", "progress", "status", "mode", "speed", "output"),
            show="tree headings",
            selectmode="browse",
            height=4,
        )
        self.jobs_tree.heading("#0", text="名稱", anchor="w")
        self.jobs_tree.heading("size", text="大小", anchor="e")
        self.jobs_tree.heading("progress", text="進度", anchor="center")
        self.jobs_tree.heading("status", text="狀態", anchor="center")
        self.jobs_tree.heading("mode", text="模式", anchor="w")
        self.jobs_tree.heading("speed", text="速度", anchor="e")
        self.jobs_tree.heading("output", text="輸出", anchor="w")
        self.jobs_tree.column("#0", width=320, minwidth=180, stretch=True)
        self.jobs_tree.column("size", width=100, anchor="e", stretch=False)
        self.jobs_tree.column("progress", width=100, anchor="center", stretch=False)
        self.jobs_tree.column("status", width=120, anchor="center", stretch=False)
        self.jobs_tree.column("mode", width=150, anchor="w", stretch=False)
        self.jobs_tree.column("speed", width=130, anchor="e", stretch=False)
        self.jobs_tree.column("output", width=320, anchor="w", stretch=True)
        self.jobs_tree.grid(row=1, column=0, sticky="nsew")
        jobs_scroll = ttk.Scrollbar(jobs_panel, orient="vertical", command=self.jobs_tree.yview)
        jobs_scroll.grid(row=1, column=1, sticky="ns")
        self.jobs_tree.configure(yscrollcommand=jobs_scroll.set)

        details_panel = ttk.Frame(workspace, style="Shell.TFrame")
        details_panel.grid(row=1, column=0, sticky="nsew")
        details_panel.columnconfigure(0, weight=1)
        details_panel.rowconfigure(0, weight=1)
        self.notebook = ttk.Notebook(details_panel)
        self.notebook.grid(row=0, column=0, sticky="nsew")

        self.output_tab = ttk.Frame(self.notebook, padding=12, style="App.TFrame")
        self.extract_tab = ttk.Frame(self.notebook, padding=12, style="App.TFrame")
        self.hashcat_tab = ttk.Frame(self.notebook, padding=12, style="App.TFrame")
        self.john_tab = ttk.Frame(self.notebook, padding=12, style="App.TFrame")
        self.settings_tab = ttk.Frame(self.notebook, padding=12, style="App.TFrame")
        self.help_tab = ttk.Frame(self.notebook, padding=12, style="App.TFrame")

        self.notebook.add(self.output_tab, text="狀態")
        self.notebook.add(self.extract_tab, text="雜湊轉換")
        self.notebook.add(self.hashcat_tab, text="Hashcat")
        self.notebook.add(self.john_tab, text="John")
        self.notebook.add(self.settings_tab, text="設定")
        self.notebook.add(self.help_tab, text="說明")

        self._build_output_tab()
        self._build_extract_tab()
        self._build_hashcat_tab()
        self._build_john_tab()
        self._build_settings_tab()
        self._build_help_tab()
        self._advanced_tabs = (self.extract_tab, self.hashcat_tab, self.john_tab, self.settings_tab)
        self.set_advanced_visible(False)

        bottom = ttk.Frame(root, padding=(2, 10, 2, 0), style="StatusBar.TFrame")
        bottom.grid(row=2, column=0, sticky="ew")
        ttk.Label(bottom, text="密碼工具GUI", style="StatusBar.TLabel").pack(side="left", padx=(0, 18))
        ttk.Label(bottom, textvariable=self.status_var, style="StatusBar.TLabel").pack(side="left", fill="x", expand=True)
        ttk.Label(bottom, textvariable=self.output_speed_var, style="StatusBar.TLabel").pack(side="right", padx=(18, 0))

    def set_advanced_visible(self, visible: bool) -> None:
        self._advanced_visible = visible
        state = "normal" if visible else "hidden"
        for tab in self._advanced_tabs:
            self.notebook.tab(tab, state=state)
        self.advanced_toggle.configure(text="隱藏進階工具" if visible else "顯示進階工具")

    def _build_launcher_panel(self, parent: ttk.Frame) -> None:
        self.quick_input = tk.StringVar()
        self.quick_wordlist = tk.StringVar(value=self.config_data.get("default_wordlist", ""))
        self.quick_combo_wordlist = tk.StringVar(value=self.config_data.get("combo_wordlist", ""))
        self.quick_combo_key = tk.StringVar(value=self.config_data.get("combo_key", ""))
        self.common_wordlist = tk.StringVar(value=COMMON_WORDLISTS[1][0])
        self.quick_auto_download = tk.BooleanVar(value=True)
        self.quick_expand_wordlist = tk.BooleanVar(value=True)
        self.quick_follow_order = tk.BooleanVar(value=config_bool(self.config_data.get("auto_follow_order", "1"), True))
        self.quick_status = tk.StringVar(value="有字典會優先拆字組合；沒有字典才使用遮罩破解。")

        parent.columnconfigure(0, weight=1)
        ttk.Label(parent, text="快速破解", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(parent, text="支援壓縮包、Office、PDF 與常見雜湊檔。", style="Muted.TLabel", wraplength=280).grid(row=1, column=0, sticky="w", pady=(4, 18))

        ttk.Label(parent, text="目標檔案", style="MetricName.TLabel").grid(row=2, column=0, sticky="w")
        file_box = ttk.Frame(parent, style="Panel.TFrame")
        file_box.grid(row=3, column=0, sticky="ew", pady=(6, 12))
        file_box.columnconfigure(0, weight=1)
        ttk.Entry(file_box, textvariable=self.quick_input).grid(row=0, column=0, sticky="ew")
        ttk.Button(file_box, text="瀏覽", command=self._browse_quick_file).grid(row=0, column=1, padx=(8, 0))

        ttk.Button(parent, text="選擇檔案並開始", command=self.select_and_auto_start, style="Accent.TButton").grid(row=4, column=0, sticky="ew", pady=(0, 10))
        ttk.Button(parent, text="開始目前檔案", command=self.auto_start_selected).grid(row=5, column=0, sticky="ew", pady=(0, 18))

        ttk.Label(parent, text="字典檔（可空白）", style="MetricName.TLabel").grid(row=6, column=0, sticky="w")
        dict_box = ttk.Frame(parent, style="Panel.TFrame")
        dict_box.grid(row=7, column=0, sticky="ew", pady=(6, 12))
        dict_box.columnconfigure(0, weight=1)
        ttk.Entry(dict_box, textvariable=self.quick_wordlist).grid(row=0, column=0, sticky="ew")
        ttk.Button(dict_box, text="瀏覽", command=lambda: self._browse_file(self.quick_wordlist)).grid(row=0, column=1, padx=(8, 0))

        ttk.Checkbutton(parent, text="依序破解：字典 → 組合 → 硬破解", variable=self.quick_follow_order, style="Card.TCheckbutton").grid(row=8, column=0, sticky="w", pady=(0, 8))
        ttk.Checkbutton(parent, text="導入字典時自動拆字與組合", variable=self.quick_expand_wordlist, style="Card.TCheckbutton").grid(row=9, column=0, sticky="w", pady=(0, 14))

        ttk.Label(parent, text="組合密碼檔（可空白）", style="MetricName.TLabel").grid(row=10, column=0, sticky="w")
        combo_box = ttk.Frame(parent, style="Panel.TFrame")
        combo_box.grid(row=11, column=0, sticky="ew", pady=(6, 12))
        combo_box.columnconfigure(0, weight=1)
        ttk.Entry(combo_box, textvariable=self.quick_combo_wordlist).grid(row=0, column=0, sticky="ew")
        ttk.Button(combo_box, text="瀏覽", command=lambda: self._browse_file(self.quick_combo_wordlist)).grid(row=0, column=1, padx=(8, 0))

        ttk.Label(parent, text="組合 Key / 提示詞（可空白）", style="MetricName.TLabel").grid(row=12, column=0, sticky="w")
        ttk.Entry(parent, textvariable=self.quick_combo_key).grid(row=13, column=0, sticky="ew", pady=(6, 12))

        ttk.Label(parent, text="常見字典", style="MetricName.TLabel").grid(row=14, column=0, sticky="w")
        ttk.Combobox(parent, textvariable=self.common_wordlist, values=[item[0] for item in COMMON_WORDLISTS], state="readonly").grid(row=15, column=0, sticky="ew", pady=(6, 8))
        ttk.Button(parent, text="下載並導入字典", command=self.download_selected_wordlist).grid(row=16, column=0, sticky="ew", pady=(0, 14))

        ttk.Checkbutton(parent, text="缺少 hashcat / John 時自動下載", variable=self.quick_auto_download, style="Card.TCheckbutton").grid(row=17, column=0, sticky="w", pady=(0, 10))
        ttk.Button(parent, text="檢查/下載環境", command=lambda: self.ensure_tools_async(force_download=True)).grid(row=18, column=0, sticky="ew", pady=(0, 8))
        ttk.Button(parent, text="停止目前工作", command=self.stop_current_work, style="Danger.TButton").grid(row=19, column=0, sticky="ew", pady=(0, 14))

        status_box = ttk.Frame(parent, padding=12, style="Soft.TFrame")
        status_box.grid(row=20, column=0, sticky="ew")
        status_box.columnconfigure(0, weight=1)
        ttk.Label(status_box, text="目前狀態", style="Soft.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(status_box, textvariable=self.quick_status, style="Soft.TLabel", wraplength=260).grid(row=1, column=0, sticky="w", pady=(6, 0))

    def _browse_quick_file(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("支援檔案", "*.zip *.zipx *.rar *.7z *.pdf *.doc *.docx *.xls *.xlsx *.ppt *.pptx *.odt *.ods *.odp *.hash *.txt"), ("所有檔案", "*.*")])
        if path:
            self.quick_input.set(path)
            self.update_jobs_tree(name=Path(path).name, status="等待開始")

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

    def _metric_card(self, parent: ttk.Widget, column: int, title: str, var: tk.StringVar) -> ttk.Frame:
        card = ttk.Frame(parent, padding=(14, 12), style="Card.TFrame")
        card.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 10, 0))
        parent.columnconfigure(column, weight=1)
        ttk.Label(card, text=title, style="MetricName.TLabel").pack(anchor="w")
        ttk.Label(card, textvariable=var, style="MetricValue.TLabel").pack(anchor="w", pady=(6, 0))
        return card

    def _build_quick_tab(self) -> None:
        self.quick_input = tk.StringVar()
        self.quick_wordlist = tk.StringVar()
        self.common_wordlist = tk.StringVar(value=COMMON_WORDLISTS[1][0])
        self.quick_auto_download = tk.BooleanVar(value=True)
        self.quick_status = tk.StringVar(value="選擇壓縮包、Office、PDF、RAR、7Z 或雜湊檔後即可開始。")

        frame = self.quick_tab
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        ttk.Label(frame, text="傻瓜式自動破解", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(frame, text="選檔後自動偵測格式、準備工具、轉換雜湊並開始破解。", style="Status.TLabel").grid(row=0, column=0, sticky="w", pady=(34, 0))

        card = self._card(frame, 1, 0, pady=(22, 0))
        card.columnconfigure(1, weight=1)
        ttk.Label(card, text="目標檔案", style="Card.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8))
        ttk.Entry(card, textvariable=self.quick_input).grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 12))
        ttk.Button(card, text="選擇檔案並開始", command=self.select_and_auto_start, style="Accent.TButton").grid(row=1, column=2, padx=(12, 0), pady=(0, 12))

        ttk.Label(card, text="字典檔（可空白）", style="Card.TLabel").grid(row=2, column=0, sticky="w", pady=(4, 8))
        ttk.Entry(card, textvariable=self.quick_wordlist).grid(row=3, column=0, columnspan=2, sticky="ew")
        ttk.Button(card, text="瀏覽", command=lambda: self._browse_file(self.quick_wordlist)).grid(row=3, column=2, padx=(12, 0))

        ttk.Label(card, text="常見字典下載", style="Card.TLabel").grid(row=4, column=0, sticky="w", pady=(14, 8))
        ttk.Combobox(card, textvariable=self.common_wordlist, values=[item[0] for item in COMMON_WORDLISTS], state="readonly").grid(row=5, column=0, columnspan=2, sticky="ew")
        ttk.Button(card, text="下載並導入", command=self.download_selected_wordlist).grid(row=5, column=2, padx=(12, 0))

        ttk.Checkbutton(card, text="缺少 hashcat / John 時自動下載", variable=self.quick_auto_download, style="Card.TCheckbutton").grid(row=6, column=0, columnspan=3, sticky="w", pady=(14, 4))

        buttons = ttk.Frame(card, style="Card.TFrame")
        buttons.grid(row=7, column=0, columnspan=3, sticky="w", pady=(14, 0))
        ttk.Button(buttons, text="開始自動破解", command=self.auto_start_selected, style="Accent.TButton").pack(side="left", padx=(0, 10))
        ttk.Button(buttons, text="檢查/下載環境", command=lambda: self.ensure_tools_async(force_download=True)).pack(side="left", padx=(0, 10))
        ttk.Button(buttons, text="停止目前工作", command=self.stop_current_work, style="Danger.TButton").pack(side="left")

        status_card = self._card(frame, 2, 0, pady=(14, 0))
        ttk.Label(status_card, text="目前狀態", style="MetricName.TLabel").pack(anchor="w")
        ttk.Label(status_card, textvariable=self.quick_status, style="Card.TLabel", wraplength=920).pack(anchor="w", pady=(6, 0))
        ttk.Label(status_card, text="輸出會集中在 exe 旁的「密碼工具GUI_輸出」資料夾。沒有指定字典時會使用短遮罩優先策略。", style="Muted.TLabel", wraplength=920).pack(anchor="w", pady=(8, 0))

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
        ttk.Button(frame, text="建議輸出路徑", command=self.suggest_extract_output).grid(row=1, column=3, padx=(8, 0))
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
        ttk.Checkbutton(checks, text="中文/空白路徑使用安全暫存名", variable=self.extract_safe_copy).pack(side="left", padx=(0, 14))
        ttk.Checkbutton(checks, text="完成後填入 Hashcat", variable=self.extract_fill_hashcat).pack(side="left", padx=(0, 14))
        ttk.Checkbutton(checks, text="完成後填入 John", variable=self.extract_fill_john).pack(side="left")

        buttons = ttk.Frame(frame)
        buttons.grid(row=6, column=1, sticky="w", pady=(10, 8))
        ttk.Button(buttons, text="開始轉換", command=self.start_extract).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="開啟輸出資料夾", command=self.open_output_folder).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="填入兩套工具", command=self.fill_hash_targets).pack(side="left")

        info = (
            "支援 ZIP/RAR/7Z、Office、PDF、DMG、GPG、KeePass、BitLocker 等 John 轉換器。\n"
            "缺少 hashcat / John 會自動下載；.pl 轉換器仍需要手動安裝 Perl。"
        )
        ttk.Label(frame, text=info, foreground="#555555", wraplength=880).grid(row=7, column=1, columnspan=3, sticky="w", pady=(8, 0))

    def _build_hashcat_tab(self) -> None:
        self.hashcat_hash_file = tk.StringVar()
        self.hashcat_mode = tk.StringVar(value=HASHCAT_MODES[0])
        self.hashcat_attack = tk.StringVar(value=HASHCAT_ATTACKS[0])
        self.hashcat_wordlist = tk.StringVar(value=self.config_data.get("default_wordlist", ""))
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
        ttk.Checkbutton(options, text="--username", variable=self.hashcat_username).pack(side="left", padx=(0, 10))
        ttk.Checkbutton(options, text="--remove", variable=self.hashcat_remove).pack(side="left", padx=(0, 10))
        ttk.Checkbutton(options, text="-O 最佳化", variable=self.hashcat_optimized).pack(side="left", padx=(0, 10))
        ttk.Label(options, text="工作量 -w").pack(side="left", padx=(8, 4))
        ttk.Entry(options, textvariable=self.hashcat_workload, width=4).pack(side="left")
        ttk.Label(options, text="裝置 -d").pack(side="left", padx=(12, 4))
        ttk.Entry(options, textvariable=self.hashcat_device, width=12).pack(side="left")
        ttk.Label(options, text="狀態秒數").pack(side="left", padx=(12, 4))
        ttk.Entry(options, textvariable=self.hashcat_status_timer, width=5).pack(side="left")

        session_row = ttk.Frame(frame)
        session_row.grid(row=10, column=1, sticky="ew", pady=4)
        ttk.Label(frame, text="Session").grid(row=10, column=0, sticky="w", padx=(0, 8), pady=4)
        session_row.columnconfigure(0, weight=1)
        ttk.Entry(session_row, textvariable=self.hashcat_session).grid(row=0, column=0, sticky="ew")
        ttk.Label(frame, text="進階參數").grid(row=11, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(frame, textvariable=self.hashcat_extra).grid(row=11, column=1, sticky="ew", pady=4)

        buttons = ttk.Frame(frame)
        buttons.grid(row=12, column=1, columnspan=3, sticky="w", pady=(10, 8))
        ttk.Button(buttons, text="開始 hashcat", command=self.start_hashcat).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="顯示已破解", command=self.hashcat_show).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="自訂執行", command=self.hashcat_custom).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="裝置資訊", command=self.hashcat_devices).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="基準測試", command=self.hashcat_benchmark).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="說明", command=self.hashcat_help).pack(side="left", padx=(0, 8))

        controls = ttk.Frame(frame)
        controls.grid(row=13, column=1, sticky="w", pady=4)
        ttk.Button(controls, text="狀態(s)", command=lambda: self.runner.send_key("s")).pack(side="left", padx=(0, 8))
        ttk.Button(controls, text="暫停(p)", command=lambda: self.runner.send_key("p")).pack(side="left", padx=(0, 8))
        ttk.Button(controls, text="繼續(r)", command=lambda: self.runner.send_key("r")).pack(side="left", padx=(0, 8))
        ttk.Button(controls, text="檢查點(c)", command=lambda: self.runner.send_key("c")).pack(side="left", padx=(0, 8))
        ttk.Button(controls, text="離開(q)", command=lambda: self.runner.send_key("q")).pack(side="left")

        note = "進階參數會原樣加入命令，可使用 hashcat 全部選項；GUI 不顯示任何命令視窗。"
        ttk.Label(frame, text=note, foreground="#555555").grid(row=14, column=1, sticky="w", pady=(8, 0))

    def _build_john_tab(self) -> None:
        self.john_hash_file = tk.StringVar()
        self.john_format = tk.StringVar()
        self.john_mode = tk.StringVar(value=JOHN_MODES[0])
        self.john_wordlist = tk.StringVar(value=self.config_data.get("default_wordlist", ""))
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
        ttk.Entry(compact, textvariable=self.john_session).grid(row=0, column=1, sticky="ew", padx=(6, 16))
        ttk.Label(compact, text="--fork").grid(row=0, column=2, sticky="w")
        ttk.Entry(compact, textvariable=self.john_fork, width=8).grid(row=0, column=3, sticky="w", padx=(6, 0))

        ttk.Label(frame, text="進階參數").grid(row=8, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(frame, textvariable=self.john_extra).grid(row=8, column=1, sticky="ew", pady=4)

        buttons = ttk.Frame(frame)
        buttons.grid(row=9, column=1, columnspan=3, sticky="w", pady=(10, 8))
        ttk.Button(buttons, text="開始 John", command=self.start_john).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="顯示已破解", command=self.john_show).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="自訂執行", command=self.john_custom).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="查狀態", command=self.john_status).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="恢復 Session", command=self.john_restore).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="測速", command=self.john_test).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="說明", command=self.john_help).pack(side="left")

        note = "John 也可直接在進階參數使用所有官方選項，例如 --incremental、--external、--subsets。"
        ttk.Label(frame, text=note, foreground="#555555").grid(row=10, column=1, sticky="w", pady=(8, 0))

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
        ttk.Button(actions, text="停止目前工作", command=self.stop_current_work, style="Danger.TButton").pack(side="left")

        metrics = ttk.Frame(frame, style="App.TFrame")
        metrics.grid(row=1, column=0, sticky="ew", pady=(12, 10))
        metric_items = [
            ("狀態", self.output_status_var),
            ("進度", self.output_progress_var),
            ("耗時", self.output_elapsed_var),
            ("速度", self.output_speed_var),
            ("溫度", self.output_temp_var),
            ("已破解", self.output_recovered_var),
            ("位數", self.output_length_var),
            ("佇列", self.output_queue_var),
            ("候選", self.output_candidate_var),
        ]
        for idx, (title, var) in enumerate(metric_items):
            row, col = divmod(idx, 4)
            card = ttk.Frame(metrics, padding=(12, 8), style="Card.TFrame")
            card.grid(row=row, column=col, sticky="nsew", padx=(0 if col == 0 else 8, 0), pady=(0 if row == 0 else 8, 0))
            metrics.columnconfigure(col, weight=1)
            ttk.Label(card, text=title, style="MetricName.TLabel").pack(anchor="w")
            ttk.Label(card, textvariable=var, style="MetricValue.TLabel").pack(anchor="w", pady=(4, 0))

        middle = ttk.Frame(frame, style="App.TFrame")
        middle.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        middle.columnconfigure(0, weight=3)
        middle.columnconfigure(1, weight=2)

        progress_card = self._card(middle, 0, 0, padx=(0, 10))
        progress_card.columnconfigure(0, weight=1)
        ttk.Label(progress_card, text="破解概覽", style="MetricName.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(progress_card, textvariable=self.output_mode_var, style="Card.TLabel").grid(row=0, column=1, sticky="e")
        ttk.Progressbar(progress_card, variable=self.progress_value, maximum=100).grid(row=1, column=0, columnspan=2, sticky="ew", pady=(10, 8))
        ttk.Label(progress_card, textvariable=self.output_overview_var, style="Card.TLabel", wraplength=980).grid(row=2, column=0, columnspan=2, sticky="w")
        ttk.Label(progress_card, textvariable=self.output_file_var, style="Muted.TLabel", wraplength=980).grid(row=3, column=0, columnspan=2, sticky="w", pady=(6, 0))

        cracked_card = self._card(middle, 0, 1)
        cracked_card.rowconfigure(1, weight=1)
        cracked_card.columnconfigure(0, weight=1)
        ttk.Label(cracked_card, text="破解密碼", style="MetricName.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8))
        cracked_actions = ttk.Frame(cracked_card, style="Card.TFrame")
        cracked_actions.grid(row=0, column=1, sticky="e", pady=(0, 8))
        ttk.Button(cracked_actions, text="複製密碼", command=self.copy_cracked_passwords).pack(side="left", padx=(0, 8))
        ttk.Button(cracked_actions, text="開啟結果檔", command=self.open_cracked_file).pack(side="left")
        self.cracked_text = scrolledtext.ScrolledText(
            cracked_card,
            wrap="word",
            height=4,
            font=(MONO_FONT, 11),
            background="#F8FAFC",
            foreground=TEXT,
            insertbackground=TEXT,
            relief="flat",
            borderwidth=0,
            padx=12,
            pady=10,
        )
        self.cracked_text.grid(row=1, column=0, columnspan=2, sticky="nsew")
        self.cracked_text.insert("1.0", self.cracked_display_var.get())
        self.cracked_text.configure(state="disabled")

        details = self._card(frame, 3, 0)
        details.rowconfigure(1, weight=1)
        details.columnconfigure(0, weight=1)
        ttk.Label(details, text="詳細記錄", style="MetricName.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8))
        self.output = scrolledtext.ScrolledText(
            details,
            wrap="word",
            height=7,
            font=(MONO_FONT, 9),
            background="#FFFFFF",
            foreground=TEXT,
            insertbackground=TEXT,
            relief="solid",
            borderwidth=1,
            padx=12,
            pady=10,
        )
        self.output.grid(row=1, column=0, sticky="nsew")

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
            ("default_wordlist", "預設字典（可空白）"),
            ("auto_follow_order", "依序破解 1/0"),
            ("combo_wordlist", "組合密碼檔"),
            ("combo_key", "組合 Key / 提示詞"),
            ("output_dir", "輸出目錄"),
            ("tools_dir", "自動工具目錄"),
        ]
        for idx, (key, label) in enumerate(rows, start=1):
            var = tk.StringVar(value=self.config_data.get(key, ""))
            self.setting_vars[key] = var
            browse = "dir" if key in {"john_run_dir", "output_dir", "tools_dir"} else ("file" if key not in {"auto_follow_order", "combo_key"} else None)
            self._row(frame, idx, label, var, browse)
        buttons = ttk.Frame(frame)
        buttons.grid(row=len(rows) + 1, column=1, sticky="w", pady=(12, 8))
        ttk.Button(buttons, text="儲存設定", command=self.save_settings).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="自動偵測", command=self.detect_settings).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="健康檢查", command=self.health_check).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="開啟輸出資料夾", command=self.open_output_folder).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="開啟設定檔", command=self.open_config_file).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="匯入設定檔", command=self.import_config_file).pack(side="left")
        ttk.Label(frame, text=f"目前設定檔：{CONFIG_PATH}", foreground="#555555", wraplength=860).grid(row=len(rows) + 2, column=1, columnspan=2, sticky="w", pady=(8, 0))
        tip = "Perl 未安裝時，7z2john.pl、pdf2john.pl 等 .pl 轉換器會無法使用；安裝後在此指定路徑即可。"
        ttk.Label(frame, text=tip, foreground="#555555", wraplength=860).grid(row=len(rows) + 3, column=1, columnspan=2, sticky="w", pady=(8, 0))

    def _build_help_tab(self) -> None:
        frame = self.help_tab
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        text = scrolledtext.ScrolledText(frame, wrap="word", font=(UI_FONT, 10))
        text.grid(row=0, column=0, sticky="nsew")
        text.insert(
            "1.0",
            (
                "使用流程\n"
                "1. 在「快速破解」選擇 ZIP/RAR/7Z/Office/PDF 或雜湊檔。\n"
                "2. 工具會自動偵測環境、必要時下載 hashcat / John，並自動開始。\n"
                "3. 密碼、雜湊與記錄會集中在 exe 旁的「密碼工具GUI_輸出」資料夾。\n\n"
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
        hashcat_path = self.config_data.get("hashcat_path", "")
        rule_dir = Path(hashcat_path).parent / "rules" if hashcat_path else TOOLS_DIR / "hashcat" / "rules"
        if not rule_dir.exists():
            return []
        return [str(path) for path in sorted(rule_dir.rglob("*.rule"))]

    def refresh_converters(self) -> None:
        run_dir = Path(self.config_data.get("john_run_dir", ""))
        names: list[str] = []
        if run_dir.exists():
            for path in sorted(run_dir.glob("*2john.*")):
                if path.is_file():
                    names.append(path.name)
        self.converter_names = names
        values = ["自動偵測"] + names
        if hasattr(self, "converter_combo"):
            self.converter_combo.configure(values=values)
            if self.extract_converter.get() not in values:
                self.extract_converter.set("自動偵測")

    def enqueue_log(self, text: str) -> None:
        self.log_queue.put(text)

    def enqueue_status(self, text: str) -> None:
        self.status_queue.put(text)

    def enqueue_ui(self, callback) -> None:
        self.ui_queue.put(callback)

    def _drain_queues(self) -> None:
        try:
            while True:
                self.log(self.log_queue.get_nowait())
        except queue.Empty:
            pass
        try:
            while True:
                self.set_status(self.status_queue.get_nowait())
        except queue.Empty:
            pass
        try:
            while True:
                self.ui_queue.get_nowait()()
        except queue.Empty:
            pass
        self.update_elapsed()
        self.after(80, self._drain_queues)

    def log(self, text: str) -> None:
        self.update_output_dashboard(text)
        self.output.insert("end", text)
        self.output.see("end")

    def set_status(self, text: str) -> None:
        self.status_var.set(text)
        self.update_jobs_tree(status=text)
        self.refresh_output_overview()

    def clear_output_view(self) -> None:
        self.output.delete("1.0", "end")
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
        if hasattr(self, "jobs_tree"):
            for item in self.jobs_tree.get_children():
                self.jobs_tree.delete(item)

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
        if hasattr(self, "output_elapsed_var"):
            self.output_elapsed_var.set(format_elapsed(self.runner.elapsed_seconds()))

    def format_file_size(self, path: Path) -> str:
        try:
            size = path.stat().st_size
        except OSError:
            return "-"
        units = ("B", "KiB", "MiB", "GiB", "TiB")
        value = float(size)
        for unit in units:
            if value < 1024 or unit == units[-1]:
                return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
            value /= 1024
        return "-"

    def update_jobs_tree(self, name: str | None = None, status: str | None = None) -> None:
        if not hasattr(self, "jobs_tree"):
            return
        src_text = self.quick_input.get().strip() if hasattr(self, "quick_input") else ""
        src = Path(src_text) if src_text else None
        job_name = name or (src.name if src else "")
        if not job_name and hasattr(self, "output_job_var"):
            job_name = self.output_job_var.get()
        if not job_name or job_name == "尚未開始":
            return
        size = self.format_file_size(src) if src and src.exists() else "-"
        progress = self.output_progress_var.get() if hasattr(self, "output_progress_var") else "0%"
        job_status = status or (self.output_status_var.get() if hasattr(self, "output_status_var") else "就緒")
        mode = self.output_mode_var.get() if hasattr(self, "output_mode_var") else "-"
        speed = self.output_speed_var.get() if hasattr(self, "output_speed_var") else "-"
        output = self.output_file_var.get() if hasattr(self, "output_file_var") else ""
        if output == "尚未產生輸出":
            output = ""
        values = (
            size,
            self.short_metric(progress, 18),
            self.short_metric(job_status, 18),
            self.short_metric(mode, 28),
            self.short_metric(speed, 24),
            self.short_metric(output, 72),
        )
        if self.jobs_tree.exists("active"):
            self.jobs_tree.item("active", text=job_name, values=values)
        else:
            self.jobs_tree.insert("", "end", iid="active", text=job_name, values=values)
            self.jobs_tree.selection_set("active")
            self.jobs_tree.focus("active")

    def update_output_dashboard(self, text: str) -> None:
        if not hasattr(self, "output_status_var"):
            return
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if "啟動 " in line:
                self.output_job_var.set(line.strip("[]"))
                self.output_status_var.set("執行中")
            if "結束，代碼" in line:
                self.output_status_var.set("已結束")
                self.output_progress_var.set("100%" if "代碼 0" in line else self.output_progress_var.get())
                if "代碼 0" in line:
                    self.progress_value.set(100)
            if "[錯誤]" in line or "[環境錯誤]" in line or "[自動流程錯誤]" in line:
                self.output_status_var.set("需要處理")
            match = re.match(r"Status\.+:\s*(.+)", line, re.I)
            if match:
                self.output_status_var.set(match.group(1).strip())
            match = re.match(r"Hash\.Mode\.+:\s*(.+)", line, re.I)
            if match:
                self.output_mode_var.set(self.short_metric(match.group(1).strip(), 52))
            match = re.match(r"Input\.Mode\.+:\s*(.+)", line, re.I)
            if match:
                self.output_mode_var.set(self.short_metric(match.group(1).strip(), 52))
            match = re.match(r"Guess\.Mask\.+:\s*(.+)", line, re.I)
            if match:
                mask_text = match.group(1).strip()
                length_match = re.search(r"\[(\d+)\]\s*$", mask_text)
                if length_match:
                    self.output_length_var.set(f"{length_match.group(1)} 位")
                else:
                    self.output_length_var.set(f"{estimate_mask_length(mask_text)} 位")
            match = re.match(r"Guess\.Queue\.+:\s*(.+)", line, re.I)
            if match:
                self.output_queue_var.set(self.short_metric(match.group(1).strip(), 32))
            match = re.match(r"Candidates(?:\.#\d+)?\.+:\s*(.+)", line, re.I)
            if match:
                self.output_candidate_var.set(self.short_metric(match.group(1).strip(), 36))
            match = re.match(r"Speed(?:\.#\d+)?\.+:\s*(.+)", line, re.I)
            if match:
                self.output_speed_var.set(self.short_metric(match.group(1).strip().split("@", 1)[0].strip(), 28))
            match = re.match(r"Recovered\.+:\s*(.+)", line, re.I)
            if match:
                self.output_recovered_var.set(self.short_metric(match.group(1).strip(), 28))
            match = re.match(r"Progress\.+:\s*(.+)", line, re.I)
            if match:
                progress_text = match.group(1).strip()
                pct = re.search(r"\(([\d.]+)%\)", progress_text)
                if pct:
                    value = max(0.0, min(100.0, float(pct.group(1))))
                    self.progress_value.set(value)
                    self.output_progress_var.set(f"{value:.2f}%")
                else:
                    self.output_progress_var.set(progress_text)
            temps = re.findall(r"Temp:\s*([0-9]+c)", line, re.I)
            if temps:
                self.output_temp_var.set(" / ".join(temps).upper())
            john_speed = re.search(r"\b([0-9.]+[kmg]?[cp]?/s)\b", line, re.I)
            if john_speed and ("g " in line or "guesses" in line.lower()):
                self.output_speed_var.set(john_speed.group(1))
            john_guess = re.match(r"(\d+)g\s+", line, re.I)
            if john_guess:
                self.output_recovered_var.set(john_guess.group(1))
                self.output_status_var.set("執行中")
            trying = re.search(r"\b(?:trying|Try)\s*:?\s*(.+)$", line, re.I)
            if trying:
                self.output_candidate_var.set(self.short_metric(trying.group(1).strip(), 36))
            loaded = re.search(r"Loaded\s+(\d+)\s+password hash", line, re.I)
            if loaded:
                self.output_queue_var.set(f"已載入 {loaded.group(1)} hash")
            if "已輸出密碼：" in line or "_cracked.txt" in line:
                self.output_file_var.set(line)
        self.refresh_output_overview()
        self.update_jobs_tree()

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
            detected = find_tool_paths(self.config_data)
            self.config_data.update({k: v for k, v in detected.items() if v})
            if not self.config_data.get("hashcat_path") and auto_download:
                self.enqueue_log("\n找不到 hashcat，開始自動下載。\n")
                self.config_data["hashcat_path"] = self.download_hashcat()
            if not self.config_data.get("john_path") and auto_download:
                self.enqueue_log("\n找不到 John the Ripper，開始自動下載。\n")
                john_path, john_run = self.download_john()
                self.config_data["john_path"] = john_path
                self.config_data["john_run_dir"] = john_run
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
        self.config_data["tools_dir"] = str(TOOLS_DIR)
        save_config(self.config_data)
        self.refresh_converters()
        self.sync_config_to_ui()
        self.quick_status.set("工具環境已就緒。可直接選擇檔案開始。")

    def download_hashcat(self) -> str:
        url = latest_hashcat_url()
        archive_name = Path(urllib.parse.urlparse(url).path).name or "hashcat.7z"
        archive = DOWNLOADS_DIR / archive_name
        if not archive.exists():
            self.enqueue_log(f"下載：{url}\n")
            download_file(url, archive, self.enqueue_log)
        extract_archive(archive, TOOLS_DIR / "hashcat", self.enqueue_log)
        path = find_hashcat_under(TOOLS_DIR / "hashcat")
        if not path:
            raise SetupError("hashcat 已下載但找不到 hashcat.exe。", HASHCAT_DOWNLOAD_PAGE)
        return path

    def download_john(self) -> tuple[str, str]:
        url = latest_john_url()
        archive_name = Path(urllib.parse.urlparse(url).path).name or "john.7z"
        archive = DOWNLOADS_DIR / archive_name
        if not archive.exists():
            self.enqueue_log(f"下載：{url}\n")
            download_file(url, archive, self.enqueue_log)
        extract_archive(archive, TOOLS_DIR / "JohnRipper", self.enqueue_log)
        john_path, john_run = find_john_under(TOOLS_DIR / "JohnRipper")
        if not john_path:
            raise SetupError("John 已下載但找不到 john.exe。", JOHN_RELEASE_PAGE)
        return john_path, john_run

    def download_selected_wordlist(self) -> None:
        selected = self.common_wordlist.get()
        item = next((entry for entry in COMMON_WORDLISTS if entry[0] == selected), None)
        if not item:
            messagebox.showerror("字典錯誤", "請選擇要下載的字典。")
            return
        thread = threading.Thread(target=self._download_wordlist_worker, args=(item,), daemon=True)
        thread.start()

    def _download_wordlist_worker(self, item: tuple[str, str, str]) -> None:
        name, filename, url = item
        try:
            ensure_tool_dirs()
            dest = WORDLISTS_DIR / filename
            self.enqueue_status(f"下載字典：{name}")
            self.enqueue_log(f"\n下載字典：{name}\n{url}\n")
            if not dest.exists():
                download_file(url, dest, self.enqueue_log)
            self.enqueue_ui(lambda: self.apply_downloaded_wordlist(dest, name))
            self.enqueue_status("字典已導入")
        except Exception as exc:
            self.enqueue_log(f"\n[字典下載錯誤] {exc}\n")
            self.enqueue_status("字典下載失敗")

    def apply_downloaded_wordlist(self, path: Path, name: str) -> None:
        self.quick_wordlist.set(str(path))
        self.hashcat_wordlist.set(str(path))
        self.john_wordlist.set(str(path))
        self.quick_status.set(f"已導入字典：{name}")

    def sync_config_to_ui(self) -> None:
        for key, var in self.setting_vars.items():
            if key in self.config_data:
                var.set(self.config_data.get(key, ""))
        if hasattr(self, "quick_wordlist"):
            self.quick_wordlist.set(self.config_data.get("default_wordlist", ""))
            self.quick_combo_wordlist.set(self.config_data.get("combo_wordlist", ""))
            self.quick_combo_key.set(self.config_data.get("combo_key", ""))
            self.quick_follow_order.set(config_bool(self.config_data.get("auto_follow_order", "1"), True))
        if hasattr(self, "hashcat_wordlist"):
            self.hashcat_wordlist.set(self.config_data.get("default_wordlist", ""))
        if hasattr(self, "john_wordlist"):
            self.john_wordlist.set(self.config_data.get("default_wordlist", ""))

    def open_output_folder(self) -> None:
        out_dir = Path(self.config_data.get("output_dir", str(RESULTS_DIR)) or RESULTS_DIR)
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.startfile(str(out_dir))
        except Exception as exc:
            messagebox.showerror("無法開啟資料夾", str(exc))

    def open_config_file(self) -> None:
        try:
            save_config(self.config_data)
            os.startfile(str(CONFIG_PATH))
        except Exception as exc:
            messagebox.showerror("無法開啟設定檔", str(exc))

    def import_config_file(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("JSON 設定檔", "*.json"), ("所有檔案", "*.*")])
        if not path:
            return
        try:
            data = read_config_file(Path(path))
            for key in default_config():
                if key in data:
                    self.config_data[key] = data[key]
            self.config_data["tools_dir"] = str(TOOLS_DIR)
            save_config(self.config_data)
            self.sync_config_to_ui()
            self.refresh_converters()
            self.set_status("設定檔已匯入")
            messagebox.showinfo("已匯入", f"設定檔已匯入：{path}")
        except Exception as exc:
            messagebox.showerror("匯入失敗", str(exc))

    def suggest_extract_output(self) -> None:
        src = Path(self.extract_input.get().strip())
        out_dir = result_dir_for_source(src) if src.name else Path(self.config_data.get("output_dir", str(RESULTS_DIR)) or RESULTS_DIR)
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

    def select_and_auto_start(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("支援檔案", "*.zip *.zipx *.rar *.7z *.pdf *.doc *.docx *.xls *.xlsx *.ppt *.pptx *.odt *.ods *.odp *.hash *.txt"), ("所有檔案", "*.*")])
        if path:
            self.quick_input.set(path)
            self.auto_start_selected()

    def auto_start_selected(self) -> None:
        src = Path(self.quick_input.get().strip())
        if not src.exists():
            messagebox.showerror("檔案不存在", "請先選擇要破解的檔案。")
            return
        if self.runner.running() or any(
            thread and thread.is_alive() for thread in (self.extract_thread, self.auto_thread)
        ):
            messagebox.showwarning("已有工作執行中", "請先停止或等待目前工作完成。")
            return
        self.config_data["default_wordlist"] = self.quick_wordlist.get().strip()
        self.config_data["combo_wordlist"] = self.quick_combo_wordlist.get().strip()
        self.config_data["combo_key"] = self.quick_combo_key.get().strip()
        self.config_data["auto_follow_order"] = "1" if self.quick_follow_order.get() else "0"
        for key, var in self.setting_vars.items():
            if key in self.config_data:
                var.set(self.config_data[key])
        save_config(self.config_data)
        self.notebook.select(self.output_tab)
        self.quick_status.set("自動流程執行中。")
        self.output_job_var.set(src.name)
        self.output_status_var.set("準備中")
        self.output_progress_var.set("0%")
        self.output_elapsed_var.set("-")
        self.output_speed_var.set("-")
        self.output_temp_var.set("-")
        self.output_recovered_var.set("-")
        self.output_length_var.set("-")
        self.output_queue_var.set("-")
        self.output_candidate_var.set("-")
        self.output_mode_var.set("-")
        self.output_file_var.set(str(result_dir_for_source(src)))
        self.refresh_output_overview()
        self.progress_value.set(0)
        self.set_cracked_passwords([])
        self.update_jobs_tree(name=src.name, status="準備中")
        wordlist = self.quick_wordlist.get().strip()
        settings = {
            "auto_download": bool(self.quick_auto_download.get()),
            "converter": self.converter_for_input(src),
            "safe_copy": bool(self.extract_safe_copy.get()),
            "expand_wordlist": bool(self.quick_expand_wordlist.get()),
            "hashcat_mask": self.hashcat_mask.get().strip(),
            "john_mask": self.john_mask.get().strip(),
        }
        self.conversion_cancel.clear()
        self.auto_thread = threading.Thread(target=self._auto_workflow, args=(src, wordlist, settings), daemon=True)
        self.auto_thread.start()

    def _auto_output_paths(self, src: Path) -> dict[str, Path]:
        out_dir = result_dir_for_source(src)
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
        add(self.config_data.get("default_wordlist", ""))
        if WORDLISTS_DIR.exists():
            for path in sorted(WORDLISTS_DIR.rglob("*")):
                if path.is_file():
                    add(str(path))
        return sources

    def prepare_library_wordlist(self, sources: list[Path], dest: Path) -> str:
        if not sources:
            return ""
        count = merge_wordlist_files(sources, dest)
        if count <= 0:
            return ""
        self.enqueue_log("\n[階段 1] 字典庫破解\n")
        self.enqueue_log("字典來源：\n" + "\n".join(f"- {path}" for path in sources) + "\n")
        self.enqueue_log(f"合併字典：{dest}\n候選數：{count:,} 筆\n")
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
            count = build_expanded_wordlist(paths["combo_seed"], paths["combo_key_wordlist"])
            if count > 0:
                sources.append(paths["combo_key_wordlist"])
                self.enqueue_log(f"\n[階段 2] 已由 Key 生成組合候選：{count:,} 筆\n")
        if not sources:
            return ""
        if len(sources) == 1:
            return str(sources[0])
        count = merge_wordlist_files(sources, paths["combo_wordlist"])
        if count <= 0:
            return ""
        self.enqueue_log(f"\n[階段 2] 組合候選已合併：{paths['combo_wordlist']}\n候選數：{count:,} 筆\n")
        return str(paths["combo_wordlist"])

    def prepare_auto_wordlist(self, wordlist: str, expanded_path: Path, should_expand: bool) -> str:
        if not wordlist:
            return ""
        source = Path(wordlist)
        if not source.exists():
            raise FileNotFoundError(f"字典檔不存在：{wordlist}")
        if not should_expand:
            return str(source)
        count = build_expanded_wordlist(source, expanded_path)
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
    ) -> list[dict[str, object]]:
        follow_order = config_bool(self.config_data.get("auto_follow_order", "1"), True)
        combo_file = self.config_data.get("combo_wordlist", "").strip()
        combo_key = self.config_data.get("combo_key", "").strip()
        dictionary_sources = self.collect_dictionary_sources(manual_wordlist)
        stages: list[dict[str, object]] = []

        def add_stage(stage_name: str, wordlist: str, suffix: str) -> None:
            if engine == "hashcat":
                cmd = self.build_auto_hashcat_command(
                    paths["hashcat_hash"], mode_label, wordlist, paths["cracked"], paths["mask"],
                    src, str(settings["hashcat_mask"]), suffix,
                )
                cwd = str(Path(self.config_data["hashcat_path"]).parent)
            else:
                cmd = self.build_auto_john_command(paths["john_hash"], wordlist, src, str(settings["john_mask"]), suffix)
                cwd = self.config_data.get("john_run_dir") or None
            stages.append(
                {
                    "name": f"{engine} {stage_name}",
                    "cmd": cmd,
                    "cwd": cwd,
                    "session_log": paths["session"],
                    "engine": engine,
                    "hash_file": hash_file,
                    "mode_label": mode_label,
                    "cracked": paths["cracked"],
                    "stage_name": stage_name,
                }
            )

        if follow_order:
            library_wordlist = self.prepare_library_wordlist(dictionary_sources, paths["library_wordlist"])
            if library_wordlist:
                add_stage("階段1 字典庫破解", library_wordlist, "dict")
            combo_wordlist = self.prepare_combo_wordlist(combo_file, combo_key, paths)
            if combo_wordlist:
                add_stage("階段2 組合破解", combo_wordlist, "combo")
            add_stage("階段3 硬破解", "", "brute")
            return stages

        selected_wordlist = manual_wordlist or self.config_data.get("default_wordlist", "")
        if selected_wordlist:
            attack_wordlist = self.prepare_auto_wordlist(
                selected_wordlist, paths["expanded_wordlist"], bool(settings["expand_wordlist"])
            )
            add_stage("單次字典破解", attack_wordlist, "single")
        elif combo_file or combo_key:
            combo_wordlist = self.prepare_combo_wordlist(combo_file, combo_key, paths)
            if combo_wordlist:
                add_stage("單次組合破解", combo_wordlist, "combo")
        else:
            add_stage("單次硬破解", "", "brute")
        return stages

    def _auto_workflow(self, src: Path, wordlist: str, settings: dict[str, object]) -> None:
        try:
            self._ensure_tools_worker(bool(settings["auto_download"]))
            paths = self._auto_output_paths(src)

            converter = str(settings["converter"])
            if converter:
                john_text = self.convert_file_to_hash_text(src, converter, bool(settings["safe_copy"]))
            else:
                john_text = self.read_hash_text(src)

            if not john_text.strip():
                raise RuntimeError("沒有取得可破解的雜湊。")

            paths["john_hash"].write_text(self.prepare_hash_output(john_text, "john"), encoding="utf-8", newline="\n")
            hashcat_text = self.prepare_hash_output(john_text, "hashcat")
            paths["hashcat_hash"].write_text(hashcat_text, encoding="utf-8", newline="\n")

            mode_label = self.detect_hashcat_mode(hashcat_text)
            if mode_label.startswith("13000") and self.config_data.get("john_path") and Path(self.config_data["john_path"]).exists():
                stages = self.build_auto_attack_stages(src, paths, "john", paths["john_hash"], "", wordlist, settings)
                self.enqueue_ui(lambda: self.start_auto_stages(stages, 0))
            elif mode_label and self.config_data.get("hashcat_path") and Path(self.config_data["hashcat_path"]).exists():
                stages = self.build_auto_attack_stages(src, paths, "hashcat", paths["hashcat_hash"], mode_label, wordlist, settings)
                self.enqueue_ui(lambda: self.start_auto_stages(stages, 0))
            elif self.config_data.get("john_path") and Path(self.config_data["john_path"]).exists():
                stages = self.build_auto_attack_stages(src, paths, "john", paths["john_hash"], "", wordlist, settings)
                self.enqueue_ui(lambda: self.start_auto_stages(stages, 0))
            else:
                raise SetupError("找不到可用的 hashcat 或 John。", HASHCAT_DOWNLOAD_PAGE)
        except InterruptedError as exc:
            self.enqueue_log(f"\n[自動流程停止] {exc}\n")
            self.enqueue_status("自動流程已停止")
        except SetupError as exc:
            message = str(exc)
            if exc.url:
                message += f"\n下載網址：{exc.url}"
            self.enqueue_log(f"\n[自動流程錯誤] {message}\n")
            self.enqueue_status("自動流程失敗")
        except Exception as exc:
            self.enqueue_log(f"\n[自動流程錯誤] {exc}\n")
            self.enqueue_status("自動流程失敗")

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
            proc = self.runner.capture("雜湊轉換", cmd, cwd=self.config_data.get("john_run_dir") or None)
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

    def detect_hashcat_mode(self, hash_text: str) -> str:
        lines = [line.strip() for line in hash_text.splitlines() if line.strip()]
        for line in lines:
            lower = line.lower()
            for pattern, mode_label in HASHCAT_PREFIX_MODES:
                if fnmatch.fnmatch(lower, pattern.lower()):
                    return mode_label
        if lines and re.fullmatch(r"[0-9a-fA-F]{32}", lines[0]):
            return "0 - MD5"
        if lines and re.fullmatch(r"[0-9a-fA-F]{40}", lines[0]):
            return "100 - SHA1"
        return ""

    def build_auto_hashcat_command(
        self, hash_file: Path, mode_label: str, wordlist: str, cracked: Path, mask_file: Path,
        src: Path, configured_mask: str, session_suffix: str = "",
    ) -> list[str]:
        mode = first_number(mode_label)
        session_base = f"auto_{src.stem}_{session_suffix}" if session_suffix else f"auto_{src.stem}"
        session = re.sub(r"[^A-Za-z0-9_.-]+", "_", session_base)[:60] or "auto_hashcat"
        cmd = [
            self.config_data["hashcat_path"],
            "-m", mode,
            "--session", session,
            "--status",
            "--status-timer", "10",
            "--outfile", str(cracked),
            "--outfile-format", "2",
        ]
        if wordlist:
            cmd += ["-a", "0", str(hash_file), wordlist]
        else:
            if configured_mask and configured_mask != HASHCAT_DEFAULT_MASK:
                cmd += ["-a", "3", str(hash_file), configured_mask]
            else:
                mask_file.write_text("\n".join(AUTO_MASKS) + "\n", encoding="utf-8", newline="\n")
                cmd += ["-a", "3", str(hash_file), str(mask_file)]
        return cmd

    def build_auto_john_command(
        self, hash_file: Path, wordlist: str, src: Path, configured_mask: str, session_suffix: str = ""
    ) -> list[str]:
        session_base = f"auto_{src.stem}_{session_suffix}" if session_suffix else f"auto_{src.stem}"
        session = re.sub(r"[^A-Za-z0-9_.-]+", "_", session_base)[:60] or "auto_john"
        cmd = [self.config_data["john_path"], f"--session={session}"]
        if wordlist:
            cmd.append(f"--wordlist={wordlist}")
        else:
            if configured_mask and configured_mask != JOHN_DEFAULT_MASK:
                cmd.append(f"--mask={configured_mask}")
            else:
                cmd += ["--mask=?d?d?d?d?d?d?d?d", "--min-length=4"]
        cmd.append(str(hash_file))
        return cmd

    def describe_auto_attack_plan(self, name: str, cmd: list[str], cwd: str | None, session_log: Path, engine: str, hash_file: Path, mode_label: str, cracked: Path) -> str:
        attack_mode = "-"
        wordlist = ""
        mask_text = ""
        candidate_count = "-"
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
            wordlist_path = Path(wordlist)
            candidate_count = count_text_lines(wordlist_path)
            length_summary = "依字典候選"
            self.output_candidate_var.set(candidate_count)
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
            self.output_candidate_var.set("遮罩即時計算")
        self.output_length_var.set(length_summary)

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

    def start_auto_stages(self, stages: list[dict[str, object]], index: int) -> None:
        if index >= len(stages):
            self.quick_status.set("自動流程已完成。")
            return
        stage = stages[index]

        def continue_stages(_code: int) -> None:
            cracked = Path(stage["cracked"])
            if cracked.exists() and cracked.read_text(encoding="utf-8", errors="replace").strip():
                self.quick_status.set("已找到密碼，停止後續破解階段。")
                return
            self.start_auto_stages(stages, index + 1)

        self.start_auto_command(
            str(stage["name"]),
            list(stage["cmd"]),
            stage["cwd"] or None,
            Path(stage["session_log"]),
            str(stage["engine"]),
            Path(stage["hash_file"]),
            str(stage["mode_label"]),
            Path(stage["cracked"]),
            on_finish=continue_stages,
        )

    def start_auto_command(self, name: str, cmd: list[str], cwd: str | None, session_log: Path, engine: str, hash_file: Path, mode_label: str, cracked: Path, on_finish=None) -> None:
        self.quick_status.set(f"{name} 執行中，結果會寫入 {cracked.name}")
        self.output_job_var.set(name)
        self.output_status_var.set("執行中")
        self.output_mode_var.set(mode_label or engine)
        self.output_file_var.set(str(cracked))
        self.refresh_output_overview()
        self.update_jobs_tree(status="執行中")
        plan = self.describe_auto_attack_plan(name, cmd, cwd, session_log, engine, hash_file, mode_label, cracked)
        self.refresh_output_overview()
        self.log(plan)
        try:
            session_log.parent.mkdir(parents=True, exist_ok=True)
            with session_log.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(plan + "\n")
        except Exception:
            pass
        def finish(code: int) -> None:
            self.finalize_auto_cracked(engine, hash_file, mode_label, cracked)
            if on_finish:
                on_finish(code)

        self.runner.start(
            name,
            cmd,
            cwd=cwd,
            log_path=session_log,
            on_finish=finish,
        )

    def finalize_auto_cracked(self, engine: str, hash_file: Path, mode_label: str, cracked: Path) -> None:
        try:
            if engine == "hashcat":
                cmd = [self.config_data["hashcat_path"], "-m", first_number(mode_label), "--show", str(hash_file)]
                cwd = str(Path(self.config_data["hashcat_path"]).parent)
            else:
                cmd = [self.config_data["john_path"], "--show", str(hash_file)]
                cwd = self.config_data.get("john_run_dir") or None
            creationflags, startupinfo = hidden_startup()
            proc = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=creationflags, startupinfo=startupinfo, timeout=60)
            shown = clean_output(decode_bytes(proc.stdout + proc.stderr))
            passwords = self.extract_passwords_from_show(shown)
            if passwords:
                existing = cracked.read_text(encoding="utf-8", errors="replace").splitlines() if cracked.exists() else []
                merged = list(dict.fromkeys([line for line in existing + passwords if line.strip()]))
                cracked.write_text("\n".join(merged) + "\n", encoding="utf-8", newline="\n")
                self.set_cracked_passwords(merged, cracked)
                self.log(f"\n已輸出密碼：{cracked}\n")
                self.quick_status.set(f"已輸出密碼：{cracked.name}")
            elif cracked.exists() and cracked.read_text(encoding="utf-8", errors="replace").strip():
                existing = cracked.read_text(encoding="utf-8", errors="replace").splitlines()
                self.set_cracked_passwords(existing, cracked)
                self.log(f"\n已輸出密碼：{cracked}\n")
                self.quick_status.set(f"已輸出密碼：{cracked.name}")
            else:
                self.set_cracked_passwords([], cracked)
                self.quick_status.set("尚未破解出密碼。")
        except Exception as exc:
            self.log(f"\n[輸出密碼錯誤] {exc}\n")

    def extract_passwords_from_show(self, text: str) -> list[str]:
        passwords: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.lower().startswith(("0 password", "no password", "remaining", "guesses:")):
                continue
            if ":" in line:
                passwords.append(line.rsplit(":", 1)[-1])
        return passwords

    def converter_for_input(self, input_path: Path) -> str:
        chosen = self.extract_converter.get()
        if chosen and chosen != "自動偵測":
            return chosen
        return ARCHIVE_CONVERTER_MAP.get(input_path.suffix.lower(), "")

    def converter_command(self, converter_name: str, input_path: Path) -> list[str]:
        run_dir = Path(self.config_data.get("john_run_dir", ""))
        converter_path = run_dir / converter_name
        if not converter_path.exists():
            raise FileNotFoundError(f"找不到轉換器：{converter_path}")
        suffix = converter_path.suffix.lower()
        if suffix == ".exe":
            return [str(converter_path), str(input_path)]
        if suffix == ".py":
            python_path = self.config_data.get("python_path", "")
            if not python_path or not Path(python_path).exists():
                raise SetupError("未設定可用的 python.exe，無法執行 .py 轉換器。", PYTHON_DOWNLOAD_PAGE)
            return [python_path, str(converter_path), str(input_path)]
        if suffix == ".pl":
            perl_path = self.config_data.get("perl_path", "")
            if not perl_path or not Path(perl_path).exists():
                raise SetupError("未設定可用的 perl.exe，無法執行 .pl 轉換器。", PERL_DOWNLOAD_PAGE)
            return [perl_path, str(converter_path), str(input_path)]
        if suffix == ".js":
            node_path = self.config_data.get("node_path", "")
            if not node_path or not Path(node_path).exists():
                raise SetupError("未設定可用的 node.exe，無法執行 .js 轉換器。", NODE_DOWNLOAD_PAGE)
            return [node_path, str(converter_path), str(input_path)]
        return [str(converter_path), str(input_path)]

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
            proc = self.runner.capture("雜湊轉換", cmd, cwd=self.config_data.get("john_run_dir") or None)
            if self.conversion_cancel.is_set():
                raise InterruptedError("雜湊轉換已停止")
            stdout = clean_output(decode_bytes(proc.stdout))
            stderr = clean_output(decode_bytes(proc.stderr))
            if stderr.strip():
                self.enqueue_log(stderr + ("\n" if not stderr.endswith("\n") else ""))
            if proc.returncode != 0 and not stdout.strip():
                raise RuntimeError(f"轉換器結束代碼 {proc.returncode}")
            result = self.prepare_hash_output(stdout, str(settings["target"]))
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

    def prepare_hash_output(self, text: str, target: str) -> str:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if target != "hashcat":
            return "\n".join(lines) + ("\n" if lines else "")
        cleaned: list[str] = []
        for line in lines:
            dollar = line.find("$")
            if dollar > 0 and ":" in line[:dollar]:
                line = line[dollar:]
            cleaned.append(line)
        return "\n".join(cleaned) + ("\n" if cleaned else "")

    def hashcat_common_args(self) -> list[str]:
        self.config_data.update({k: v for k, v in find_tool_paths(self.config_data).items() if v})
        exe = self.config_data.get("hashcat_path", "")
        if not exe or not Path(exe).exists():
            raise SetupError("找不到 hashcat.exe，可按「檢查/下載環境」自動下載。", HASHCAT_DOWNLOAD_PAGE)
        return [exe]

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
        self.notebook.select(self.output_tab)
        self.runner.start("hashcat", cmd, cwd=str(Path(self.config_data["hashcat_path"]).parent))

    def hashcat_show(self) -> None:
        try:
            cmd = self.build_hashcat_command(show=True)
        except Exception as exc:
            messagebox.showerror("Hashcat 設定錯誤", str(exc))
            return
        self.notebook.select(self.output_tab)
        self.runner.start("hashcat --show", cmd, cwd=str(Path(self.config_data["hashcat_path"]).parent))

    def hashcat_custom(self) -> None:
        try:
            extra = split_extra_args(self.hashcat_extra.get())
            if not extra:
                raise ValueError("請在進階參數輸入要執行的 hashcat 選項。")
            cmd = self.hashcat_common_args() + extra
        except Exception as exc:
            messagebox.showerror("Hashcat 設定錯誤", str(exc))
            return
        self.notebook.select(self.output_tab)
        self.runner.start("hashcat custom", cmd, cwd=str(Path(self.config_data["hashcat_path"]).parent))

    def hashcat_devices(self) -> None:
        try:
            cmd = self.hashcat_common_args() + ["-I"]
        except Exception as exc:
            messagebox.showerror("Hashcat 設定錯誤", str(exc))
            return
        self.notebook.select(self.output_tab)
        self.runner.start("hashcat -I", cmd, cwd=str(Path(self.config_data["hashcat_path"]).parent))

    def hashcat_benchmark(self) -> None:
        try:
            cmd = self.hashcat_common_args() + ["-b"]
        except Exception as exc:
            messagebox.showerror("Hashcat 設定錯誤", str(exc))
            return
        self.notebook.select(self.output_tab)
        self.runner.start("hashcat benchmark", cmd, cwd=str(Path(self.config_data["hashcat_path"]).parent))

    def hashcat_help(self) -> None:
        try:
            cmd = self.hashcat_common_args() + ["--help"]
        except Exception as exc:
            messagebox.showerror("Hashcat 設定錯誤", str(exc))
            return
        self.notebook.select(self.output_tab)
        self.runner.start("hashcat help", cmd, cwd=str(Path(self.config_data["hashcat_path"]).parent))

    def john_common_args(self) -> list[str]:
        self.config_data.update({k: v for k, v in find_tool_paths(self.config_data).items() if v})
        exe = self.config_data.get("john_path", "")
        if not exe or not Path(exe).exists():
            raise SetupError("找不到 john.exe，可按「檢查/下載環境」自動下載。", JOHN_RELEASE_PAGE)
        return [exe]

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
        self.notebook.select(self.output_tab)
        self.runner.start("John", cmd, cwd=self.config_data.get("john_run_dir") or None)

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
        self.notebook.select(self.output_tab)
        self.runner.start("John --show", cmd, cwd=self.config_data.get("john_run_dir") or None)

    def john_custom(self) -> None:
        try:
            extra = split_extra_args(self.john_extra.get())
            if not extra:
                raise ValueError("請在進階參數輸入要執行的 John 選項。")
            cmd = self.john_common_args() + extra
        except Exception as exc:
            messagebox.showerror("John 設定錯誤", str(exc))
            return
        self.notebook.select(self.output_tab)
        self.runner.start("John custom", cmd, cwd=self.config_data.get("john_run_dir") or None)

    def john_status(self) -> None:
        try:
            cmd = self.john_common_args()
            session = self.john_session.get().strip()
            cmd.append(f"--status={session}" if session else "--status")
        except Exception as exc:
            messagebox.showerror("John 設定錯誤", str(exc))
            return
        self.notebook.select(self.output_tab)
        self.runner.start("John status", cmd, cwd=self.config_data.get("john_run_dir") or None)

    def john_restore(self) -> None:
        try:
            cmd = self.john_common_args()
            session = self.john_session.get().strip()
            cmd.append(f"--restore={session}" if session else "--restore")
        except Exception as exc:
            messagebox.showerror("John 設定錯誤", str(exc))
            return
        self.notebook.select(self.output_tab)
        self.runner.start("John restore", cmd, cwd=self.config_data.get("john_run_dir") or None)

    def john_test(self) -> None:
        try:
            cmd = self.john_common_args() + ["--test=5"]
        except Exception as exc:
            messagebox.showerror("John 設定錯誤", str(exc))
            return
        self.notebook.select(self.output_tab)
        self.runner.start("John test", cmd, cwd=self.config_data.get("john_run_dir") or None)

    def john_help(self) -> None:
        try:
            cmd = self.john_common_args() + ["--help"]
        except Exception as exc:
            messagebox.showerror("John 設定錯誤", str(exc))
            return
        self.notebook.select(self.output_tab)
        self.runner.start("John help", cmd, cwd=self.config_data.get("john_run_dir") or None)

    def load_john_formats(self) -> None:
        try:
            cmd = self.john_common_args() + ["--list=formats"]
            creationflags, startupinfo = hidden_startup()
            proc = subprocess.run(
                cmd,
                cwd=self.config_data.get("john_run_dir") or None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=creationflags,
                startupinfo=startupinfo,
                timeout=20,
            )
            text = clean_output(decode_bytes(proc.stdout + proc.stderr))
            values = sorted({part.strip() for part in re.split(r"[,\s]+", text) if part.strip() and not part.startswith("-")})
            self.john_format_combo.configure(values=values)
            self.log("\n已載入 John formats：" + str(len(values)) + "\n")
        except Exception as exc:
            messagebox.showerror("載入失敗", str(exc))

    def apply_settings(self) -> None:
        for key, var in self.setting_vars.items():
            self.config_data[key] = var.get().strip()
        if hasattr(self, "quick_follow_order"):
            self.config_data["auto_follow_order"] = "1" if self.quick_follow_order.get() else "0"
            self.config_data["default_wordlist"] = self.quick_wordlist.get().strip()
            self.config_data["combo_wordlist"] = self.quick_combo_wordlist.get().strip()
            self.config_data["combo_key"] = self.quick_combo_key.get().strip()
        save_config(self.config_data)
        Path(self.config_data.get("output_dir", str(RESULTS_DIR)) or RESULTS_DIR).mkdir(parents=True, exist_ok=True)
        self.refresh_converters()
        self.sync_config_to_ui()

    def save_settings(self) -> None:
        self.apply_settings()
        messagebox.showinfo("已儲存", "設定已儲存。")

    def detect_settings(self) -> None:
        detected = default_config()
        for key, value in detected.items():
            current = self.setting_vars.get(key)
            if current and (value or not current.get().strip()):
                current.set(value)

    def health_check(self) -> None:
        self.apply_settings()
        self.config_data.update({k: v for k, v in find_tool_paths(self.config_data).items() if v})
        tests = []
        if self.config_data.get("hashcat_path") and Path(self.config_data["hashcat_path"]).exists():
            tests.append(("hashcat", [self.config_data["hashcat_path"], "--version"], str(Path(self.config_data["hashcat_path"]).parent)))
        else:
            self.log(f"\n[健康檢查] hashcat: 未找到，下載網址 {HASHCAT_DOWNLOAD_PAGE}\n")
        if self.config_data.get("john_path") and Path(self.config_data["john_path"]).exists():
            tests.append(("john", [self.config_data["john_path"], "--list=build-info"], self.config_data.get("john_run_dir") or None))
        else:
            self.log(f"\n[健康檢查] john: 未找到，下載網址 {JOHN_RELEASE_PAGE}\n")
        self.notebook.select(self.output_tab)
        for name, cmd, cwd in tests:
            try:
                creationflags, startupinfo = hidden_startup()
                proc = subprocess.run(
                    cmd,
                    cwd=cwd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=creationflags,
                    startupinfo=startupinfo,
                    timeout=20,
                )
                text = clean_output(decode_bytes(proc.stdout + proc.stderr)).strip()
                first = text.splitlines()[0] if text else f"return {proc.returncode}"
                self.log(f"\n[健康檢查] {name}: {first}\n")
            except Exception as exc:
                self.log(f"\n[健康檢查] {name}: 失敗 {exc}\n")
        perl_path = self.config_data.get("perl_path", "")
        if not perl_path:
            self.log("[健康檢查] perl: 未設定，.pl 轉換器不可用\n")

    def stop_current_work(self) -> None:
        workers = [thread for thread in (self.extract_thread, self.auto_thread) if thread and thread.is_alive()]
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
        if self.runner.running() or extract_running or auto_running:
            if not messagebox.askyesno("仍有工作執行中", "關閉前要停止目前工作嗎？"):
                return
            self.stop_current_work()
            if self.runner.running():
                self.runner.wait()
            if extract_running:
                self.extract_thread.join()
            if auto_running:
                self.auto_thread.join()
        self.destroy()


def main() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    app = PasswordToolGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
