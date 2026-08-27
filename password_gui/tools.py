from __future__ import annotations

import hashlib
import os
import shutil
import ssl
import subprocess
import time
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from .runner import hidden_startup
from .text import clean_output, decode_bytes


SEVENZIP_DOWNLOAD_PAGE = "https://www.7-zip.org/download.html"


class SetupError(RuntimeError):
    def __init__(self, message: str, url: str = "") -> None:
        super().__init__(message)
        self.url = url


def existing_exe(path_text: str) -> str:
    if not path_text:
        return ""
    path = Path(path_text).expanduser()
    return str(path) if path.is_file() else ""


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


def find_tool_paths(
    saved: dict[str, str] | None = None, tools_dir: Path | None = None
) -> dict[str, str]:
    saved = saved or {}
    hashcat_path = existing_exe(saved.get("hashcat_path", ""))
    john_path = existing_exe(saved.get("john_path", ""))
    john_run_dir = saved.get("john_run_dir", "") if john_path else ""

    if not hashcat_path:
        hashcat_path = find_in_env("HASHCAT_PATH", "hashcat.exe")
    if not john_path:
        john_path = find_in_env("JOHN_PATH", "john.exe")
    if not hashcat_path:
        hashcat_path = shutil.which("hashcat.exe") or shutil.which("hashcat") or ""
    if not john_path:
        john_path = shutil.which("john.exe") or shutil.which("john") or ""
    if tools_dir is not None and not hashcat_path:
        hashcat_path = find_hashcat_under(tools_dir / "hashcat")
    if tools_dir is not None and not john_path:
        john_path, john_run_dir = find_john_under(tools_dir / "JohnRipper")
    elif john_path and (not john_run_dir or not Path(john_run_dir).exists()):
        parent = Path(john_path).parent
        john_run_dir = str(parent if parent.name.lower() == "run" else parent)

    python_path = (
        existing_exe(saved.get("python_path", ""))
        or find_in_env("PYTHON_PATH", "python.exe")
        or shutil.which("python.exe")
        or shutil.which("python")
        or ""
    )
    perl_path = (
        existing_exe(saved.get("perl_path", ""))
        or find_in_env("PERL_PATH", "perl.exe")
        or shutil.which("perl.exe")
        or shutil.which("perl")
        or ""
    )
    node_path = (
        existing_exe(saved.get("node_path", ""))
        or find_in_env("NODE_PATH", "node.exe")
        or shutil.which("node.exe")
        or shutil.which("node")
        or ""
    )

    return {
        "hashcat_path": str(hashcat_path),
        "john_path": str(john_path),
        "john_run_dir": str(john_run_dir),
        "python_path": str(python_path),
        "perl_path": str(perl_path),
        "node_path": str(node_path),
    }


def validate_download_url(url: str, allowed_hosts: frozenset[str]) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.hostname not in allowed_hosts:
        raise SetupError(f"拒絕非官方下載來源：{url}")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_file(
    url: str,
    dest: Path,
    log_cb=None,
    expected_sha256: str = "",
    allowed_hosts: frozenset[str] | None = None,
) -> Path:
    if allowed_hosts:
        validate_download_url(url, allowed_hosts)
    if expected_sha256 and dest.is_file() and file_sha256(dest).lower() == expected_sha256.lower():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    temp = dest.with_suffix(dest.suffix + ".part")
    temp.unlink(missing_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "PasswordToolsGUI/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=60, context=ssl.create_default_context()) as response, temp.open("wb") as fh:
            if allowed_hosts:
                validate_download_url(response.geturl(), allowed_hosts)
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
        if total and done != total:
            raise SetupError(f"下載不完整：預期 {total} bytes，實際 {done} bytes。")
        if expected_sha256 and file_sha256(temp).lower() != expected_sha256.lower():
            raise SetupError(f"下載檔案 SHA-256 驗證失敗：{dest.name}")
        temp.replace(dest)
        return dest
    except Exception:
        temp.unlink(missing_ok=True)
        raise


def replace_tool_directory(staged: Path, target: Path) -> None:
    backup = staged.parent / "previous"
    if target.exists():
        target.replace(backup)
    try:
        staged.replace(target)
    except Exception:
        if backup.exists():
            backup.replace(target)
        raise


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
