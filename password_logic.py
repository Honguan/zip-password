from __future__ import annotations

import fnmatch
import re
from pathlib import Path


AUTO_MASKS = [
    "?d?d?d?d", "?d?d?d?d?d", "?d?d?d?d?d?d", "?d?d?d?d?d?d?d", "?d?d?d?d?d?d?d?d",
    "?l?l?l?l", "?l?l?l?l?l", "?l?l?l?l?l?l", "?l?l?l?d?d", "?l?l?l?l?d?d", "?u?l?l?l?d?d",
]
HASHCAT_DEFAULT_MASK = "?a?a?a?a?a?a"
JOHN_DEFAULT_MASK = "?a?a?a?a?a?a"
HASHCAT_PREFIX_MODES = [
    ("$zip2$*", "13600 - WinZip"),
    ("$pkzip2$*", "17200 - PKZIP"),
    ("$rar5$*", "13000 - RAR5"),
    ("$rar3$*", "12500 - RAR3-hp"),
    ("$7z$*", "11600 - 7-Zip"),
    ("$office$*2007*", "9400 - MS Office 2007"),
    ("$office$*2010*", "9500 - MS Office 2010"),
    ("$office$*2013*", "9600 - MS Office 2013"),
    ("$pdf$*", "10500 - PDF 1.4-1.6"),
]


def config_bool(value: str | bool | None, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if not text:
        return default
    return text not in {"0", "false", "no", "off", "關", "否", "停用"}


def merge_config(defaults: dict[str, str], saved: dict[str, str]) -> dict[str, str]:
    return {key: str(saved.get(key, value)) for key, value in defaults.items()}


def prepare_hash_output(text: str, target: str) -> str:
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


def detect_hashcat_mode(hash_text: str) -> str:
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


def extract_passwords_from_show(text: str) -> list[str]:
    passwords: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.lower().startswith(("0 password", "no password", "remaining", "guesses:")):
            continue
        if ":" in line:
            passwords.append(line.rsplit(":", 1)[-1])
    return passwords


def build_auto_hashcat_command(
    executable: str, hash_file: Path, mode: str, wordlist: str, cracked: Path, mask_file: Path,
    source: Path, configured_mask: str, session_suffix: str = "",
) -> list[str]:
    session_base = f"auto_{source.stem}_{session_suffix}" if session_suffix else f"auto_{source.stem}"
    session = re.sub(r"[^A-Za-z0-9_.-]+", "_", session_base)[:60] or "auto_hashcat"
    command = [
        executable, "-m", mode, "--session", session, "--status", "--status-timer", "10",
        "--outfile", str(cracked), "--outfile-format", "2",
    ]
    if wordlist:
        return command + ["-a", "0", str(hash_file), wordlist]
    mask = configured_mask if configured_mask and configured_mask != HASHCAT_DEFAULT_MASK else str(mask_file)
    return command + ["-a", "3", str(hash_file), mask]


def build_auto_john_command(
    executable: str, hash_file: Path, wordlist: str, source: Path, configured_mask: str,
    session_suffix: str = "",
) -> list[str]:
    session_base = f"auto_{source.stem}_{session_suffix}" if session_suffix else f"auto_{source.stem}"
    session = re.sub(r"[^A-Za-z0-9_.-]+", "_", session_base)[:60] or "auto_john"
    command = [executable, f"--session={session}"]
    if wordlist:
        command.append(f"--wordlist={wordlist}")
    elif configured_mask and configured_mask != JOHN_DEFAULT_MASK:
        command.append(f"--mask={configured_mask}")
    else:
        command += ["--mask=?d?d?d?d?d?d?d?d", "--min-length=4"]
    return command + [str(hash_file)]
