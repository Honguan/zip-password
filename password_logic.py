from __future__ import annotations

from dataclasses import dataclass
import fnmatch
import hashlib
import re
from pathlib import Path
from typing import Callable


AUTO_MASKS = [
    "?d?d?d?d", "?d?d?d?d?d", "?d?d?d?d?d?d", "?d?d?d?d?d?d?d", "?d?d?d?d?d?d?d?d",
    "?l?l?l?l", "?l?l?l?l?l", "?l?l?l?l?l?l", "?l?l?l?d?d", "?l?l?l?l?d?d", "?u?l?l?l?d?d",
]
HASHCAT_DEFAULT_MASK = "?a?a?a?a?a?a"
JOHN_DEFAULT_MASK = "?a?a?a?a?a?a"
PDF_HASHCAT_MODES = {
    ("1", "2", "40"): "10400 - PDF 1.1-1.3",
    ("2", "2", "40"): "10400 - PDF 1.1-1.3",
    ("1", "3", "40"): "10510 - PDF 1.3-1.6 RC4-40",
    ("2", "3", "40"): "10510 - PDF 1.3-1.6 RC4-40",
    ("4", "4", "40"): "10510 - PDF 1.3-1.6 RC4-40",
    ("2", "3", "128"): "10500 - PDF 1.4-1.6",
    ("4", "4", "128"): "10500 - PDF 1.4-1.6",
    ("5", "5", "256"): "10600 - PDF 1.7 Level 3",
    ("5", "6", "256"): "10700 - PDF 1.7 Level 8",
}


@dataclass(frozen=True)
class HashModeDetection:
    status: str
    mode: str = ""
    candidates: tuple[str, ...] = ()
    format_name: str = ""
    preferred_engine: str = ""


HashDetector = Callable[[str], HashModeDetection | None]


@dataclass(frozen=True)
class FormatSpec:
    name: str
    extensions: tuple[str, ...]
    converter: str = ""
    runtime: str = ""
    preferred_engine: str = "john"
    hashcat_modes: tuple[str, ...] = ()
    hash_prefix_modes: tuple[tuple[str, str], ...] = ()
    detector: HashDetector | None = None


def _detect_pdf(line: str) -> HashModeDetection | None:
    lower = line.lower()
    if not lower.startswith("$pdf$"):
        return None
    match = re.match(r"^\$pdf\$(\d+)\*(\d+)\*(\d+)\*", lower)
    if not match:
        return HashModeDetection("unsupported", format_name="PDF", preferred_engine="john")
    if match.groups() in {("2", "3", "128"), ("4", "4", "128")} and lower.count("*") == 11:
        return HashModeDetection(
            "detected", "25400 - PDF 1.4-1.6 user/owner", format_name="PDF", preferred_engine="hashcat"
        )
    mode = PDF_HASHCAT_MODES.get(match.groups(), "")
    if mode:
        return HashModeDetection("detected", mode, format_name="PDF", preferred_engine="hashcat")
    return HashModeDetection("unsupported", format_name="PDF", preferred_engine="john")


def _detect_raw_hash(line: str) -> HashModeDetection | None:
    if re.fullmatch(r"[0-9a-fA-F]{32}", line):
        return HashModeDetection(
            "ambiguous", candidates=("0 - MD5", "1000 - NTLM"), format_name="原始雜湊", preferred_engine="hashcat"
        )
    if re.fullmatch(r"[0-9a-fA-F]{40}", line):
        return HashModeDetection("detected", "100 - SHA1", format_name="原始雜湊", preferred_engine="hashcat")
    if re.fullmatch(r"[0-9a-fA-F]{64}", line):
        return HashModeDetection(
            "ambiguous", candidates=("1400 - SHA2-256", "其他 64-hex 模式"), format_name="原始雜湊", preferred_engine="hashcat"
        )
    if re.fullmatch(r"[0-9a-fA-F]{128}", line):
        return HashModeDetection(
            "ambiguous", candidates=("1700 - SHA2-512", "其他 128-hex 模式"), format_name="原始雜湊", preferred_engine="hashcat"
        )
    return None


FORMAT_REGISTRY = (
    FormatSpec(
        "ZIP", (".zip", ".zipx", ".jar", ".apk", ".epub"), "zip2john.exe", preferred_engine="hashcat",
        hashcat_modes=(
            "13600 - WinZip", "17200 - PKZIP", "17220 - PKZIP Multi-File", "17225 - PKZIP Mixed Multi-File",
            "17230 - PKZIP Mixed", "23001 - SecureZIP AES-128", "23002 - SecureZIP AES-192", "23003 - SecureZIP AES-256",
        ),
        hash_prefix_modes=(("$zip2$*", "13600 - WinZip"), ("$pkzip2$*", "17200 - PKZIP")),
    ),
    FormatSpec(
        "RAR", (".rar",), "rar2john.exe", preferred_engine="hashcat",
        hashcat_modes=("12500 - RAR3-hp", "13000 - RAR5"),
        hash_prefix_modes=(("$rar5$*", "13000 - RAR5"), ("$rar3$*", "12500 - RAR3-hp")),
    ),
    FormatSpec(
        "7-Zip", (".7z",), "7z2john.pl", "perl_path", "hashcat", ("11600 - 7-Zip",),
        (("$7z$*", "11600 - 7-Zip"),),
    ),
    FormatSpec(
        "PDF", (".pdf",), "pdf2john.pl", "perl_path", "hashcat",
        tuple(dict.fromkeys((*PDF_HASHCAT_MODES.values(), "25400 - PDF 1.4-1.6 user/owner"))), detector=_detect_pdf,
    ),
    FormatSpec(
        "Office", (".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pps", ".ppsx"),
        "office2john.py", "python_path", "hashcat", ("9400 - MS Office 2007", "9500 - MS Office 2010", "9600 - MS Office 2013"),
        (("$office$*2007*", "9400 - MS Office 2007"), ("$office$*2010*", "9500 - MS Office 2010"), ("$office$*2013*", "9600 - MS Office 2013")),
    ),
    FormatSpec("OpenDocument", (".odt", ".ods", ".odp"), "libreoffice2john.py", "python_path"),
    FormatSpec("DMG", (".dmg",), "dmg2john.exe"),
    FormatSpec("GPG", (".gpg",), "gpg2john.exe"),
    FormatSpec("KeePass", (".kdbx",), "keepass2john.exe"),
    FormatSpec("PKCS#12", (".pfx", ".p12"), "pfx2john.py", "python_path"),
    FormatSpec("PEM", (".pem",), "pem2john.py", "python_path"),
    FormatSpec("SSH Key", (".key",), "ssh2john.py", "python_path"),
    FormatSpec("BitLocker", (".vhd", ".vhdx"), "bitlocker2john.exe"),
    FormatSpec("TrueCrypt", (".hc", ".tc"), "truecrypt2john.py", "python_path"),
    FormatSpec(
        "原始雜湊", (".hash", ".txt"), preferred_engine="hashcat",
        hashcat_modes=("0 - MD5", "100 - SHA1", "1400 - SHA2-256", "1700 - SHA2-512", "1000 - NTLM", "3000 - LM", "3200 - bcrypt", "5500 - NetNTLMv1", "5600 - NetNTLMv2"),
        detector=_detect_raw_hash,
    ),
)


def format_for_extension(extension: str) -> FormatSpec | None:
    extension = extension.lower()
    return next((spec for spec in FORMAT_REGISTRY if extension in spec.extensions), None)


def converter_names() -> tuple[str, ...]:
    return tuple(dict.fromkeys(spec.converter for spec in FORMAT_REGISTRY if spec.converter))


def converter_runtime(converter: str) -> str | None:
    return next((spec.runtime for spec in FORMAT_REGISTRY if spec.converter == converter), None)


def hashcat_mode_labels() -> list[str]:
    return list(dict.fromkeys(mode for spec in FORMAT_REGISTRY for mode in spec.hashcat_modes))


def supported_file_pattern() -> str:
    return " ".join(f"*{extension}" for spec in FORMAT_REGISTRY for extension in spec.extensions)


def supported_format_summary() -> str:
    return f"{len(FORMAT_REGISTRY) - 1} 類加密檔與原始雜湊"


def source_identity(source: Path) -> str:
    resolved = source.resolve(strict=False)
    digest = hashlib.sha1(str(resolved).encode("utf-8", errors="ignore")).hexdigest()[:8]
    stem = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", source.stem).strip(" ._")[:40] or "output"
    return f"{stem}_{digest}"


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
        lower = line.lower()
        if lower.startswith("$rar5$") and ":" in line:
            line = line.split(":", 1)[0]
            lower = line.lower()
        for marker in ("$/zip2$", "$/pkzip2$"):
            end = lower.find(marker)
            if end >= 0:
                line = line[:end + len(marker)]
                break
        cleaned.append(line)
    return "\n".join(cleaned) + ("\n" if cleaned else "")


def detect_hashcat_mode(hash_text: str) -> HashModeDetection:
    lines = [line.strip() for line in hash_text.splitlines() if line.strip()]
    for line in lines:
        lower = line.lower()
        for spec in FORMAT_REGISTRY:
            if spec.detector:
                result = spec.detector(line)
                if result:
                    return result
            for pattern, mode_label in spec.hash_prefix_modes:
                if fnmatch.fnmatch(lower, pattern.lower()):
                    return HashModeDetection(
                        "detected", mode_label, format_name=spec.name, preferred_engine=spec.preferred_engine
                    )
    return HashModeDetection("unsupported")


def extract_passwords_from_show(text: str, engine: str, plaintext_only: bool = False) -> list[str]:
    if plaintext_only:
        return [line for line in text.splitlines() if line]

    passwords: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.lower().startswith(("0 password", "no password", "remaining", "guesses:")):
            continue
        if ":" in line:
            fields = line.split(":")
            if engine == "john" and len(fields) >= 7 and fields[-5].isdigit() and fields[-4].isdigit():
                passwords.append(":".join(fields[1:-5]))
            elif engine == "john":
                passwords.append(line.split(":", 1)[1])
            else:
                passwords.append(fields[-1])
    return passwords


def build_auto_hashcat_command(
    executable: str, hash_file: Path, mode: str, wordlist: str, cracked: Path, mask_file: Path,
    source: Path, configured_mask: str, session_suffix: str = "",
) -> list[str]:
    identity = source_identity(source)
    session_base = f"auto_{identity}_{session_suffix}" if session_suffix else f"auto_{identity}"
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
    identity = source_identity(source)
    session_base = f"auto_{identity}_{session_suffix}" if session_suffix else f"auto_{identity}"
    session = re.sub(r"[^A-Za-z0-9_.-]+", "_", session_base)[:60] or "auto_john"
    command = [executable, f"--session={session}"]
    if wordlist:
        command.append(f"--wordlist={wordlist}")
    elif configured_mask and configured_mask != JOHN_DEFAULT_MASK:
        command.append(f"--mask={configured_mask}")
    else:
        command += ["--mask=?d?d?d?d?d?d?d?d", "--min-length=4"]
    return command + [str(hash_file)]
