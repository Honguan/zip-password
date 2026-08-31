from __future__ import annotations

import unicodedata
import re


CATEGORY_LABELS = {
    "digits": "數字",
    "english": "英文",
    "text": "文字",
    "symbols": "特殊符號",
}
DEFAULT_CATEGORIES = tuple(CATEGORY_LABELS)
ENCODING_LABEL = "CP1252 可列印字元（非完整 Unicode）"


def _cp1252_char(value: int) -> str | None:
    try:
        return bytes([value]).decode("cp1252")
    except UnicodeDecodeError:
        return None


DIGITS = bytes(range(ord("0"), ord("9") + 1))
ENGLISH = bytes(range(ord("a"), ord("z") + 1)) + bytes(range(ord("A"), ord("Z") + 1))
TEXT = bytes(
    value for value in range(128, 256)
    if (char := _cp1252_char(value)) is not None and unicodedata.category(char).startswith("L")
)
SYMBOLS = bytes(
    value for value in range(32, 256)
    if (char := _cp1252_char(value)) is not None
    and char.isprintable()
    and value not in DIGITS + ENGLISH + TEXT
)
CATEGORY_BYTES = {
    "digits": DIGITS,
    "english": ENGLISH,
    "text": TEXT,
    "symbols": SYMBOLS,
}


def build_charset(categories: tuple[str, ...] | list[str]) -> bytes:
    unknown = set(categories) - CATEGORY_BYTES.keys()
    if unknown:
        raise ValueError(f"未知字元類別：{', '.join(sorted(unknown))}")
    return bytes(dict.fromkeys(value for category in categories for value in CATEGORY_BYTES[category]))


def john_charset_expression(categories: tuple[str, ...] | list[str]) -> str:
    build_charset(categories)
    placeholders = {
        "digits": "?d",
        "english": "?l?u",
        "text": "?L?U",
        "symbols": "?s?S?D",
    }
    return "".join(placeholders[category] for category in categories)


def candidate_count(charset_size: int, minimum: int, maximum: int) -> int:
    if charset_size < 1:
        raise ValueError("請至少選擇一個字元類別")
    if not 1 <= minimum <= maximum <= 12:
        raise ValueError("密碼長度必須是 1 至 12，且最小長度不可大於最大長度")
    return sum(charset_size ** length for length in range(minimum, maximum + 1))


def estimate_seconds(total: int, speed: float | None) -> tuple[float, float] | None:
    if not speed or speed <= 0:
        return None
    worst = total / speed
    return worst / 2, worst


def parse_hashcat_benchmark(output: str, mode: str) -> float:
    match = next((
        re.match(r"^\d+:" + re.escape(mode) + r":.*:(\d+(?:\.\d+)?)$", line.strip())
        for line in output.splitlines()
        if re.match(r"^\d+:" + re.escape(mode) + r":", line.strip())
    ), None)
    if not match:
        raise ValueError("無法讀取 Hashcat 測速結果")
    return float(match.group(1))


def format_duration(seconds: float) -> str:
    units = ((365.25 * 86400, "年"), (86400, "天"), (3600, "小時"), (60, "分鐘"))
    if seconds > 100 * 365.25 * 86400:
        return ">100 年"
    for size, label in units:
        if seconds >= size:
            return f"{seconds / size:.1f} {label}"
    return f"{seconds:.1f} 秒"
