from __future__ import annotations

import locale
import re


ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def decode_bytes(data: bytes) -> str:
    encodings = ["utf-8", locale.getpreferredencoding(False), "cp950", "big5", "latin-1"]
    for encoding in encodings:
        try:
            return data.decode(encoding)
        except Exception:
            continue
    return data.decode("utf-8", errors="replace")


def clean_output(text: str) -> str:
    return ANSI_RE.sub("", text.replace("\r\n", "\n").replace("\r", "\n"))
