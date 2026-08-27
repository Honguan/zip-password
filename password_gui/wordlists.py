from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from pathlib import Path

from .text import clean_output, decode_bytes


WORDLIST_JOINERS = ["", " ", ".", "-", "_", "/", "@", "\t"]
WORDLIST_EXPANSION_LIMIT = 500_000


def case_variants(text: str) -> list[str]:
    if not re.search(r"[A-Za-z]", text):
        return [text]
    return list(dict.fromkeys([text, text.lower(), text.upper(), text.title(), text.capitalize()]))


def split_candidate_tokens(text: str) -> list[str]:
    tokens = re.split(r"[\s./\\:_\-?&=@#\[\](){}<>\"'，。！？、；：]+", text)
    return [token for token in tokens if token]


def build_expanded_wordlist(
    source: Path,
    dest: Path,
    limit: int = WORDLIST_EXPANSION_LIMIT,
    cancel: threading.Event | None = None,
) -> int:
    dest.parent.mkdir(parents=True, exist_ok=True)
    candidates: set[str] = set()
    derived_count = 0

    with source.open("rb") as source_file, dest.open("w", encoding="utf-8", newline="\n") as dest_file:
        def add(value: str, derived: bool = False) -> bool:
            nonlocal derived_count
            value = value.strip("\r\n")
            if derived and derived_count >= limit:
                return True
            if value and len(value) <= 256 and value not in candidates:
                candidates.add(value)
                dest_file.write(value + "\n")
                if derived:
                    derived_count += 1
            return derived_count >= limit

        def add_with_case(value: str) -> bool:
            for variant in case_variants(value):
                if add(variant, derived=True):
                    return True
            return False

        for raw_line in source_file:
            if cancel and cancel.is_set():
                break
            line = clean_output(decode_bytes(raw_line)).strip()
            if not line:
                continue
            add(line)
            if derived_count >= limit:
                continue
            add_with_case(line)
            compact = re.sub(r"\s+", "", line)
            if compact != line:
                add_with_case(compact)
            tokens = split_candidate_tokens(line)
            for token in tokens:
                if add_with_case(token):
                    break
            if derived_count >= limit:
                continue
            usable = tokens[:8]
            if len(usable) < 2:
                continue
            for joiner in WORDLIST_JOINERS:
                if add(joiner.join(usable), derived=True):
                    break
                if add(joiner.join(reversed(usable)), derived=True):
                    break
                if len(usable) > 2 and add(joiner.join([usable[0], usable[-1]]), derived=True):
                    break

    return len(candidates)


def count_text_lines(
    path: Path, limit: int = 5_000_000, cancel: threading.Event | None = None
) -> str:
    try:
        count = 0
        if cancel and cancel.is_set():
            raise InterruptedError("字典候選統計已停止")
        with path.open("rb") as fh:
            for raw in fh:
                if cancel and cancel.is_set():
                    raise InterruptedError("字典候選統計已停止")
                if raw.strip():
                    count += 1
                if count >= limit:
                    return f"至少 {limit:,} 筆"
        return f"{count:,} 筆"
    except InterruptedError:
        raise
    except Exception:
        return "無法統計"


def has_text_candidate(path: Path) -> bool:
    try:
        with path.open("rb") as source:
            return any(decode_bytes(line).strip() for line in source)
    except OSError:
        return False


@dataclass(frozen=True)
class WordlistMergeFailure:
    source: Path
    error: str
    required: bool


@dataclass(frozen=True)
class WordlistMergeResult:
    written_count: int
    loaded_sources: tuple[Path, ...]
    failed_sources: tuple[WordlistMergeFailure, ...]
    truncated_by_limit: bool


def merge_wordlist_files(
    sources: list[Path],
    dest: Path,
    limit: int = 5_000_000,
    optional_sources: set[Path] | None = None,
) -> WordlistMergeResult:
    dest.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    loaded: list[Path] = []
    failed: list[WordlistMergeFailure] = []
    optional = {path.resolve() for path in optional_sources or set()}
    with dest.open("w", encoding="utf-8", newline="\n") as out:
        for source in sources:
            try:
                with source.open("rb") as fh:
                    loaded.append(source)
                    for raw in fh:
                        line = decode_bytes(raw).strip()
                        if not line:
                            continue
                        out.write(line + "\n")
                        count += 1
                        if count >= limit:
                            return WordlistMergeResult(count, tuple(loaded), tuple(failed), True)
            except OSError as exc:
                failed.append(
                    WordlistMergeFailure(
                        source,
                        f"{type(exc).__name__}: {exc}",
                        source.resolve() not in optional,
                    )
                )
    return WordlistMergeResult(count, tuple(loaded), tuple(failed), False)
