from __future__ import annotations

from dataclasses import dataclass, fields, replace
from pathlib import Path
from typing import Mapping


PATH_FIELDS = {
    "hashcat_path",
    "john_path",
    "john_run_dir",
    "python_path",
    "perl_path",
    "node_path",
    "output_dir",
    "default_wordlist",
    "combo_wordlist",
}


@dataclass
class AppConfig:
    hashcat_path: Path | None = None
    john_path: Path | None = None
    john_run_dir: Path | None = None
    python_path: Path | None = None
    perl_path: Path | None = None
    node_path: Path | None = None
    output_dir: Path = Path(".")
    default_wordlist: Path | None = None
    auto_follow_order: bool = True
    combo_wordlist: Path | None = None
    combo_key: str = ""

    @classmethod
    def from_mapping(cls, data: Mapping[str, object], defaults: AppConfig) -> AppConfig:
        config = replace(defaults)
        known = {item.name for item in fields(cls)}
        for key, value in data.items():
            if key not in known:
                continue
            if key in PATH_FIELDS:
                if value is None or value == "":
                    if key != "output_dir":
                        setattr(config, key, None)
                    continue
                if not isinstance(value, str):
                    raise ValueError(f"設定 {key} 必須是路徑字串")
                setattr(config, key, Path(value))
            elif key == "auto_follow_order":
                if isinstance(value, bool):
                    config.auto_follow_order = value
                elif value in {"1", "0"}:
                    config.auto_follow_order = value == "1"
                else:
                    raise ValueError("設定 auto_follow_order 必須是 true/false 或舊格式 1/0")
            elif key == "combo_key":
                if not isinstance(value, str):
                    raise ValueError("設定 combo_key 必須是字串")
                config.combo_key = value
        return config

    def to_mapping(self) -> dict[str, object]:
        return {
            item.name: str(value) if item.name in PATH_FIELDS and value is not None else value
            for item in fields(self)
            if (value := getattr(self, item.name)) is not None
        }

    def tool_paths(self) -> dict[str, str]:
        return {
            key: str(getattr(self, key) or "")
            for key in ("hashcat_path", "john_path", "john_run_dir", "python_path", "perl_path", "node_path")
        }

    def update_tool_paths(self, detected: Mapping[str, str]) -> None:
        for key in ("hashcat_path", "john_path", "john_run_dir", "python_path", "perl_path", "node_path"):
            if key in detected:
                value = detected[key]
                setattr(self, key, Path(value) if value else None)
