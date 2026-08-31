from __future__ import annotations

from dataclasses import dataclass, fields, replace
from enum import Enum
import json
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


class AttackStrategy(str, Enum):
    AUTO = "AUTO"
    DICTIONARY = "DICTIONARY"
    HINTS = "HINTS"
    MASK = "MASK"


@dataclass
class AppConfig:
    language: str = "zh-TW"
    hashcat_path: Path | None = None
    john_path: Path | None = None
    john_run_dir: Path | None = None
    python_path: Path | None = None
    perl_path: Path | None = None
    node_path: Path | None = None
    output_dir: Path = Path(".")
    default_wordlist: Path | None = None
    attack_strategy: AttackStrategy = AttackStrategy.AUTO
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
            elif key == "attack_strategy":
                try:
                    config.attack_strategy = AttackStrategy(value)
                except (TypeError, ValueError):
                    raise ValueError("設定 attack_strategy 必須是 AUTO/DICTIONARY/HINTS/MASK") from None
            elif key == "combo_key":
                if not isinstance(value, str):
                    raise ValueError("設定 combo_key 必須是字串")
                config.combo_key = value
            elif key == "language":
                config.language = value if value in {"en", "zh-TW"} else defaults.language
        if "attack_strategy" not in data and "auto_follow_order" in data:
            legacy = data["auto_follow_order"]
            if not isinstance(legacy, bool) and not (isinstance(legacy, str) and legacy in {"1", "0"}):
                raise ValueError("舊設定 auto_follow_order 必須是 true/false 或 1/0")
            config.attack_strategy = AttackStrategy.AUTO
        return config

    def to_mapping(self) -> dict[str, object]:
        return {
            item.name: (
                str(value) if item.name in PATH_FIELDS and value is not None
                else value.value if isinstance(value, Enum) else value
            )
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

def read_config_file(path: Path) -> dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("設定檔格式不是 JSON object")
    return data


def load_config_file(
    defaults: AppConfig, search_paths: list[Path]
) -> tuple[AppConfig, str, Path | None]:
    loaded_path = next((path for path in search_paths if path.exists()), None)
    if not loaded_path:
        return defaults, "", None
    try:
        return AppConfig.from_mapping(read_config_file(loaded_path), defaults), "", loaded_path
    except Exception as exc:
        return defaults, f"{loaded_path}：{type(exc).__name__}: {exc}", loaded_path


def save_config_file(config: AppConfig, path: Path) -> None:
    path.write_text(json.dumps(config.to_mapping(), ensure_ascii=False, indent=2), encoding="utf-8")
