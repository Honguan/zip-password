from __future__ import annotations

from password_gui.config import AttackStrategy


def attack_steps(
    strategy: AttackStrategy, *, has_dictionary: bool, has_hints: bool
) -> tuple[str, ...]:
    """Return the user-level attack plan without depending on Tk or an engine."""
    if strategy == AttackStrategy.DICTIONARY:
        if not has_dictionary:
            raise ValueError("DICTIONARY 策略需要明確選擇可用字典。")
        return ("dictionary",)
    if strategy == AttackStrategy.HINTS:
        if not has_hints:
            raise ValueError("HINTS 策略需要提示詞或組合密碼檔。")
        return ("hints",)
    if strategy == AttackStrategy.MASK:
        return ("mask",)

    steps: list[str] = []
    if has_dictionary:
        steps.append("dictionary")
    if has_hints:
        steps.append("hints")
    steps.append("mask")
    return tuple(steps)
