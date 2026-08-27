"""Parse Hashcat and John output into UI-independent events."""

from __future__ import annotations

from dataclasses import dataclass, replace
import re


@dataclass(frozen=True)
class JobEvent:
    """Base type for events emitted from one engine output line."""

    value: str


@dataclass(frozen=True)
class ProgressChanged(JobEvent):
    """A progress display value and, when available, its numeric percentage."""

    percent: float | None = None
    raw: str = ""

    @property
    def progress(self) -> float | None:
        return self.percent

    @property
    def display(self) -> str:
        return self.value

    @property
    def text(self) -> str:
        return self.value


@dataclass(frozen=True)
class SpeedChanged(JobEvent):
    @property
    def speed(self) -> str:
        return self.value


@dataclass(frozen=True)
class TemperatureChanged(JobEvent):
    @property
    def temperature(self) -> str:
        return self.value


@dataclass(frozen=True)
class CandidateChanged(JobEvent):
    @property
    def candidate(self) -> str:
        return self.value


@dataclass(frozen=True)
class RecoveredChanged(JobEvent):
    @property
    def recovered(self) -> str:
        return self.value


@dataclass(frozen=True)
class EngineStatusChanged(JobEvent):
    @property
    def status(self) -> str:
        return self.value


@dataclass(frozen=True)
class DashboardSnapshot:
    status: str = "就緒"
    progress: str = "0%"
    progress_percent: float = 0.0
    speed: str = "-"
    temperature: str = "-"
    candidate: str = "-"
    recovered: str = "-"


def apply_event(snapshot: DashboardSnapshot, event: JobEvent) -> DashboardSnapshot:
    if isinstance(event, EngineStatusChanged):
        return replace(snapshot, status=event.value)
    if isinstance(event, ProgressChanged):
        changes: dict[str, object] = {"progress": event.value}
        if event.percent is not None:
            changes["progress_percent"] = event.percent
        return replace(snapshot, **changes)
    if isinstance(event, SpeedChanged):
        return replace(snapshot, speed=event.value)
    if isinstance(event, TemperatureChanged):
        return replace(snapshot, temperature=event.value)
    if isinstance(event, CandidateChanged):
        return replace(snapshot, candidate=event.value)
    if isinstance(event, RecoveredChanged):
        return replace(snapshot, recovered=event.value)
    return snapshot


_STATUS_RE = re.compile(r"Status\.+:\s*(.+)", re.IGNORECASE)
_CANDIDATES_RE = re.compile(r"Candidates(?:\.#\d+)?\.+:\s*(.+)", re.IGNORECASE)
_SPEED_RE = re.compile(r"Speed(?:\.#\d+)?\.+:\s*(.+)", re.IGNORECASE)
_RECOVERED_RE = re.compile(r"Recovered\.+:\s*(.+)", re.IGNORECASE)
_PROGRESS_RE = re.compile(r"Progress\.+:\s*(.+)", re.IGNORECASE)
_TEMPERATURE_RE = re.compile(r"Temp:\s*([0-9]+c)", re.IGNORECASE)
_JOHN_SPEED_RE = re.compile(r"\b([0-9.]+[kmg]?[cp]?/s)\b", re.IGNORECASE)
_JOHN_GUESS_RE = re.compile(r"(\d+)g\s+", re.IGNORECASE)
_TRYING_RE = re.compile(r"\b(?:trying|Try)\s*:?\s*(.+)$", re.IGNORECASE)


def short_metric(value: str, limit: int) -> str:
    """Keep dashboard metric text bounded while preserving its old ellipsis."""

    return value if len(value) <= limit else value[: max(0, limit - 1)] + "…"


class EngineOutputParser:
    """Turn Hashcat/John output lines into immutable :class:`JobEvent` values.

    ``engine`` can be ``"hashcat"`` or ``"john"`` to ignore the other
    engine's specialised metrics.  With no engine, both output formats are
    accepted, matching the mixed log stream used by the GUI.
    """

    def __init__(self, engine: str | None = None) -> None:
        self.engine = (engine or "").strip().lower()

    def feed(self, line: str) -> list[JobEvent]:
        """Parse one line (or a small newline-delimited chunk) of output."""

        events: list[JobEvent] = []
        for raw_line in line.splitlines():
            current = raw_line.strip()
            if not current:
                continue
            events.extend(self._parse_line(current))
        return events

    def _parse_line(self, line: str) -> list[JobEvent]:
        events: list[JobEvent] = []

        if "啟動 " in line:
            events.append(EngineStatusChanged("執行中"))
        if "結束，代碼" in line:
            events.append(EngineStatusChanged("已結束"))
            if "代碼 0" in line:
                events.append(ProgressChanged("100%", 100.0, "100%"))
        if any(marker in line for marker in ("[錯誤]", "[環境錯誤]", "[自動流程錯誤]")):
            events.append(EngineStatusChanged("需要處理"))

        status = _STATUS_RE.match(line)
        if status:
            events.append(EngineStatusChanged(status.group(1).strip()))

        if self._allows("hashcat"):
            candidate = _CANDIDATES_RE.match(line)
            if candidate:
                events.append(CandidateChanged(short_metric(candidate.group(1).strip(), 36)))

            speed = _SPEED_RE.match(line)
            if speed:
                value = speed.group(1).strip().split("@", 1)[0].strip()
                events.append(SpeedChanged(short_metric(value, 28)))

            recovered = _RECOVERED_RE.match(line)
            if recovered:
                events.append(RecoveredChanged(short_metric(recovered.group(1).strip(), 28)))

            progress = _PROGRESS_RE.match(line)
            if progress:
                events.append(self._progress_event(progress.group(1).strip()))

            temperatures = _TEMPERATURE_RE.findall(line)
            if temperatures:
                events.append(TemperatureChanged(" / ".join(temperatures).upper()))

        if self._allows("john"):
            john_speed = _JOHN_SPEED_RE.search(line)
            if john_speed and ("g " in line or "guesses" in line.lower()):
                events.append(SpeedChanged(john_speed.group(1)))

            john_guess = _JOHN_GUESS_RE.match(line)
            if john_guess:
                events.append(RecoveredChanged(john_guess.group(1)))
                events.append(EngineStatusChanged("執行中"))

            trying = _TRYING_RE.search(line)
            if trying:
                events.append(CandidateChanged(short_metric(trying.group(1).strip(), 36)))

        return events

    def _allows(self, engine: str) -> bool:
        if not self.engine:
            return True
        if self.engine.startswith("hashcat"):
            return engine == "hashcat"
        if self.engine.startswith("john"):
            return engine == "john"
        return True

    @staticmethod
    def _progress_event(progress_text: str) -> ProgressChanged:
        match = re.search(r"\(([\d.]+)%\)", progress_text)
        if not match:
            return ProgressChanged(progress_text, None, progress_text)
        try:
            value = max(0.0, min(100.0, float(match.group(1))))
        except ValueError:
            return ProgressChanged(progress_text, None, progress_text)
        return ProgressChanged(f"{value:.2f}%", value, progress_text)


def parse_output_line(line: str, engine: str | None = None) -> list[JobEvent]:
    """Parse a line without retaining a parser instance."""

    return EngineOutputParser(engine).feed(line)


__all__ = [
    "CandidateChanged",
    "DashboardSnapshot",
    "EngineOutputParser",
    "EngineStatusChanged",
    "JobEvent",
    "ProgressChanged",
    "RecoveredChanged",
    "SpeedChanged",
    "TemperatureChanged",
    "apply_event",
    "parse_output_line",
    "short_metric",
]
