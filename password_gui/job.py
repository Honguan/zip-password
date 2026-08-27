"""UI-independent job and stage state models."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from threading import Event, RLock
import time
from typing import Callable, Mapping, Sequence


class JobState(str, Enum):
    IDLE = "IDLE"
    PREPARING = "PREPARING"
    CHECKING_ENV = "CHECKING_ENV"
    CONVERTING = "CONVERTING"
    BUILDING_CANDIDATES = "BUILDING_CANDIDATES"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    SUCCEEDED = "SUCCEEDED"
    EXHAUSTED = "EXHAUSTED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class StageStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    FOUND = "FOUND"
    EXHAUSTED = "EXHAUSTED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class StageResult(str, Enum):
    FOUND = "FOUND"
    EXHAUSTED = "EXHAUSTED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ErrorCategory(str, Enum):
    UNKNOWN = "unknown"
    MISSING_TOOL = "missing_tool"
    UNSUPPORTED_FORMAT = "unsupported_format"
    CONVERTER = "converter"
    INVALID_DICTIONARY = "invalid_dictionary"
    ENGINE_LAUNCH = "engine_launch"
    ENGINE_RUNTIME = "engine_runtime"
    CANCELLED = "cancelled"


class JobError(Exception):
    category = ErrorCategory.UNKNOWN

    def __init__(
        self,
        message: str = "",
        *,
        details: str | None = None,
        command: Sequence[str] | None = None,
        stderr: str | None = None,
        exit_code: int | None = None,
    ) -> None:
        self.message = message or type(self).__name__
        self.details = details
        self.command = tuple(command) if command is not None else None
        self.stderr = stderr
        self.exit_code = exit_code
        super().__init__(self.message)

    @property
    def human_message(self) -> str:
        return self.message

    @property
    def technical_detail(self) -> str | None:
        parts = [self.details] if self.details else []
        if self.command:
            parts.append("command: " + " ".join(self.command))
        if self.stderr:
            parts.append("stderr: " + self.stderr)
        if self.exit_code is not None:
            parts.append(f"exit_code: {self.exit_code}")
        return "\n".join(parts) or None


class MissingToolError(JobError):
    category = ErrorCategory.MISSING_TOOL


class UnsupportedFormatError(JobError):
    category = ErrorCategory.UNSUPPORTED_FORMAT


class ConverterError(JobError):
    category = ErrorCategory.CONVERTER


class InvalidDictionaryError(JobError):
    category = ErrorCategory.INVALID_DICTIONARY


class EngineLaunchError(JobError):
    category = ErrorCategory.ENGINE_LAUNCH


class EngineRuntimeError(JobError):
    category = ErrorCategory.ENGINE_RUNTIME


class CancelledError(JobError):
    category = ErrorCategory.CANCELLED


class InvalidTransitionError(ValueError):
    """Raised when a transition is not explicitly allowed."""


class JobAlreadyRunningError(RuntimeError):
    """Raised when ``start`` is called while a job is active."""


@dataclass(frozen=True)
class JobStage:
    id: str = ""
    display_name: str = ""
    engine: str = ""
    attack_type: str = ""
    command: tuple[str, ...] = ()
    cwd: str | Path | None = None
    candidate_count: int | str | None = None
    status: StageStatus = StageStatus.PENDING
    started_at: float | None = None
    finished_at: float | None = None
    exit_code: int | None = None
    error: JobError | Exception | str | None = None
    result: StageResult | None = None
    session_log: Path | None = None
    hash_file: Path | None = None
    mode_label: str = ""
    cracked_file: Path | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.command, tuple):
            object.__setattr__(self, "command", tuple(self.command))
        if not isinstance(self.status, StageStatus):
            object.__setattr__(self, "status", StageStatus(self.status))
        if self.result is not None and not isinstance(self.result, StageResult):
            object.__setattr__(self, "result", StageResult(self.result))


@dataclass
class JobContext:
    source_file: str | Path | None = None
    detected_type: str | None = None
    converter: str | None = None
    selected_engine: str | None = None
    output_paths: dict[str, str | Path] = field(default_factory=dict)
    stages: list[JobStage] = field(default_factory=list)
    current_stage_index: int = 0
    total_stages: int | None = None
    recovered_passwords: list[str] = field(default_factory=list)
    recovered_count: str | None = None
    elapsed_time: float = 0.0
    progress: float | str | None = None
    speed: str | None = None
    temperature: str | None = None
    current_candidate: str | None = None
    candidate_count: str | None = None
    password_length: str | None = None
    queue: str | None = None
    mode: str | None = None
    cancellation_token: Event = field(default_factory=Event)
    error: str | None = None
    technical_error: str | None = None
    error_category: ErrorCategory | None = None

    def __post_init__(self) -> None:
        self.output_paths = dict(self.output_paths)
        self.stages = list(self.stages)
        self.recovered_passwords = list(self.recovered_passwords)
        if self.total_stages is None:
            self.total_stages = len(self.stages)

    @property
    def human_readable_error(self) -> str | None:
        return self.error

    @property
    def technical_error_detail(self) -> str | None:
        return self.technical_error


@dataclass(frozen=True)
class JobSnapshot:
    state: JobState = JobState.IDLE
    source_file: str | Path | None = None
    detected_type: str | None = None
    converter: str | None = None
    selected_engine: str | None = None
    output_paths: tuple[tuple[str, str | Path], ...] = ()
    stages: tuple[JobStage, ...] = ()
    current_stage_index: int = 0
    total_stages: int = 0
    recovered_passwords: tuple[str, ...] = ()
    recovered_count: str | None = None
    elapsed_time: float = 0.0
    progress: float | str | None = None
    speed: str | None = None
    temperature: str | None = None
    current_candidate: str | None = None
    candidate_count: str | None = None
    password_length: str | None = None
    queue: str | None = None
    mode: str | None = None
    cancellation_requested: bool = False
    error: str | None = None
    technical_error: str | None = None
    error_category: ErrorCategory | None = None

    @property
    def current_stage(self) -> JobStage | None:
        return self.stages[self.current_stage_index] if self.current_stage_index < len(self.stages) else None

    @property
    def status(self) -> JobState:
        return self.state

    @property
    def human_readable_error(self) -> str | None:
        return self.error

    @property
    def technical_error_detail(self) -> str | None:
        return self.technical_error


_ACTIVE = frozenset(
    {
        JobState.PREPARING,
        JobState.CHECKING_ENV,
        JobState.CONVERTING,
        JobState.BUILDING_CANDIDATES,
        JobState.RUNNING,
        JobState.STOPPING,
    }
)
_TERMINAL = frozenset(
    {JobState.SUCCEEDED, JobState.EXHAUSTED, JobState.FAILED, JobState.CANCELLED}
)


class JobController:
    """Own one job and enforce its legal transitions."""

    LEGAL_TRANSITIONS: Mapping[JobState, frozenset[JobState]] = {
        JobState.IDLE: frozenset({JobState.PREPARING}),
        JobState.PREPARING: frozenset(
            {JobState.CHECKING_ENV, JobState.STOPPING, JobState.FAILED}
        ),
        JobState.CHECKING_ENV: frozenset(
            {
                JobState.CONVERTING,
                JobState.BUILDING_CANDIDATES,
                JobState.STOPPING,
                JobState.FAILED,
            }
        ),
        JobState.CONVERTING: frozenset(
            {JobState.BUILDING_CANDIDATES, JobState.STOPPING, JobState.FAILED}
        ),
        JobState.BUILDING_CANDIDATES: frozenset(
            {JobState.RUNNING, JobState.STOPPING, JobState.FAILED}
        ),
        JobState.RUNNING: frozenset(
            {
                JobState.BUILDING_CANDIDATES,
                JobState.SUCCEEDED,
                JobState.EXHAUSTED,
                JobState.STOPPING,
                JobState.FAILED,
            }
        ),
        JobState.STOPPING: frozenset({JobState.CANCELLED}),
        JobState.SUCCEEDED: frozenset({JobState.IDLE}),
        JobState.EXHAUSTED: frozenset({JobState.IDLE}),
        JobState.FAILED: frozenset({JobState.IDLE}),
        JobState.CANCELLED: frozenset({JobState.IDLE}),
    }

    def __init__(self, on_change: Callable[[JobSnapshot], None] | None = None) -> None:
        self._state = JobState.IDLE
        self._context: JobContext | None = None
        self._started_at: float | None = None
        self._on_change = on_change
        self._lock = RLock()

    @property
    def state(self) -> JobState:
        with self._lock:
            return self._state

    @property
    def context(self) -> JobContext | None:
        with self._lock:
            return self._context

    @property
    def snapshot(self) -> JobSnapshot:
        with self._lock:
            return self._snapshot()

    def start(self, context: JobContext | None = None) -> JobSnapshot:
        with self._lock:
            if self._state != JobState.IDLE:
                if self._state in _ACTIVE:
                    raise JobAlreadyRunningError("已有工作正在執行。")
                raise InvalidTransitionError(f"無法從 {self._state.value} 開始；請先 reset。")
            context = context or JobContext()
            if not isinstance(context, JobContext):
                raise TypeError("context 必須是 JobContext")
            limit = len(context.stages) if context.stages else 1
            if not 0 <= context.current_stage_index < limit:
                raise ValueError("current_stage_index 超出 stages 範圍")
            if context.total_stages is None:
                context.total_stages = len(context.stages)
            context.current_stage_index = 0
            context.cancellation_token.clear()
            context.error = context.technical_error = context.error_category = None
            self._context = context
            self._started_at = time.monotonic()
            return self.transition(JobState.PREPARING)

    def transition(self, target: JobState | str) -> JobSnapshot:
        with self._lock:
            try:
                target = target if isinstance(target, JobState) else JobState(target)
            except ValueError as exc:
                raise InvalidTransitionError(f"未知工作狀態：{target!r}") from exc
            if target not in self.LEGAL_TRANSITIONS.get(self._state, frozenset()):
                raise InvalidTransitionError(
                    f"不允許狀態轉移：{self._state.value} -> {target.value}"
                )
            self._state = target
            if target == JobState.STOPPING and self._context is not None:
                self._context.cancellation_token.set()
            if target == JobState.RUNNING:
                self._set_current_stage(StageStatus.RUNNING)
            if target in _TERMINAL:
                self._finish_timer()
                self._started_at = None
            return self._emit()

    def update(self, **changes: object) -> JobSnapshot:
        with self._lock:
            if self._context is None:
                raise InvalidTransitionError("尚未建立工作。")
            for name, value in changes.items():
                if not hasattr(self._context, name):
                    raise AttributeError(name)
                setattr(self._context, name, value)
            if "stages" in changes:
                self._context.stages = list(self._context.stages)
                self._context.total_stages = len(self._context.stages)
                self._context.current_stage_index = 0
            return self._emit()

    def run(self) -> JobSnapshot:
        """Advance preparation and begin the current stage."""
        with self._lock:
            if self._state == JobState.PREPARING:
                self.transition(JobState.CHECKING_ENV)
            if self._state == JobState.CHECKING_ENV:
                if self._context is not None and self._context.converter:
                    self.transition(JobState.CONVERTING)
                self.transition(JobState.BUILDING_CANDIDATES)
            elif self._state == JobState.CONVERTING:
                self.transition(JobState.BUILDING_CANDIDATES)
            return self.transition(JobState.RUNNING)

    def request_cancel(self) -> JobSnapshot:
        with self._lock:
            if self._state not in _ACTIVE - {JobState.STOPPING}:
                raise InvalidTransitionError(f"無法從 {self._state.value} 要求取消工作。")
            return self.transition(JobState.STOPPING)

    def complete_stage(
        self,
        result: StageResult | str,
        *,
        exit_code: int | None = None,
        error: JobError | Exception | str | None = None,
        recovered_password: str | None = None,
    ) -> JobSnapshot:
        with self._lock:
            try:
                result = result if isinstance(result, StageResult) else StageResult(result)
            except ValueError as exc:
                raise InvalidTransitionError(f"未知階段結果：{result!r}") from exc
            if result == StageResult.CANCELLED:
                if self._state != JobState.STOPPING:
                    raise InvalidTransitionError("階段取消必須先將工作轉為 STOPPING。")
            elif self._state != JobState.RUNNING:
                raise InvalidTransitionError(
                    f"只能在 RUNNING 完成階段，目前是 {self._state.value}。"
                )
            self._set_current_stage(StageStatus(result.value), result, exit_code, error)
            if result == StageResult.FOUND:
                if recovered_password is not None and self._context is not None:
                    self._context.recovered_passwords.append(recovered_password)
                return self.transition(JobState.SUCCEEDED)
            if result == StageResult.FAILED:
                self._record_error(error)
                return self.transition(JobState.FAILED)
            if result == StageResult.CANCELLED:
                self._record_error(error)
                return self.transition(JobState.CANCELLED)
            if self._context is not None and self._context.current_stage_index + 1 < len(
                self._context.stages
            ):
                self._context.current_stage_index += 1
                return self.transition(JobState.BUILDING_CANDIDATES)
            return self.transition(JobState.EXHAUSTED)

    def fail(self, error: JobError | Exception | str | None = None) -> JobSnapshot:
        with self._lock:
            if self._state not in _ACTIVE - {JobState.STOPPING}:
                raise InvalidTransitionError(f"無法從 {self._state.value} 標記失敗。")
            self._set_current_stage(StageStatus.FAILED, StageResult.FAILED, error=error)
            self._record_error(error)
            return self.transition(JobState.FAILED)

    def reset(self) -> JobSnapshot:
        with self._lock:
            if self._state not in _TERMINAL:
                raise InvalidTransitionError(f"只能從終止狀態 reset，目前是 {self._state.value}。")
            self._context = None
            self._started_at = None
            self._state = JobState.IDLE
            return self._emit()

    def _set_current_stage(
        self,
        status: StageStatus,
        result: StageResult | None = None,
        exit_code: int | None = None,
        error: JobError | Exception | str | None = None,
    ) -> None:
        if self._context is None or self._context.current_stage_index >= len(self._context.stages):
            return
        index = self._context.current_stage_index
        stage = self._context.stages[index]
        self._context.stages[index] = replace(
            stage,
            status=status,
            result=result,
            started_at=stage.started_at or time.monotonic(),
            finished_at=None if status == StageStatus.RUNNING else time.monotonic(),
            exit_code=exit_code,
            error=error,
        )

    def _record_error(self, error: JobError | Exception | str | None) -> None:
        if self._context is None or error is None:
            return
        if isinstance(error, JobError):
            self._context.error = error.human_message
            self._context.technical_error = error.technical_detail
            self._context.error_category = error.category
        elif isinstance(error, BaseException):
            self._context.error = str(error) or type(error).__name__
            self._context.technical_error = f"{type(error).__name__}: {error}"
            self._context.error_category = ErrorCategory.UNKNOWN
        else:
            self._context.error = str(error)
            self._context.technical_error = str(error)
            self._context.error_category = ErrorCategory.UNKNOWN

    def _finish_timer(self) -> None:
        if self._context is not None and self._started_at is not None:
            self._context.elapsed_time = max(
                self._context.elapsed_time, time.monotonic() - self._started_at
            )

    def _snapshot(self) -> JobSnapshot:
        self._finish_timer()
        if self._context is None:
            return JobSnapshot(state=self._state)
        context = self._context
        return JobSnapshot(
            state=self._state,
            source_file=context.source_file,
            detected_type=context.detected_type,
            converter=context.converter,
            selected_engine=context.selected_engine,
            output_paths=tuple(context.output_paths.items()),
            stages=tuple(context.stages),
            current_stage_index=context.current_stage_index,
            total_stages=context.total_stages or len(context.stages),
            recovered_passwords=tuple(context.recovered_passwords),
            recovered_count=context.recovered_count,
            elapsed_time=context.elapsed_time,
            progress=context.progress,
            speed=context.speed,
            temperature=context.temperature,
            current_candidate=context.current_candidate,
            candidate_count=context.candidate_count,
            password_length=context.password_length,
            queue=context.queue,
            mode=context.mode,
            cancellation_requested=context.cancellation_token.is_set(),
            error=context.error,
            technical_error=context.technical_error,
            error_category=context.error_category,
        )

    def _emit(self) -> JobSnapshot:
        snapshot = self._snapshot()
        if self._on_change is not None:
            self._on_change(snapshot)
        return snapshot


__all__ = [
    "CancelledError",
    "ConverterError",
    "EngineLaunchError",
    "EngineRuntimeError",
    "ErrorCategory",
    "InvalidDictionaryError",
    "InvalidTransitionError",
    "JobAlreadyRunningError",
    "JobContext",
    "JobController",
    "JobError",
    "JobSnapshot",
    "JobStage",
    "JobState",
    "MissingToolError",
    "StageResult",
    "StageStatus",
    "UnsupportedFormatError",
]
