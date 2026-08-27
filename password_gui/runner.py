from __future__ import annotations

import os
import subprocess
import threading
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .text import clean_output, decode_bytes


SESSION_LOG_BUFFER_SIZE = 64 * 1024


def hidden_startup() -> tuple[int, subprocess.STARTUPINFO | None]:
    if os.name != "nt":
        return 0, None
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    return subprocess.CREATE_NO_WINDOW, startupinfo


def quote_command(args: list[str]) -> str:
    return " ".join(subprocess.list2cmdline([arg]) for arg in args)


def format_elapsed(seconds: float | None) -> str:
    if seconds is None:
        return "-"
    total = max(0, int(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02}:{minutes:02}:{seconds:02}" if hours else f"{minutes:02}:{seconds:02}"


@dataclass(frozen=True)
class ProcessResult:
    exit_code: int | None
    cancelled: bool
    error: Exception | None
    elapsed: float


class JobBusyError(RuntimeError):
    pass


class CommandRunner:
    def __init__(
        self, app: object, notify: Callable[[str, str, str], None] | None = None
    ) -> None:
        self.app = app
        self.notify = notify or (lambda *_args: None)
        self.process: subprocess.Popen[bytes] | None = None
        self.thread: threading.Thread | None = None
        self.lock = threading.Lock()
        self.job_lock = threading.Lock()
        self.current_name = ""
        self.log_path: Path | None = None
        self.on_finish = None
        self.started_at: float | None = None
        self.last_elapsed: float | None = None
        self.last_result: ProcessResult | None = None
        self.cancel_requested = False
        self.session_log_buffer: list[str] = []
        self.session_log_buffer_size = 0

    def running(self) -> bool:
        with self.lock:
            return self.process is not None and self.process.poll() is None

    def start(
        self,
        name: str,
        args: list[str],
        cwd: str | None = None,
        log_path: Path | None = None,
        on_finish=None,
    ) -> bool:
        try:
            proc = self._spawn(name, args, cwd, "stream", log_path, on_finish)
        except JobBusyError:
            self.app.log(f"\n[啟動失敗] {name}：已有工作執行中。\n")
            self.notify("warning", "已有工作執行中", "請先停止或等待目前工作完成。")
            return False
        except Exception as exc:
            self.app.log(f"\n[啟動失敗] {name}\n{traceback.format_exc()}\n")
            self.notify("error", "啟動失敗", str(exc))
            return False
        start_text = (
            f"\n[{time.strftime('%H:%M:%S')}] 啟動 {name}\n"
            f"工作目錄：{cwd or Path.cwd()}\n"
            f"Session 記錄：{log_path or '未指定'}\n"
            f"執行命令：{quote_command(args)}\n"
        )
        session_start_text = start_text + "\n"
        self.app.log(start_text)
        self._append_session_log(session_start_text)
        self.thread = threading.Thread(target=self._reader, args=(proc, name), daemon=True)
        self.thread.start()
        self.app.set_status(f"{name} 執行中")
        return True

    def capture(
        self, name: str, args: list[str], cwd: str | None = None
    ) -> subprocess.CompletedProcess[bytes]:
        proc = self._spawn(name, args, cwd, "capture")
        self.app.enqueue_status(f"{name} 執行中")
        error: Exception | None = None
        try:
            stdout, stderr = proc.communicate()
            with self.lock:
                if self.cancel_requested:
                    error = InterruptedError(f"{name} 已停止")
            if error:
                raise InterruptedError(f"{name} 已停止")
            return subprocess.CompletedProcess(args, proc.returncode, stdout, stderr)
        except Exception as exc:
            error = exc
            raise
        finally:
            self._finalize_process(proc, proc.returncode, error)

    def _spawn(
        self,
        name: str,
        args: list[str],
        cwd: str | None,
        output_mode: str,
        log_path: Path | None = None,
        on_finish=None,
    ) -> subprocess.Popen[bytes]:
        if not self.job_lock.acquire(blocking=False):
            raise JobBusyError("已有工作執行中，請先停止或等待目前工作完成。")
        creationflags, startupinfo = hidden_startup()
        try:
            proc = subprocess.Popen(
                args,
                cwd=cwd or None,
                stdin=subprocess.PIPE if output_mode == "stream" else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT if output_mode == "stream" else subprocess.PIPE,
                creationflags=creationflags,
                startupinfo=startupinfo,
            )
        except Exception as exc:
            self.last_result = ProcessResult(None, False, exc, 0.0)
            self.job_lock.release()
            raise
        with self.lock:
            self.process = proc
            self.current_name = name
            self.log_path = log_path
            self.on_finish = on_finish
            self.started_at = time.monotonic()
            self.last_elapsed = None
            self.last_result = None
            self.cancel_requested = False
            self.session_log_buffer.clear()
            self.session_log_buffer_size = 0
        return proc

    def _finalize_process(
        self,
        proc: subprocess.Popen[bytes],
        exit_code: int | None,
        error: Exception | None = None,
        name: str | None = None,
    ) -> tuple[ProcessResult, object]:
        callback = None
        with self.lock:
            cancelled = self.cancel_requested
            elapsed = time.monotonic() - self.started_at if self.started_at is not None else 0.0
            if self.process is proc:
                self.process = None
                self.started_at = None
                self.last_elapsed = elapsed
                callback = self.on_finish
                self.log_path = None
                self.on_finish = None
        result = ProcessResult(exit_code, cancelled, error, elapsed)
        self.last_result = result
        self.job_lock.release()
        self.app.enqueue_status(f"{name or self.current_name} {'已停止' if cancelled else '已結束'}")
        return result, callback

    def elapsed_seconds(self) -> float | None:
        with self.lock:
            if self.started_at is None:
                return self.last_elapsed
            return time.monotonic() - self.started_at

    def _append_session_log(self, text: str, flush: bool = False) -> None:
        path = self.log_path
        if not path:
            return
        self.session_log_buffer.append(text)
        self.session_log_buffer_size += len(text.encode("utf-8"))
        if not flush and self.session_log_buffer_size < SESSION_LOG_BUFFER_SIZE:
            return
        buffered = "".join(self.session_log_buffer)
        self.session_log_buffer.clear()
        self.session_log_buffer_size = 0
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(buffered)
        except Exception:
            pass

    def _reader(self, proc: subprocess.Popen[bytes], name: str) -> None:
        assert proc.stdout is not None
        error: Exception | None = None
        code: int | None = None
        try:
            while True:
                chunk = proc.stdout.readline()
                if not chunk:
                    break
                text = clean_output(decode_bytes(chunk))
                self.app.enqueue_log(text)
                self._append_session_log(text)
            code = proc.wait()
        except Exception as exc:
            error = exc
            code = proc.poll()
        end_text = f"\n[{time.strftime('%H:%M:%S')}] {name} 結束，代碼 {code}\n"
        self.app.enqueue_log(end_text)
        self._append_session_log(end_text, flush=True)
        result, finish_callback = self._finalize_process(proc, code, error, name)
        if finish_callback:
            self.app.enqueue_ui(lambda: finish_callback(code, result.cancelled))

    def send_key(self, key: str) -> None:
        with self.lock:
            proc = self.process
        if not proc or proc.poll() is not None or not proc.stdin:
            self.notify("info", "無執行中工作", "目前沒有可控制的工作。")
            return
        try:
            proc.stdin.write(key.encode("ascii", errors="ignore"))
            proc.stdin.flush()
            self.app.log(f"\n[控制] 已送出 {key!r}\n")
        except Exception as exc:
            self.notify("error", "控制失敗", str(exc))

    def stop(self) -> None:
        with self.lock:
            proc = self.process
            if proc and proc.poll() is None:
                self.cancel_requested = True
        if not proc or proc.poll() is not None:
            self.notify("info", "無執行中工作", "目前沒有可停止的工作。")
            return
        try:
            proc.terminate()
            self.app.log("\n[控制] 已要求停止目前工作\n")
        except Exception as exc:
            self.notify("error", "停止失敗", str(exc))

    def wait(self, timeout: float = 5) -> None:
        with self.lock:
            proc = self.process
        if not proc or proc.poll() is not None:
            return
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
