from unittest import TestCase, main
from unittest.mock import patch

from password_gui.job import (
    ConverterError,
    EngineLaunchError,
    EngineRuntimeError,
    ErrorCategory,
    InvalidDictionaryError,
    InvalidTransitionError,
    JobAlreadyRunningError,
    JobContext,
    JobController,
    JobStage,
    JobState,
    MissingToolError,
    StageResult,
    StageStatus,
    UnsupportedFormatError,
)


def make_controller() -> JobController:
    return JobController()


def make_context() -> JobContext:
    return JobContext(
        source_file="sample.zip",
        stages=[JobStage(id="dictionary", display_name="Dictionary")],
    )


class JobControllerTests(TestCase):
    def test_full_run_emits_legal_state_sequence(self):
        states = []
        controller = JobController(lambda snapshot: states.append(snapshot.state))
        context = make_context()
        context.converter = "zip2john.exe"

        controller.start(context)
        controller.run()
        controller.complete_stage(StageResult.FOUND)

        self.assertEqual(
            states,
            [
                JobState.PREPARING,
                JobState.CHECKING_ENV,
                JobState.CONVERTING,
                JobState.BUILDING_CANDIDATES,
                JobState.RUNNING,
                JobState.SUCCEEDED,
            ],
        )

    def test_start_run_success(self):
        controller = make_controller()

        self.assertEqual(controller.start(make_context()).state, JobState.PREPARING)
        self.assertEqual(controller.run().state, JobState.RUNNING)
        snapshot = controller.complete_stage(StageResult.FOUND, recovered_password="secret")

        self.assertEqual(snapshot.state, JobState.SUCCEEDED)
        self.assertEqual(snapshot.recovered_passwords, ("secret",))
        self.assertEqual(snapshot.stages[0].status, StageStatus.FOUND)

    def test_terminal_elapsed_time_stops_increasing(self):
        controller = make_controller()
        with patch("password_gui.job.time.monotonic", return_value=10):
            controller.start(make_context())
            controller.run()
        with patch("password_gui.job.time.monotonic", return_value=20):
            snapshot = controller.complete_stage(StageResult.FOUND)
        with patch("password_gui.job.time.monotonic", return_value=100):
            later = controller.snapshot

        self.assertEqual(snapshot.elapsed_time, 10)
        self.assertEqual(later.elapsed_time, 10)

    def test_start_run_exhausted(self):
        controller = make_controller()
        controller.start(make_context())
        controller.run()

        self.assertEqual(
            controller.complete_stage(StageResult.EXHAUSTED).state,
            JobState.EXHAUSTED,
        )

    def test_exhausted_stage_advances_before_final_exhaustion(self):
        controller = make_controller()
        context = JobContext(
            source_file="sample.zip",
            stages=[JobStage(id="dictionary"), JobStage(id="mask")],
        )
        controller.start(context)
        controller.run()

        snapshot = controller.complete_stage(StageResult.EXHAUSTED)
        self.assertEqual(snapshot.state, JobState.BUILDING_CANDIDATES)
        self.assertEqual(snapshot.current_stage_index, 1)

        controller.transition(JobState.RUNNING)
        self.assertEqual(
            controller.complete_stage(StageResult.EXHAUSTED).state,
            JobState.EXHAUSTED,
        )

    def test_start_run_failure_keeps_structured_error(self):
        controller = make_controller()
        controller.start(make_context())
        controller.run()

        snapshot = controller.complete_stage(
            StageResult.FAILED, error=EngineRuntimeError("引擎失敗", details="stderr")
        )

        self.assertEqual(snapshot.state, JobState.FAILED)
        self.assertEqual(snapshot.error, "引擎失敗")
        self.assertIn("stderr", snapshot.technical_error or "")

    def test_structured_errors_keep_distinct_categories(self):
        cases = (
            (MissingToolError, ErrorCategory.MISSING_TOOL),
            (UnsupportedFormatError, ErrorCategory.UNSUPPORTED_FORMAT),
            (ConverterError, ErrorCategory.CONVERTER),
            (InvalidDictionaryError, ErrorCategory.INVALID_DICTIONARY),
            (EngineLaunchError, ErrorCategory.ENGINE_LAUNCH),
            (EngineRuntimeError, ErrorCategory.ENGINE_RUNTIME),
        )
        for error_type, category in cases:
            with self.subTest(error=error_type.__name__):
                controller = make_controller()
                controller.start(make_context())
                snapshot = controller.fail(error_type("使用者訊息", details="技術細節"))
                self.assertEqual(snapshot.error_category, category)
                self.assertEqual(snapshot.error, "使用者訊息")
                self.assertEqual(snapshot.technical_error, "技術細節")

    def test_cancel_has_stopping_intermediate_state(self):
        controller = make_controller()
        controller.start(make_context())
        controller.run()

        self.assertEqual(controller.request_cancel().state, JobState.STOPPING)
        self.assertEqual(
            controller.complete_stage(StageResult.CANCELLED).state,
            JobState.CANCELLED,
        )

    def test_illegal_transition_is_rejected(self):
        controller = JobController()

        with self.assertRaises(InvalidTransitionError):
            controller.transition(JobState.RUNNING)

    def test_duplicate_start_is_rejected(self):
        controller = make_controller()
        controller.start(make_context())

        with self.assertRaises(JobAlreadyRunningError):
            controller.start(JobContext())


if __name__ == "__main__":
    main()
