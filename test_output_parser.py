from unittest import TestCase, main

from password_gui.output_parser import (
    CandidateChanged,
    DashboardSnapshot,
    EngineOutputParser,
    EngineStatusChanged,
    ModeChanged,
    OutputFileChanged,
    PasswordLengthChanged,
    ProgressChanged,
    QueueChanged,
    RecoveredChanged,
    SpeedChanged,
    TemperatureChanged,
    apply_event,
)


class OutputParserTests(TestCase):
    def test_hashcat_metrics_are_structured_and_bounded(self):
        events = EngineOutputParser("hashcat").feed(
            "Status.........: Running\n"
            "Candidates.#1....: " + "a" * 40 + "\n"
            "Speed.#1.........: 1.23 MH/s @ 1000 MHz\n"
            "Recovered........: 1/2 (50.00%)\n"
            "Progress.........: 10/20 (50%)\n"
            "Temp: 65c Temp: 70C\n"
        )

        self.assertEqual(
            [type(event) for event in events],
            [
                EngineStatusChanged,
                CandidateChanged,
                SpeedChanged,
                RecoveredChanged,
                ProgressChanged,
                TemperatureChanged,
            ],
        )
        self.assertEqual(events[0].status, "Running")
        self.assertEqual(events[1].candidate, "a" * 35 + "…")
        self.assertEqual(events[2].speed, "1.23 MH/s")
        self.assertEqual(events[3].recovered, "1/2 (50.00%)")
        self.assertEqual((events[4].value, events[4].percent), ("50.00%", 50.0))
        self.assertEqual(events[5].temperature, "65C / 70C")

    def test_john_metrics_include_trying_candidate_and_running_status(self):
        events = EngineOutputParser("john").feed("12g 0:00:01:00 2.5Kc/s trying: secret")

        self.assertEqual(
            [type(event) for event in events],
            [SpeedChanged, RecoveredChanged, EngineStatusChanged, CandidateChanged],
        )
        self.assertEqual(events[0].speed, "2.5Kc/s")
        self.assertEqual(events[1].recovered, "12")
        self.assertEqual(events[2].status, "執行中")
        self.assertEqual(events[3].candidate, "secret")

    def test_completion_and_malformed_progress_keep_existing_display_semantics(self):
        parser = EngineOutputParser()

        completed = parser.feed("[12:00:00] hashcat 結束，代碼 0")
        self.assertEqual([type(event) for event in completed], [EngineStatusChanged, ProgressChanged])
        self.assertEqual((completed[0].status, completed[1].value, completed[1].percent), ("已結束", "100%", 100.0))

        raw = parser.feed("Progress.........: 10/20")
        self.assertEqual((raw[0].value, raw[0].percent, raw[0].raw), ("10/20", None, "10/20"))

    def test_events_build_one_ui_independent_snapshot(self):
        snapshot = DashboardSnapshot()
        for event in EngineOutputParser("hashcat").feed(
            "Status.........: Running\nProgress.........: 1/2 (50%)\nSpeed.#1.........: 1 MH/s"
        ):
            snapshot = apply_event(snapshot, event)

        self.assertEqual((snapshot.status, snapshot.progress, snapshot.progress_percent), ("Running", "50.00%", 50.0))
        self.assertEqual(snapshot.speed, "1 MH/s")

    def test_mode_mask_queue_and_output_file_are_structured(self):
        snapshot = DashboardSnapshot()
        events = EngineOutputParser("hashcat").feed(
            "Hash.Mode.........: 0 (MD5)\n"
            "Guess.Mask........: ?l?l?d [3]\n"
            "Guess.Queue.......: 1/2 (50%)\n"
            "Loaded 2 password hashes\n"
            "已輸出密碼：sample_cracked.txt"
        )
        self.assertEqual(
            [type(event) for event in events],
            [ModeChanged, PasswordLengthChanged, QueueChanged, QueueChanged, OutputFileChanged],
        )
        for event in events:
            snapshot = apply_event(snapshot, event)
        self.assertEqual(snapshot.mode, "0 (MD5)")
        self.assertEqual(snapshot.password_length, "3 位")
        self.assertEqual(snapshot.queue, "已載入 2 hash")
        self.assertEqual(snapshot.output_file, "已輸出密碼：sample_cracked.txt")


if __name__ == "__main__":
    main()
