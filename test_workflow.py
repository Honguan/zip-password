from unittest import TestCase, main

from password_gui.config import AttackStrategy
from password_gui.workflow import attack_steps


class WorkflowTests(TestCase):
    def test_plans_each_strategy_without_tk(self):
        self.assertEqual(
            attack_steps(AttackStrategy.AUTO, has_dictionary=True, has_hints=True),
            ("dictionary", "hints", "mask"),
        )
        self.assertEqual(
            attack_steps(AttackStrategy.DICTIONARY, has_dictionary=True, has_hints=False),
            ("dictionary",),
        )
        self.assertEqual(
            attack_steps(AttackStrategy.HINTS, has_dictionary=False, has_hints=True),
            ("hints",),
        )
        self.assertEqual(
            attack_steps(AttackStrategy.MASK, has_dictionary=False, has_hints=False),
            ("mask",),
        )

    def test_source_only_strategies_require_candidates(self):
        for strategy, message in (
            (AttackStrategy.DICTIONARY, "需要明確選擇"),
            (AttackStrategy.HINTS, "需要提示詞"),
        ):
            with self.subTest(strategy=strategy), self.assertRaisesRegex(ValueError, message):
                attack_steps(strategy, has_dictionary=False, has_hints=False)


if __name__ == "__main__":
    main()
