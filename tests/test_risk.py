"""Tests for the versioned risk formula."""

from __future__ import annotations

import unittest

from autosoc.models import Severity
from autosoc.scoring.risk import calculate_risk_score, severity_from_score


class RiskScoringTests(unittest.TestCase):
    def test_score_is_the_clamped_sum_of_visible_components(self) -> None:
        assessment = calculate_risk_score(
            Severity.HIGH,
            confidence_score=0.94,
            ip_reputation_score=50,
        )

        self.assertEqual(assessment.score, 71)
        self.assertEqual(
            assessment.score,
            sum(component.points for component in assessment.components),
        )
        self.assertEqual(
            [component.points for component in assessment.components],
            [65, -4, 10],
        )

    def test_missing_reputation_is_neutral(self) -> None:
        assessment = calculate_risk_score(Severity.MEDIUM, 1.0)

        self.assertEqual(assessment.score, 45)
        self.assertEqual(assessment.components[-1].points, 0)
        self.assertIn("neutral", assessment.components[-1].reason)

    def test_score_clamps_to_one_hundred(self) -> None:
        assessment = calculate_risk_score(Severity.CRITICAL, 1.0, 100)
        self.assertEqual(assessment.score, 100)

    def test_invalid_inputs_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            calculate_risk_score(Severity.HIGH, 1.1)
        with self.assertRaises(ValueError):
            calculate_risk_score(Severity.HIGH, 1.0, 101)
        with self.assertRaises(TypeError):
            calculate_risk_score(Severity.HIGH, True)

    def test_severity_bands_are_stable(self) -> None:
        expected = {
            0: Severity.INFORMATIONAL,
            20: Severity.LOW,
            40: Severity.MEDIUM,
            60: Severity.HIGH,
            80: Severity.CRITICAL,
            100: Severity.CRITICAL,
        }
        for score, severity in expected.items():
            with self.subTest(score=score):
                self.assertEqual(severity_from_score(score), severity)


if __name__ == "__main__":
    unittest.main()
