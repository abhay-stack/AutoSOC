"""Tests for the versioned risk formula."""

from __future__ import annotations

import unittest
from uuid import uuid4

from autosoc.models import (
    GreyNoiseClassification,
    GreyNoiseLookupStatus,
    GreyNoiseResult,
    Severity,
    ThreatIntelMode,
)
from autosoc.scoring.risk import calculate_risk_score, severity_from_score


def _live_greynoise(
    classification: GreyNoiseClassification,
    *,
    noise: bool,
    riot: bool = False,
) -> GreyNoiseResult:
    return GreyNoiseResult(
        ip_address="8.8.8.8",
        noise=noise,
        riot=riot,
        classification=classification,
        mode=ThreatIntelMode.LIVE,
        lookup_status=GreyNoiseLookupStatus.MATCHED,
        retrieval_reason="validated test context",
    )


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
        self.assertEqual(
            [component.component for component in assessment.components],
            [
                "severity_baseline",
                "confidence_adjustment",
                "ip_reputation",
            ],
        )

    def test_benign_greynoise_classification_retains_one_quarter(self) -> None:
        assessment = calculate_risk_score(
            Severity.HIGH,
            confidence_score=0.94,
            ip_reputation_score=50,
            greynoise_result=_live_greynoise(
                GreyNoiseClassification.BENIGN,
                noise=False,
                riot=True,
            ),
        )

        self.assertEqual(assessment.score, 18)
        self.assertEqual(
            [component.points for component in assessment.components],
            [65, -4, 10, -53],
        )
        self.assertEqual(
            assessment.components[-1].component,
            "greynoise_noise_filter",
        )
        self.assertIn("retained 25%", assessment.components[-1].reason)
        self.assertEqual(
            assessment.score,
            sum(component.points for component in assessment.components),
        )

    def test_unknown_greynoise_scanner_noise_is_suppressed(self) -> None:
        assessment = calculate_risk_score(
            Severity.HIGH,
            confidence_score=0.94,
            ip_reputation_score=50,
            greynoise_result=_live_greynoise(
                GreyNoiseClassification.UNKNOWN,
                noise=True,
            ),
        )

        self.assertEqual(assessment.score, 18)
        self.assertEqual(assessment.components[-1].points, -53)

    def test_mock_greynoise_result_cannot_suppress_risk(self) -> None:
        mock_result = GreyNoiseResult(
            ip_address="8.8.8.8",
            mode=ThreatIntelMode.MOCK,
            lookup_status=GreyNoiseLookupStatus.MISSING_KEY,
            retrieval_reason="API key is unavailable",
        )
        assessment = calculate_risk_score(
            Severity.HIGH,
            confidence_score=0.94,
            ip_reputation_score=50,
            greynoise_result=mock_result,
        )

        self.assertEqual(assessment.score, 71)
        self.assertEqual(len(assessment.components), 3)

    def test_authoritative_not_found_result_is_visible_but_neutral(self) -> None:
        not_found = GreyNoiseResult(
            ip_address="8.8.8.8",
            mode=ThreatIntelMode.LIVE,
            lookup_status=GreyNoiseLookupStatus.NOT_FOUND,
            retrieval_reason="live IP not found",
        )
        assessment = calculate_risk_score(
            Severity.HIGH,
            confidence_score=0.94,
            ip_reputation_score=50,
            greynoise_result=not_found,
        )

        self.assertEqual(assessment.score, 71)
        self.assertEqual(assessment.components[-1].points, 0)
        self.assertIn("not_found", assessment.components[-1].reason)

    def test_malicious_greynoise_classification_overrides_noise(self) -> None:
        assessment = calculate_risk_score(
            Severity.HIGH,
            confidence_score=0.94,
            ip_reputation_score=50,
            greynoise_result=_live_greynoise(
                GreyNoiseClassification.MALICIOUS,
                noise=True,
            ),
        )

        self.assertEqual(assessment.score, 71)
        self.assertEqual(assessment.components[-1].points, 0)
        self.assertIn("Malicious", assessment.components[-1].reason)

    def test_greynoise_filter_reduces_clamped_hundred_to_twenty_five(self) -> None:
        assessment = calculate_risk_score(
            Severity.CRITICAL,
            confidence_score=1.0,
            ip_reputation_score=100,
            greynoise_result=_live_greynoise(
                GreyNoiseClassification.UNKNOWN,
                noise=True,
            ),
        )

        self.assertEqual(assessment.score, 25)
        self.assertEqual(
            [component.points for component in assessment.components],
            [80, 0, 20, -75],
        )

    def test_greynoise_component_preserves_evidence_ids(self) -> None:
        greynoise_evidence_id = uuid4()

        assessment = calculate_risk_score(
            Severity.MEDIUM,
            confidence_score=1.0,
            greynoise_result=_live_greynoise(
                GreyNoiseClassification.UNKNOWN,
                noise=True,
            ),
            greynoise_evidence_ids=[greynoise_evidence_id],
        )

        self.assertEqual(
            assessment.components[-1].evidence_ids,
            [greynoise_evidence_id],
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
        with self.assertRaises(TypeError):
            calculate_risk_score(
                Severity.HIGH,
                1.0,
                greynoise_result={"noise": True},  # type: ignore[arg-type]
            )

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
