"""Versioned, deterministic risk scoring for AutoSOC findings."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP
from math import isfinite
from types import MappingProxyType
from uuid import UUID

from autosoc.models import ScoreContribution, Severity

FORMULA_VERSION = "1.0"
IP_REPUTATION_MAX_POINTS = 20

SEVERITY_BASE_POINTS = MappingProxyType(
    {
        Severity.INFORMATIONAL: 10,
        Severity.LOW: 25,
        Severity.MEDIUM: 45,
        Severity.HIGH: 65,
        Severity.CRITICAL: 80,
    }
)


def _round_half_up(value: float) -> int:
    return int(
        Decimal(str(value)).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    )


def _validated_unit_score(value: float, field_name: str) -> float:
    if isinstance(value, bool):
        raise TypeError(f"{field_name} must be a number, not bool")
    numeric_value = float(value)
    if not isfinite(numeric_value) or not 0.0 <= numeric_value <= 1.0:
        raise ValueError(f"{field_name} must be between 0.0 and 1.0")
    return numeric_value


def _validated_reputation(value: float | None) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise TypeError("ip_reputation_score must be a number, not bool")
    numeric_value = float(value)
    if not isfinite(numeric_value) or not 0.0 <= numeric_value <= 100.0:
        raise ValueError("ip_reputation_score must be between 0 and 100")
    return numeric_value


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """Calculated score plus the exact additive components used to derive it."""

    score: int
    components: tuple[ScoreContribution, ...]
    formula_version: str = FORMULA_VERSION

    def trace_details(self) -> dict[str, object]:
        """Return a JSON-safe scoring record for a decision-trace entry."""

        return {
            "formula_version": self.formula_version,
            "score": self.score,
            "calculation": "clamp(severity + confidence_adjustment + ip_reputation)",
            "components": [
                component.model_dump(mode="json") for component in self.components
            ],
        }


def calculate_risk_score(
    severity: Severity | str,
    confidence_score: float,
    ip_reputation_score: float | None = None,
    *,
    evidence_ids: Iterable[UUID] = (),
    ip_reputation_evidence_ids: Iterable[UUID] = (),
) -> RiskAssessment:
    """Calculate a 0-100 score using a documented additive formula.

    ``ip_reputation_score`` follows AbuseIPDB-style semantics: 0 means no known
    abuse and 100 means highly likely malicious.  ``None`` is deliberately
    neutral, which allows Step 3 to operate before threat-intelligence
    enrichment is available.
    """

    try:
        normalized_severity = Severity(severity)
    except ValueError as exc:
        raise ValueError(f"unsupported severity: {severity!r}") from exc
    confidence = _validated_unit_score(confidence_score, "confidence_score")
    reputation = _validated_reputation(ip_reputation_score)
    detection_evidence_ids = list(evidence_ids)
    reputation_evidence_ids = list(ip_reputation_evidence_ids)

    severity_points = SEVERITY_BASE_POINTS[normalized_severity]
    confidence_adjusted_points = _round_half_up(severity_points * confidence)
    confidence_adjustment = confidence_adjusted_points - severity_points
    reputation_points = (
        0
        if reputation is None
        else _round_half_up(
            reputation / 100.0 * IP_REPUTATION_MAX_POINTS
        )
    )

    components = (
        ScoreContribution(
            component="severity_baseline",
            points=severity_points,
            reason=(
                f"{normalized_severity.value} severity contributes "
                f"{severity_points} baseline points under formula {FORMULA_VERSION}."
            ),
            evidence_ids=detection_evidence_ids,
        ),
        ScoreContribution(
            component="confidence_adjustment",
            points=confidence_adjustment,
            reason=(
                f"Confidence {confidence:.3f} scales the severity baseline from "
                f"{severity_points} to {confidence_adjusted_points} points."
            ),
            evidence_ids=detection_evidence_ids,
        ),
        ScoreContribution(
            component="ip_reputation",
            points=reputation_points,
            reason=(
                "No IP reputation was supplied; a neutral 0-point placeholder "
                "was applied."
                if reputation is None
                else (
                    f"IP reputation {reputation:.1f}/100 contributes "
                    f"{reputation_points}/{IP_REPUTATION_MAX_POINTS} points."
                )
            ),
            evidence_ids=reputation_evidence_ids,
        ),
    )
    score = max(0, min(100, sum(component.points for component in components)))
    return RiskAssessment(score=score, components=components)


def severity_from_score(score: int) -> Severity:
    """Map an aggregate numeric score to stable report severity bands."""

    if isinstance(score, bool) or not isinstance(score, int):
        raise TypeError("score must be an integer")
    if not 0 <= score <= 100:
        raise ValueError("score must be between 0 and 100")
    if score >= 80:
        return Severity.CRITICAL
    if score >= 60:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    if score >= 20:
        return Severity.LOW
    return Severity.INFORMATIONAL


__all__ = [
    "FORMULA_VERSION",
    "IP_REPUTATION_MAX_POINTS",
    "RiskAssessment",
    "SEVERITY_BASE_POINTS",
    "calculate_risk_score",
    "severity_from_score",
]
