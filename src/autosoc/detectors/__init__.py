"""Deterministic threat detectors."""

from autosoc.detectors.sigma_engine import (
    SigmaEngine,
    SigmaEngineError,
    SigmaEvaluationPlan,
)
from autosoc.detectors.sqli import detect_sqli
from autosoc.detectors.weak_tls import detect_weak_tls

__all__ = [
    "SigmaEngine",
    "SigmaEngineError",
    "SigmaEvaluationPlan",
    "detect_sqli",
    "detect_weak_tls",
]
