"""Deterministic threat detectors."""

from autosoc.detectors.sqli import detect_sqli
from autosoc.detectors.weak_tls import detect_weak_tls

__all__ = ["detect_sqli", "detect_weak_tls"]
