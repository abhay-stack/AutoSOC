"""Deterministic detection of deprecated TLS protocols and weak ciphers."""

from __future__ import annotations

from dataclasses import dataclass
import re

from autosoc.models import (
    DecisionTraceEntry,
    DetectionCategory,
    DetectionFinding,
    Evidence,
    SecurityEvent,
    Severity,
    TraceOutcome,
    TraceStage,
)
from autosoc.scoring.risk import calculate_risk_score

RULE_VERSION = "1.0.0"
_DEPRECATED_PROTOCOL_PATTERN = (
    r"(?i)^(?:SSL[\s._-]*V?2(?:[._]0)?|SSL[\s._-]*V?3(?:[._]0)?|"
    r"TLS[\s._-]*V?1(?:[._][01])?)$"
)
_DEPRECATED_PROTOCOL_REGEX = re.compile(_DEPRECATED_PROTOCOL_PATTERN)
_PROTOCOL_ALIASES = {
    "SSL2": ("SSLv2", Severity.HIGH),
    "SSLV2": ("SSLv2", Severity.HIGH),
    "SSL20": ("SSLv2", Severity.HIGH),
    "SSLV20": ("SSLv2", Severity.HIGH),
    "SSL3": ("SSLv3", Severity.HIGH),
    "SSLV3": ("SSLv3", Severity.HIGH),
    "SSL30": ("SSLv3", Severity.HIGH),
    "SSLV30": ("SSLv3", Severity.HIGH),
    "TLS1": ("TLS 1.0", Severity.MEDIUM),
    "TLSV1": ("TLS 1.0", Severity.MEDIUM),
    "TLS10": ("TLS 1.0", Severity.MEDIUM),
    "TLSV10": ("TLS 1.0", Severity.MEDIUM),
    "TLS11": ("TLS 1.1", Severity.MEDIUM),
    "TLSV11": ("TLS 1.1", Severity.MEDIUM),
}
_SEVERITY_ORDER = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True, slots=True)
class _CipherWeakness:
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    explanation: str


_CIPHER_WEAKNESSES = (
    _CipherWeakness(
        name="null encryption",
        pattern=re.compile(
            r"(?<![A-Z0-9])(?:NULL|ENULL)(?![A-Z0-9])",
            flags=re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        explanation="The cipher provides no payload encryption.",
    ),
    _CipherWeakness(
        name="export-grade encryption",
        pattern=re.compile(
            r"(?<![A-Z0-9])EXP(?:ORT)?(?:40|56)?(?![A-Z0-9])",
            flags=re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        explanation="Export-grade suites use deliberately weakened cryptography.",
    ),
    _CipherWeakness(
        name="RC2/RC4 encryption",
        pattern=re.compile(r"(?<![A-Z0-9])RC[24](?![A-Z0-9])", re.IGNORECASE),
        severity=Severity.HIGH,
        explanation="RC2 and RC4 cipher families are cryptographically obsolete.",
    ),
    _CipherWeakness(
        name="3DES encryption",
        pattern=re.compile(
            r"(?<![A-Z0-9])(?:3DES|DES[_-]?EDE(?:3)?|CBC3)(?![A-Z0-9])",
            flags=re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        explanation="3DES has a small block size and is no longer acceptable for TLS.",
    ),
    _CipherWeakness(
        name="single-DES encryption",
        pattern=re.compile(
            r"(?<![A-Z0-9])DES(?=$|[_-](?!(?:EDE|CBC3)))",
            flags=re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        explanation="Single DES does not provide adequate encryption strength.",
    ),
    _CipherWeakness(
        name="MD5 integrity",
        pattern=re.compile(r"(?<![A-Z0-9])MD5(?![A-Z0-9])", re.IGNORECASE),
        severity=Severity.MEDIUM,
        explanation="MD5 is not an acceptable integrity primitive for modern TLS.",
    ),
    _CipherWeakness(
        name="anonymous key exchange",
        pattern=re.compile(
            r"(?<![A-Z0-9])(?:ADH|AECDH|(?:EC)?DH[_-]ANON)(?![A-Z0-9])",
            flags=re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        explanation="Anonymous key exchange does not authenticate the peer.",
    ),
    _CipherWeakness(
        name="IDEA encryption",
        pattern=re.compile(r"(?<![A-Z0-9])IDEA(?![A-Z0-9])", re.IGNORECASE),
        severity=Severity.MEDIUM,
        explanation="IDEA suites are obsolete and not approved for modern TLS.",
    ),
)


def _canonical_protocol(value: str) -> tuple[str, Severity] | None:
    if _DEPRECATED_PROTOCOL_REGEX.fullmatch(value) is None:
        return None
    normalized = re.sub(r"[\s._-]", "", value).upper()
    return _PROTOCOL_ALIASES.get(normalized)


def _cipher_candidates(event: SecurityEvent) -> tuple[tuple[str, str], ...]:
    candidates: list[tuple[str, str]] = []
    for key in ("tls_cipher", "cipher", "cipher_suite", "ssl_cipher"):
        value = event.attributes.get(key)
        if isinstance(value, str) and value:
            candidates.append((f"attributes.{key}", value))
        elif isinstance(value, list):
            candidates.extend(
                (f"attributes.{key}[{index}]", item)
                for index, item in enumerate(value)
                if isinstance(item, str) and item
            )

    unique: dict[tuple[str, str], None] = {}
    for candidate in candidates:
        unique[candidate] = None
    return tuple(unique)


def _configuration_mapping_note() -> str:
    return (
        "No MITRE ATT&CK technique assigned: deprecated TLS is a configuration "
        "weakness, not evidence that an adversary performed network sniffing, a "
        "downgrade attack, or adversary-in-the-middle activity."
    )


def _protocol_finding(
    event: SecurityEvent,
    canonical_protocol: str,
    severity: Severity,
    *,
    ip_reputation_score: float | None,
) -> DetectionFinding:
    assert event.tls_version is not None
    evidence = Evidence(
        event_id=event.event_id,
        source_field="tls_version",
        observed_value=event.tls_version,
        description=(
            f"Negotiated protocol {event.tls_version!r} normalized to deprecated "
            f"{canonical_protocol}."
        ),
        matched_pattern=_DEPRECATED_PROTOCOL_PATTERN,
        match_start=0,
        match_end=len(event.tls_version),
    )
    confidence = 1.0
    risk = calculate_risk_score(
        severity,
        confidence,
        ip_reputation_score,
        evidence_ids=[evidence.evidence_id],
    )
    return DetectionFinding(
        event_id=event.event_id,
        rule_id="TLS.DEPRECATED_PROTOCOL",
        rule_version=RULE_VERSION,
        title=f"Deprecated TLS protocol negotiated: {canonical_protocol}",
        description=(
            f"The connection negotiated {canonical_protocol}, which does not meet "
            "the AutoSOC minimum TLS policy. This is a configuration finding; it "
            "does not assert that traffic interception occurred."
        ),
        category=DetectionCategory.WEAK_TLS,
        severity=severity,
        risk_score=risk.score,
        risk_score_components=list(risk.components),
        confidence_score=confidence,
        confidence_basis=(
            "The normalized protocol value exactly matched the versioned "
            "deprecated-protocol allowlist."
        ),
        evidence=[evidence],
        mitre_attack_mappings=[],
        decision_trace=[
            DecisionTraceEntry(
                sequence=1,
                stage=TraceStage.DETECTION,
                component="weak_tls_detector",
                operation="canonicalize and compare protocol against exact denylist",
                outcome=TraceOutcome.MATCHED,
                rule_id="TLS.DEPRECATED_PROTOCOL",
                evidence_ids=[evidence.evidence_id],
                details={
                    "canonical_protocol": canonical_protocol,
                    "cwe_id": "CWE-326",
                    "mitre_mapping_decision": _configuration_mapping_note(),
                },
            ),
            DecisionTraceEntry(
                sequence=2,
                stage=TraceStage.SCORING,
                component="risk_scorer",
                operation="apply deterministic risk formula",
                outcome=TraceOutcome.CALCULATED,
                rule_id="TLS.DEPRECATED_PROTOCOL",
                evidence_ids=[evidence.evidence_id],
                details=risk.trace_details(),
            ),
        ],
        recommended_actions=[
            "Disable the deprecated protocol after change approval and testing.",
            "Require TLS 1.2 or TLS 1.3 on the affected listener.",
            "Retest supported protocols before closing the finding.",
        ],
    )


def _cipher_finding(
    event: SecurityEvent,
    evidence: list[Evidence],
    weakness_names: list[str],
    severity: Severity,
    *,
    ip_reputation_score: float | None,
) -> DetectionFinding:
    evidence_ids = [item.evidence_id for item in evidence]
    confidence = 0.99
    risk = calculate_risk_score(
        severity,
        confidence,
        ip_reputation_score,
        evidence_ids=evidence_ids,
    )
    return DetectionFinding(
        event_id=event.event_id,
        rule_id="TLS.WEAK_CIPHER",
        rule_version=RULE_VERSION,
        title="Known weak TLS cipher negotiated",
        description=(
            "The negotiated cipher contains an explicitly denied cryptographic "
            "primitive. This is a configuration finding; it does not assert that "
            "the connection was decrypted."
        ),
        category=DetectionCategory.WEAK_TLS,
        severity=severity,
        risk_score=risk.score,
        risk_score_components=list(risk.components),
        confidence_score=confidence,
        confidence_basis=(
            "One or more bounded token signatures matched the explicit weak-cipher "
            "denylist. Generic CBC and static-RSA suites are not matched."
        ),
        evidence=evidence,
        mitre_attack_mappings=[],
        decision_trace=[
            DecisionTraceEntry(
                sequence=1,
                stage=TraceStage.DETECTION,
                component="weak_tls_detector",
                operation="match cipher tokens against explicit weak-cipher denylist",
                outcome=TraceOutcome.MATCHED,
                rule_id="TLS.WEAK_CIPHER",
                evidence_ids=evidence_ids,
                details={
                    "weaknesses": sorted(set(weakness_names)),
                    "cwe_id": "CWE-326",
                    "mitre_mapping_decision": _configuration_mapping_note(),
                },
            ),
            DecisionTraceEntry(
                sequence=2,
                stage=TraceStage.SCORING,
                component="risk_scorer",
                operation="apply deterministic risk formula",
                outcome=TraceOutcome.CALCULATED,
                rule_id="TLS.WEAK_CIPHER",
                evidence_ids=evidence_ids,
                details=risk.trace_details(),
            ),
        ],
        recommended_actions=[
            "Remove NULL, EXPORT, RC2/RC4, DES/3DES, MD5, IDEA, and anonymous suites.",
            "Prefer authenticated AEAD suites supported by TLS 1.2 or TLS 1.3.",
            "Apply cipher-policy changes only after human approval and testing.",
        ],
    )


def detect_weak_tls(
    event: SecurityEvent,
    *,
    ip_reputation_score: float | None = None,
) -> list[DetectionFinding]:
    """Return explicit protocol and cipher findings for a normalized event."""

    findings: list[DetectionFinding] = []
    if event.tls_version:
        protocol_match = _canonical_protocol(event.tls_version)
        if protocol_match is not None:
            canonical_protocol, severity = protocol_match
            findings.append(
                _protocol_finding(
                    event,
                    canonical_protocol,
                    severity,
                    ip_reputation_score=ip_reputation_score,
                )
            )

    cipher_evidence: list[Evidence] = []
    weakness_names: list[str] = []
    matched_severities: list[Severity] = []
    seen_matches: set[tuple[str, int, int, str]] = set()
    for source_field, cipher in _cipher_candidates(event):
        for weakness in _CIPHER_WEAKNESSES:
            for match in weakness.pattern.finditer(cipher):
                match_key = (source_field, match.start(), match.end(), weakness.name)
                if match_key in seen_matches:
                    continue
                seen_matches.add(match_key)
                weakness_names.append(weakness.name)
                matched_severities.append(weakness.severity)
                cipher_evidence.append(
                    Evidence(
                        event_id=event.event_id,
                        source_field=source_field,
                        observed_value=cipher,
                        description=(
                            f"Weak cipher token {match.group(0)!r} matched: "
                            f"{weakness.explanation}"
                        ),
                        matched_pattern=weakness.pattern.pattern,
                        match_start=match.start(),
                        match_end=match.end(),
                    )
                )

    if cipher_evidence:
        severity = max(
            matched_severities,
            key=_SEVERITY_ORDER.__getitem__,
        )
        findings.append(
            _cipher_finding(
                event,
                cipher_evidence,
                weakness_names,
                severity,
                ip_reputation_score=ip_reputation_score,
            )
        )

    return findings


__all__ = ["RULE_VERSION", "detect_weak_tls"]
