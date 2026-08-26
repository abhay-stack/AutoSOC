"""Deterministic SQL-injection signatures for normalized web events."""

from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import unquote, unquote_plus

from autosoc.models import (
    DecisionTraceEntry,
    DetectionCategory,
    DetectionFinding,
    Evidence,
    MitreAttackMapping,
    MitreTactic,
    SecurityEvent,
    Severity,
    TraceOutcome,
    TraceStage,
)
from autosoc.scoring.risk import calculate_risk_score

MAX_URL_DECODE_ROUNDS = 3
RULE_VERSION = "1.0.0"

_SQL_GAP = r"\s+"
_SQL_LITERAL = (
    r"(?:-?\d+(?:\.\d+)?|'[^'\r\n]{0,64}'|\"[^\"\r\n]{0,64}\")"
)


@dataclass(frozen=True, slots=True)
class _SQLiSignature:
    rule_id: str
    name: str
    description: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: float
    confidence_basis: str


@dataclass(frozen=True, slots=True)
class _PayloadCandidate:
    source_field: str
    value: str
    decoding_mode: str


_SIGNATURES = (
    _SQLiSignature(
        rule_id="SQLI.UNION_SELECT",
        name="UNION SELECT SQL injection attempt",
        description=(
            "A UNION-based SQL injection sequence was found after bounded URL "
            "decoding. This indicates an attempt, not proof of exploitation."
        ),
        pattern=re.compile(
            rf"\bUNION{_SQL_GAP}(?:ALL{_SQL_GAP})?SELECT\b",
            flags=re.IGNORECASE | re.DOTALL,
        ),
        severity=Severity.HIGH,
        confidence=0.99,
        confidence_basis=(
            "High-specificity UNION [ALL] SELECT syntax matched in a request "
            "payload after bounded URL decoding."
        ),
    ),
    _SQLiSignature(
        rule_id="SQLI.BOOLEAN_INFERENCE",
        name="Boolean-inference SQL injection attempt",
        description=(
            "A SQL logical operator followed by a constant comparison was found "
            "after bounded URL decoding."
        ),
        pattern=re.compile(
            rf"(?<![A-Z0-9_])(?:OR|AND)\b\s*\(?\s*{_SQL_LITERAL}"
            rf"\s*(?:=|!=|<>|<=|>=|<|>)\s*{_SQL_LITERAL}",
            flags=re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        confidence=0.94,
        confidence_basis=(
            "A boolean SQL predicate such as OR 1=1 or AND 'a'='b' matched in "
            "an explicit request payload field."
        ),
    ),
    _SQLiSignature(
        rule_id="SQLI.TIME_BASED",
        name="Time-based blind SQL injection attempt",
        description=(
            "A database delay primitive associated with time-based blind SQL "
            "injection was found after bounded URL decoding."
        ),
        pattern=re.compile(
            r"(?:\b(?:SLEEP|PG_SLEEP|BENCHMARK)\s*\(|\bWAITFOR\s+DELAY\b)",
            flags=re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        confidence=0.97,
        confidence_basis=(
            "A database-specific delay primitive matched in an explicit request "
            "payload field."
        ),
    ),
    _SQLiSignature(
        rule_id="SQLI.STACKED_QUERY",
        name="Stacked-query SQL injection attempt",
        description=(
            "A statement delimiter followed by a data-changing or execution SQL "
            "verb was found after bounded URL decoding."
        ),
        pattern=re.compile(
            r";\s*(?:DROP|ALTER|TRUNCATE|INSERT|UPDATE|DELETE|EXEC(?:UTE)?)\b",
            flags=re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        confidence=0.97,
        confidence_basis=(
            "A semicolon-delimited destructive or execution statement matched in "
            "an explicit request payload field."
        ),
    ),
)


def _decode_component(value: str, *, plus_as_space: bool) -> tuple[str, int]:
    current = value
    decode_rounds = 0
    decoder = unquote_plus if plus_as_space else unquote
    for _ in range(MAX_URL_DECODE_ROUNDS):
        decoded = decoder(current, encoding="utf-8", errors="replace")
        if decoded == current:
            break
        current = decoded
        decode_rounds += 1
    return current, decode_rounds


def _decode_request_target(value: str) -> tuple[str, int]:
    """Decode path and query with their respective URL semantics."""

    current = value
    decode_rounds = 0
    for _ in range(MAX_URL_DECODE_ROUNDS):
        path, separator, query_and_fragment = current.partition("?")
        decoded_path = unquote(path, encoding="utf-8", errors="replace")
        decoded_suffix = ""
        if separator:
            query, fragment_separator, fragment = query_and_fragment.partition("#")
            decoded_query = unquote_plus(query, encoding="utf-8", errors="replace")
            decoded_fragment = (
                unquote_plus(fragment, encoding="utf-8", errors="replace")
                if fragment_separator
                else ""
            )
            decoded_suffix = f"?{decoded_query}"
            if fragment_separator:
                decoded_suffix += f"#{decoded_fragment}"
        decoded = f"{decoded_path}{decoded_suffix}"
        if decoded == current:
            break
        current = decoded
        decode_rounds += 1
    return current, decode_rounds


def _payload_candidates(event: SecurityEvent) -> tuple[_PayloadCandidate, ...]:
    candidates: list[_PayloadCandidate] = []
    if event.request_path:
        candidates.append(
            _PayloadCandidate(
                source_field="request_path",
                value=event.request_path,
                decoding_mode="request_target",
            )
        )

    attribute_modes = {
        "query_string": "form",
        "request_query": "form",
        "query": "form",
        "request_body": "form",
        "form_data": "form",
    }
    for key, decoding_mode in attribute_modes.items():
        value = event.attributes.get(key)
        if isinstance(value, str) and value:
            candidates.append(
                _PayloadCandidate(
                    source_field=f"attributes.{key}",
                    value=value,
                    decoding_mode=decoding_mode,
                )
            )

    # Preserve field provenance while eliminating exact duplicates.
    unique: dict[tuple[str, str], _PayloadCandidate] = {}
    for candidate in candidates:
        unique[(candidate.source_field, candidate.value)] = candidate
    return tuple(unique.values())


def _decoded_candidate(candidate: _PayloadCandidate) -> tuple[str, int]:
    if candidate.decoding_mode == "request_target":
        return _decode_request_target(candidate.value)
    return _decode_component(candidate.value, plus_as_space=True)


def _mask_block_comments(value: str) -> str:
    """Replace closed SQL block comments with equal-length whitespace."""

    characters = list(value)
    position = 0
    while True:
        start = value.find("/*", position)
        if start == -1:
            break
        end = value.find("*/", start + 2)
        if end == -1:
            break
        end += 2
        characters[start:end] = " " * (end - start)
        position = end
    return "".join(characters)


def _mitre_mapping() -> MitreAttackMapping:
    return MitreAttackMapping(
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic=MitreTactic.INITIAL_ACCESS,
        mapping_reason=(
            "A crafted SQL injection payload was observed targeting an application "
            "request. This records an exploitation attempt; it does not assert that "
            "initial access succeeded."
        ),
    )


def detect_sqli(
    event: SecurityEvent,
    *,
    ip_reputation_score: float | None = None,
) -> list[DetectionFinding]:
    """Return one auditable finding per SQLi signature matched in ``event``."""

    decoded_candidates = [
        (candidate, *_decoded_candidate(candidate))
        for candidate in _payload_candidates(event)
    ]
    findings: list[DetectionFinding] = []

    for signature in _SIGNATURES:
        evidence: list[Evidence] = []
        decoded_fields: list[str] = []
        maximum_decode_rounds = 0
        seen_matches: set[tuple[str, int, int, str]] = set()

        for candidate, decoded_value, decode_rounds in decoded_candidates:
            inspection_value = _mask_block_comments(decoded_value)
            for match in signature.pattern.finditer(inspection_value):
                maximum_decode_rounds = max(maximum_decode_rounds, decode_rounds)
                matched_text = decoded_value[match.start() : match.end()]
                match_key = (
                    candidate.source_field,
                    match.start(),
                    match.end(),
                    matched_text,
                )
                if match_key in seen_matches:
                    continue
                seen_matches.add(match_key)
                decoded_fields.append(candidate.source_field)
                evidence.append(
                    Evidence(
                        event_id=event.event_id,
                        source_field=candidate.source_field,
                        observed_value=decoded_value,
                        description=(
                            f"{signature.name} matched after {decode_rounds} URL "
                            f"decode round(s): {matched_text!r}."
                        ),
                        matched_pattern=signature.pattern.pattern,
                        match_start=match.start(),
                        match_end=match.end(),
                    )
                )

        if not evidence:
            continue

        evidence_ids = [item.evidence_id for item in evidence]
        risk = calculate_risk_score(
            signature.severity,
            signature.confidence,
            ip_reputation_score,
            evidence_ids=evidence_ids,
        )
        findings.append(
            DetectionFinding(
                event_id=event.event_id,
                rule_id=signature.rule_id,
                rule_version=RULE_VERSION,
                title=signature.name,
                description=signature.description,
                category=DetectionCategory.SQL_INJECTION,
                severity=signature.severity,
                risk_score=risk.score,
                risk_score_components=list(risk.components),
                confidence_score=signature.confidence,
                confidence_basis=signature.confidence_basis,
                evidence=evidence,
                mitre_attack_mappings=[_mitre_mapping()],
                decision_trace=[
                    DecisionTraceEntry(
                        sequence=1,
                        stage=TraceStage.DETECTION,
                        component="sqli_detector",
                        operation=(
                            "bounded URL decode, length-preserving SQL comment "
                            "masking, and signature matching"
                        ),
                        outcome=TraceOutcome.MATCHED,
                        rule_id=signature.rule_id,
                        evidence_ids=evidence_ids,
                        details={
                            "signature_name": signature.name,
                            "matched_fields": sorted(set(decoded_fields)),
                            "match_count": len(evidence),
                            "maximum_decode_rounds": maximum_decode_rounds,
                            "decode_round_limit": MAX_URL_DECODE_ROUNDS,
                        },
                    ),
                    DecisionTraceEntry(
                        sequence=2,
                        stage=TraceStage.SCORING,
                        component="risk_scorer",
                        operation="apply deterministic risk formula",
                        outcome=TraceOutcome.CALCULATED,
                        rule_id=signature.rule_id,
                        evidence_ids=evidence_ids,
                        details=risk.trace_details(),
                    ),
                ],
                recommended_actions=[
                    "Preserve the source request and correlated application logs.",
                    "Review parameterized-query controls for the targeted endpoint.",
                    "Consider blocking the source IP only after analyst approval.",
                ],
            )
        )

    return findings


__all__ = ["MAX_URL_DECODE_ROUNDS", "RULE_VERSION", "detect_sqli"]
