"""Validated, auditable data contracts for the AutoSOC pipeline.

The models in this module contain factual processing records only.  They expose
the evidence and rule outcomes that led to a finding; they are not a container
for private model reasoning or an LLM chain of thought.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Literal, Self
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    JsonValue,
    field_validator,
    model_validator,
)


def utc_now() -> datetime:
    """Return an aware UTC timestamp for reproducible audit records."""

    return datetime.now(timezone.utc)


def _normalise_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must include a timezone")
    return value.astimezone(timezone.utc)


def _clamped_score(components: list[ScoreContribution]) -> int:
    return max(0, min(100, sum(component.points for component in components)))


class AutoSOCModel(BaseModel):
    """Base configuration shared by every public AutoSOC schema."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )


class EventType(StrEnum):
    WEB_ACCESS = "web_access"
    NETWORK_CONNECTION = "network_connection"
    TLS_HANDSHAKE = "tls_handshake"
    GENERIC = "generic"


class DetectionCategory(StrEnum):
    SQL_INJECTION = "sql_injection"
    WEAK_TLS = "weak_tls"
    OTHER = "other"


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(StrEnum):
    NEW = "new"
    TRIAGED = "triaged"
    AWAITING_APPROVAL = "awaiting_approval"
    CLOSED = "closed"


class MitreTactic(StrEnum):
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class TraceStage(StrEnum):
    INGESTION = "ingestion"
    DETECTION = "detection"
    SCORING = "scoring"
    ENRICHMENT = "enrichment"
    TRIAGE = "triage"
    RESPONSE = "response"


class TraceOutcome(StrEnum):
    MATCHED = "matched"
    NOT_MATCHED = "not_matched"
    CALCULATED = "calculated"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"
    RECOMMENDED = "recommended"


class ThreatIntelMode(StrEnum):
    LIVE = "live"
    MOCK = "mock"


class Evidence(AutoSOCModel):
    """A concrete value observed in a source event and used by a rule."""

    evidence_id: UUID = Field(default_factory=uuid4)
    event_id: UUID
    source_field: str = Field(min_length=1, max_length=128)
    observed_value: JsonValue
    description: str = Field(min_length=1, max_length=1000)
    matched_pattern: str | None = Field(default=None, min_length=1, max_length=1000)
    match_start: int | None = Field(default=None, ge=0)
    match_end: int | None = Field(default=None, ge=1)
    redacted: bool = False

    @model_validator(mode="after")
    def validate_match_offsets(self) -> Self:
        if (self.match_start is None) != (self.match_end is None):
            raise ValueError("match_start and match_end must be supplied together")

        if self.match_start is not None and self.match_end is not None:
            if not isinstance(self.observed_value, str):
                raise ValueError("match offsets require a string observed_value")
            if self.match_end <= self.match_start:
                raise ValueError("match_end must be greater than match_start")
            if self.match_end > len(self.observed_value):
                raise ValueError("match_end cannot exceed the observed value length")

        return self


class MitreAttackMapping(AutoSOCModel):
    """An evidence-backed MITRE ATT&CK technique association."""

    technique_id: str = Field(pattern=r"^T\d{4}(?:\.\d{3})?$")
    technique_name: str = Field(min_length=1, max_length=200)
    tactic: MitreTactic
    mapping_reason: str = Field(min_length=1, max_length=1000)


class ScoreContribution(AutoSOCModel):
    """One additive input to a deterministic, clamped 0-100 risk score."""

    component: str = Field(min_length=1, max_length=100)
    points: int = Field(ge=-100, le=100)
    reason: str = Field(min_length=1, max_length=1000)
    evidence_ids: list[UUID] = Field(default_factory=list)


class DecisionTraceEntry(AutoSOCModel):
    """A concise record of a rule operation and its observable outcome."""

    sequence: int = Field(ge=1)
    stage: TraceStage
    component: str = Field(min_length=1, max_length=128)
    operation: str = Field(min_length=1, max_length=256)
    outcome: TraceOutcome
    rule_id: str | None = Field(default=None, min_length=1, max_length=64)
    evidence_ids: list[UUID] = Field(default_factory=list)
    details: dict[str, JsonValue] = Field(default_factory=dict)
    recorded_at: datetime = Field(default_factory=utc_now)

    @field_validator("recorded_at")
    @classmethod
    def normalise_recorded_at(cls, value: datetime) -> datetime:
        return _normalise_timestamp(value)


class ContainmentRecommendation(AutoSOCModel):
    """A non-executing response proposal that always requires approval."""

    action_id: UUID = Field(default_factory=uuid4)
    action_type: str = Field(min_length=1, max_length=100)
    target: str = Field(min_length=1, max_length=500)
    rationale: str = Field(min_length=1, max_length=2000)
    command_preview: str | None = Field(default=None, min_length=1, max_length=4000)
    related_finding_ids: list[UUID] = Field(default_factory=list)
    dry_run: Literal[True] = True
    requires_human_approval: Literal[True] = True


class ThreatIntelResult(AutoSOCModel):
    """A minimal AbuseIPDB enrichment record safe for incident reports."""

    provider: Literal["AbuseIPDB"] = "AbuseIPDB"
    ip_address: IPvAnyAddress | None = None
    abuse_confidence_score: int = Field(ge=0, le=100)
    country_code: str | None = Field(default=None, min_length=2, max_length=2)
    usage_type: str | None = Field(default=None, min_length=1, max_length=200)
    mode: ThreatIntelMode
    retrieval_reason: str = Field(min_length=1, max_length=500)
    max_age_in_days: int = Field(ge=1, le=365)
    checked_at: datetime = Field(default_factory=utc_now)

    @field_validator("country_code")
    @classmethod
    def normalise_country_code(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value.isalpha():
            raise ValueError("country_code must contain two letters")
        return value.upper()

    @field_validator("checked_at")
    @classmethod
    def normalise_checked_at(cls, value: datetime) -> datetime:
        return _normalise_timestamp(value)

    @model_validator(mode="after")
    def validate_retrieval_mode(self) -> Self:
        if self.mode == ThreatIntelMode.LIVE and self.ip_address is None:
            raise ValueError("live threat intelligence must identify the queried IP")
        return self


class SecurityEvent(AutoSOCModel):
    """A normalized event emitted by an AutoSOC log parser."""

    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime
    ingested_at: datetime = Field(default_factory=utc_now)
    event_type: EventType
    source: str = Field(
        min_length=1,
        max_length=500,
        description="Log file, stream, or sensor identifier.",
    )
    parser_name: str = Field(min_length=1, max_length=128)
    raw_log: str = Field(min_length=1)
    source_ip: IPvAnyAddress | None = None
    destination_ip: IPvAnyAddress | None = None
    source_port: int | None = Field(default=None, ge=1, le=65535)
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str | None = Field(default=None, min_length=1, max_length=32)
    http_method: str | None = Field(default=None, min_length=1, max_length=16)
    request_path: str | None = Field(default=None, min_length=1, max_length=8192)
    http_status: int | None = Field(default=None, ge=100, le=599)
    tls_version: str | None = Field(default=None, min_length=1, max_length=32)
    attributes: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("timestamp", "ingested_at")
    @classmethod
    def normalise_event_timestamps(cls, value: datetime) -> datetime:
        return _normalise_timestamp(value)

    @field_validator("protocol", "http_method")
    @classmethod
    def normalise_uppercase_fields(cls, value: str | None) -> str | None:
        return value.upper() if value is not None else None


class DetectionFinding(AutoSOCModel):
    """A deterministic rule match with a complete, verifiable audit trail."""

    finding_id: UUID = Field(default_factory=uuid4)
    event_id: UUID
    detected_at: datetime = Field(default_factory=utc_now)
    rule_id: str = Field(pattern=r"^[A-Z0-9][A-Z0-9_.-]{2,63}$")
    rule_version: str = Field(min_length=1, max_length=32)
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2000)
    category: DetectionCategory
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    risk_score_components: list[ScoreContribution] = Field(min_length=1)
    confidence_score: float = Field(ge=0.0, le=1.0)
    confidence_basis: str = Field(min_length=1, max_length=1000)
    evidence: list[Evidence] = Field(min_length=1)
    mitre_attack_mappings: list[MitreAttackMapping] = Field(
        description=(
            "Evidence-backed ATT&CK mappings. Supply an empty list when no mapping "
            "is defensible; never invent a technique to populate this field."
        )
    )
    decision_trace: list[DecisionTraceEntry] = Field(min_length=1)
    recommended_actions: list[str] = Field(default_factory=list)
    analysis_method: Literal["deterministic_rule"] = "deterministic_rule"

    @field_validator("detected_at")
    @classmethod
    def normalise_detected_at(cls, value: datetime) -> datetime:
        return _normalise_timestamp(value)

    @model_validator(mode="after")
    def validate_audit_integrity(self) -> Self:
        evidence_ids = [item.evidence_id for item in self.evidence]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("evidence_id values must be unique within a finding")
        if any(item.event_id != self.event_id for item in self.evidence):
            raise ValueError("all evidence must reference the finding's event_id")

        referenced_evidence = {
            evidence_id
            for component in self.risk_score_components
            for evidence_id in component.evidence_ids
        } | {
            evidence_id
            for entry in self.decision_trace
            for evidence_id in entry.evidence_ids
        }
        unknown_evidence = referenced_evidence - set(evidence_ids)
        if unknown_evidence:
            raise ValueError("score or trace entries reference unknown evidence IDs")

        if _clamped_score(self.risk_score_components) != self.risk_score:
            raise ValueError(
                "risk_score must equal the component sum clamped to the 0-100 range"
            )

        sequences = [entry.sequence for entry in self.decision_trace]
        if sequences != list(range(1, len(sequences) + 1)):
            raise ValueError("decision_trace sequence values must be contiguous from 1")
        stages = {entry.stage for entry in self.decision_trace}
        if TraceStage.DETECTION not in stages or TraceStage.SCORING not in stages:
            raise ValueError("finding trace must include detection and scoring stages")

        mapping_keys = [
            (mapping.technique_id, mapping.tactic)
            for mapping in self.mitre_attack_mappings
        ]
        if len(mapping_keys) != len(set(mapping_keys)):
            raise ValueError(
                "MITRE ATT&CK mappings must be unique per technique and tactic"
            )

        return self


class IncidentReport(AutoSOCModel):
    """The final portable report produced by the AutoSOC workflow."""

    schema_version: Literal["1.0"] = "1.0"
    report_id: UUID = Field(default_factory=uuid4)
    generated_at: datetime = Field(default_factory=utc_now)
    status: IncidentStatus = IncidentStatus.NEW
    title: str = Field(min_length=1, max_length=200)
    summary: str = Field(min_length=1, max_length=10000)
    events: list[SecurityEvent] = Field(min_length=1)
    findings: list[DetectionFinding]
    overall_risk_score: int = Field(ge=0, le=100)
    overall_risk_score_components: list[ScoreContribution] = Field(min_length=1)
    overall_confidence_score: float = Field(ge=0.0, le=1.0)
    overall_confidence_basis: str = Field(min_length=1, max_length=2000)
    mitre_attack_mappings: list[MitreAttackMapping]
    decision_trace: list[DecisionTraceEntry] = Field(min_length=1)
    threat_intelligence: list[ThreatIntelResult] = Field(default_factory=list)
    containment_recommendations: list[ContainmentRecommendation] = Field(
        default_factory=list
    )
    offline_mode: bool = False
    dry_run: Literal[True] = True
    requires_human_approval: Literal[True] = True
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("generated_at")
    @classmethod
    def normalise_generated_at(cls, value: datetime) -> datetime:
        return _normalise_timestamp(value)

    @model_validator(mode="after")
    def validate_report_integrity(self) -> Self:
        if self.offline_mode and any(
            result.mode == ThreatIntelMode.LIVE
            for result in self.threat_intelligence
        ):
            raise ValueError(
                "offline reports cannot contain live threat-intelligence results"
            )

        event_ids = [event.event_id for event in self.events]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("event_id values must be unique within a report")

        finding_ids = [finding.finding_id for finding in self.findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("finding_id values must be unique within a report")
        unknown_event_ids = {
            finding.event_id for finding in self.findings
        } - set(event_ids)
        if unknown_event_ids:
            raise ValueError(
                "findings reference events that are absent from the report"
            )

        all_evidence_ids = {
            evidence.evidence_id
            for finding in self.findings
            for evidence in finding.evidence
        }
        referenced_evidence = {
            evidence_id
            for component in self.overall_risk_score_components
            for evidence_id in component.evidence_ids
        } | {
            evidence_id
            for entry in self.decision_trace
            for evidence_id in entry.evidence_ids
        }
        if referenced_evidence - all_evidence_ids:
            raise ValueError("report score or trace references unknown evidence IDs")

        if (
            _clamped_score(self.overall_risk_score_components)
            != self.overall_risk_score
        ):
            raise ValueError(
                "overall_risk_score must equal the component sum clamped to 0-100"
            )

        sequences = [entry.sequence for entry in self.decision_trace]
        if sequences != list(range(1, len(sequences) + 1)):
            raise ValueError("report decision_trace must be contiguous from sequence 1")

        expected_mappings = {
            (mapping.technique_id, mapping.tactic)
            for finding in self.findings
            for mapping in finding.mitre_attack_mappings
        }
        report_mappings = {
            (mapping.technique_id, mapping.tactic)
            for mapping in self.mitre_attack_mappings
        }
        if len(report_mappings) != len(self.mitre_attack_mappings):
            raise ValueError("report MITRE ATT&CK mappings must be unique")
        if report_mappings != expected_mappings:
            raise ValueError(
                "report MITRE ATT&CK mappings must exactly aggregate finding mappings"
            )

        known_finding_ids = set(finding_ids)
        recommendation_finding_ids = {
            finding_id
            for recommendation in self.containment_recommendations
            for finding_id in recommendation.related_finding_ids
        }
        if recommendation_finding_ids - known_finding_ids:
            raise ValueError("containment recommendation references an unknown finding")

        return self


__all__ = [
    "ContainmentRecommendation",
    "DecisionTraceEntry",
    "DetectionCategory",
    "DetectionFinding",
    "Evidence",
    "EventType",
    "IncidentReport",
    "IncidentStatus",
    "MitreAttackMapping",
    "MitreTactic",
    "ScoreContribution",
    "SecurityEvent",
    "Severity",
    "TraceOutcome",
    "TraceStage",
    "ThreatIntelMode",
    "ThreatIntelResult",
]
