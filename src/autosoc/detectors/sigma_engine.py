"""Deterministic Sigma rule evaluation for normalized AutoSOC events.

pySigma deliberately parses, processes, and converts Sigma rules; it is not a
log-event execution engine. This module converts pySigma's processed condition
tree into a small, fail-closed AutoSOC predicate language and evaluates that
predicate against :class:`~autosoc.models.SecurityEvent` values.

Only positively matched, normalized event fields become finding evidence. No
LLM participates in rule evaluation or MITRE ATT&CK mapping.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from ipaddress import ip_address
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal
from urllib.parse import unquote, unquote_plus

from pydantic import BaseModel, ConfigDict, Field, ValidationError
import regex
from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation
from sigma.rule import SigmaRule
from sigma.types import (
    CompareOperators,
    Placeholder,
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

from autosoc.models import (
    DecisionTraceEntry,
    DetectionCategory,
    DetectionFinding,
    EventType,
    Evidence,
    MitreAttackMapping,
    MitreTactic,
    SecurityEvent,
    Severity,
    TraceOutcome,
    TraceStage,
)
from autosoc.scoring.risk import calculate_risk_score

ENGINE_VERSION = "1.0.0"
MAX_RULE_BYTES = 1_048_576
MAX_REGEX_LENGTH = 900
MAX_INSPECTED_VALUE_LENGTH = 8_192
MAX_URL_DECODE_ROUNDS = 3
REGEX_TIMEOUT_SECONDS = 0.025

_AUTOSOC_FIELD_MAPPING = MappingProxyType(
    {
        "DestinationIp": "destination_ip",
        "DestinationPort": "destination_port",
        "HttpMethod": "http_method",
        "HttpStatus": "http_status",
        "NetworkProtocol": "protocol",
        "RequestBody": "attributes.request_body",
        "RequestTarget": "request_path",
        "SourceIp": "source_ip",
        "SourcePort": "source_port",
        "TlsVersion": "tls_version",
        "destination.ip": "destination_ip",
        "destination.port": "destination_port",
        "http.request.body.content": "attributes.request_body",
        "http.request.method": "http_method",
        "http.response.status_code": "http_status",
        "network.transport": "protocol",
        "source.ip": "source_ip",
        "source.port": "source_port",
        "tls.version": "tls_version",
        "url.original": "request_path",
    }
)

_DIRECT_EVENT_FIELDS = frozenset(
    {
        "destination_ip",
        "destination_port",
        "event_type",
        "http_method",
        "http_status",
        "parser_name",
        "protocol",
        "request_path",
        "source",
        "source_ip",
        "source_port",
        "timestamp",
        "tls_version",
    }
)
_ATTRIBUTE_FIELD = regex.compile(r"^attributes\.[A-Za-z0-9_.-]{1,100}$")
_URL_FORM_FIELDS = frozenset(
    {
        "attributes.form_data",
        "attributes.query",
        "attributes.query_string",
        "attributes.request_body",
        "attributes.request_query",
    }
)

_SEVERITY_BY_LEVEL = MappingProxyType(
    {
        "informational": Severity.INFORMATIONAL,
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }
)

_EVENT_TYPES_BY_LOGSOURCE_CATEGORY = MappingProxyType(
    {
        "network_connection": frozenset({EventType.NETWORK_CONNECTION}),
        "network_traffic": frozenset({EventType.NETWORK_CONNECTION}),
        "tls_handshake": frozenset({EventType.TLS_HANDSHAKE}),
        "webproxy": frozenset({EventType.WEB_ACCESS}),
        "webserver": frozenset({EventType.WEB_ACCESS}),
    }
)

_MITRE_CATALOG = MappingProxyType(
    {
        "T1190": (
            "Exploit Public-Facing Application",
            MitreTactic.INITIAL_ACCESS,
            (
                "The Sigma rule explicitly carries attack.t1190 and matched a "
                "normalized application request field. This records an "
                "exploitation attempt, not proof that access succeeded."
            ),
        ),
    }
)


class SigmaEngineError(RuntimeError):
    """Raised when a Sigma ruleset cannot be converted safely."""


class SigmaEvaluationPlan(BaseModel):
    """A stable, non-executable description of a converted Sigma rule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str
    sigma_rule_id: str
    rule_id: str
    title: str
    condition: str
    event_types: tuple[EventType, ...]
    field_mappings: dict[str, tuple[str, ...]]


class _AutoSOCSigmaMetadata(BaseModel):
    """Required local metadata that turns a Sigma match into a finding."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    rule_id: str = Field(pattern=r"^[A-Z0-9][A-Z0-9_.-]{2,63}$")
    rule_version: str = Field(min_length=1, max_length=32)
    category: DetectionCategory
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_basis: str = Field(min_length=1, max_length=1_000)
    event_types: tuple[EventType, ...] = Field(min_length=1)
    recommended_actions: tuple[str, ...] = ()


class _FindingText(BaseModel):
    """Validate rule text before it reaches DetectionFinding construction."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2_000)


@dataclass(frozen=True, slots=True)
class _Candidate:
    value: Any
    decode_rounds: int = 0
    normalization: str = "none"


@dataclass(frozen=True, slots=True)
class _Match:
    field: str
    value: Any
    pattern: str
    decode_rounds: int
    normalization: str
    start: int | None = None
    end: int | None = None


@dataclass(frozen=True, slots=True)
class _Evaluation:
    matched: bool
    matches: tuple[_Match, ...] = ()


@dataclass(frozen=True, slots=True)
class _Matcher:
    kind: str
    display: str
    expected: Any = None
    regex: regex.Pattern[str] | None = None

    def evaluate(self, candidate: _Candidate, *, present: bool) -> _Evaluation:
        value = candidate.value
        matched = False
        start: int | None = None
        end: int | None = None

        if self.kind == "exists":
            matched = present is bool(self.expected)
        elif self.kind == "null":
            matched = value is None
        elif self.kind in {"string", "regex"}:
            if isinstance(value, str) and self.regex is not None:
                inspected = value[:MAX_INSPECTED_VALUE_LENGTH]
                try:
                    match = (
                        self.regex.fullmatch(
                            inspected,
                            timeout=REGEX_TIMEOUT_SECONDS,
                        )
                        if self.kind == "string"
                        else self.regex.search(
                            inspected,
                            timeout=REGEX_TIMEOUT_SECONDS,
                        )
                    )
                except TimeoutError as exc:
                    raise SigmaEngineError(
                        "Sigma pattern evaluation exceeded the enforced "
                        f"{REGEX_TIMEOUT_SECONDS:.3f}-second timeout"
                    ) from exc
                if match is not None:
                    matched = True
                    start, end = match.span()
                    if end <= start:
                        start = end = None
        elif self.kind == "number":
            matched = (
                isinstance(value, (int, float))
                and not isinstance(value, bool)
                and value == self.expected
            )
        elif self.kind == "boolean":
            matched = isinstance(value, bool) and value is self.expected
        elif self.kind == "cidr":
            try:
                matched = ip_address(str(value)) in self.expected
            except ValueError:
                matched = False
        elif self.kind == "compare":
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                operator, expected = self.expected
                matched = {
                    CompareOperators.LT: value < expected,
                    CompareOperators.LTE: value <= expected,
                    CompareOperators.GT: value > expected,
                    CompareOperators.GTE: value >= expected,
                    CompareOperators.NEQ: value != expected,
                }[operator]
        else:  # Defensive guard: compilation should make this unreachable.
            raise SigmaEngineError(f"unsupported compiled matcher: {self.kind}")

        if not matched:
            return _Evaluation(False)
        return _Evaluation(
            True,
            (
                _Match(
                    field="",
                    value=value,
                    pattern=self.display,
                    decode_rounds=candidate.decode_rounds,
                    normalization=candidate.normalization,
                    start=start,
                    end=end,
                ),
            ),
        )


@dataclass(frozen=True, slots=True)
class _Expression:
    operator: Literal["and", "or", "not", "field"]
    children: tuple[_Expression, ...] = ()
    field: str | None = None
    matcher: _Matcher | None = None

    def render(self) -> str:
        if self.operator == "field":
            assert self.field is not None and self.matcher is not None
            return f"{self.field} MATCHES {self.matcher.display}"
        if self.operator == "not":
            return f"NOT ({self.children[0].render()})"
        separator = f" {self.operator.upper()} "
        return "(" + separator.join(child.render() for child in self.children) + ")"

    def guarantees_evidence(self) -> bool:
        """Return whether every successful branch yields positive evidence."""

        if self.operator == "field":
            return True
        if self.operator == "not":
            return False
        if self.operator == "and":
            return any(child.guarantees_evidence() for child in self.children)
        return all(child.guarantees_evidence() for child in self.children)

    def evaluate(self, event_data: Mapping[str, Any]) -> _Evaluation:
        if self.operator == "field":
            assert self.field is not None and self.matcher is not None
            present, candidates = _resolve_candidates(event_data, self.field)
            if self.matcher.kind == "exists" and not candidates:
                candidates = (_Candidate(None),)
            evaluations = [
                self.matcher.evaluate(candidate, present=present)
                for candidate in candidates
            ]
            successful = [result for result in evaluations if result.matched]
            if not successful:
                return _Evaluation(False)
            return _Evaluation(
                True,
                tuple(
                    _Match(
                        field=self.field,
                        value=match.value,
                        pattern=match.pattern,
                        decode_rounds=match.decode_rounds,
                        normalization=match.normalization,
                        start=match.start,
                        end=match.end,
                    )
                    for result in successful
                    for match in result.matches
                ),
            )

        if self.operator == "not":
            result = self.children[0].evaluate(event_data)
            return _Evaluation(not result.matched)

        evaluations = [child.evaluate(event_data) for child in self.children]
        if self.operator == "and":
            if not all(result.matched for result in evaluations):
                return _Evaluation(False)
            return _Evaluation(
                True,
                tuple(
                    match
                    for result in evaluations
                    for match in result.matches
                ),
            )

        successful = [result for result in evaluations if result.matched]
        if not successful:
            return _Evaluation(False)
        return _Evaluation(
            True,
            tuple(match for result in successful for match in result.matches),
        )


@dataclass(frozen=True, slots=True)
class _CompiledRule:
    metadata: _AutoSOCSigmaMetadata
    sigma_rule_id: str
    title: str
    description: str
    severity: Severity
    source: str
    expressions: tuple[_Expression, ...]
    mappings: tuple[MitreAttackMapping, ...]
    plan: SigmaEvaluationPlan
    logsource: dict[str, str]


def _processing_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="AutoSOC SecurityEvent field mapping",
        items=[
            ProcessingItem(
                identifier="autosoc_security_event_fields",
                transformation=FieldMappingTransformation(
                    mapping=dict(_AUTOSOC_FIELD_MAPPING)
                ),
            )
        ],
    )


def _compile_sigma_string(value: SigmaString) -> _Matcher:
    if value.contains_placeholder():
        raise SigmaEngineError("Sigma placeholders are not supported")

    regex_parts: list[str] = []
    display_parts: list[str] = []
    for part in value.s:
        if isinstance(part, str):
            regex_parts.append(regex.escape(part))
            display_parts.append(part)
        elif part == SpecialChars.WILDCARD_MULTI:
            regex_parts.append(".*")
            display_parts.append("*")
        elif part == SpecialChars.WILDCARD_SINGLE:
            regex_parts.append(".")
            display_parts.append("?")
        elif isinstance(part, Placeholder):
            raise SigmaEngineError("Sigma placeholders are not supported")
        else:
            raise SigmaEngineError(
                f"unsupported Sigma string part: {type(part).__name__}"
            )

    case_sensitive = isinstance(value, SigmaCasedString)
    flags = regex.DOTALL if case_sensitive else regex.DOTALL | regex.IGNORECASE
    pattern = "".join(regex_parts)
    if len(pattern) > MAX_REGEX_LENGTH:
        raise SigmaEngineError("converted Sigma string pattern is too long")
    return _Matcher(
        kind="string",
        display=repr("".join(display_parts)),
        regex=regex.compile(pattern, flags),
    )


def _compile_matcher(value: Any) -> _Matcher:
    if isinstance(value, SigmaRegularExpression):
        pattern = str(value.regexp)
        if len(pattern) > MAX_REGEX_LENGTH:
            raise SigmaEngineError("Sigma regular expression is too long")
        flags = 0
        for flag in value.flags:
            flags |= value.sigma_to_python_flags[flag]
        try:
            compiled = regex.compile(pattern, flags)
        except regex.error as exc:
            raise SigmaEngineError(f"invalid Sigma regular expression: {exc}") from exc
        suffix = "".join(
            sorted(value.sigma_to_re_flag[flag] for flag in value.flags)
        )
        return _Matcher(
            kind="regex",
            display=f"/{pattern}/{suffix}",
            regex=compiled,
        )
    if isinstance(value, SigmaString):
        return _compile_sigma_string(value)
    if isinstance(value, SigmaNumber):
        return _Matcher(kind="number", display=str(value.number), expected=value.number)
    if isinstance(value, SigmaBool):
        return _Matcher(
            kind="boolean",
            display=str(value.boolean).lower(),
            expected=value.boolean,
        )
    if isinstance(value, SigmaNull):
        return _Matcher(kind="null", display="null")
    if isinstance(value, SigmaExists):
        return _Matcher(
            kind="exists",
            display=f"exists:{str(value.exists).lower()}",
            expected=value.exists,
        )
    if isinstance(value, SigmaCIDRExpression):
        return _Matcher(kind="cidr", display=str(value.cidr), expected=value.network)
    if isinstance(value, SigmaCompareExpression):
        symbols = {
            CompareOperators.LT: "<",
            CompareOperators.LTE: "<=",
            CompareOperators.GT: ">",
            CompareOperators.GTE: ">=",
            CompareOperators.NEQ: "!=",
        }
        expected = value.number.number
        return _Matcher(
            kind="compare",
            display=f"{symbols[value.op]} {expected}",
            expected=(value.op, expected),
        )
    if isinstance(value, (SigmaFieldReference, SigmaExpansion)):
        raise SigmaEngineError(
            f"unsupported Sigma value type: {type(value).__name__}"
        )
    raise SigmaEngineError(f"unsupported Sigma value type: {type(value).__name__}")


def _validate_processed_field(field: str | None) -> str:
    if field is None:
        raise SigmaEngineError("unbound Sigma keyword conditions are not supported")
    if field in _DIRECT_EVENT_FIELDS or _ATTRIBUTE_FIELD.fullmatch(field):
        return field
    raise SigmaEngineError(
        f"Sigma field {field!r} is not mapped to an allowed SecurityEvent field"
    )


def _compile_expression(node: Any) -> _Expression:
    if isinstance(node, ConditionAND):
        if not node.args:
            raise SigmaEngineError("empty Sigma AND condition is not supported")
        return _Expression(
            operator="and",
            children=tuple(_compile_expression(arg) for arg in node.args),
        )
    if isinstance(node, ConditionOR):
        if not node.args:
            raise SigmaEngineError("empty Sigma OR condition is not supported")
        return _Expression(
            operator="or",
            children=tuple(_compile_expression(arg) for arg in node.args),
        )
    if isinstance(node, ConditionNOT):
        if len(node.args) != 1:
            raise SigmaEngineError("Sigma NOT condition must have exactly one operand")
        return _Expression(
            operator="not",
            children=(_compile_expression(node.args[0]),),
        )
    if isinstance(node, ConditionFieldEqualsValueExpression):
        field = _validate_processed_field(node.field)
        return _Expression(
            operator="field",
            field=field,
            matcher=_compile_matcher(node.value),
        )
    if isinstance(node, ConditionValueExpression):
        raise SigmaEngineError(
            "unbound Sigma keyword conditions are not supported; use mapped fields"
        )
    raise SigmaEngineError(f"unsupported Sigma condition: {type(node).__name__}")


def _normalise_metadata(rule: SigmaRule) -> _AutoSOCSigmaMetadata:
    raw_metadata = rule.custom_attributes.get("autosoc")
    if not isinstance(raw_metadata, dict):
        raise SigmaEngineError(
            f"Sigma rule {rule.title!r} requires an 'autosoc' metadata mapping"
        )
    try:
        return _AutoSOCSigmaMetadata.model_validate(raw_metadata)
    except ValidationError as exc:
        raise SigmaEngineError(
            f"invalid autosoc metadata in Sigma rule {rule.title!r}: {exc}"
        ) from exc


def _mitre_mappings(rule: SigmaRule) -> tuple[MitreAttackMapping, ...]:
    technique_ids = {
        tag.name.upper()
        for tag in rule.tags
        if tag.namespace.lower() == "attack"
        and regex.fullmatch(
            r"t\d{4}(?:\.\d{3})?",
            tag.name,
            regex.IGNORECASE,
        )
    }
    unsupported = technique_ids - set(_MITRE_CATALOG)
    if unsupported:
        formatted = ", ".join(sorted(unsupported))
        raise SigmaEngineError(
            f"MITRE ATT&CK mapping is not in AutoSOC's offline catalog: {formatted}"
        )
    return tuple(
        MitreAttackMapping(
            technique_id=technique_id,
            technique_name=_MITRE_CATALOG[technique_id][0],
            tactic=_MITRE_CATALOG[technique_id][1],
            mapping_reason=_MITRE_CATALOG[technique_id][2],
        )
        for technique_id in sorted(technique_ids)
    )


def _validate_logsource(
    rule: SigmaRule,
    metadata: _AutoSOCSigmaMetadata,
) -> dict[str, str]:
    logsource = {
        key: str(value)
        for key, value in {
            "category": rule.logsource.category,
            "product": rule.logsource.product,
            "service": rule.logsource.service,
        }.items()
        if value is not None
    }
    category = logsource.get("category")
    if category is None:
        raise SigmaEngineError(
            "Sigma event rules require a logsource category that maps to a "
            "SecurityEvent type"
        )

    allowed_event_types = _EVENT_TYPES_BY_LOGSOURCE_CATEGORY.get(
        category.casefold()
    )
    if allowed_event_types is None:
        raise SigmaEngineError(
            f"Sigma logsource category {category!r} has no deterministic "
            "SecurityEvent mapping"
        )
    incompatible = set(metadata.event_types) - allowed_event_types
    if incompatible:
        values = ", ".join(sorted(item.value for item in incompatible))
        raise SigmaEngineError(
            f"Sigma logsource category {category!r} contradicts autosoc "
            f"event_types: {values}"
        )
    return logsource


def _compile_rule(rule: SigmaRule, source: str) -> _CompiledRule:
    if rule.id is None:
        raise SigmaEngineError(f"Sigma rule {rule.title!r} requires a canonical UUID")
    if rule.level is None or str(rule.level) not in _SEVERITY_BY_LEVEL:
        raise SigmaEngineError(f"Sigma rule {rule.title!r} requires a valid level")

    metadata = _normalise_metadata(rule)
    description = (
        rule.description
        or f"Sigma rule {rule.title!r} matched a normalized SecurityEvent."
    )
    try:
        finding_text = _FindingText(title=rule.title, description=description)
    except ValidationError as exc:
        raise SigmaEngineError(
            f"Sigma rule {rule.title!r} cannot populate a finding: {exc}"
        ) from exc
    logsource = _validate_logsource(rule, metadata)
    processed = _processing_pipeline().apply(deepcopy(rule))
    try:
        expressions = tuple(
            _compile_expression(condition.parsed)
            for condition in processed.detection.parsed_condition
        )
    except SigmaEngineError:
        raise
    except Exception as exc:
        raise SigmaEngineError(
            f"unable to convert Sigma rule {rule.title!r}: {exc}"
        ) from exc
    if not expressions:
        raise SigmaEngineError(f"Sigma rule {rule.title!r} has no conditions")
    if not all(expression.guarantees_evidence() for expression in expressions):
        raise SigmaEngineError(
            f"Sigma rule {rule.title!r} has a successful branch that cannot "
            "produce auditable positive evidence"
        )

    condition = (
        expressions[0].render()
        if len(expressions) == 1
        else "(" + " OR ".join(item.render() for item in expressions) + ")"
    )
    field_mappings = {
        source_field: (target,) if isinstance(target, str) else tuple(target)
        for source_field, target in _AUTOSOC_FIELD_MAPPING.items()
    }
    sigma_rule_id = str(rule.id)
    plan = SigmaEvaluationPlan(
        source=source,
        sigma_rule_id=sigma_rule_id,
        rule_id=metadata.rule_id,
        title=finding_text.title,
        condition=condition,
        event_types=metadata.event_types,
        field_mappings=field_mappings,
    )
    return _CompiledRule(
        metadata=metadata,
        sigma_rule_id=sigma_rule_id,
        title=finding_text.title,
        description=finding_text.description,
        severity=_SEVERITY_BY_LEVEL[str(rule.level)],
        source=source,
        expressions=expressions,
        mappings=_mitre_mappings(rule),
        plan=plan,
        logsource=logsource,
    )


def _decode_request_target(value: str) -> tuple[str, int]:
    current = value
    decode_rounds = 0
    for _ in range(MAX_URL_DECODE_ROUNDS):
        path, separator, suffix = current.partition("?")
        decoded_path = unquote(path, encoding="utf-8", errors="replace")
        decoded_suffix = ""
        if separator:
            query, fragment_separator, fragment = suffix.partition("#")
            decoded_suffix = "?" + unquote_plus(
                query,
                encoding="utf-8",
                errors="replace",
            )
            if fragment_separator:
                decoded_suffix += "#" + unquote_plus(
                    fragment,
                    encoding="utf-8",
                    errors="replace",
                )
        decoded = decoded_path + decoded_suffix
        if decoded == current:
            break
        current = decoded
        decode_rounds += 1
    return current, decode_rounds


def _decode_form_value(value: str) -> tuple[str, int]:
    current = value
    decode_rounds = 0
    for _ in range(MAX_URL_DECODE_ROUNDS):
        decoded = unquote_plus(current, encoding="utf-8", errors="replace")
        if decoded == current:
            break
        current = decoded
        decode_rounds += 1
    return current, decode_rounds


def _candidate_values(field: str, raw_value: Any) -> tuple[_Candidate, ...]:
    if isinstance(raw_value, list):
        return tuple(
            candidate
            for value in raw_value
            for candidate in _candidate_values(field, value)
        )
    if not isinstance(raw_value, (str, int, float, bool)) and raw_value is not None:
        return ()
    if not isinstance(raw_value, str):
        return (_Candidate(raw_value),)

    if len(raw_value) > MAX_INSPECTED_VALUE_LENGTH:
        return ()
    inspected = raw_value
    candidates = [_Candidate(inspected)]
    if field == "request_path":
        decoded, rounds = _decode_request_target(inspected)
        normalization = "bounded_request_target_url_decode"
    elif field in _URL_FORM_FIELDS:
        decoded, rounds = _decode_form_value(inspected)
        normalization = "bounded_form_url_decode"
    else:
        decoded, rounds = inspected, 0
        normalization = "none"
    if rounds and decoded != inspected:
        candidates.append(_Candidate(decoded, rounds, normalization))

    unique: dict[tuple[str, int], _Candidate] = {}
    for candidate in candidates:
        unique[(str(candidate.value), candidate.decode_rounds)] = candidate
    return tuple(unique.values())


def _resolve_candidates(
    event_data: Mapping[str, Any],
    field: str,
) -> tuple[bool, tuple[_Candidate, ...]]:
    if field.startswith("attributes."):
        key = field.removeprefix("attributes.")
        attributes = event_data.get("attributes")
        if not isinstance(attributes, dict) or key not in attributes:
            return False, ()
        raw_value = attributes[key]
    else:
        if field not in event_data:
            return False, ()
        raw_value = event_data[field]
    present = raw_value is not None
    return present, _candidate_values(field, raw_value)


def _deduplicate_matches(matches: Iterable[_Match]) -> tuple[_Match, ...]:
    unique: dict[tuple[str, str, str, int, int | None, int | None], _Match] = {}
    for match in matches:
        key = (
            match.field,
            repr(match.value),
            match.pattern,
            match.decode_rounds,
            match.start,
            match.end,
        )
        unique[key] = match
    return tuple(unique.values())


def _package_version() -> str:
    try:
        return version("pysigma")
    except PackageNotFoundError:  # pragma: no cover - import implies installation.
        return "unknown"


class SigmaEngine:
    """Load once, then deterministically evaluate Sigma rules against events."""

    def __init__(self, rules: Iterable[_CompiledRule]) -> None:
        self._rules = tuple(rules)
        if not self._rules:
            raise SigmaEngineError("the Sigma ruleset contains no event rules")

    @classmethod
    def from_path(cls, path: str | Path) -> SigmaEngine:
        """Load a UTF-8 Sigma YAML file with a bounded input size."""

        rule_path = Path(path)
        try:
            raw = rule_path.read_bytes()
        except OSError as exc:
            raise SigmaEngineError(
                f"unable to read Sigma ruleset {rule_path}: {exc}"
            ) from exc
        if len(raw) > MAX_RULE_BYTES:
            raise SigmaEngineError(
                f"Sigma ruleset exceeds the {MAX_RULE_BYTES}-byte limit"
            )
        try:
            yaml_text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SigmaEngineError("Sigma ruleset must be valid UTF-8") from exc
        return cls.from_yaml(yaml_text, source=str(rule_path))

    @classmethod
    def from_yaml(cls, yaml_text: str, *, source: str = "<memory>") -> SigmaEngine:
        """Parse, process, and compile one or more Sigma YAML documents."""

        try:
            collection = SigmaCollection.from_yaml(yaml_text, collect_errors=False)
        except Exception as exc:
            raise SigmaEngineError(
                f"unable to parse Sigma ruleset {source}: {exc}"
            ) from exc

        non_event_rules = [
            rule for rule in collection.rules if not isinstance(rule, SigmaRule)
        ]
        if non_event_rules:
            kinds = ", ".join(
                sorted({type(rule).__name__ for rule in non_event_rules})
            )
            raise SigmaEngineError(
                "Sigma correlation and non-event rules are not supported by the "
                f"per-event evaluator ({kinds})"
            )
        try:
            compiled = [
                _compile_rule(rule, source)
                for rule in collection.rules
                if isinstance(rule, SigmaRule)
            ]
        except SigmaEngineError:
            raise
        except Exception as exc:
            raise SigmaEngineError(
                f"unable to compile Sigma ruleset {source}: {exc}"
            ) from exc
        return cls(compiled)

    def convert(self) -> tuple[SigmaEvaluationPlan, ...]:
        """Return stable, declarative plans for audit and review.

        The returned plans contain no commands or callables. They describe the
        exact predicates produced from pySigma's processed condition trees.
        """

        return tuple(rule.plan.model_copy(deep=True) for rule in self._rules)

    def evaluate_event(
        self,
        event: SecurityEvent,
        *,
        ip_reputation_score: float | None = None,
    ) -> list[DetectionFinding]:
        """Evaluate all compatible rules against one normalized event."""

        event_data = event.model_dump(mode="json")
        findings: list[DetectionFinding] = []
        for rule in self._rules:
            if event.event_type not in rule.metadata.event_types:
                continue

            evaluations = [
                expression.evaluate(event_data) for expression in rule.expressions
            ]
            matches = _deduplicate_matches(
                match
                for result in evaluations
                if result.matched
                for match in result.matches
            )
            if not matches:
                continue

            evidence = [
                Evidence(
                    event_id=event.event_id,
                    source_field=match.field,
                    observed_value=match.value,
                    description=(
                        f"Sigma rule {rule.sigma_rule_id} matched {match.field} "
                        f"using {match.normalization} after "
                        f"{match.decode_rounds} URL decode round(s)."
                    ),
                    matched_pattern=match.pattern,
                    match_start=match.start,
                    match_end=match.end,
                )
                for match in matches
            ]
            evidence_ids = [item.evidence_id for item in evidence]
            risk = calculate_risk_score(
                rule.severity,
                rule.metadata.confidence,
                ip_reputation_score,
                evidence_ids=evidence_ids,
            )
            findings.append(
                DetectionFinding(
                    event_id=event.event_id,
                    rule_id=rule.metadata.rule_id,
                    rule_version=rule.metadata.rule_version,
                    title=rule.title,
                    description=rule.description,
                    category=rule.metadata.category,
                    severity=rule.severity,
                    risk_score=risk.score,
                    risk_score_components=list(risk.components),
                    confidence_score=rule.metadata.confidence,
                    confidence_basis=rule.metadata.confidence_basis,
                    evidence=evidence,
                    mitre_attack_mappings=list(rule.mappings),
                    decision_trace=[
                        DecisionTraceEntry(
                            sequence=1,
                            stage=TraceStage.DETECTION,
                            component="sigma_engine",
                            operation=(
                                "evaluate a pySigma-processed deterministic "
                                "condition plan"
                            ),
                            outcome=TraceOutcome.MATCHED,
                            rule_id=rule.metadata.rule_id,
                            evidence_ids=evidence_ids,
                            details={
                                "engine_version": ENGINE_VERSION,
                                "pysigma_version": _package_version(),
                                "sigma_rule_id": rule.sigma_rule_id,
                                "sigma_source": rule.source,
                                "condition_plan": rule.plan.condition,
                                "event_type": event.event_type.value,
                                "logsource": rule.logsource,
                                "matched_fields": sorted(
                                    {match.field for match in matches}
                                ),
                                "match_count": len(matches),
                                "maximum_decode_rounds": max(
                                    match.decode_rounds for match in matches
                                ),
                                "decode_round_limit": MAX_URL_DECODE_ROUNDS,
                            },
                        ),
                        DecisionTraceEntry(
                            sequence=2,
                            stage=TraceStage.SCORING,
                            component="risk_scorer",
                            operation="apply deterministic risk formula",
                            outcome=TraceOutcome.CALCULATED,
                            rule_id=rule.metadata.rule_id,
                            evidence_ids=evidence_ids,
                            details=risk.trace_details(),
                        ),
                    ],
                    recommended_actions=list(rule.metadata.recommended_actions),
                )
            )
        return findings

    def evaluate(
        self,
        events: Iterable[SecurityEvent],
        *,
        ip_reputation_score: float | None = None,
    ) -> list[DetectionFinding]:
        """Evaluate an event stream while retaining deterministic input order."""

        return [
            finding
            for event in events
            for finding in self.evaluate_event(
                event,
                ip_reputation_score=ip_reputation_score,
            )
        ]


__all__ = [
    "ENGINE_VERSION",
    "MAX_RULE_BYTES",
    "MAX_URL_DECODE_ROUNDS",
    "SigmaEngine",
    "SigmaEngineError",
    "SigmaEvaluationPlan",
]
