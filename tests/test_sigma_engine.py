"""Contract tests for deterministic Sigma detection-as-code evaluation."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from autosoc.detectors.sigma_engine import SigmaEngine, SigmaEngineError
from autosoc.models import (
    DetectionCategory,
    DetectionFinding,
    EventType,
    MitreTactic,
    SecurityEvent,
    Severity,
    TraceOutcome,
    TraceStage,
)
from autosoc.parsers.log_parser import parse_json_log


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_RULE_PATH = PROJECT_ROOT / "data" / "rules" / "sqli.yml"


def _web_event(target: str) -> SecurityEvent:
    return parse_json_log(
        json.dumps(
            {
                "timestamp": "2026-08-27T09:00:00Z",
                "event_type": "web_access",
                "source_ip": "198.51.100.40",
                "destination_ip": "203.0.113.10",
                "method": "GET",
                "request_path": target,
                "status": 403,
            }
        ),
        source="sigma-test.jsonl",
    )


def _custom_rule(
    selection: str,
    *,
    condition: str = "selection",
    logsource_category: str = "webserver",
    title: str = "Custom Sigma Test Rule",
) -> str:
    return f"""
title: {title}
id: f659f77f-abcd-4017-a6c4-0612f378a669
status: test
description: Exercises a bounded AutoSOC Sigma engine behavior.
logsource:
  category: {logsource_category}
detection:
  selection:
    {selection}
  condition: {condition}
level: high
autosoc:
  rule_id: SIGMA.TEST.BOUNDED
  rule_version: 1.0.0
  category: other
  confidence: 0.90
  confidence_basis: A deterministic test selector matched a normalized field.
  event_types: [web_access]
""".lstrip()


class SigmaEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not SAMPLE_RULE_PATH.is_file():
            raise AssertionError(f"sample Sigma rule is missing: {SAMPLE_RULE_PATH}")
        cls.engine = SigmaEngine.from_path(SAMPLE_RULE_PATH)

    def test_convert_returns_a_stable_non_executable_plan(self) -> None:
        first = self.engine.convert()
        second = self.engine.convert()

        self.assertIsInstance(first, (tuple, list))
        self.assertGreater(len(first), 0)
        self.assertEqual(first, second)
        self.assertTrue(all(not callable(item) for item in first))

    def test_detects_url_encoded_union_select(self) -> None:
        event = _web_event(
            "/products?id=-1%20UNION%20SELECT%20username,password%20FROM%20users"
        )

        findings = self.engine.evaluate_event(event)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertIsInstance(finding, DetectionFinding)
        self.assertEqual(finding.event_id, event.event_id)
        self.assertEqual(finding.rule_id, "SIGMA.SQLI.WEB_REQUEST")
        self.assertEqual(finding.rule_version, "1.0.0")
        self.assertEqual(finding.category, DetectionCategory.SQL_INJECTION)
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.analysis_method, "deterministic_rule")
        self.assertTrue(
            any(
                "UNION SELECT" in str(item.observed_value).upper()
                for item in finding.evidence
            )
        )

    def test_detects_double_encoded_boolean_inference(self) -> None:
        event = _web_event("/login?id=%2527%2520OR%25201%253D1--")

        findings = self.engine.evaluate_event(event)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertTrue(
            any(
                "OR 1=1" in str(item.observed_value).upper()
                for item in finding.evidence
            )
        )
        detection_trace = next(
            item
            for item in finding.decision_trace
            if item.stage == TraceStage.DETECTION
        )
        self.assertGreaterEqual(
            int(detection_trace.details["maximum_decode_rounds"]),
            2,
        )

    def test_benign_baseline_does_not_match(self) -> None:
        benign_targets = (
            "/health",
            "/search?q=union+membership&sort=select",
            "/docs/sql/boolean-operators",
        )

        for target in benign_targets:
            with self.subTest(target=target):
                self.assertEqual(self.engine.evaluate_event(_web_event(target)), [])

    def test_finding_contains_complete_auditable_trace(self) -> None:
        finding = self.engine.evaluate_event(
            _web_event("/items?id=1%20UNION%20SELECT%20email%20FROM%20accounts")
        )[0]

        self.assertGreaterEqual(finding.confidence_score, 0.9)
        self.assertLessEqual(finding.confidence_score, 1.0)
        self.assertTrue(finding.confidence_basis)

        mappings = {
            (mapping.technique_id, mapping.technique_name, mapping.tactic)
            for mapping in finding.mitre_attack_mappings
        }
        self.assertIn(
            (
                "T1190",
                "Exploit Public-Facing Application",
                MitreTactic.INITIAL_ACCESS,
            ),
            mappings,
        )

        evidence_ids = {item.evidence_id for item in finding.evidence}
        self.assertTrue(evidence_ids)
        self.assertTrue(
            all(item.event_id == finding.event_id for item in finding.evidence)
        )
        referenced_ids = {
            evidence_id
            for contribution in finding.risk_score_components
            for evidence_id in contribution.evidence_ids
        } | {
            evidence_id
            for trace in finding.decision_trace
            for evidence_id in trace.evidence_ids
        }
        self.assertLessEqual(referenced_ids, evidence_ids)
        self.assertEqual(
            finding.risk_score,
            max(
                0,
                min(
                    100,
                    sum(item.points for item in finding.risk_score_components),
                ),
            ),
        )

        self.assertEqual(
            [item.sequence for item in finding.decision_trace],
            list(range(1, len(finding.decision_trace) + 1)),
        )
        stages = {item.stage for item in finding.decision_trace}
        self.assertIn(TraceStage.DETECTION, stages)
        self.assertIn(TraceStage.SCORING, stages)
        detection_trace = next(
            item
            for item in finding.decision_trace
            if item.stage == TraceStage.DETECTION
        )
        self.assertEqual(detection_trace.component, "sigma_engine")
        self.assertEqual(detection_trace.outcome, TraceOutcome.MATCHED)
        self.assertEqual(detection_trace.rule_id, finding.rule_id)
        self.assertTrue(detection_trace.details["sigma_rule_id"])
        self.assertTrue(detection_trace.details["matched_fields"])

    def test_logsource_mismatch_prevents_a_condition_match(self) -> None:
        event = SecurityEvent(
            timestamp=datetime(2026, 8, 27, 9, 0, tzinfo=timezone.utc),
            event_type=EventType.TLS_HANDSHAKE,
            source="sigma-test",
            parser_name="test",
            raw_log="synthetic TLS event containing UNION SELECT",
            source_ip="198.51.100.40",
            request_path="/?id=1%20UNION%20SELECT%20password",
            tls_version="TLSv1.3",
        )

        self.assertEqual(self.engine.evaluate_event(event), [])

    def test_malformed_rule_fails_closed(self) -> None:
        with TemporaryDirectory() as directory:
            rule_path = Path(directory) / "malformed.yml"
            rule_path.write_text("title: [unterminated\n", encoding="utf-8")

            with self.assertRaises(SigmaEngineError):
                SigmaEngine.from_path(rule_path)

    def test_unsupported_correlation_rule_fails_closed(self) -> None:
        unsupported_rule = """
title: Base SQLi Event
id: 30d88d2c-bf45-4f41-bdc1-600d9091d22f
name: base_sqli_event
status: test
logsource:
  category: webserver
  product: autosoc
  service: web_access
detection:
  selection:
    request_path|contains: 'UNION SELECT'
  condition: selection
level: high
autosoc:
  rule_id: SIGMA.SQLI.BASE
  rule_version: 1.0.0
  category: sql_injection
  confidence: 0.95
  confidence_basis: A bounded literal selection matched a normalized request field.
---
title: Repeated SQLi Events
id: 9ae14878-c282-403f-9474-a5fd5493802d
status: test
correlation:
  type: event_count
  rules:
    - base_sqli_event
  group-by:
    - source_ip
  timespan: 5m
  condition:
    gte: 3
level: high
""".lstrip()
        with TemporaryDirectory() as directory:
            rule_path = Path(directory) / "correlation.yml"
            rule_path.write_text(unsupported_rule, encoding="utf-8")

            with self.assertRaises(SigmaEngineError):
                SigmaEngine.from_path(rule_path)

    def test_catastrophic_regex_is_stopped_by_evaluation_timeout(self) -> None:
        engine = SigmaEngine.from_yaml(
            _custom_rule("url.original|re: '(a+)+$'")
        )
        event = _web_event("/" + ("a" * 5_000) + "!")

        with self.assertRaisesRegex(SigmaEngineError, "timeout"):
            engine.evaluate_event(event)

    def test_logsource_contradiction_fails_at_rule_load(self) -> None:
        rule = _custom_rule(
            "url.original|contains: attack",
            logsource_category="process_creation",
        )

        with self.assertRaisesRegex(SigmaEngineError, "logsource category"):
            SigmaEngine.from_yaml(rule)

    def test_output_metadata_limits_fail_at_rule_load(self) -> None:
        rule = _custom_rule(
            "url.original|contains: attack",
            title="X" * 201,
        )

        with self.assertRaisesRegex(SigmaEngineError, "populate a finding"):
            SigmaEngine.from_yaml(rule)

    def test_whitespace_only_metadata_fails_at_rule_load(self) -> None:
        rule = _custom_rule(
            "url.original|contains: attack",
        ).replace("rule_version: 1.0.0", "rule_version: '   '")

        with self.assertRaisesRegex(SigmaEngineError, "autosoc metadata"):
            SigmaEngine.from_yaml(rule)

    def test_negative_only_condition_fails_without_positive_evidence(self) -> None:
        rule = _custom_rule(
            "url.original|contains: benign",
            condition="not selection",
        )

        with self.assertRaisesRegex(SigmaEngineError, "positive evidence"):
            SigmaEngine.from_yaml(rule)

    def test_oversized_attribute_is_skipped_without_prefix_false_positive(
        self,
    ) -> None:
        engine = SigmaEngine.from_yaml(
            _custom_rule("http.request.body.content|endswith: TARGET")
        )
        event = parse_json_log(
            json.dumps(
                {
                    "timestamp": "2026-08-27T09:00:00Z",
                    "event_type": "web_access",
                    "method": "POST",
                    "request_path": "/submit",
                    "request_body": ("a" * 8_186) + "TARGETTRAILING",
                }
            )
        )

        self.assertGreater(len(event.attributes["request_body"]), 8_192)
        self.assertEqual(engine.evaluate_event(event), [])


if __name__ == "__main__":
    unittest.main()
