"""Tests for URL-aware deterministic SQLi signatures."""

from __future__ import annotations

import json
import unittest

from autosoc.detectors.sqli import detect_sqli
from autosoc.parsers.log_parser import parse_json_log


def _event_for_target(target: str):
    return parse_json_log(
        json.dumps(
            {
                "timestamp": "2026-08-26T12:00:00Z",
                "source_ip": "198.51.100.20",
                "method": "GET",
                "request_path": target,
            }
        )
    )


class SQLiDetectorTests(unittest.TestCase):
    def test_detects_encoded_union_select_with_inline_comment(self) -> None:
        event = _event_for_target(
            "/items?id=-1%20UNION%2F**%2FSELECT%20password%20FROM%20users"
        )

        findings = detect_sqli(event)

        self.assertEqual([item.rule_id for item in findings], ["SQLI.UNION_SELECT"])
        finding = findings[0]
        self.assertEqual(finding.mitre_attack_mappings[0].technique_id, "T1190")
        self.assertEqual(
            finding.mitre_attack_mappings[0].tactic.value,
            "initial-access",
        )
        self.assertIn("UNION/**/SELECT", finding.evidence[0].observed_value)
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

    def test_detects_double_encoded_boolean_inference(self) -> None:
        event = _event_for_target("/login?id=%2527%2520OR%25201%253D1--")

        findings = detect_sqli(event)

        self.assertEqual(
            [item.rule_id for item in findings],
            ["SQLI.BOOLEAN_INFERENCE"],
        )
        self.assertIn("OR 1=1", findings[0].evidence[0].observed_value)
        self.assertEqual(
            findings[0].decision_trace[0].details["maximum_decode_rounds"],
            2,
        )

    def test_detects_form_encoded_request_body(self) -> None:
        event = parse_json_log(
            json.dumps(
                {
                    "timestamp": "2026-08-26T12:00:00Z",
                    "method": "POST",
                    "path": "/login",
                    "request_body": "username=admin%27+AND+%27x%27%3D%27x%27",
                }
            )
        )

        findings = detect_sqli(event)

        self.assertEqual(
            [item.rule_id for item in findings],
            ["SQLI.BOOLEAN_INFERENCE"],
        )
        self.assertEqual(
            findings[0].evidence[0].source_field,
            "attributes.request_body",
        )

    def test_detects_standalone_json_query_string(self) -> None:
        event = parse_json_log(
            json.dumps(
                {
                    "timestamp": "2026-08-26T12:00:00Z",
                    "url": {"path": "/login", "query": "id=1%20OR%201=1"},
                }
            )
        )

        findings = detect_sqli(event)

        self.assertEqual(
            [item.rule_id for item in findings],
            ["SQLI.BOOLEAN_INFERENCE"],
        )

    def test_detects_time_based_and_stacked_query_payloads(self) -> None:
        time_based = detect_sqli(_event_for_target("/?id=1%20AND%20SLEEP(5)"))
        stacked = detect_sqli(_event_for_target("/?id=1;%20DROP%20TABLE%20users"))

        self.assertIn("SQLI.TIME_BASED", {item.rule_id for item in time_based})
        self.assertEqual([item.rule_id for item in stacked], ["SQLI.STACKED_QUERY"])

    def test_benign_query_returns_no_findings(self) -> None:
        event = _event_for_target("/search?q=union+membership&limit=10")
        self.assertEqual(detect_sqli(event), [])


if __name__ == "__main__":
    unittest.main()
