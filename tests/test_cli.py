"""Offline and mocked-live tests for the AutoSOC CLI workflow."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import httpx
from pydantic import ValidationError
from typer.testing import CliRunner

from autosoc.cli import analyze_file, app
from autosoc.integrations.abuseipdb import AbuseIPDBClient
from autosoc.models import IncidentReport, ThreatIntelMode, TraceStage


def _malicious_log(source_ip: str = "8.8.8.8") -> str:
    return json.dumps(
        {
            "timestamp": "2026-08-26T12:00:00Z",
            "source_ip": source_ip,
            "method": "GET",
            "request_path": "/?id=1%20UNION%20SELECT%20password",
            "tls_version": "TLSv1.0",
            "cipher": "TLS_RSA_WITH_RC4_128_MD5",
        }
    )


class CLIWorkflowTests(unittest.TestCase):
    def test_offline_analysis_builds_valid_report(self) -> None:
        with TemporaryDirectory() as directory:
            log_path = Path(directory) / "events.jsonl"
            log_path.write_text(_malicious_log(), encoding="utf-8")

            report = asyncio.run(analyze_file(log_path, offline=True))

        self.assertTrue(report.offline_mode)
        self.assertEqual(len(report.events), 1)
        self.assertEqual(len(report.findings), 3)
        self.assertEqual(len(report.threat_intelligence), 1)
        self.assertEqual(
            report.threat_intelligence[0].mode,
            ThreatIntelMode.MOCK,
        )
        self.assertEqual(report.threat_intelligence[0].abuse_confidence_score, 0)
        self.assertEqual(report.mitre_attack_mappings[0].technique_id, "T1190")
        for finding in report.findings:
            self.assertEqual(finding.decision_trace[-2].stage, TraceStage.ENRICHMENT)
            self.assertEqual(finding.decision_trace[-1].stage, TraceStage.SCORING)
            self.assertTrue(
                any(
                    evidence.source_field.startswith("threat_intelligence.")
                    for evidence in finding.evidence
                )
            )

    def test_one_live_lookup_is_cached_across_three_findings(self) -> None:
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(
                200,
                request=request,
                json={
                    "data": {
                        "ipAddress": "8.8.8.8",
                        "abuseConfidenceScore": 100,
                        "countryCode": "US",
                        "usageType": "Data Center/Web Hosting/Transit",
                    }
                },
            )

        client = AbuseIPDBClient(
            api_key="secret",
            transport=httpx.MockTransport(handler),
        )
        with TemporaryDirectory() as directory:
            log_path = Path(directory) / "event.json"
            log_path.write_text(_malicious_log(), encoding="utf-8")
            report = asyncio.run(
                analyze_file(log_path, intel_client=client)
            )

        self.assertEqual(calls, 1)
        self.assertEqual(report.threat_intelligence[0].mode, ThreatIntelMode.LIVE)
        self.assertEqual(report.overall_risk_score, 84)
        self.assertTrue(
            all(
                finding.risk_score_components[-1].points == 20
                for finding in report.findings
            )
        )

    def test_private_ip_never_reaches_injected_transport(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise AssertionError("private address must not reach the transport")

        client = AbuseIPDBClient(
            api_key="secret",
            transport=httpx.MockTransport(handler),
        )
        with TemporaryDirectory() as directory:
            log_path = Path(directory) / "private.json"
            log_path.write_text(_malicious_log("192.168.1.50"), encoding="utf-8")
            report = asyncio.run(
                analyze_file(log_path, intel_client=client)
            )

        self.assertEqual(report.threat_intelligence[0].mode, ThreatIntelMode.MOCK)
        self.assertEqual(
            report.threat_intelligence[0].usage_type,
            "Private/Reserved",
        )

    def test_offline_flag_overrides_an_injected_live_client(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise AssertionError("offline mode must override the injected client")

        client = AbuseIPDBClient(
            api_key="secret",
            mock_score=31,
            transport=httpx.MockTransport(handler),
        )
        with TemporaryDirectory() as directory:
            log_path = Path(directory) / "offline.json"
            log_path.write_text(_malicious_log(), encoding="utf-8")
            report = asyncio.run(
                analyze_file(
                    log_path,
                    offline=True,
                    intel_client=client,
                )
            )

        self.assertTrue(report.offline_mode)
        self.assertEqual(report.threat_intelligence[0].mode, ThreatIntelMode.MOCK)
        self.assertEqual(report.threat_intelligence[0].abuse_confidence_score, 31)

        contradictory = report.model_dump()
        contradictory["threat_intelligence"][0]["mode"] = ThreatIntelMode.LIVE
        with self.assertRaises(ValidationError):
            IncidentReport.model_validate(contradictory)

    def test_no_findings_still_produces_a_report(self) -> None:
        safe_event = json.dumps(
            {
                "timestamp": "2026-08-26T12:00:00Z",
                "source_ip": "8.8.8.8",
                "path": "/health",
                "tls_version": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
            }
        )
        with TemporaryDirectory() as directory:
            log_path = Path(directory) / "safe.json"
            log_path.write_text(safe_event, encoding="utf-8")
            report = asyncio.run(analyze_file(log_path, offline=True))

        self.assertEqual(report.findings, [])
        self.assertEqual(report.threat_intelligence, [])
        self.assertEqual(report.overall_risk_score, 0)

    def test_analyze_command_prints_json(self) -> None:
        runner = CliRunner()
        with TemporaryDirectory() as directory:
            log_path = Path(directory) / "event.json"
            log_path.write_text(_malicious_log(), encoding="utf-8")
            result = runner.invoke(app, ["analyze", str(log_path), "--offline"])

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["offline_mode"])
        self.assertEqual(len(payload["findings"]), 3)

    def test_orchestrate_command_streams_updates_and_safe_playbook(self) -> None:
        runner = CliRunner()
        with TemporaryDirectory() as directory:
            log_path = Path(directory) / "event.json"
            log_path.write_text(_malicious_log(), encoding="utf-8")
            result = runner.invoke(
                app,
                ["orchestrate", str(log_path), "--offline"],
            )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Deterministic Incident Report", result.stdout)
        self.assertIn("Triage Agent Update", result.stdout)
        self.assertIn("Intel Agent Update", result.stdout)
        self.assertIn("Response Agent Update", result.stdout)
        self.assertIn("Final Containment Playbook", result.stdout)
        self.assertIn("PENDING HUMAN APPROVAL", result.stdout)
        self.assertIn("No action has been executed", result.stdout)
        self.assertIn("8.8.8.8/32", result.stdout)

    def test_serve_command_starts_loopback_uvicorn(self) -> None:
        runner = CliRunner()

        with patch("uvicorn.run") as run_server:
            result = runner.invoke(app, ["serve", "--port", "8123"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("http://localhost:8123", result.stdout)
        self.assertIn("Listening on loopback only", result.stdout)
        run_server.assert_called_once_with(
            "autosoc.web.app:app",
            host="127.0.0.1",
            port=8123,
            log_level="info",
        )


if __name__ == "__main__":
    unittest.main()
