"""Safety-contract tests for approval-gated remediation generation."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from autosoc.models import IncidentReport
from autosoc.web.app import app
from autosoc.web.remediation import generate_firewall_remediation


def _sqli_log(source_ip: str = "8.8.8.8") -> str:
    return json.dumps(
        {
            "timestamp": "2026-08-27T12:00:00Z",
            "source_ip": source_ip,
            "method": "GET",
            "request_path": "/search?id=1%20UNION%20SELECT%20password",
            "tls_version": "TLSv1.3",
        }
    )


def _tls_only_log() -> str:
    return json.dumps(
        {
            "timestamp": "2026-08-27T12:00:00Z",
            "event_type": "tls_handshake",
            "source_ip": "8.8.4.4",
            "tls_version": "SSLv3",
            "cipher": "TLS_RSA_WITH_RC4_128_MD5",
        }
    )


class RemediationEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app, raise_server_exceptions=False)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()

    def _report(self, raw_log: str) -> IncidentReport:
        response = self.client.post(
            "/api/orchestrate",
            json={"raw_log": raw_log, "offline": True},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return IncidentReport.model_validate(response.json()["incident_report"])

    @staticmethod
    def _approval(report: IncidentReport) -> dict[str, object]:
        return {
            "incident_report": report.model_dump(mode="json"),
            "report_id": str(report.report_id),
            "approval_confirmed": True,
            "approved_by": "analyst@example.com",
            "approval_reason": "SOC ticket INC-2048 reviewed",
        }

    def test_endpoint_generates_only_an_inert_atomic_artifact(self) -> None:
        report = self._report(_sqli_log())
        with tempfile.TemporaryDirectory() as directory:
            with patch(
                "autosoc.web.remediation.load_setting",
                return_value=directory,
            ):
                first = self.client.post(
                    "/api/execute-playbook",
                    json=self._approval(report),
                )
                second = self.client.post(
                    "/api/execute-playbook",
                    json=self._approval(report),
                )

            self.assertEqual(first.status_code, 201, first.text)
            self.assertEqual(second.status_code, 201, second.text)
            payload = second.json()
            self.assertEqual(payload["status"], "artifact_generated")
            self.assertFalse(payload["executed"])
            self.assertEqual(payload["targets"], ["8.8.8.8"])
            self.assertTrue(payload["artifact"]["command_lines_inert"])
            self.assertTrue(payload["artifact"]["replaced_existing"])

            artifact = Path(directory) / "remediation/firewall_remediation.sh"
            content = artifact.read_bytes()
            text = content.decode("utf-8")
            self.assertEqual(sha256(content).hexdigest(), payload["artifact"]["sha256"])
            self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)
            self.assertFalse(artifact.stat().st_mode & stat.S_IXUSR)
            self.assertTrue(
                all(not line or line.startswith("#") for line in text.splitlines())
            )
            self.assertIn("# sudo iptables -I INPUT 1 -s 8.8.8.8 -j DROP", text)
            self.assertEqual(
                list((Path(directory) / "remediation").glob("*.tmp")),
                [],
            )

    def test_approval_is_literal_bounded_and_bound_to_report(self) -> None:
        report = self._report(_sqli_log())
        valid = self._approval(report)
        invalid_payloads = [
            {**valid, "approval_confirmed": False},
            {**valid, "approval_confirmed": 1},
            {**valid, "report_id": "f541df0c-c5a5-411e-8adc-37a13a03d85b"},
            {**valid, "approved_by": "analyst\nroot"},
            {**valid, "approval_reason": "line one\nline two"},
            {**valid, "unexpected": "field"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            with patch(
                "autosoc.web.remediation.load_setting",
                return_value=directory,
            ):
                responses = [
                    self.client.post("/api/execute-playbook", json=payload)
                    for payload in invalid_payloads
                ]
        for response in responses:
            with self.subTest(response=response.text):
                self.assertEqual(response.status_code, 422, response.text)
                self.assertEqual(
                    response.json()["detail"],
                    "Playbook approval request failed validation.",
                )

    def test_no_sqli_or_unsafe_source_has_no_firewall_target(self) -> None:
        reports = [
            self._report(_tls_only_log()),
            self._report(_sqli_log("127.0.0.1")),
            self._report(_sqli_log("fec0::1")),
        ]
        with tempfile.TemporaryDirectory() as directory:
            with patch(
                "autosoc.web.remediation.load_setting",
                return_value=directory,
            ):
                responses = [
                    self.client.post(
                        "/api/execute-playbook",
                        json=self._approval(report),
                    )
                    for report in reports
                ]
            self.assertFalse((Path(directory) / "remediation").exists())
        for response in responses:
            self.assertEqual(response.status_code, 422, response.text)
            self.assertIn("deterministic SQL-injection", response.json()["detail"])

    def test_private_and_documentation_ranges_can_generate_inert_targets(self) -> None:
        reports = [
            self._report(_sqli_log("192.168.10.20")),
            self._report(_sqli_log("198.51.100.21")),
        ]
        with tempfile.TemporaryDirectory() as directory:
            with patch(
                "autosoc.web.remediation.load_setting",
                return_value=directory,
            ):
                responses = [
                    self.client.post(
                        "/api/execute-playbook",
                        json=self._approval(report),
                    )
                    for report in reports
                ]
        self.assertEqual(
            [response.status_code for response in responses],
            [201, 201],
        )
        self.assertEqual(responses[0].json()["targets"], ["192.168.10.20"])
        self.assertEqual(responses[1].json()["targets"], ["198.51.100.21"])

    def test_symlinked_directory_and_target_are_refused(self) -> None:
        report = self._report(_sqli_log())
        with tempfile.TemporaryDirectory() as directory:
            data_directory = Path(directory) / "data"
            outside_directory = Path(directory) / "outside"
            data_directory.mkdir()
            outside_directory.mkdir()
            (data_directory / "remediation").symlink_to(
                outside_directory,
                target_is_directory=True,
            )
            with patch(
                "autosoc.web.remediation.load_setting",
                return_value=str(data_directory),
            ):
                response = self.client.post(
                    "/api/execute-playbook",
                    json=self._approval(report),
                )
            self.assertEqual(response.status_code, 500, response.text)
            self.assertFalse((outside_directory / "firewall_remediation.sh").exists())

        with tempfile.TemporaryDirectory() as directory:
            data_directory = Path(directory) / "data"
            remediation_directory = data_directory / "remediation"
            remediation_directory.mkdir(parents=True)
            victim = Path(directory) / "victim.txt"
            victim.write_text("do not overwrite", encoding="utf-8")
            (remediation_directory / "firewall_remediation.sh").symlink_to(victim)
            with patch(
                "autosoc.web.remediation.load_setting",
                return_value=str(data_directory),
            ):
                response = self.client.post(
                    "/api/execute-playbook",
                    json=self._approval(report),
                )
            self.assertEqual(response.status_code, 500, response.text)
            self.assertEqual(victim.read_text(encoding="utf-8"), "do not overwrite")

    def test_concurrent_writes_are_complete_and_atomic(self) -> None:
        report = self._report(_sqli_log())
        with tempfile.TemporaryDirectory() as directory:
            data_directory = Path(directory)
            with ThreadPoolExecutor(max_workers=8) as executor:
                receipts = list(
                    executor.map(
                        lambda index: generate_firewall_remediation(
                            report,
                            approved_by=f"analyst-{index}",
                            data_directory=data_directory,
                        ),
                        range(8),
                    )
                )
            artifact = data_directory / "remediation/firewall_remediation.sh"
            content = artifact.read_bytes()
            self.assertIn(
                sha256(content).hexdigest(),
                {receipt.artifact_sha256 for receipt in receipts},
            )
            self.assertEqual(sum(not item.replaced_existing for item in receipts), 1)
            self.assertTrue(
                all(
                    not line or line.startswith("#")
                    for line in content.decode("utf-8").splitlines()
                )
            )

    def test_generator_rejects_comment_breakout_from_direct_callers(self) -> None:
        report = self._report(_sqli_log())
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "approver identity"):
                generate_firewall_remediation(
                    report,
                    approved_by="analyst\nsudo iptables -F",
                    data_directory=Path(directory),
                )
            self.assertFalse((Path(directory) / "remediation").exists())

    def test_endpoint_preserves_auth_origin_rate_and_error_boundaries(self) -> None:
        report = self._report(_sqli_log())
        approval = self._approval(report)
        password = "correct-horse-battery-staple"
        with (
            patch("autosoc.web.app._WEB_USERNAME", "analyst"),
            patch("autosoc.web.app._WEB_PASSWORD", password),
        ):
            unauthorized = self.client.post("/api/execute-playbook", json=approval)
            cross_origin = self.client.post(
                "/api/execute-playbook",
                json=approval,
                headers={
                    "origin": "https://attacker.example",
                    "sec-fetch-site": "cross-site",
                },
                auth=("analyst", password),
            )
        self.assertEqual(unauthorized.status_code, 401, unauthorized.text)
        self.assertEqual(cross_origin.status_code, 403, cross_origin.text)

        secret = "sensitive path /private/tmp/autosoc-secret"
        with patch(
            "autosoc.web.app.generate_firewall_remediation",
            side_effect=RuntimeError(secret),
        ):
            failed = self.client.post("/api/execute-playbook", json=approval)
        self.assertEqual(failed.status_code, 500, failed.text)
        self.assertNotIn(secret, failed.text)
        self.assertNotIn("RuntimeError", failed.text)

    def test_request_size_and_media_type_are_bounded(self) -> None:
        with patch("autosoc.web.app.MAX_APPROVAL_REQUEST_BYTES", 32):
            oversized = self.client.post(
                "/api/execute-playbook",
                content=b"{" + (b"x" * 64) + b"}",
                headers={"content-type": "application/json"},
            )
        unsupported = self.client.post(
            "/api/execute-playbook",
            content=b"approval=true",
            headers={"content-type": "text/plain"},
        )
        self.assertEqual(oversized.status_code, 413, oversized.text)
        self.assertEqual(unsupported.status_code, 415, unsupported.text)


if __name__ == "__main__":
    unittest.main()
