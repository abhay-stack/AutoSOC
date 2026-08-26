"""Public-contract tests for the local AutoSOC FastAPI dashboard."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from autosoc.cli import app as cli_app
from autosoc.models import IncidentReport
from autosoc.web.app import (
    MAX_LOG_BYTES,
    _GlobalRateLimiter,
    _configured_allowed_hosts,
    app as web_app,
)


def _malicious_json_log() -> str:
    return json.dumps(
        {
            "timestamp": "2026-08-27T12:00:00Z",
            "source_ip": "8.8.8.8",
            "method": "GET",
            "request_path": "/search?id=1%20UNION%20SELECT%20password",
            "tls_version": "TLSv1.0",
            "cipher": "TLS_RSA_WITH_RC4_128_MD5",
        }
    )


def _apache_boolean_sqli_log() -> str:
    return (
        '8.8.4.4 - - [27/Aug/2026:12:00:00 +0000] '
        '"GET /login?user=admin%27%20OR%201=1-- HTTP/1.1" '
        '403 512 "-" "curl/8.7.1"'
    )


def _assert_public_error(
    testcase: unittest.TestCase,
    response: object,
    expected_status: int,
) -> str:
    testcase.assertEqual(response.status_code, expected_status, response.text)
    payload = response.json()
    testcase.assertIsInstance(payload, dict)
    detail = payload.get("detail")
    testcase.assertIsInstance(detail, str)
    testcase.assertTrue(detail.strip())
    return detail


class WebDashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(web_app, raise_server_exceptions=False)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()

    def test_root_renders_dashboard_template(self) -> None:
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("text/html", response.headers["content-type"])
        self.assertIn("AutoSOC", response.text)
        self.assertIn("Analyze &amp; Orchestrate", response.text)
        self.assertIn("/api/orchestrate", response.text)
        self.assertIn("/api/execute-playbook", response.text)
        self.assertIn("Approve &amp; Execute", response.text)
        self.assertIn("Generates only · never invokes shell", response.text)
        self.assertIn("Artifact generated · commands not executed", response.text)
        self.assertIn("PENDING HUMAN APPROVAL", response.text)
        self.assertIn("tailwindcss.com", response.text)
        self.assertIn("hosting firewall blocked this batch", response.text)

        # Keep the hosted demo representative without batching multiple SQLi
        # signatures into one request, which managed perimeter WAFs may reject.
        self.assertIn("UNION%20SELECT", response.text)
        self.assertIn('"tls_version":"SSLv3"', response.text)
        self.assertIn('"request_path":"/health"', response.text)
        self.assertNotIn("password=%27%20OR%201%3D1", response.text)

    def test_healthz_is_fixed_auth_exempt_and_provider_free(self) -> None:
        with (
            patch(
                "autosoc.web.app._WEB_PASSWORD",
                "portfolio-health-password",
            ),
            patch(
                "autosoc.web.app.analyze_file",
                new_callable=AsyncMock,
                side_effect=AssertionError("health check ran analysis"),
            ) as analyze,
            patch(
                "autosoc.web.app.build_graph",
                side_effect=AssertionError("health check built agent graph"),
            ) as graph_builder,
            patch(
                "autosoc.integrations.abuseipdb.AbuseIPDBClient._request",
                new_callable=AsyncMock,
                side_effect=AssertionError("health check reached AbuseIPDB"),
            ) as abuse_request,
        ):
            response = self.client.get("/healthz")

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), {"status": "ok", "service": "autosoc"})
        self.assertEqual(response.headers["cache-control"], "no-store")
        analyze.assert_not_awaited()
        graph_builder.assert_not_called()
        abuse_request.assert_not_awaited()

    def test_configured_allowed_hosts_are_exact_and_fail_closed(self) -> None:
        self.assertEqual(
            _configured_allowed_hosts(
                render_hostname=None,
                configured_hosts=None,
            ),
            ["localhost", "127.0.0.1", "testserver"],
        )
        self.assertEqual(
            _configured_allowed_hosts(
                render_hostname="AutoSOC-Demo.onrender.com",
                configured_hosts=(
                    "soc.example.com, AUTOSOC-DEMO.ONRENDER.COM, "
                    "*.preview.example.com"
                ),
            ),
            [
                "autosoc-demo.onrender.com",
                "soc.example.com",
                "*.preview.example.com",
            ],
        )

        invalid_hosts = (
            "*",
            "https://soc.example.com",
            "soc.example.com:443",
            "soc.example.com/dashboard",
            ".soc.example.com",
            "soc..example.com",
        )
        for invalid_host in invalid_hosts:
            with self.subTest(invalid_host=invalid_host):
                with self.assertRaises(RuntimeError):
                    _configured_allowed_hosts(
                        render_hostname="autosoc-demo.onrender.com",
                        configured_hosts=invalid_host,
                    )

        rejected = self.client.get(
            "/healthz",
            headers={"host": "attacker.example"},
        )
        self.assertEqual(rejected.status_code, 400, rejected.text)

    def test_basic_auth_protects_dashboard_and_api_but_not_health(self) -> None:
        password = "correct-horse-battery-staple"
        with (
            patch("autosoc.web.app._WEB_USERNAME", "analyst"),
            patch("autosoc.web.app._WEB_PASSWORD", password),
            patch(
                "autosoc.web.app.analyze_file",
                new_callable=AsyncMock,
                side_effect=AssertionError("unauthorized request ran analysis"),
            ) as analyze,
        ):
            missing = self.client.post(
                "/api/orchestrate",
                json={"raw_log": _malicious_json_log()},
            )
            wrong = self.client.get(
                "/",
                auth=("analyst", "incorrect-password"),
            )
            accepted = self.client.get("/", auth=("analyst", password))
            health = self.client.get("/healthz")

        self.assertEqual(missing.status_code, 401, missing.text)
        self.assertIn("Basic", missing.headers["www-authenticate"])
        self.assertEqual(wrong.status_code, 401, wrong.text)
        self.assertEqual(accepted.status_code, 200, accepted.text)
        self.assertEqual(health.status_code, 200, health.text)
        analyze.assert_not_awaited()

    def test_dashboard_security_headers_and_browser_origin_boundary(self) -> None:
        root = self.client.get("/")

        self.assertEqual(root.headers["cache-control"], "no-store")
        self.assertEqual(root.headers["x-content-type-options"], "nosniff")
        self.assertEqual(root.headers["x-frame-options"], "DENY")
        self.assertIn("frame-ancestors 'none'", root.headers["content-security-policy"])

        rejected = self.client.post(
            "/api/orchestrate",
            json={"raw_log": _malicious_json_log()},
            headers={
                "origin": "https://attacker.example",
                "sec-fetch-site": "cross-site",
            },
        )
        detail = _assert_public_error(self, rejected, 403)
        self.assertIn("Cross-origin", detail)

        accepted = self.client.post(
            "/api/orchestrate",
            json={"raw_log": _malicious_json_log()},
            headers={
                "origin": "http://testserver",
                "sec-fetch-site": "same-origin",
            },
        )
        self.assertEqual(accepted.status_code, 200, accepted.text)

    def test_json_request_defaults_to_offline_without_provider_calls(self) -> None:
        with (
            patch(
                "autosoc.integrations.abuseipdb.AbuseIPDBClient._request",
                new_callable=AsyncMock,
                side_effect=AssertionError("offline request reached AbuseIPDB"),
            ) as abuse_request,
            patch(
                "autosoc.integrations.greynoise.GreyNoiseClient._request",
                new_callable=AsyncMock,
                side_effect=AssertionError("offline request reached GreyNoise"),
            ) as greynoise_request,
            patch(
                "autosoc.agents.nodes.create_chat_model",
                side_effect=AssertionError("offline request created an LLM client"),
            ) as model_factory,
        ):
            response = self.client.post(
                "/api/orchestrate",
                json={"raw_log": _malicious_json_log()},
            )

        self.assertEqual(response.status_code, 200, response.text)
        abuse_request.assert_not_awaited()
        greynoise_request.assert_not_awaited()
        model_factory.assert_not_called()

        payload = response.json()
        self.assertGreaterEqual(
            set(payload),
            {"incident_report", "agent_thread", "playbook"},
        )
        report = IncidentReport.model_validate(payload["incident_report"])
        self.assertTrue(report.offline_mode)
        self.assertTrue(report.findings)
        self.assertTrue(report.threat_intelligence)
        self.assertTrue(
            all(item.mode.value == "mock" for item in report.threat_intelligence)
        )
        self.assertTrue(report.greynoise_intelligence)
        self.assertTrue(
            all(
                item.mode.value == "mock"
                for item in report.greynoise_intelligence
            )
        )

        thread = payload["agent_thread"]
        self.assertEqual(len(thread), 3)
        normalised_agents = {
            entry["agent"].lower().replace("_agent", "").replace(" agent", "")
            for entry in thread
        }
        self.assertEqual(normalised_agents, {"triage", "intel", "response"})
        for entry in thread:
            self.assertGreaterEqual(
                set(entry),
                {"agent", "content", "generation_mode"},
            )
            self.assertTrue(entry["content"].strip())
            self.assertEqual(entry["generation_mode"], "deterministic_fallback")

    def test_urlencoded_form_accepts_apache_log(self) -> None:
        response = self.client.post(
            "/api/orchestrate",
            data={
                "raw_log": _apache_boolean_sqli_log(),
                "offline": "true",
                "log_format": "apache",
            },
        )

        self.assertEqual(response.status_code, 200, response.text)
        report = IncidentReport.model_validate(
            response.json()["incident_report"]
        )
        self.assertTrue(report.offline_mode)
        self.assertTrue(
            any(
                finding.category.value == "sql_injection"
                for finding in report.findings
            )
        )

    def test_multipart_file_upload_is_accepted_and_filename_is_sanitized(self) -> None:
        response = self.client.post(
            "/api/orchestrate",
            data={"offline": "true", "log_format": "json"},
            files={
                "file": (
                    "../../attack.json",
                    _malicious_json_log().encode("utf-8"),
                    "application/json",
                )
            },
        )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        report = IncidentReport.model_validate(payload["incident_report"])
        self.assertEqual(len(report.events), 1)
        self.assertTrue(report.findings)
        self.assertNotIn("../../attack.json", json.dumps(payload))
        self._assert_no_temporary_path(payload)

    def test_plain_text_body_is_accepted(self) -> None:
        response = self.client.post(
            "/api/orchestrate?offline=true&log_format=json",
            content=_malicious_json_log().encode("utf-8"),
            headers={"content-type": "text/plain; charset=utf-8"},
        )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["incident_report"]["offline_mode"])

    def test_response_contains_grounded_mitre_data_and_approval_gate(self) -> None:
        response = self.client.post(
            "/api/orchestrate",
            json={"raw_log": _malicious_json_log(), "offline": True},
        )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        report = IncidentReport.model_validate(payload["incident_report"])
        self.assertIn(
            "T1190",
            {item.technique_id for item in report.mitre_attack_mappings},
        )
        self.assertTrue(report.dry_run)
        self.assertTrue(report.requires_human_approval)
        self.assertIn("DRY RUN / RECOMMENDATION ONLY", payload["playbook"])
        self.assertIn("PENDING HUMAN APPROVAL", payload["playbook"])
        self.assertIn("No action has been executed", payload["playbook"])

    def test_missing_credentials_degrade_safely_when_offline_is_false(self) -> None:
        password = "portfolio-live-mode-password"
        with (
            patch("autosoc.web.app._ENABLE_LIVE_PROVIDERS", True),
            patch("autosoc.web.app._WEB_USERNAME", "analyst"),
            patch("autosoc.web.app._WEB_PASSWORD", password),
            patch(
                "autosoc.integrations.abuseipdb.load_setting",
                return_value=None,
            ),
            patch(
                "autosoc.integrations.greynoise.load_setting",
                return_value=None,
            ),
            patch("autosoc.agents.nodes.load_setting", return_value=None),
            patch(
                "autosoc.integrations.abuseipdb.AbuseIPDBClient._request",
                new_callable=AsyncMock,
                side_effect=AssertionError("missing-key request reached provider"),
            ) as abuse_request,
            patch(
                "autosoc.integrations.greynoise.GreyNoiseClient._request",
                new_callable=AsyncMock,
                side_effect=AssertionError("missing-key request reached provider"),
            ) as greynoise_request,
        ):
            response = self.client.post(
                "/api/orchestrate",
                json={
                    "raw_log": _malicious_json_log(),
                    "offline": False,
                    "log_format": "json",
                },
                auth=("analyst", password),
            )

        self.assertEqual(response.status_code, 200, response.text)
        abuse_request.assert_not_awaited()
        greynoise_request.assert_not_awaited()
        payload = response.json()
        self.assertFalse(payload["incident_report"]["offline_mode"])
        self.assertTrue(
            all(
                item["mode"] == "mock"
                for item in payload["incident_report"]["threat_intelligence"]
            )
        )
        self.assertTrue(
            all(
                item["mode"] == "mock"
                for item in payload["incident_report"]["greynoise_intelligence"]
            )
        )
        self.assertTrue(
            all(
                entry["generation_mode"] == "deterministic_fallback"
                for entry in payload["agent_thread"]
            )
        )

    def test_disabled_live_mode_rejects_without_provider_calls(self) -> None:
        with (
            patch("autosoc.web.app._ENABLE_LIVE_PROVIDERS", False),
            patch("autosoc.web.app._WEB_PASSWORD", None),
            patch(
                "autosoc.integrations.abuseipdb.AbuseIPDBClient._request",
                new_callable=AsyncMock,
                side_effect=AssertionError("disabled live mode reached AbuseIPDB"),
            ) as abuse_request,
            patch(
                "autosoc.integrations.greynoise.GreyNoiseClient._request",
                new_callable=AsyncMock,
                side_effect=AssertionError("disabled live mode reached GreyNoise"),
            ) as greynoise_request,
            patch(
                "autosoc.agents.nodes.create_chat_model",
                side_effect=AssertionError("disabled live mode created a model"),
            ) as model_factory,
            patch(
                "autosoc.web.app.analyze_file",
                new_callable=AsyncMock,
                side_effect=AssertionError("disabled live mode ran analysis"),
            ) as analyze,
        ):
            response = self.client.post(
                "/api/orchestrate",
                json={
                    "raw_log": _malicious_json_log(),
                    "offline": False,
                    "log_format": "json",
                },
            )

        detail = _assert_public_error(self, response, 403)
        self.assertIn("disabled by server policy", detail)
        analyze.assert_not_awaited()
        abuse_request.assert_not_awaited()
        greynoise_request.assert_not_awaited()
        model_factory.assert_not_called()

    def test_global_rate_limiter_uses_a_sliding_window(self) -> None:
        limiter = _GlobalRateLimiter(1)
        with patch(
            "autosoc.web.app.monotonic",
            side_effect=(100.0, 101.0, 160.1),
        ):
            self.assertIsNone(limiter.consume())
            self.assertEqual(limiter.consume(), 59)
            self.assertIsNone(limiter.consume())

        disabled = _GlobalRateLimiter(0)
        self.assertIsNone(disabled.consume())
        self.assertIsNone(disabled.consume())

    def test_orchestration_rate_limit_returns_retry_contract(self) -> None:
        limiter = _GlobalRateLimiter(1)
        with (
            patch("autosoc.web.app._RATE_LIMITER", limiter),
            patch("autosoc.web.app._RATE_LIMIT_PER_MINUTE", 1),
        ):
            accepted = self.client.post(
                "/api/orchestrate",
                json={"raw_log": _malicious_json_log()},
            )
            health = self.client.get("/healthz")
            rejected = self.client.post(
                "/api/orchestrate",
                json={"raw_log": _malicious_json_log()},
            )

        self.assertEqual(accepted.status_code, 200, accepted.text)
        self.assertEqual(accepted.headers["x-ratelimit-limit"], "1")
        self.assertEqual(health.status_code, 200, health.text)
        detail = _assert_public_error(self, rejected, 429)
        self.assertIn("request limit", detail)
        self.assertGreaterEqual(int(rejected.headers["retry-after"]), 1)
        self.assertEqual(rejected.headers["x-ratelimit-limit"], "1")

    def test_empty_and_ambiguous_inputs_return_422(self) -> None:
        responses = [
            self.client.post("/api/orchestrate", json={}),
            self.client.post(
                "/api/orchestrate",
                json={"raw_log": "   ", "offline": True},
            ),
            self.client.post(
                "/api/orchestrate",
                data={"raw_log": _malicious_json_log()},
                files={
                    "file": (
                        "event.json",
                        _malicious_json_log().encode("utf-8"),
                        "application/json",
                    )
                },
            ),
        ]

        for response in responses:
            with self.subTest(body=response.text):
                _assert_public_error(self, response, 422)

    def test_oversize_input_returns_413(self) -> None:
        self.assertEqual(MAX_LOG_BYTES, 2 * 1024 * 1024)

        response = self.client.post(
            "/api/orchestrate",
            json={"raw_log": "A" * (MAX_LOG_BYTES + 1), "offline": True},
        )

        _assert_public_error(self, response, 413)

    def test_invalid_utf8_upload_returns_400(self) -> None:
        response = self.client.post(
            "/api/orchestrate",
            data={"offline": "true"},
            files={"file": ("event.log", b"\xff\xfe\xfa", "text/plain")},
        )

        _assert_public_error(self, response, 400)

    def test_unsupported_media_type_returns_415(self) -> None:
        response = self.client.post(
            "/api/orchestrate",
            content=b"<event />",
            headers={"content-type": "application/xml"},
        )

        _assert_public_error(self, response, 415)

    def test_malformed_json_body_returns_400(self) -> None:
        response = self.client.post(
            "/api/orchestrate",
            content=b'{"raw_log":',
            headers={"content-type": "application/json"},
        )

        _assert_public_error(self, response, 400)

    def test_unparseable_log_and_invalid_options_return_422(self) -> None:
        responses = [
            self.client.post(
                "/api/orchestrate",
                json={"raw_log": "this is not a supported log record"},
            ),
            self.client.post(
                "/api/orchestrate",
                json={
                    "raw_log": _malicious_json_log(),
                    "offline": "sometimes",
                },
            ),
            self.client.post(
                "/api/orchestrate",
                json={
                    "raw_log": _malicious_json_log(),
                    "log_format": "csv",
                },
            ),
        ]

        for response in responses:
            with self.subTest(body=response.text):
                _assert_public_error(self, response, 422)

    def test_unexpected_failure_returns_sanitized_500(self) -> None:
        secret = "sensitive-provider-detail /private/tmp/autosoc-secret"
        with patch(
            "autosoc.web.app.analyze_file",
            new_callable=AsyncMock,
            side_effect=RuntimeError(secret),
        ):
            response = self.client.post(
                "/api/orchestrate",
                json={"raw_log": _malicious_json_log()},
            )

        detail = _assert_public_error(self, response, 500)
        self.assertNotIn(secret, response.text)
        self.assertNotIn("RuntimeError", response.text)
        self.assertNotIn("Traceback", response.text)
        self.assertNotIn("/private/tmp", detail)

    def test_serve_command_calls_uvicorn_without_starting_a_server(self) -> None:
        runner = CliRunner()
        with patch("uvicorn.run") as uvicorn_run:
            result = runner.invoke(cli_app, ["serve", "--port", "8765"])

        self.assertEqual(result.exit_code, 0, result.output)
        uvicorn_run.assert_called_once()
        _, kwargs = uvicorn_run.call_args
        self.assertEqual(kwargs.get("port"), 8765)
        self.assertIn(kwargs.get("host"), {"127.0.0.1", "localhost"})

    def _assert_no_temporary_path(self, payload: dict[str, object]) -> None:
        report = payload["incident_report"]
        input_file = str(report["metadata"].get("input_file", ""))
        self.assertFalse(Path(input_file).is_absolute())
        for event in report["events"]:
            self.assertFalse(Path(str(event["source"])).is_absolute())

        serialized = json.dumps(payload)
        self.assertNotIn(tempfile.gettempdir(), serialized)
        self.assertNotIn("/private/tmp/", serialized)


if __name__ == "__main__":
    unittest.main()
