"""Contract tests for the offline-safe GreyNoise Community integration."""

from __future__ import annotations

from datetime import date
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import httpx
from pydantic import ValidationError

from autosoc.integrations.greynoise import (
    GREYNOISE_COMMUNITY_URL,
    GreyNoiseClient,
)
from autosoc.models import (
    GreyNoiseClassification,
    GreyNoiseLookupStatus,
    GreyNoiseResult,
    ThreatIntelMode,
)


def _matched_payload(
    ip_value: str,
    *,
    noise: bool = True,
    riot: bool = False,
    classification: str = "unknown",
) -> dict[str, object]:
    return {
        "ip": ip_value,
        "noise": noise,
        "riot": riot,
        "classification": classification,
        "name": "Example Internet Scanner",
        "link": f"https://viz.greynoise.io/ip/{ip_value}",
        "last_seen": "2026-08-27",
        "message": "IP context found",
    }


def _assert_neutral_mock(
    testcase: unittest.TestCase,
    result: GreyNoiseResult,
    *,
    status: GreyNoiseLookupStatus,
) -> None:
    testcase.assertEqual(result.mode, ThreatIntelMode.MOCK)
    testcase.assertEqual(result.lookup_status, status)
    testcase.assertFalse(result.noise)
    testcase.assertFalse(result.riot)
    testcase.assertIsNone(result.classification)
    testcase.assertFalse(result.risk_reduction_eligible)


class GreyNoiseClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_key_returns_neutral_mock_without_request(self) -> None:
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            raise AssertionError("missing-key lookup must not reach the transport")

        with patch.dict(os.environ, {}, clear=True):
            client = GreyNoiseClient.from_env(
                env_file="does-not-exist.env",
                transport=httpx.MockTransport(handler),
            )
            result = await client.check_ip("8.8.8.8")

        _assert_neutral_mock(
            self,
            result,
            status=GreyNoiseLookupStatus.MISSING_KEY,
        )
        self.assertIn("key", result.retrieval_reason.casefold())
        self.assertEqual(calls, 0)

    async def test_offline_non_global_ipv6_and_invalid_inputs_never_call_api(
        self,
    ) -> None:
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            raise AssertionError("safety-gated lookup reached the transport")

        transport = httpx.MockTransport(handler)
        cases = [
            (
                GreyNoiseClient(
                    api_key="secret",
                    offline=True,
                    transport=transport,
                ),
                "8.8.8.8",
                GreyNoiseLookupStatus.OFFLINE,
                "8.8.8.8",
            ),
            (
                GreyNoiseClient(api_key="secret", transport=transport),
                "192.168.10.20",
                GreyNoiseLookupStatus.NON_GLOBAL,
                "192.168.10.20",
            ),
            (
                GreyNoiseClient(api_key="secret", transport=transport),
                "127.0.0.1",
                GreyNoiseLookupStatus.NON_GLOBAL,
                "127.0.0.1",
            ),
            (
                GreyNoiseClient(api_key="secret", transport=transport),
                "2606:4700:4700::1111",
                GreyNoiseLookupStatus.NON_GLOBAL,
                "2606:4700:4700::1111",
            ),
            (
                GreyNoiseClient(api_key="secret", transport=transport),
                "not-an-ip",
                GreyNoiseLookupStatus.INVALID,
                None,
            ),
            (
                GreyNoiseClient(api_key="secret", transport=transport),
                None,
                GreyNoiseLookupStatus.INVALID,
                None,
            ),
        ]

        for client, ip_value, expected_status, expected_ip in cases:
            with self.subTest(ip_value=ip_value, status=expected_status):
                result = await client.check_ip(ip_value)
                _assert_neutral_mock(self, result, status=expected_status)
                self.assertEqual(
                    str(result.ip_address)
                    if result.ip_address is not None
                    else None,
                    expected_ip,
                )

        self.assertEqual(calls, 0)

    async def test_live_request_contract_and_benign_noise_parsing(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            requested_ip = request.url.path.rsplit("/", 1)[-1]
            if requested_ip == "8.8.8.8":
                payload = _matched_payload(
                    requested_ip,
                    noise=False,
                    riot=True,
                    classification="BENIGN",
                )
            else:
                payload = _matched_payload(
                    requested_ip,
                    noise=True,
                    riot=False,
                    classification="unknown",
                )
            return httpx.Response(200, request=request, json=payload)

        client = GreyNoiseClient(
            api_key="test-secret",
            transport=httpx.MockTransport(handler),
        )
        async with client:
            benign = await client.check_ip("8.8.8.8")
            noise = await client.check_ip("1.1.1.1")

        self.assertEqual(
            [str(request.url) for request in requests],
            [
                f"{GREYNOISE_COMMUNITY_URL}/8.8.8.8",
                f"{GREYNOISE_COMMUNITY_URL}/1.1.1.1",
            ],
        )
        for request in requests:
            self.assertEqual(request.method, "GET")
            self.assertEqual(request.headers["key"], "test-secret")
            self.assertEqual(request.headers["Accept"], "application/json")
            self.assertEqual(request.url.query, b"")

        self.assertEqual(benign.mode, ThreatIntelMode.LIVE)
        self.assertEqual(benign.lookup_status, GreyNoiseLookupStatus.MATCHED)
        self.assertEqual(benign.classification, GreyNoiseClassification.BENIGN)
        self.assertFalse(benign.noise)
        self.assertTrue(benign.riot)
        self.assertEqual(benign.last_seen, date(2026, 8, 27))
        self.assertEqual(benign.name, "Example Internet Scanner")
        self.assertTrue(benign.risk_reduction_eligible)

        self.assertEqual(noise.mode, ThreatIntelMode.LIVE)
        self.assertEqual(noise.lookup_status, GreyNoiseLookupStatus.MATCHED)
        self.assertEqual(noise.classification, GreyNoiseClassification.UNKNOWN)
        self.assertTrue(noise.noise)
        self.assertFalse(noise.riot)
        self.assertTrue(noise.risk_reduction_eligible)

    async def test_404_is_authoritative_but_neutral(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                404,
                request=request,
                json={
                    "ip": "8.8.8.8",
                    "noise": False,
                    "riot": False,
                    "classification": None,
                    "name": None,
                    "link": None,
                    "last_seen": None,
                    "message": "IP not found",
                },
            )

        client = GreyNoiseClient(
            api_key="secret",
            transport=httpx.MockTransport(handler),
        )
        result = await client.check_ip("8.8.8.8")

        self.assertEqual(result.mode, ThreatIntelMode.LIVE)
        self.assertEqual(result.lookup_status, GreyNoiseLookupStatus.NOT_FOUND)
        self.assertEqual(str(result.ip_address), "8.8.8.8")
        self.assertFalse(result.noise)
        self.assertFalse(result.riot)
        self.assertIsNone(result.classification)
        self.assertFalse(result.risk_reduction_eligible)
        self.assertIn("not found", result.retrieval_reason.casefold())

    async def test_malformed_mismatched_and_http_errors_fall_back_neutrally(
        self,
    ) -> None:
        def mismatched(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                request=request,
                json=_matched_payload("1.1.1.1"),
            )

        def malformed(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                request=request,
                json={
                    "ip": "8.8.8.8",
                    "noise": "yes",
                    "riot": False,
                    "classification": "unknown",
                },
            )

        def internally_inconsistent(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                request=request,
                json=_matched_payload(
                    "8.8.8.8",
                    noise=False,
                    riot=False,
                    classification="benign",
                ),
            )

        def invalid_json(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                request=request,
                content=b"not-json",
                headers={"content-type": "application/json"},
            )

        def server_error(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, request=request, json={"message": "down"})

        def network_error(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("provider unavailable", request=request)

        handlers = [
            mismatched,
            malformed,
            internally_inconsistent,
            invalid_json,
            server_error,
            network_error,
        ]
        for handler in handlers:
            with self.subTest(handler=handler.__name__):
                client = GreyNoiseClient(
                    api_key="secret",
                    transport=httpx.MockTransport(handler),
                )
                result = await client.check_ip("8.8.8.8")
                _assert_neutral_mock(
                    self,
                    result,
                    status=GreyNoiseLookupStatus.PROVIDER_ERROR,
                )
                self.assertEqual(str(result.ip_address), "8.8.8.8")
                self.assertIn(
                    "validation failed",
                    result.retrieval_reason.casefold(),
                )

    async def test_dotenv_key_is_loaded_literally_without_evaluation(self) -> None:
        observed_key: str | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal observed_key
            observed_key = request.headers["key"]
            return httpx.Response(
                200,
                request=request,
                json=_matched_payload("8.8.8.8"),
            )

        with TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text(
                'GREYNOISE_API_KEY="dotenv-secret"\n'
                "IGNORED=$(must-not-run)\n",
                encoding="utf-8",
            )
            with patch.dict(os.environ, {}, clear=True):
                client = GreyNoiseClient.from_env(
                    env_file=env_file,
                    transport=httpx.MockTransport(handler),
                )
                result = await client.check_ip("8.8.8.8")

        self.assertEqual(observed_key, "dotenv-secret")
        self.assertEqual(result.mode, ThreatIntelMode.LIVE)
        self.assertEqual(result.lookup_status, GreyNoiseLookupStatus.MATCHED)

    def test_model_enforces_neutrality_and_authority_invariants(self) -> None:
        invalid_values = [
            {
                "ip_address": "8.8.8.8",
                "noise": True,
                "mode": ThreatIntelMode.MOCK,
                "lookup_status": GreyNoiseLookupStatus.OFFLINE,
                "retrieval_reason": "invalid noisy mock",
            },
            {
                "ip_address": "8.8.8.8",
                "classification": GreyNoiseClassification.UNKNOWN,
                "mode": ThreatIntelMode.MOCK,
                "lookup_status": GreyNoiseLookupStatus.PROVIDER_ERROR,
                "retrieval_reason": "invalid classified mock",
            },
            {
                "ip_address": "8.8.8.8",
                "message": "unverified provider claim",
                "mode": ThreatIntelMode.MOCK,
                "lookup_status": GreyNoiseLookupStatus.PROVIDER_ERROR,
                "retrieval_reason": "invalid provider data in mock",
            },
            {
                "ip_address": "8.8.8.8",
                "mode": ThreatIntelMode.MOCK,
                "lookup_status": GreyNoiseLookupStatus.MATCHED,
                "retrieval_reason": "invalid authoritative mock",
            },
            {
                "ip_address": None,
                "classification": GreyNoiseClassification.UNKNOWN,
                "mode": ThreatIntelMode.LIVE,
                "lookup_status": GreyNoiseLookupStatus.MATCHED,
                "retrieval_reason": "invalid missing live IP",
            },
            {
                "ip_address": "8.8.8.8",
                "mode": ThreatIntelMode.LIVE,
                "lookup_status": GreyNoiseLookupStatus.OFFLINE,
                "retrieval_reason": "invalid live status",
            },
            {
                "ip_address": "8.8.8.8",
                "mode": ThreatIntelMode.LIVE,
                "lookup_status": GreyNoiseLookupStatus.MATCHED,
                "retrieval_reason": "invalid match without classification",
            },
            {
                "ip_address": "8.8.8.8",
                "classification": GreyNoiseClassification.BENIGN,
                "mode": ThreatIntelMode.LIVE,
                "lookup_status": GreyNoiseLookupStatus.MATCHED,
                "retrieval_reason": "invalid match without dataset context",
            },
            {
                "ip_address": "192.168.1.50",
                "noise": True,
                "classification": GreyNoiseClassification.UNKNOWN,
                "mode": ThreatIntelMode.LIVE,
                "lookup_status": GreyNoiseLookupStatus.MATCHED,
                "retrieval_reason": "invalid private live authority",
            },
            {
                "ip_address": "2606:4700:4700::1111",
                "riot": True,
                "classification": GreyNoiseClassification.BENIGN,
                "mode": ThreatIntelMode.LIVE,
                "lookup_status": GreyNoiseLookupStatus.MATCHED,
                "retrieval_reason": "invalid IPv6 live authority",
            },
            {
                "ip_address": "8.8.8.8",
                "noise": True,
                "classification": GreyNoiseClassification.UNKNOWN,
                "mode": ThreatIntelMode.LIVE,
                "lookup_status": GreyNoiseLookupStatus.NOT_FOUND,
                "retrieval_reason": "invalid noisy not-found result",
            },
            {
                "ip_address": "8.8.8.8",
                "name": "Unverified Actor",
                "mode": ThreatIntelMode.LIVE,
                "lookup_status": GreyNoiseLookupStatus.NOT_FOUND,
                "retrieval_reason": "invalid attribution on not-found result",
            },
        ]

        for values in invalid_values:
            with self.subTest(reason=values["retrieval_reason"]):
                with self.assertRaises(ValidationError):
                    GreyNoiseResult(**values)

        malicious_noise = GreyNoiseResult(
            ip_address="8.8.8.8",
            noise=True,
            classification=GreyNoiseClassification.MALICIOUS,
            mode=ThreatIntelMode.LIVE,
            lookup_status=GreyNoiseLookupStatus.MATCHED,
            retrieval_reason="authoritative malicious classification",
        )
        quiet_unknown = GreyNoiseResult(
            ip_address="1.1.1.1",
            noise=False,
            riot=True,
            classification=GreyNoiseClassification.UNKNOWN,
            mode=ThreatIntelMode.LIVE,
            lookup_status=GreyNoiseLookupStatus.MATCHED,
            retrieval_reason="authoritative unknown classification",
        )

        self.assertFalse(malicious_noise.risk_reduction_eligible)
        self.assertFalse(quiet_unknown.risk_reduction_eligible)


if __name__ == "__main__":
    unittest.main()
