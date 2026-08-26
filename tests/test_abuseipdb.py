"""Tests for AbuseIPDB safety gates and response extraction."""

from __future__ import annotations

import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import httpx
from pydantic import ValidationError

from autosoc.integrations.abuseipdb import AbuseIPDBClient
from autosoc.models import ThreatIntelMode, ThreatIntelResult


class AbuseIPDBClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_key_returns_mock_without_a_request(self) -> None:
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            raise AssertionError("network transport must not be called")

        with patch.dict(os.environ, {}, clear=True):
            client = AbuseIPDBClient.from_env(
                env_file="does-not-exist.env",
                transport=httpx.MockTransport(handler),
            )
            result = await client.check_ip("8.8.8.8")

        self.assertEqual(result.mode, ThreatIntelMode.MOCK)
        self.assertEqual(result.abuse_confidence_score, 0)
        self.assertIn("key", result.retrieval_reason)
        self.assertEqual(calls, 0)

    async def test_private_reserved_and_offline_inputs_never_call_api(self) -> None:
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            raise AssertionError("network transport must not be called")

        transport = httpx.MockTransport(handler)
        private_client = AbuseIPDBClient(
            api_key="secret",
            mock_score=87,
            transport=transport,
        )
        private = await private_client.check_ip("192.168.10.20")
        loopback = await private_client.check_ip("127.0.0.1")
        multicast = await private_client.check_ip("224.0.0.1")
        ipv6_multicast = await private_client.check_ip("ff02::1")
        offline_client = AbuseIPDBClient(
            api_key="secret",
            offline=True,
            transport=transport,
        )
        offline = await offline_client.check_ip("8.8.8.8")

        self.assertEqual(private.abuse_confidence_score, 87)
        self.assertEqual(private.usage_type, "Private/Reserved")
        self.assertEqual(loopback.mode, ThreatIntelMode.MOCK)
        self.assertEqual(multicast.mode, ThreatIntelMode.MOCK)
        self.assertEqual(ipv6_multicast.mode, ThreatIntelMode.MOCK)
        self.assertIn("offline", offline.retrieval_reason)
        self.assertEqual(calls, 0)

    async def test_live_response_fields_and_request_contract(self) -> None:
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            self.assertEqual(request.method, "GET")
            self.assertEqual(request.headers["Key"], "test-secret")
            self.assertEqual(request.headers["Accept"], "application/json")
            self.assertEqual(request.url.params["ipAddress"], "8.8.8.8")
            self.assertEqual(request.url.params["maxAgeInDays"], "90")
            self.assertNotIn("verbose", request.url.params)
            return httpx.Response(
                200,
                request=request,
                json={
                    "data": {
                        "ipAddress": "8.8.8.8",
                        "abuseConfidenceScore": 73,
                        "countryCode": "us",
                        "usageType": "Data Center/Web Hosting/Transit",
                    }
                },
            )

        client = AbuseIPDBClient(
            api_key="test-secret",
            transport=httpx.MockTransport(handler),
        )
        async with client:
            result = await client.check_ip("8.8.8.8")

        self.assertEqual(calls, 1)
        self.assertEqual(result.mode, ThreatIntelMode.LIVE)
        self.assertEqual(result.abuse_confidence_score, 73)
        self.assertEqual(result.country_code, "US")
        self.assertEqual(
            result.usage_type,
            "Data Center/Web Hosting/Transit",
        )

    async def test_invalid_or_mismatched_response_falls_back_to_mock(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                request=request,
                json={
                    "data": {
                        "ipAddress": "1.1.1.1",
                        "abuseConfidenceScore": 100,
                    }
                },
            )

        client = AbuseIPDBClient(
            api_key="secret",
            transport=httpx.MockTransport(handler),
        )
        result = await client.check_ip("8.8.8.8")

        self.assertEqual(result.mode, ThreatIntelMode.MOCK)
        self.assertIn("validation failed", result.retrieval_reason)

    async def test_dotenv_key_is_loaded_without_evaluation(self) -> None:
        observed_key: str | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal observed_key
            observed_key = request.headers["Key"]
            return httpx.Response(
                200,
                request=request,
                json={
                    "data": {
                        "ipAddress": "8.8.8.8",
                        "abuseConfidenceScore": 0,
                        "countryCode": None,
                        "usageType": None,
                    }
                },
            )

        with TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text(
                'ABUSEIPDB_API_KEY="dotenv-secret"\n'
                "IGNORED=$(should-not-run)\n",
                encoding="utf-8",
            )
            with patch.dict(os.environ, {}, clear=True):
                client = AbuseIPDBClient.from_env(
                    env_file=env_file,
                    transport=httpx.MockTransport(handler),
                )
                result = await client.check_ip("8.8.8.8")

        self.assertEqual(result.mode, ThreatIntelMode.LIVE)
        self.assertEqual(observed_key, "dotenv-secret")

    async def test_invalid_ip_is_mocked(self) -> None:
        client = AbuseIPDBClient(api_key="secret")
        result = await client.check_ip("not-an-ip")
        self.assertEqual(result.mode, ThreatIntelMode.MOCK)
        self.assertIsNone(result.ip_address)

    def test_live_result_requires_a_queried_ip(self) -> None:
        with self.assertRaises(ValidationError):
            ThreatIntelResult(
                ip_address=None,
                abuse_confidence_score=50,
                mode=ThreatIntelMode.LIVE,
                retrieval_reason="invalid live result",
                max_age_in_days=90,
            )


if __name__ == "__main__":
    unittest.main()
