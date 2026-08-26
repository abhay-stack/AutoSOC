"""Asynchronous AbuseIPDB enrichment with strict no-call safety gates."""

from __future__ import annotations

from collections.abc import Mapping
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
from types import TracebackType
from typing import Any, Self

import httpx

from autosoc.config import clean_setting, load_setting
from autosoc.models import ThreatIntelMode, ThreatIntelResult

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
DEFAULT_MAX_AGE_DAYS = 90
DEFAULT_TIMEOUT_SECONDS = 5.0
_API_KEY_NAMES = ("ABUSEIPDB_API_KEY", "ABUSEIPDB_KEY")

IPAddress = IPv4Address | IPv6Address


def _is_global_unicast(address: IPAddress) -> bool:
    """Allow only publicly routable unicast addresses to leave the host."""

    return bool(
        address.is_global
        and not address.is_multicast
        and not address.is_unspecified
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_reserved
        and not address.is_private
    )


class AbuseIPDBClient:
    """Minimal async client that never queries non-global addresses."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        offline: bool = False,
        mock_score: int = 0,
        max_age_in_days: int = DEFAULT_MAX_AGE_DAYS,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if (
            isinstance(mock_score, bool)
            or not isinstance(mock_score, int)
            or not 0 <= mock_score <= 100
        ):
            raise ValueError("mock_score must be an integer between 0 and 100")
        if (
            isinstance(max_age_in_days, bool)
            or not isinstance(max_age_in_days, int)
            or not 1 <= max_age_in_days <= 365
        ):
            raise ValueError("max_age_in_days must be between 1 and 365")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be positive")

        self._api_key = clean_setting(api_key)
        self.offline = offline
        self.mock_score = mock_score
        self.max_age_in_days = max_age_in_days
        self.timeout_seconds = timeout_seconds
        self._transport = transport
        self._http_client: httpx.AsyncClient | None = None
        self._owns_http_client = False

    @classmethod
    def from_env(
        cls,
        *,
        env_file: str | Path = ".env",
        offline: bool = False,
        mock_score: int = 0,
        max_age_in_days: int = DEFAULT_MAX_AGE_DAYS,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> Self:
        """Create a client with environment variables overriding ``.env``."""

        return cls(
            api_key=load_setting(_API_KEY_NAMES, env_file=env_file),
            offline=offline,
            mock_score=mock_score,
            max_age_in_days=max_age_in_days,
            timeout_seconds=timeout_seconds,
            transport=transport,
        )

    async def __aenter__(self) -> Self:
        if not self.offline and self._api_key is not None:
            self._http_client = self._new_http_client()
            self._owns_http_client = True
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    def _new_http_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout_seconds),
            follow_redirects=False,
            trust_env=False,
            transport=self._transport,
        )

    async def aclose(self) -> None:
        if self._http_client is not None and self._owns_http_client:
            await self._http_client.aclose()
        self._http_client = None
        self._owns_http_client = False

    def _mock_result(
        self,
        address: IPAddress | None,
        *,
        reason: str,
        usage_type: str = "Mock/Unavailable",
    ) -> ThreatIntelResult:
        return ThreatIntelResult(
            ip_address=address,
            abuse_confidence_score=self.mock_score,
            country_code=None,
            usage_type=usage_type,
            mode=ThreatIntelMode.MOCK,
            retrieval_reason=reason,
            max_age_in_days=self.max_age_in_days,
        )

    async def check_ip(
        self,
        value: str | IPAddress | None,
    ) -> ThreatIntelResult:
        """Check one IP or immediately return a clearly labeled mock result."""

        if value is None:
            return self._mock_result(None, reason="source IP is missing")
        try:
            address = ip_address(str(value))
        except ValueError:
            return self._mock_result(None, reason="source IP is invalid")

        if self.offline:
            return self._mock_result(address, reason="offline mode was requested")
        if not _is_global_unicast(address):
            return self._mock_result(
                address,
                reason="non-global IP addresses are never sent to AbuseIPDB",
                usage_type="Private/Reserved",
            )
        if self._api_key is None:
            return self._mock_result(
                address,
                reason="AbuseIPDB API key is unavailable",
            )

        try:
            response = await self._request(address)
            response.raise_for_status()
            payload = response.json()
            return self._parse_live_response(address, payload)
        except (httpx.HTTPError, TypeError, ValueError, KeyError):
            return self._mock_result(
                address,
                reason="AbuseIPDB request or response validation failed",
            )

    async def _request(self, address: IPAddress) -> httpx.Response:
        if self._api_key is None:
            raise RuntimeError("API request attempted without a key")
        headers = {
            "Accept": "application/json",
            "Key": self._api_key,
        }
        params = {
            "ipAddress": str(address),
            "maxAgeInDays": self.max_age_in_days,
        }
        if self._http_client is not None:
            return await self._http_client.get(
                ABUSEIPDB_CHECK_URL,
                headers=headers,
                params=params,
            )

        async with self._new_http_client() as client:
            return await client.get(
                ABUSEIPDB_CHECK_URL,
                headers=headers,
                params=params,
            )

    def _parse_live_response(
        self,
        requested_address: IPAddress,
        payload: Any,
    ) -> ThreatIntelResult:
        if not isinstance(payload, Mapping):
            raise ValueError("response payload must be an object")
        data = payload.get("data")
        if not isinstance(data, Mapping):
            raise ValueError("response data must be an object")

        returned_ip = data.get("ipAddress")
        if (
            returned_ip is not None
            and ip_address(str(returned_ip)) != requested_address
        ):
            raise ValueError("response IP does not match the requested IP")

        score = data.get("abuseConfidenceScore")
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise ValueError("abuseConfidenceScore must be numeric")
        if int(score) != score or not 0 <= int(score) <= 100:
            raise ValueError("abuseConfidenceScore must be an integer from 0 to 100")

        country_code = data.get("countryCode")
        if country_code is not None and not isinstance(country_code, str):
            raise ValueError("countryCode must be a string or null")
        usage_type = data.get("usageType")
        if usage_type is not None and not isinstance(usage_type, str):
            raise ValueError("usageType must be a string or null")

        return ThreatIntelResult(
            ip_address=requested_address,
            abuse_confidence_score=int(score),
            country_code=country_code,
            usage_type=usage_type,
            mode=ThreatIntelMode.LIVE,
            retrieval_reason="live AbuseIPDB response",
            max_age_in_days=self.max_age_in_days,
        )


async def check_ip_reputation(
    ip_value: str | IPAddress | None,
    *,
    offline: bool = False,
    env_file: str | Path = ".env",
    mock_score: int = 0,
) -> ThreatIntelResult:
    """Convenience wrapper for one offline-safe AbuseIPDB lookup."""

    async with AbuseIPDBClient.from_env(
        env_file=env_file,
        offline=offline,
        mock_score=mock_score,
    ) as client:
        return await client.check_ip(ip_value)


__all__ = [
    "ABUSEIPDB_CHECK_URL",
    "AbuseIPDBClient",
    "DEFAULT_MAX_AGE_DAYS",
    "check_ip_reputation",
]
