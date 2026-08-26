"""Async GreyNoise Community enrichment with neutral offline fallbacks."""

from __future__ import annotations

from collections.abc import Mapping
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
from types import TracebackType
from typing import Any, Self, TypeGuard

import httpx

from autosoc.config import clean_setting, load_setting
from autosoc.models import (
    GreyNoiseClassification,
    GreyNoiseLookupStatus,
    GreyNoiseResult,
    ThreatIntelMode,
)

GREYNOISE_COMMUNITY_URL = "https://api.greynoise.io/v3/community"
DEFAULT_TIMEOUT_SECONDS = 5.0
_API_KEY_NAMES = ("GREYNOISE_API_KEY",)

IPAddress = IPv4Address | IPv6Address


def _is_global_ipv4(address: IPAddress) -> TypeGuard[IPv4Address]:
    """Allow only publicly routable IPv4 addresses to leave the host."""

    return bool(
        isinstance(address, IPv4Address)
        and address.is_global
        and not address.is_multicast
        and not address.is_unspecified
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_reserved
        and not address.is_private
    )


class GreyNoiseClient:
    """Minimal Community API client with explicit no-call safety gates."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        offline: bool = False,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be positive")

        self._api_key = clean_setting(api_key)
        self.offline = offline
        self.timeout_seconds = float(timeout_seconds)
        self._transport = transport
        self._http_client: httpx.AsyncClient | None = None
        self._owns_http_client = False

    @classmethod
    def from_env(
        cls,
        *,
        env_file: str | Path = ".env",
        offline: bool = False,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> Self:
        """Create a client with process environment overriding ``.env``."""

        return cls(
            api_key=load_setting(_API_KEY_NAMES, env_file=env_file),
            offline=offline,
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

    @staticmethod
    def _mock_result(
        address: IPAddress | None,
        *,
        status: GreyNoiseLookupStatus,
        reason: str,
    ) -> GreyNoiseResult:
        return GreyNoiseResult(
            ip_address=address,
            noise=False,
            riot=False,
            classification=None,
            mode=ThreatIntelMode.MOCK,
            lookup_status=status,
            retrieval_reason=reason,
        )

    async def check_ip(
        self,
        value: str | IPAddress | None,
    ) -> GreyNoiseResult:
        """Check one IPv4 address or return a neutral, labeled fallback."""

        if value is None:
            return self._mock_result(
                None,
                status=GreyNoiseLookupStatus.INVALID,
                reason="source IP is missing",
            )
        try:
            address = ip_address(str(value))
        except ValueError:
            return self._mock_result(
                None,
                status=GreyNoiseLookupStatus.INVALID,
                reason="source IP is invalid",
            )

        if self.offline:
            return self._mock_result(
                address,
                status=GreyNoiseLookupStatus.OFFLINE,
                reason="offline mode was requested",
            )
        if not _is_global_ipv4(address):
            return self._mock_result(
                address,
                status=GreyNoiseLookupStatus.NON_GLOBAL,
                reason=(
                    "only globally routable IPv4 addresses may be sent to "
                    "GreyNoise Community"
                ),
            )
        if self._api_key is None:
            return self._mock_result(
                address,
                status=GreyNoiseLookupStatus.MISSING_KEY,
                reason="GreyNoise API key is unavailable",
            )

        try:
            response = await self._request(address)
            if response.status_code not in {200, 404}:
                response.raise_for_status()
            payload = response.json()
            return self._parse_live_response(
                address,
                payload,
                status_code=response.status_code,
            )
        except (httpx.HTTPError, TypeError, ValueError, KeyError):
            return self._mock_result(
                address,
                status=GreyNoiseLookupStatus.PROVIDER_ERROR,
                reason="GreyNoise request or response validation failed",
            )

    async def _request(self, address: IPv4Address) -> httpx.Response:
        if self._api_key is None:
            raise RuntimeError("API request attempted without a key")
        headers = {
            "Accept": "application/json",
            "key": self._api_key,
        }
        url = f"{GREYNOISE_COMMUNITY_URL}/{address}"
        if self._http_client is not None:
            return await self._http_client.get(url, headers=headers)

        async with self._new_http_client() as client:
            return await client.get(url, headers=headers)

    @staticmethod
    def _parse_live_response(
        requested_address: IPv4Address,
        payload: Any,
        *,
        status_code: int,
    ) -> GreyNoiseResult:
        if not isinstance(payload, Mapping):
            raise ValueError("response payload must be an object")

        returned_ip = payload.get("ip")
        if returned_ip is None or ip_address(str(returned_ip)) != requested_address:
            raise ValueError("response IP does not match the requested IP")
        noise = payload.get("noise")
        riot = payload.get("riot")
        if not isinstance(noise, bool) or not isinstance(riot, bool):
            raise ValueError("noise and riot must be booleans")

        raw_classification = payload.get("classification")
        if raw_classification is None:
            classification = None
        elif isinstance(raw_classification, str):
            classification = GreyNoiseClassification(raw_classification.casefold())
        else:
            raise ValueError("classification must be a string or null")

        optional_strings: dict[str, str | None] = {}
        for field in ("name", "link", "message"):
            field_value = payload.get(field)
            if field_value is not None and not isinstance(field_value, str):
                raise ValueError(f"{field} must be a string or null")
            optional_strings[field] = field_value

        last_seen = payload.get("last_seen")
        if last_seen is not None and not isinstance(last_seen, str):
            raise ValueError("last_seen must be a date string or null")

        if status_code == 404:
            if noise or riot or classification is not None:
                raise ValueError("not-found response must be neutral")
            lookup_status = GreyNoiseLookupStatus.NOT_FOUND
            retrieval_reason = "live GreyNoise response: IP not found"
        elif status_code == 200:
            if classification is None:
                raise ValueError("matched response requires a classification")
            lookup_status = GreyNoiseLookupStatus.MATCHED
            retrieval_reason = "live GreyNoise Community response"
        else:
            raise ValueError("unsupported GreyNoise response status")

        return GreyNoiseResult(
            ip_address=requested_address,
            noise=noise,
            riot=riot,
            classification=classification,
            name=optional_strings["name"],
            link=optional_strings["link"],
            last_seen=last_seen,
            message=optional_strings["message"],
            mode=ThreatIntelMode.LIVE,
            lookup_status=lookup_status,
            retrieval_reason=retrieval_reason,
        )


async def check_greynoise(
    ip_value: str | IPAddress | None,
    *,
    offline: bool = False,
    env_file: str | Path = ".env",
) -> GreyNoiseResult:
    """Convenience wrapper for one offline-safe Community lookup."""

    async with GreyNoiseClient.from_env(
        env_file=env_file,
        offline=offline,
    ) as client:
        return await client.check_ip(ip_value)


__all__ = [
    "GREYNOISE_COMMUNITY_URL",
    "GreyNoiseClient",
    "check_greynoise",
]
