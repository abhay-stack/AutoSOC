"""FastAPI interface for AutoSOC's deterministic and agent pipelines.

The API treats agent messages as auditable analyst summaries. It never exposes
private model reasoning and never executes a command from a generated playbook.
"""

from __future__ import annotations

import base64
import binascii
from collections import deque
from datetime import datetime
import json
from math import ceil
from pathlib import Path
import re
import secrets
from tempfile import TemporaryDirectory
from threading import Lock
from time import monotonic
from typing import Literal, NamedTuple, Self
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    ValidationError,
    field_validator,
    model_validator,
)
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile
from starlette.formparsers import FormParser, MultiPartException, MultiPartParser
from starlette.middleware.trustedhost import TrustedHostMiddleware

from autosoc.agents.graph import build_graph
from autosoc.cli import AnalysisError, analyze_file
from autosoc.config import load_setting
from autosoc.models import IncidentReport
from autosoc.parsers.log_parser import LogFormat
from autosoc.web.remediation import (
    NoRemediationTargetsError,
    RemediationError,
    TooManyRemediationTargetsError,
    generate_firewall_remediation,
)

MAX_LOG_BYTES = 2 * 1024 * 1024
MAX_APPROVAL_REQUEST_BYTES = 4 * 1024 * 1024
_MAX_REQUEST_OVERHEAD = 64 * 1024
_MAX_REQUEST_BYTES = MAX_LOG_BYTES + _MAX_REQUEST_OVERHEAD
_READ_CHUNK_BYTES = 64 * 1024
_ALLOWED_FORMATS: frozenset[str] = frozenset(
    {"auto", "json", "apache", "nginx"}
)
_ALLOWED_AGENT_ROLES: frozenset[str] = frozenset(
    {"triage", "intel", "response"}
)
_ALLOWED_GENERATION_MODES: frozenset[str] = frozenset(
    {"deterministic_fallback", "llm_selected_validated_facts"}
)
_LOCAL_ALLOWED_HOSTS: tuple[str, ...] = (
    "localhost",
    "127.0.0.1",
    "testserver",
)
_HOST_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST_PATTERN = re.compile(
    rf"^(?:\*\.)?{_HOST_LABEL}(?:\.{_HOST_LABEL})*$",
    re.IGNORECASE,
)


def _normalise_allowed_host(value: str) -> str:
    host = value.strip().casefold()
    if (
        not host
        or host == "*"
        or len(host) > 253
        or _HOST_PATTERN.fullmatch(host) is None
    ):
        raise RuntimeError(
            "AUTOSOC_ALLOWED_HOSTS and RENDER_EXTERNAL_HOSTNAME must contain "
            "hostnames only (no schemes, ports, paths, or unrestricted '*')."
        )
    return host


def _configured_allowed_hosts(
    *,
    render_hostname: str | None,
    configured_hosts: str | None,
) -> list[str]:
    """Build a fail-closed TrustedHost allowlist for local and hosted use."""

    candidates: list[str] = (
        [render_hostname] if render_hostname is not None else list(_LOCAL_ALLOWED_HOSTS)
    )
    if configured_hosts is not None:
        candidates.extend(
            item for item in configured_hosts.split(",") if item.strip()
        )

    allowed_hosts: list[str] = []
    for candidate in candidates:
        host = _normalise_allowed_host(candidate)
        if host not in allowed_hosts:
            allowed_hosts.append(host)
    return allowed_hosts


def _boolean_setting(value: str | None, *, name: str, default: bool) -> bool:
    if value is None:
        return default
    normalized = value.casefold()
    if normalized in {"true", "1", "yes", "on"}:
        return True
    if normalized in {"false", "0", "no", "off"}:
        return False
    raise RuntimeError(f"{name} must be a boolean value.")


def _integer_setting(
    value: str | None,
    *,
    name: str,
    default: int,
    maximum: int,
) -> int:
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError:
        raise RuntimeError(f"{name} must be an integer.") from None
    if not 0 <= parsed <= maximum:
        raise RuntimeError(f"{name} must be between 0 and {maximum}.")
    return parsed


class _GlobalRateLimiter:
    """Small per-process sliding-window guard for the portfolio deployment."""

    def __init__(self, requests_per_minute: int) -> None:
        self.requests_per_minute = requests_per_minute
        self._requests: deque[float] = deque()
        self._lock = Lock()

    def consume(self) -> int | None:
        """Record one request, or return seconds until a retry is allowed."""

        if self.requests_per_minute == 0:
            return None
        now = monotonic()
        cutoff = now - 60.0
        with self._lock:
            while self._requests and self._requests[0] <= cutoff:
                self._requests.popleft()
            if len(self._requests) >= self.requests_per_minute:
                return max(1, ceil(60.0 - (now - self._requests[0])))
            self._requests.append(now)
        return None


_ALLOWED_HOSTS = _configured_allowed_hosts(
    render_hostname=load_setting(("RENDER_EXTERNAL_HOSTNAME",)),
    configured_hosts=load_setting(("AUTOSOC_ALLOWED_HOSTS",)),
)
_ENABLE_LIVE_PROVIDERS = _boolean_setting(
    load_setting(("AUTOSOC_ENABLE_LIVE_PROVIDERS",)),
    name="AUTOSOC_ENABLE_LIVE_PROVIDERS",
    default=False,
)
_WEB_USERNAME = load_setting(("AUTOSOC_WEB_USERNAME",)) or "autosoc"
_WEB_PASSWORD = load_setting(("AUTOSOC_WEB_PASSWORD",))
_RATE_LIMIT_PER_MINUTE = _integer_setting(
    load_setting(("AUTOSOC_RATE_LIMIT_PER_MINUTE",)),
    name="AUTOSOC_RATE_LIMIT_PER_MINUTE",
    default=0,
    maximum=600,
)
if ":" in _WEB_USERNAME or len(_WEB_USERNAME) > 128:
    raise RuntimeError(
        "AUTOSOC_WEB_USERNAME must be at most 128 characters and omit ':'."
    )
if _WEB_PASSWORD is not None and len(_WEB_PASSWORD) < 16:
    raise RuntimeError("AUTOSOC_WEB_PASSWORD must contain at least 16 characters.")
if _ENABLE_LIVE_PROVIDERS and _WEB_PASSWORD is None:
    raise RuntimeError(
        "AUTOSOC_ENABLE_LIVE_PROVIDERS requires AUTOSOC_WEB_PASSWORD so "
        "paid provider calls are not exposed anonymously."
    )
_RATE_LIMITER = _GlobalRateLimiter(_RATE_LIMIT_PER_MINUTE)

_WEB_DIRECTORY = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(_WEB_DIRECTORY / "templates"))

app = FastAPI(
    title="AutoSOC Dashboard",
    summary="Deterministic-first SOC analysis and approval-gated orchestration",
    description=(
        "Analyze local log text, enrich deterministic findings, and generate a "
        "containment playbook. Playbooks are recommendations only and are never "
        "executed by this service."
    ),
    version="0.1.0",
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=_ALLOWED_HOSTS,
)

_CONTENT_SECURITY_POLICY = "; ".join(
    [
        "default-src 'self'",
        (
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com "
            "https://cdn.jsdelivr.net"
        ),
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
        "img-src 'self' data: https://fastapi.tiangolo.com",
        "connect-src 'self'",
        "font-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ]
)


def _same_origin(request: Request, origin: str) -> bool:
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return False
    host = request.headers.get("host", "").casefold()
    return (
        parsed.scheme in {"http", "https"}
        and parsed.netloc.casefold() == host
        and parsed.path in {"", "/"}
        and not parsed.query
        and not parsed.fragment
    )


def _has_valid_basic_auth(request: Request) -> bool:
    if _WEB_PASSWORD is None:
        return True
    scheme, separator, credentials = request.headers.get(
        "authorization",
        "",
    ).partition(" ")
    if not separator or scheme.casefold() != "basic":
        return False
    try:
        decoded = base64.b64decode(credentials, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return False
    username, separator, password = decoded.partition(":")
    if not separator:
        return False
    return secrets.compare_digest(
        username.encode("utf-8"),
        _WEB_USERNAME.encode("utf-8"),
    ) and secrets.compare_digest(
        password.encode("utf-8"),
        _WEB_PASSWORD.encode("utf-8"),
    )


@app.middleware("http")
async def dashboard_security_boundary(
    request: Request,
    call_next,
) -> Response:
    """Authenticate, bound public use, and attach dashboard security headers."""

    is_health_check = request.url.path == "/healthz"
    is_rate_limited_api = (
        request.url.path
        in {"/api/orchestrate", "/api/execute-playbook"}
        and request.method == "POST"
    )
    if not is_health_check and not _has_valid_basic_auth(request):
        response: Response = JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Dashboard authentication is required."},
            headers={
                "WWW-Authenticate": 'Basic realm="AutoSOC", charset="UTF-8"'
            },
        )
    elif request.url.path.startswith("/api/") and request.method not in {
        "GET",
        "HEAD",
        "OPTIONS",
    }:
        fetch_site = request.headers.get("sec-fetch-site", "").casefold()
        origin = request.headers.get("origin")
        if fetch_site == "cross-site" or (
            origin is not None and not _same_origin(request, origin)
        ):
            response: Response = JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Cross-origin API requests are not allowed."},
            )
        elif is_rate_limited_api and (
            retry_after := _RATE_LIMITER.consume()
        ) is not None:
            response = JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Dashboard request limit reached; retry later."
                },
                headers={"Retry-After": str(retry_after)},
            )
        else:
            response = await call_next(request)
    else:
        response = await call_next(request)

    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("Content-Security-Policy", _CONTENT_SECURITY_POLICY)
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(), geolocation=(), microphone=()",
    )
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Robots-Tag", "noindex, nofollow")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    if is_rate_limited_api and _RATE_LIMIT_PER_MINUTE:
        response.headers.setdefault(
            "X-RateLimit-Limit",
            str(_RATE_LIMIT_PER_MINUTE),
        )
    return response


class AgentThreadEntry(BaseModel):
    """One grounded agent summary safe to display to an analyst."""

    model_config = ConfigDict(extra="forbid")

    agent: Literal["triage", "intel", "response"]
    content: str = Field(min_length=1)
    generation_mode: Literal[
        "deterministic_fallback",
        "llm_selected_validated_facts",
    ]
    message_id: str | None = None


class OrchestrationResponse(BaseModel):
    """Validated response returned by the dashboard orchestration endpoint."""

    model_config = ConfigDict(extra="forbid")

    incident_report: IncidentReport
    agent_thread: list[AgentThreadEntry]
    playbook: str = Field(min_length=1)


class PlaybookApprovalRequest(BaseModel):
    """Bounded, explicit human approval tied to one validated incident report."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    incident_report: IncidentReport
    report_id: UUID
    approval_confirmed: Literal[True]
    approved_by: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._@+:-]{0,127}$",
    )
    approval_reason: str | None = Field(default=None, min_length=1, max_length=500)

    @field_validator("approval_confirmed", mode="before")
    @classmethod
    def require_literal_boolean_approval(cls, value: object) -> object:
        if value is not True:
            raise ValueError("approval_confirmed must be the boolean true")
        return value

    @field_validator("approval_reason")
    @classmethod
    def reject_control_characters(cls, value: str | None) -> str | None:
        if value is not None and any(ord(character) < 32 for character in value):
            raise ValueError("approval_reason must be a single line")
        if value is not None and "\x7f" in value:
            raise ValueError("approval_reason contains a control character")
        return value

    @model_validator(mode="after")
    def validate_report_binding(self) -> Self:
        if self.report_id != self.incident_report.report_id:
            raise ValueError("report_id must match incident_report.report_id")
        return self


class RemediationArtifactReceipt(BaseModel):
    """Integrity and safety properties of the generated local artifact."""

    model_config = ConfigDict(extra="forbid")

    path: Literal["remediation/firewall_remediation.sh"]
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size_bytes: int = Field(gt=0, le=64 * 1024)
    file_mode: Literal["0600"] = "0600"
    command_lines_inert: Literal[True] = True
    replaced_existing: bool


class PlaybookExecutionResponse(BaseModel):
    """Auditable receipt proving generation without host command execution."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["artifact_generated"] = "artifact_generated"
    executed: Literal[False] = False
    report_id: UUID
    receipt_id: UUID
    approved_by: str
    approval_reason: str | None = None
    approved_at: datetime
    targets: list[IPvAnyAddress] = Field(min_length=1, max_length=50)
    artifact: RemediationArtifactReceipt
    safety_notice: Literal[
        "No firewall command was executed; the generated artifact is an inert, "
        "comment-only preview."
    ] = (
        "No firewall command was executed; the generated artifact is an inert, "
        "comment-only preview."
    )


class _RequestInput(NamedTuple):
    raw_log: str
    log_format: LogFormat
    offline: bool


def _http_error(status_code: int, detail: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail=detail)


def _validate_content_length(request: Request, *, limit: int) -> None:
    value = request.headers.get("content-length")
    if value is None:
        return
    try:
        content_length = int(value)
    except ValueError:
        raise _http_error(
            status.HTTP_400_BAD_REQUEST,
            "Content-Length must be a valid non-negative integer.",
        ) from None
    if content_length < 0:
        raise _http_error(
            status.HTTP_400_BAD_REQUEST,
            "Content-Length must be a valid non-negative integer.",
        )
    if content_length > limit:
        raise _http_error(
            status.HTTP_413_CONTENT_TOO_LARGE,
            f"Log input must not exceed {MAX_LOG_BYTES} bytes.",
        )


async def _read_request_body(request: Request, *, limit: int) -> bytes:
    _validate_content_length(request, limit=limit)
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise _http_error(
                status.HTTP_413_CONTENT_TOO_LARGE,
                f"Log input must not exceed {MAX_LOG_BYTES} bytes.",
            )
    return bytes(body)


def _decode_utf8(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        raise _http_error(
            status.HTTP_400_BAD_REQUEST,
            "Log input must be valid UTF-8.",
        ) from None


def _validate_raw_log(value: object) -> str:
    if not isinstance(value, str):
        raise _http_error(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "raw_log must be a string.",
        )
    if not value.strip():
        raise _http_error(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "Supply a non-empty raw_log value or one uploaded file.",
        )
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise _http_error(
            status.HTTP_400_BAD_REQUEST,
            "Log input must be valid UTF-8.",
        ) from None
    if len(encoded) > MAX_LOG_BYTES:
        raise _http_error(
            status.HTTP_413_CONTENT_TOO_LARGE,
            f"Log input must not exceed {MAX_LOG_BYTES} bytes.",
        )
    return value


def _parse_log_format(value: object) -> LogFormat:
    if not isinstance(value, str):
        raise _http_error(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "log_format must be one of: auto, json, apache, nginx.",
        )
    normalized = value.strip().lower()
    if normalized not in _ALLOWED_FORMATS:
        raise _http_error(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "log_format must be one of: auto, json, apache, nginx.",
        )
    return normalized  # type: ignore[return-value]


def _parse_offline(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off"}:
            return False
    raise _http_error(
        status.HTTP_422_UNPROCESSABLE_CONTENT,
        "offline must be a boolean.",
    )


async def _read_upload(upload: UploadFile) -> str:
    content = bytearray()
    while chunk := await upload.read(_READ_CHUNK_BYTES):
        content.extend(chunk)
        if len(content) > MAX_LOG_BYTES:
            raise _http_error(
                status.HTTP_413_CONTENT_TOO_LARGE,
                f"Log input must not exceed {MAX_LOG_BYTES} bytes.",
            )
    return _validate_raw_log(_decode_utf8(bytes(content)))


async def _extract_json_input(request: Request) -> _RequestInput:
    body = await _read_request_body(request, limit=_MAX_REQUEST_BYTES)
    try:
        payload = json.loads(_decode_utf8(body))
    except json.JSONDecodeError:
        raise _http_error(
            status.HTTP_400_BAD_REQUEST,
            "Request body must contain a valid JSON object.",
        ) from None
    if not isinstance(payload, dict):
        raise _http_error(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "Request body must be a JSON object.",
        )

    unexpected = set(payload) - {"raw_log", "offline", "log_format"}
    if unexpected:
        raise _http_error(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "JSON request contains unsupported fields.",
        )
    return _RequestInput(
        raw_log=_validate_raw_log(payload.get("raw_log")),
        log_format=_parse_log_format(payload.get("log_format", "auto")),
        offline=_parse_offline(payload.get("offline", True)),
    )


async def _extract_form_input(request: Request) -> _RequestInput:
    body = await _read_request_body(request, limit=_MAX_REQUEST_BYTES)

    async def body_stream():
        yield body

    media_type = request.headers.get("content-type", "").partition(";")[0]
    try:
        if media_type.strip().lower() == "multipart/form-data":
            parser = MultiPartParser(
                request.headers,
                body_stream(),
                max_files=1,
                max_fields=4,
                max_part_size=MAX_LOG_BYTES,
            )
        else:
            parser = FormParser(
                request.headers,
                body_stream(),
                max_fields=4,
                max_part_size=MAX_LOG_BYTES,
            )
        form = await parser.parse()
    except MultiPartException as exc:
        message = str(exc).lower()
        status_code = (
            status.HTTP_413_CONTENT_TOO_LARGE
            if "maximum size" in message or "too large" in message
            else status.HTTP_422_UNPROCESSABLE_CONTENT
        )
        raise _http_error(status_code, "Invalid or oversized form data.") from None
    try:
        raw_values = form.getlist("raw_log")
        file_values = form.getlist("file")
        if len(raw_values) > 1 or len(file_values) > 1:
            raise _http_error(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "Supply exactly one raw_log value or one uploaded file.",
            )

        raw_value = raw_values[0] if raw_values else None
        upload_value = file_values[0] if file_values else None
        has_raw_log = isinstance(raw_value, str) and bool(raw_value.strip())
        has_upload = isinstance(upload_value, UploadFile)
        if has_raw_log == has_upload:
            raise _http_error(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "Supply exactly one non-empty raw_log value or one uploaded file.",
            )
        if raw_value is not None and not isinstance(raw_value, str):
            raise _http_error(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "raw_log must be a text field.",
            )
        if upload_value is not None and not isinstance(upload_value, UploadFile):
            raise _http_error(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "file must be a file upload.",
            )

        raw_log = (
            await _read_upload(upload_value)
            if isinstance(upload_value, UploadFile)
            else _validate_raw_log(raw_value)
        )
        return _RequestInput(
            raw_log=raw_log,
            log_format=_parse_log_format(form.get("log_format", "auto")),
            offline=_parse_offline(form.get("offline", "true")),
        )
    finally:
        await form.close()


async def _extract_text_input(request: Request) -> _RequestInput:
    body = await _read_request_body(request, limit=MAX_LOG_BYTES)
    return _RequestInput(
        raw_log=_validate_raw_log(_decode_utf8(body)),
        log_format=_parse_log_format(
            request.query_params.get("log_format", "auto")
        ),
        offline=_parse_offline(request.query_params.get("offline", "true")),
    )


async def _extract_request_input(request: Request) -> _RequestInput:
    media_type = request.headers.get("content-type", "").partition(";")[0]
    media_type = media_type.strip().lower()
    if media_type == "application/json":
        return await _extract_json_input(request)
    if media_type in {
        "multipart/form-data",
        "application/x-www-form-urlencoded",
    }:
        return await _extract_form_input(request)
    if media_type == "text/plain":
        return await _extract_text_input(request)
    raise _http_error(
        status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
        (
            "Use application/json, multipart/form-data, "
            "application/x-www-form-urlencoded, or text/plain."
        ),
    )


async def _extract_approval_request(request: Request) -> PlaybookApprovalRequest:
    media_type = request.headers.get("content-type", "").partition(";")[0]
    if media_type.strip().lower() != "application/json":
        raise _http_error(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            "Playbook approval requests must use application/json.",
        )

    value = request.headers.get("content-length")
    if value is not None:
        try:
            content_length = int(value)
        except ValueError:
            raise _http_error(
                status.HTTP_400_BAD_REQUEST,
                "Content-Length must be a valid non-negative integer.",
            ) from None
        if content_length < 0:
            raise _http_error(
                status.HTTP_400_BAD_REQUEST,
                "Content-Length must be a valid non-negative integer.",
            )
        if content_length > MAX_APPROVAL_REQUEST_BYTES:
            raise _http_error(
                status.HTTP_413_CONTENT_TOO_LARGE,
                "Playbook approval request is too large.",
            )

    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_APPROVAL_REQUEST_BYTES:
            raise _http_error(
                status.HTTP_413_CONTENT_TOO_LARGE,
                "Playbook approval request is too large.",
            )
    try:
        payload = json.loads(_decode_utf8(bytes(body)))
    except json.JSONDecodeError:
        raise _http_error(
            status.HTTP_400_BAD_REQUEST,
            "Request body must contain a valid JSON object.",
        ) from None
    if not isinstance(payload, dict):
        raise _http_error(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "Request body must be a JSON object.",
        )
    try:
        return PlaybookApprovalRequest.model_validate(payload)
    except ValidationError:
        raise _http_error(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "Playbook approval request failed validation.",
        ) from None


def _sanitise_web_report(report: IncidentReport) -> IncidentReport:
    """Remove ephemeral server paths before a report crosses the API boundary."""

    values = report.model_dump()
    values["title"] = "AutoSOC analysis: web input"
    for event in values["events"]:
        event["source"] = "web-api-input"
    metadata = dict(values.get("metadata", {}))
    metadata["input_file"] = "web-api-input"
    metadata["input_origin"] = "web_api"
    values["metadata"] = metadata
    return IncidentReport.model_validate(values)


def _message_content(message: object) -> str:
    content = getattr(message, "content", "")
    if isinstance(content, str):
        return content.strip()
    if not isinstance(content, list):
        return ""

    parts: list[str] = []
    for block in content:
        if isinstance(block, str):
            parts.append(block)
        elif isinstance(block, dict) and isinstance(block.get("text"), str):
            parts.append(block["text"])
    return "".join(parts).strip()


def _agent_thread(messages: object) -> list[AgentThreadEntry]:
    if not isinstance(messages, list):
        raise RuntimeError("agent graph returned an invalid message thread")

    thread: list[AgentThreadEntry] = []
    for message in messages:
        metadata = getattr(message, "additional_kwargs", {})
        if not isinstance(metadata, dict):
            continue
        role = metadata.get("autosoc_role")
        generation_mode = metadata.get("generation_mode")
        if role not in _ALLOWED_AGENT_ROLES:
            continue
        if generation_mode not in _ALLOWED_GENERATION_MODES:
            continue
        content = _message_content(message)
        if not content:
            continue
        message_id = getattr(message, "id", None)
        thread.append(
            AgentThreadEntry(
                agent=role,
                content=content,
                generation_mode=generation_mode,
                message_id=str(message_id) if message_id is not None else None,
            )
        )
    if [entry.agent for entry in thread] != ["triage", "intel", "response"]:
        raise RuntimeError("agent graph did not return the expected role sequence")
    return thread


async def _run_pipeline(request_input: _RequestInput) -> OrchestrationResponse:
    with TemporaryDirectory(prefix="autosoc-web-") as directory:
        input_path = Path(directory) / "web-input.log"
        input_path.write_text(request_input.raw_log, encoding="utf-8")
        report = await analyze_file(
            input_path,
            log_format=request_input.log_format,
            offline=request_input.offline,
        )
    report = _sanitise_web_report(report)

    graph = (
        build_graph(llm=None)
        if request_input.offline
        else build_graph()
    )
    initial_state = {
        "incident_report": report,
        "playbook": "",
        "messages": [],
    }
    result = await run_in_threadpool(graph.invoke, initial_state)
    if not isinstance(result, dict):
        raise RuntimeError("agent graph returned an invalid state")

    final_report = IncidentReport.model_validate(
        result.get("incident_report", report)
    )
    playbook = result.get("playbook")
    if not isinstance(playbook, str) or not playbook.strip():
        raise RuntimeError("agent graph completed without a playbook")
    return OrchestrationResponse(
        incident_report=final_report,
        agent_thread=_agent_thread(result.get("messages")),
        playbook=playbook,
    )


@app.get("/healthz", include_in_schema=False)
async def healthz() -> dict[str, str]:
    """Report process readiness without calling external providers."""

    return {"status": "ok", "service": "autosoc"}


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard(request: Request) -> HTMLResponse:
    """Render the single-page analyst dashboard."""

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"live_providers_allowed": _ENABLE_LIVE_PROVIDERS},
    )


@app.post(
    "/api/orchestrate",
    response_model=OrchestrationResponse,
    response_model_exclude_none=True,
    summary="Analyze logs and build an approval-gated playbook",
)
async def orchestrate_logs(request: Request) -> OrchestrationResponse:
    """Run deterministic analysis followed by the grounded agent workflow."""

    try:
        request_input = await _extract_request_input(request)
        if not request_input.offline and not _ENABLE_LIVE_PROVIDERS:
            raise _http_error(
                status.HTTP_403_FORBIDDEN,
                (
                    "Live provider access is disabled by server policy; "
                    "retry with offline=true."
                ),
            )
        return await _run_pipeline(request_input)
    except HTTPException:
        raise
    except AnalysisError:
        raise _http_error(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "Log input is malformed or does not match log_format.",
        ) from None
    except Exception:
        # Never disclose provider errors, temporary paths, or internal state.
        raise _http_error(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            (
                "Orchestration failed safely; no containment action was "
                "executed."
            ),
        ) from None


@app.post(
    "/api/execute-playbook",
    response_model=PlaybookExecutionResponse,
    response_model_exclude_none=True,
    status_code=status.HTTP_201_CREATED,
    summary="Generate an approved, inert firewall remediation artifact",
)
async def execute_playbook(request: Request) -> PlaybookExecutionResponse:
    """Generate a comment-only script; never execute containment commands."""

    try:
        approval = await _extract_approval_request(request)
        generated = await run_in_threadpool(
            generate_firewall_remediation,
            approval.incident_report,
            approved_by=approval.approved_by,
        )
        return PlaybookExecutionResponse(
            report_id=generated.report_id,
            receipt_id=generated.receipt_id,
            approved_by=generated.approved_by,
            approval_reason=approval.approval_reason,
            approved_at=generated.approved_at,
            targets=list(generated.targets),
            artifact=RemediationArtifactReceipt(
                path=generated.artifact_path,
                sha256=generated.artifact_sha256,
                size_bytes=generated.artifact_size_bytes,
                replaced_existing=generated.replaced_existing,
            ),
        )
    except HTTPException:
        raise
    except NoRemediationTargetsError:
        raise _http_error(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            (
                "No eligible firewall target is backed by a deterministic "
                "SQL-injection finding."
            ),
        ) from None
    except TooManyRemediationTargetsError:
        raise _http_error(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "The incident exceeds the firewall target approval limit.",
        ) from None
    except RemediationError:
        raise _http_error(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            (
                "Remediation generation failed safely; no containment action "
                "was executed."
            ),
        ) from None
    except Exception:
        raise _http_error(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            (
                "Remediation generation failed safely; no containment action "
                "was executed."
            ),
        ) from None


__all__ = [
    "AgentThreadEntry",
    "MAX_APPROVAL_REQUEST_BYTES",
    "MAX_LOG_BYTES",
    "OrchestrationResponse",
    "PlaybookApprovalRequest",
    "PlaybookExecutionResponse",
    "RemediationArtifactReceipt",
    "app",
]
