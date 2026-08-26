"""Deterministic parsers for JSON and Apache/Nginx access-log records."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
import json
from math import isfinite
import re
import shlex
from typing import Any, Literal

from pydantic import ValidationError

from autosoc.models import EventType, SecurityEvent, utc_now

LogFormat = Literal["auto", "json", "apache", "nginx"]

_MISSING = object()
_COMBINED_LOG_PATTERN = re.compile(
    r"^(?P<remote_addr>\S+)\s+"
    r"(?P<ident>\S+)\s+"
    r"(?P<authenticated_user>\S+)\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<request>(?:\\.|[^"])*)"\s+'
    r"(?P<status>\d{3})\s+"
    r"(?P<body_bytes>\d+|-)"
    r'(?:\s+"(?P<referrer>(?:\\.|[^"])*)"'
    r'\s+"(?P<user_agent>(?:\\.|[^"])*)")?'
    r"(?P<extra>.*)$"
)
_TLS_VERSION_TOKEN = re.compile(
    r"^(?:SSL|TLS)[Vv]?\s*\d(?:[._]\d)?$",
    flags=re.IGNORECASE,
)


class LogParseError(ValueError):
    """Raised when a raw log record cannot be normalized safely."""


def _decode_raw(raw_log: str | bytes) -> str:
    if isinstance(raw_log, bytes):
        try:
            raw_log = raw_log.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise LogParseError("log bytes must be valid UTF-8") from exc
    if not isinstance(raw_log, str):
        raise TypeError("raw_log must be str or bytes")
    if not raw_log.strip():
        raise LogParseError("log record is empty")
    return raw_log.rstrip("\r\n")


def _reject_non_finite_json(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not supported: {value}")


def _load_json_object(raw_log: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw_log, parse_constant=_reject_non_finite_json)
    except (json.JSONDecodeError, ValueError) as exc:
        raise LogParseError(f"invalid JSON log record: {exc}") from exc
    if not isinstance(parsed, dict):
        raise LogParseError("JSON log record must be an object")
    _validate_json_values(parsed)
    return parsed


def _validate_json_values(value: Any) -> None:
    if isinstance(value, float) and not isfinite(value):
        raise LogParseError("JSON log record contains a non-finite number")
    if isinstance(value, list):
        for item in value:
            _validate_json_values(item)
    elif isinstance(value, dict):
        for item in value.values():
            _validate_json_values(item)


def _lookup(data: Mapping[str, Any], *paths: str) -> Any:
    """Return the first non-empty direct or dotted-path value."""

    for path in paths:
        value: Any = _MISSING
        if path in data:
            value = data[path]
        else:
            current: Any = data
            for part in path.split("."):
                if not isinstance(current, Mapping) or part not in current:
                    current = _MISSING
                    break
                current = current[part]
            value = current

        if value is not _MISSING and value not in (None, "", "-"):
            return value

    return None


def _optional_string(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        raise LogParseError(f"{field_name} must be a scalar value")
    text = str(value).strip()
    return text if text and text != "-" else None


def _optional_int(value: Any, field_name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise LogParseError(f"{field_name} must be an integer")
    if isinstance(value, float) and not value.is_integer():
        raise LogParseError(f"{field_name} must be an integer")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise LogParseError(f"{field_name} must be an integer") from exc


def _parse_timestamp(value: Any) -> tuple[datetime, list[str]]:
    warnings: list[str] = []
    if value is None:
        warnings.append("timestamp missing; ingestion time used as event time")
        return utc_now(), warnings

    if isinstance(value, bool):
        raise LogParseError("timestamp must not be a boolean")

    if isinstance(value, (int, float)):
        timestamp = float(value)
        if abs(timestamp) >= 100_000_000_000:
            timestamp /= 1000
            warnings.append("numeric timestamp interpreted as milliseconds")
        try:
            return datetime.fromtimestamp(timestamp, tz=timezone.utc), warnings
        except (OverflowError, OSError, ValueError) as exc:
            raise LogParseError(
                "numeric timestamp is outside the supported range"
            ) from exc

    if not isinstance(value, str):
        raise LogParseError("timestamp must be an ISO-8601 string or Unix epoch")

    text = value.strip()
    try:
        if re.fullmatch(r"-?\d+(?:\.\d+)?", text):
            return _parse_timestamp(float(text))
        if re.fullmatch(r"\d{1,2}/[A-Za-z]{3}/\d{4}:.*", text):
            parsed = datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z")
        else:
            iso_value = f"{text[:-1]}+00:00" if text.endswith(("Z", "z")) else text
            parsed = datetime.fromisoformat(iso_value)
    except ValueError as exc:
        raise LogParseError(f"unsupported timestamp format: {value!r}") from exc

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
        warnings.append("timezone missing; UTC assumed")
    return parsed.astimezone(timezone.utc), warnings


def _looks_like_tls_version(value: str | None) -> bool:
    return bool(value and _TLS_VERSION_TOKEN.fullmatch(value.strip()))


def _infer_event_type(
    requested_type: Any,
    *,
    http_method: str | None,
    request_path: str | None,
    tls_version: str | None,
    source_ip: str | None,
    destination_ip: str | None,
    protocol: str | None,
    warnings: list[str],
) -> EventType:
    if requested_type is not None:
        try:
            return EventType(str(requested_type).strip().lower())
        except ValueError:
            warnings.append(
                f"unknown event_type {requested_type!r}; event type was inferred"
            )

    if http_method is not None or request_path is not None:
        return EventType.WEB_ACCESS
    if tls_version is not None:
        return EventType.TLS_HANDSHAKE
    if source_ip is not None or destination_ip is not None or protocol is not None:
        return EventType.NETWORK_CONNECTION
    return EventType.GENERIC


def _create_event(**values: Any) -> SecurityEvent:
    try:
        return SecurityEvent(**values)
    except ValidationError as exc:
        raise LogParseError(f"normalized event failed validation: {exc}") from exc


def parse_json_log(
    raw_log: str | bytes,
    *,
    source: str = "json-input",
) -> SecurityEvent:
    """Parse one JSON object using common flat and ECS-style field aliases."""

    decoded_raw = _decode_raw(raw_log)
    data = _load_json_object(decoded_raw)

    timestamp, warnings = _parse_timestamp(
        _lookup(data, "timestamp", "@timestamp", "time", "datetime", "event.created")
    )
    source_ip = _optional_string(
        _lookup(
            data,
            "source_ip",
            "src_ip",
            "client_ip",
            "remote_addr",
            "source.ip",
        ),
        "source_ip",
    )
    destination_ip = _optional_string(
        _lookup(data, "destination_ip", "dst_ip", "server_ip", "destination.ip"),
        "destination_ip",
    )
    source_port = _optional_int(
        _lookup(data, "source_port", "src_port", "source.port"),
        "source_port",
    )
    destination_port = _optional_int(
        _lookup(data, "destination_port", "dst_port", "destination.port"),
        "destination_port",
    )
    http_method = _optional_string(
        _lookup(data, "http_method", "method", "request_method", "http.request.method"),
        "http_method",
    )
    request_path = _optional_string(
        _lookup(
            data,
            "request_path",
            "request_uri",
            "uri",
            "path",
            "url.original",
            "url.path",
            "http.request.target",
        ),
        "request_path",
    )
    http_status = _optional_int(
        _lookup(
            data,
            "http_status",
            "status",
            "status_code",
            "http.response.status_code",
        ),
        "http_status",
    )
    tls_version = _optional_string(
        _lookup(data, "tls_version", "ssl_protocol", "protocol_version", "tls.version"),
        "tls_version",
    )
    tls_cipher = _optional_string(
        _lookup(
            data,
            "tls_cipher",
            "cipher",
            "cipher_suite",
            "ssl_cipher",
            "tls.cipher",
        ),
        "tls_cipher",
    )
    protocol = _optional_string(
        _lookup(data, "network_protocol", "network.transport", "protocol"),
        "protocol",
    )
    if tls_version is None and _looks_like_tls_version(protocol):
        tls_version = protocol
        protocol = "TLS"

    request_body_value = _lookup(
        data,
        "request_body",
        "body",
        "http.request.body.content",
    )
    request_body: str | None = None
    if request_body_value is not None:
        if isinstance(request_body_value, str):
            request_body = request_body_value
        elif isinstance(request_body_value, (dict, list)):
            request_body = json.dumps(
                request_body_value,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        else:
            request_body = _optional_string(request_body_value, "request_body")

    query_string = _optional_string(
        _lookup(data, "query_string", "request_query", "url.query"),
        "query_string",
    )

    event_type = _infer_event_type(
        _lookup(data, "event_type", "event.type"),
        http_method=http_method,
        request_path=request_path,
        tls_version=tls_version,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        warnings=warnings,
    )
    attributes: dict[str, Any] = {
        "parser_format": "json",
        "original_fields": data,
    }
    if tls_cipher is not None:
        attributes["tls_cipher"] = tls_cipher
    if request_body is not None:
        attributes["request_body"] = request_body
    if query_string is not None:
        attributes["query_string"] = query_string
    if warnings:
        attributes["parser_warnings"] = warnings

    return _create_event(
        timestamp=timestamp,
        event_type=event_type,
        source=source,
        parser_name="json",
        raw_log=decoded_raw,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        http_method=http_method,
        request_path=request_path,
        http_status=http_status,
        tls_version=tls_version,
        attributes=attributes,
    )


def _unescape_log_value(value: str | None) -> str | None:
    if value in (None, "-"):
        return None
    return value.replace(r'\"', '"').replace(r"\\", "\\")


def _parse_tls_suffix(extra: str) -> tuple[str | None, str | None, list[str]]:
    if not extra.strip():
        return None, None, []
    try:
        tokens = shlex.split(extra, posix=True)
    except ValueError:
        return None, None, ["unable to parse trailing custom log fields"]

    tls_version: str | None = None
    tls_cipher: str | None = None
    positional: list[str] = []
    for token in tokens:
        if "=" not in token:
            positional.append(token)
            continue
        key, value = token.split("=", 1)
        key = key.lower().lstrip("$")
        if key in {"ssl_protocol", "tls_version", "protocol_version"}:
            tls_version = value
        elif key in {"ssl_cipher", "tls_cipher", "cipher", "cipher_suite"}:
            tls_cipher = value

    if tls_version is None and positional and _looks_like_tls_version(positional[0]):
        tls_version = positional[0]
        if len(positional) > 1:
            tls_cipher = positional[1]
    return tls_version, tls_cipher, []


def _parse_combined_log(
    raw_log: str | bytes,
    *,
    source: str,
    parser_name: Literal["apache_combined", "nginx_combined"],
) -> SecurityEvent:
    decoded_raw = _decode_raw(raw_log)
    match = _COMBINED_LOG_PATTERN.fullmatch(decoded_raw)
    if match is None:
        raise LogParseError(
            "record does not match the Apache/Nginx common or combined log format"
        )

    fields = match.groupdict()
    timestamp, warnings = _parse_timestamp(fields["timestamp"])
    request = _unescape_log_value(fields["request"])
    method: str | None = None
    request_path: str | None = None
    protocol: str | None = None
    if request is not None:
        request_parts = request.split(" ", maxsplit=2)
        if len(request_parts) != 3 or not all(request_parts):
            raise LogParseError(
                "HTTP request field must contain method, target, and version"
            )
        method, request_path, protocol = request_parts

    tls_version, tls_cipher, suffix_warnings = _parse_tls_suffix(fields["extra"])
    warnings.extend(suffix_warnings)
    event_type = EventType.WEB_ACCESS if request_path else EventType.NETWORK_CONNECTION
    attributes: dict[str, Any] = {
        "parser_format": "combined",
        "response_bytes": (
            None if fields["body_bytes"] == "-" else int(fields["body_bytes"])
        ),
    }
    optional_attributes = {
        "ident": fields["ident"],
        "authenticated_user": fields["authenticated_user"],
        "referrer": _unescape_log_value(fields["referrer"]),
        "user_agent": _unescape_log_value(fields["user_agent"]),
        "tls_cipher": tls_cipher,
    }
    attributes.update(
        {
            key: value
            for key, value in optional_attributes.items()
            if value not in (None, "-")
        }
    )
    if warnings:
        attributes["parser_warnings"] = warnings

    return _create_event(
        timestamp=timestamp,
        event_type=event_type,
        source=source,
        parser_name=parser_name,
        raw_log=decoded_raw,
        source_ip=fields["remote_addr"],
        protocol=protocol,
        http_method=method,
        request_path=request_path,
        http_status=int(fields["status"]),
        tls_version=tls_version,
        attributes=attributes,
    )


def parse_apache_log(
    raw_log: str | bytes,
    *,
    source: str = "apache-access.log",
) -> SecurityEvent:
    """Parse one Apache common or combined access-log record."""

    return _parse_combined_log(
        raw_log,
        source=source,
        parser_name="apache_combined",
    )


def parse_nginx_log(
    raw_log: str | bytes,
    *,
    source: str = "nginx-access.log",
) -> SecurityEvent:
    """Parse one Nginx common or combined access-log record."""

    return _parse_combined_log(
        raw_log,
        source=source,
        parser_name="nginx_combined",
    )


def parse_log(
    raw_log: str | bytes,
    *,
    log_format: LogFormat = "auto",
    source: str = "log-input",
) -> SecurityEvent:
    """Normalize one record using an explicit format or safe auto-detection."""

    if log_format == "json":
        return parse_json_log(raw_log, source=source)
    if log_format == "apache":
        return parse_apache_log(raw_log, source=source)
    if log_format == "nginx":
        return parse_nginx_log(raw_log, source=source)
    if log_format != "auto":
        raise ValueError(f"unsupported log format: {log_format}")

    decoded_raw = _decode_raw(raw_log)
    if decoded_raw.lstrip().startswith("{"):
        return parse_json_log(decoded_raw, source=source)
    return parse_apache_log(decoded_raw, source=source)


def parse_log_lines(
    lines: Iterable[str | bytes],
    *,
    log_format: LogFormat = "auto",
    source: str = "log-input",
) -> list[SecurityEvent]:
    """Parse non-empty records and annotate failures with a one-based line number."""

    events: list[SecurityEvent] = []
    for line_number, raw_log in enumerate(lines, start=1):
        if isinstance(raw_log, str) and not raw_log.strip():
            continue
        if isinstance(raw_log, bytes) and not raw_log.strip():
            continue
        try:
            events.append(
                parse_log(raw_log, log_format=log_format, source=source)
            )
        except (LogParseError, ValidationError) as exc:
            raise LogParseError(f"{source}:{line_number}: {exc}") from exc
    return events


__all__ = [
    "LogFormat",
    "LogParseError",
    "parse_apache_log",
    "parse_json_log",
    "parse_log",
    "parse_log_lines",
    "parse_nginx_log",
]
