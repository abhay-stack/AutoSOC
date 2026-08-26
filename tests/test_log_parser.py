"""Tests for deterministic log normalization."""

from __future__ import annotations

from datetime import timezone
import json
import unittest

from autosoc.models import EventType
from autosoc.parsers.log_parser import (
    LogParseError,
    parse_apache_log,
    parse_json_log,
    parse_log,
    parse_log_lines,
    parse_nginx_log,
)


class LogParserTests(unittest.TestCase):
    def test_json_parser_normalizes_flat_and_ecs_aliases(self) -> None:
        raw_log = json.dumps(
            {
                "@timestamp": "2026-08-26T12:15:30+05:30",
                "source": {"ip": "198.51.100.10", "port": 43120},
                "destination": {"ip": "203.0.113.20", "port": 443},
                "http": {
                    "request": {"method": "get"},
                    "response": {"status_code": 403},
                },
                "url": {"original": "/search?q=test"},
                "tls": {
                    "version": "TLSv1.2",
                    "cipher": "TLS_AES_128_GCM_SHA256",
                },
            }
        )

        event = parse_json_log(raw_log, source="ecs.jsonl")

        self.assertEqual(event.event_type, EventType.WEB_ACCESS)
        self.assertEqual(str(event.source_ip), "198.51.100.10")
        self.assertEqual(str(event.destination_ip), "203.0.113.20")
        self.assertEqual(event.source_port, 43120)
        self.assertEqual(event.destination_port, 443)
        self.assertEqual(event.http_method, "GET")
        self.assertEqual(event.request_path, "/search?q=test")
        self.assertEqual(event.http_status, 403)
        self.assertEqual(event.tls_version, "TLSv1.2")
        self.assertEqual(event.attributes["tls_cipher"], "TLS_AES_128_GCM_SHA256")
        self.assertEqual(event.timestamp.tzinfo, timezone.utc)
        self.assertEqual(event.timestamp.hour, 6)
        self.assertEqual(event.timestamp.minute, 45)

    def test_json_parser_preserves_standalone_query_string(self) -> None:
        raw_log = json.dumps(
            {
                "timestamp": "2026-08-26T12:15:30Z",
                "url": {"path": "/search", "query": "id=1%20OR%201=1"},
            }
        )

        event = parse_json_log(raw_log)

        self.assertEqual(event.request_path, "/search")
        self.assertEqual(event.attributes["query_string"], "id=1%20OR%201=1")

    def test_json_parser_records_missing_timestamp_assumption(self) -> None:
        event = parse_json_log('{"source_ip":"192.0.2.1"}')

        self.assertEqual(event.event_type, EventType.NETWORK_CONNECTION)
        self.assertIn("parser_warnings", event.attributes)
        self.assertIn("timestamp missing", event.attributes["parser_warnings"][0])

    def test_apache_combined_parser_preserves_encoded_target(self) -> None:
        raw_log = (
            '2001:db8::5 - analyst [26/Aug/2026:17:30:00 +0530] '
            '"GET /items?id=1%20UNION%20SELECT%20name HTTP/1.1" '
            '403 512 "https://example.test/" "curl/8.0"'
        )

        event = parse_apache_log(raw_log)

        self.assertEqual(str(event.source_ip), "2001:db8::5")
        self.assertEqual(event.http_method, "GET")
        self.assertEqual(
            event.request_path,
            "/items?id=1%20UNION%20SELECT%20name",
        )
        self.assertEqual(event.protocol, "HTTP/1.1")
        self.assertEqual(event.http_status, 403)
        self.assertEqual(event.attributes["response_bytes"], 512)
        self.assertEqual(event.attributes["authenticated_user"], "analyst")

    def test_nginx_parser_supports_optional_tls_suffix(self) -> None:
        raw_log = (
            '203.0.113.8 - - [26/Aug/2026:12:00:00 +0000] '
            '"GET / HTTP/2.0" 200 42 "-" "browser" '
            '"TLSv1.0" "TLS_RSA_WITH_RC4_128_MD5"'
        )

        event = parse_nginx_log(raw_log)

        self.assertEqual(event.tls_version, "TLSv1.0")
        self.assertEqual(
            event.attributes["tls_cipher"],
            "TLS_RSA_WITH_RC4_128_MD5",
        )

    def test_auto_parser_and_batch_parser(self) -> None:
        json_line = '{"timestamp":"2026-08-26T00:00:00Z","path":"/"}'
        self.assertEqual(parse_log(json_line).parser_name, "json")
        events = parse_log_lines(["\n", json_line, json_line], source="events.log")
        self.assertEqual(len(events), 2)

    def test_malformed_records_raise_a_parse_error(self) -> None:
        with self.assertRaises(LogParseError):
            parse_json_log("[]")
        with self.assertRaises(LogParseError):
            parse_json_log('{"timestamp": NaN}')
        with self.assertRaises(LogParseError):
            parse_json_log('{"timestamp":"2026-08-26T00:00:00Z","src_port":1e999}')
        with self.assertRaises(LogParseError):
            parse_json_log('{"timestamp":"2026-08-26T00:00:00Z","src_port":12.5}')
        with self.assertRaises(LogParseError):
            parse_apache_log("not a combined log")


if __name__ == "__main__":
    unittest.main()
