"""Tests for exact weak-protocol and weak-cipher rules."""

from __future__ import annotations

from datetime import datetime, timezone
import unittest

from autosoc.detectors.weak_tls import detect_weak_tls
from autosoc.models import EventType, SecurityEvent


def _tls_event(version: str, cipher: str | None = None) -> SecurityEvent:
    attributes = {"tls_cipher": cipher} if cipher is not None else {}
    return SecurityEvent(
        timestamp=datetime(2026, 8, 26, tzinfo=timezone.utc),
        event_type=EventType.TLS_HANDSHAKE,
        source="tls-test",
        parser_name="test",
        raw_log=f"{version} {cipher or ''}",
        tls_version=version,
        attributes=attributes,
    )


class WeakTLSDetectorTests(unittest.TestCase):
    def test_required_deprecated_protocol_aliases_are_flagged(self) -> None:
        for protocol in ("SSLv2", "SSLv3", "TLSv1", "TLS 1.0", "TLSv1.1"):
            with self.subTest(protocol=protocol):
                findings = detect_weak_tls(_tls_event(protocol))
                self.assertEqual(
                    [item.rule_id for item in findings],
                    ["TLS.DEPRECATED_PROTOCOL"],
                )

    def test_tls_12_and_13_are_not_flagged(self) -> None:
        for protocol in ("TLSv1.2", "TLS 1.3"):
            with self.subTest(protocol=protocol):
                self.assertEqual(detect_weak_tls(_tls_event(protocol)), [])

    def test_known_weak_cipher_families_are_flagged(self) -> None:
        weak_ciphers = (
            "TLS_RSA_WITH_NULL_MD5",
            "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
            "TLS_RSA_WITH_RC4_128_SHA",
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            "DES-CBC3-SHA",
            "TLS_RSA_WITH_DES_CBC_SHA",
            "TLS_DH_anon_WITH_AES_128_CBC_SHA",
            "IDEA-CBC-SHA",
        )
        for cipher in weak_ciphers:
            with self.subTest(cipher=cipher):
                findings = detect_weak_tls(_tls_event("TLSv1.2", cipher))
                self.assertEqual(
                    [item.rule_id for item in findings],
                    ["TLS.WEAK_CIPHER"],
                )

    def test_modern_aes_name_does_not_trigger_des_substring(self) -> None:
        event = _tls_event("TLSv1.3", "TLS_AES_256_GCM_SHA384")
        self.assertEqual(detect_weak_tls(event), [])

    def test_tls_configuration_does_not_invent_attacker_behavior(self) -> None:
        finding = detect_weak_tls(
            _tls_event("SSLv3", "TLS_RSA_WITH_RC4_128_MD5")
        )[0]

        self.assertEqual(finding.mitre_attack_mappings, [])
        self.assertIn(
            "not evidence",
            finding.decision_trace[0].details["mitre_mapping_decision"],
        )

    def test_protocol_and_cipher_create_separate_auditable_findings(self) -> None:
        findings = detect_weak_tls(
            _tls_event("TLSv1.0", "TLS_RSA_WITH_RC4_128_MD5")
        )
        self.assertEqual(
            [item.rule_id for item in findings],
            ["TLS.DEPRECATED_PROTOCOL", "TLS.WEAK_CIPHER"],
        )


if __name__ == "__main__":
    unittest.main()
