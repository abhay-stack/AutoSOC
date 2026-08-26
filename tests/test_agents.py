"""Contract tests for grounded, approval-gated LangGraph orchestration."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import re
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from uuid import uuid4

from langchain_core.messages import AIMessage, HumanMessage

from autosoc.agents.graph import build_graph
from autosoc.agents.nodes import (
    MAX_COMMAND_TARGETS,
    MAX_EVIDENCE_PER_FINDING,
    MAX_FACT_TEXT,
    MAX_FINDINGS_FOR_LLM,
    MAX_MODEL_OUTPUT,
    response_node,
    triage_node,
)
from autosoc.cli import analyze_file
from autosoc.models import IncidentReport


RAW_LOG_SENTINEL = "RAW_LOG_SECRET_MUST_NOT_REACH_THE_MODEL"


def _record(
    *,
    source_ip: str = "8.8.8.8",
    destination_ip: str | None = None,
    request_path: str = "/?id=1%20UNION%20SELECT%20password",
    raw_only_value: str | None = None,
) -> dict[str, object]:
    record: dict[str, object] = {
        "timestamp": "2026-08-26T12:00:00Z",
        "source_ip": source_ip,
        "method": "GET",
        "request_path": request_path,
        "tls_version": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
    }
    if destination_ip is not None:
        record["destination_ip"] = destination_ip
    if raw_only_value is not None:
        record["raw_only_secret"] = raw_only_value
    return record


def _safe_record(*, source_ip: str = "9.9.9.9") -> dict[str, object]:
    return {
        "timestamp": "2026-08-26T12:00:01Z",
        "source_ip": source_ip,
        "method": "GET",
        "request_path": "/health",
        "tls_version": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
    }


def _analyze_records(records: list[dict[str, object]]) -> IncidentReport:
    """Build a real pipeline report without allowing external requests."""

    with TemporaryDirectory() as directory:
        log_path = Path(directory) / "events.jsonl"
        log_path.write_text(
            "\n".join(json.dumps(record) for record in records),
            encoding="utf-8",
        )
        return asyncio.run(analyze_file(log_path, offline=True))


def _allow_llm(report: IncidentReport) -> IncidentReport:
    """Make an offline-generated fixture eligible for an injected fake model."""

    values = report.model_dump()
    values["offline_mode"] = False
    return IncidentReport.model_validate(values)


def _initial_state(
    report: IncidentReport,
    *,
    messages: list[object] | None = None,
) -> dict[str, object]:
    return {
        "incident_report": report,
        "playbook": "",
        "messages": list(messages or []),
    }


def _content(message: object) -> str:
    value = getattr(message, "content", "")
    return value if isinstance(value, str) else str(value)


def _selection_json(report: IncidentReport, *, role: str) -> str:
    """Return a minimal, fully grounded AgentSelection response."""

    finding = report.findings[0]
    source_ip = next(
        str(event.source_ip)
        for event in report.events
        if event.event_id == finding.event_id and event.source_ip is not None
    )
    if role == "intel":
        source_ip = str(report.threat_intelligence[0].ip_address)
    payload = {
        "prioritized_finding_ids": (
            [] if role == "intel" else [str(finding.finding_id)]
        ),
        "referenced_evidence_ids": (
            [] if role == "intel" else [str(finding.evidence[0].evidence_id)]
        ),
        "referenced_mitre_technique_ids": [
            report.mitre_attack_mappings[0].technique_id
        ],
        "referenced_ip_addresses": [source_ip],
        "response_focus": (
            ["network_containment", "application_remediation"]
            if role == "response"
            else []
        ),
    }
    return json.dumps(payload)


class RecordingModel:
    """Tiny injected model double; it never opens a network connection."""

    def __init__(self, responses: list[str | Exception]) -> None:
        self.responses = responses
        self.calls: list[list[object]] = []

    def invoke(self, messages: list[object]) -> AIMessage:
        self.calls.append(list(messages))
        index = min(len(self.calls) - 1, len(self.responses) - 1)
        response = self.responses[index]
        if isinstance(response, Exception):
            raise response
        return AIMessage(content=response)


class ForbiddenModel:
    """Fails a test if offline routing accidentally invokes a provider."""

    def __init__(self) -> None:
        self.calls = 0

    def invoke(self, messages: list[object]) -> AIMessage:
        del messages
        self.calls += 1
        raise AssertionError("offline orchestration must not invoke the LLM")


class AgentGraphContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.public_report = _analyze_records(
            [
                _record(destination_ip="1.1.1.1"),
                _safe_record(),
            ]
        )
        cls.private_report = _analyze_records(
            [_record(source_ip="192.168.10.25")]
        )
        cls.clean_report = _analyze_records([_safe_record(source_ip="8.8.4.4")])

    def test_graph_order_and_add_messages_reducer(self) -> None:
        report = _allow_llm(self.public_report.model_copy(deep=True))
        model = RecordingModel(
            [
                _selection_json(report, role="triage"),
                _selection_json(report, role="intel"),
                _selection_json(report, role="response"),
            ]
        )
        seed = HumanMessage(content="analyst-start", id="seed-message")

        result = build_graph(llm=model).invoke(
            _initial_state(report, messages=[seed])
        )

        roles = [
            "triage" if "triage selector" in _content(call[0]).lower() else
            "intel" if "intel selector" in _content(call[0]).lower() else
            "response" if "response selector" in _content(call[0]).lower() else
            "unknown"
            for call in model.calls
        ]
        self.assertEqual(roles, ["triage", "intel", "response"])
        self.assertNotIn("analyst-start", _content(model.calls[1][1]))
        self.assertNotIn("analyst-start", _content(model.calls[2][1]))
        self.assertEqual(len(result["messages"]), 4)
        self.assertEqual(result["messages"][0].id, "seed-message")
        self.assertEqual(
            [message.name for message in result["messages"][1:]],
            ["triage_agent", "intel_agent", "response_agent"],
        )
        self.assertTrue(
            all(
                message.additional_kwargs["generation_mode"]
                == "llm_selected_validated_facts"
                for message in result["messages"][1:]
            )
        )

    def test_injected_model_uses_prior_context_and_succeeds(self) -> None:
        report = _allow_llm(self.public_report.model_copy(deep=True))
        model = RecordingModel(
            [
                _selection_json(report, role="triage"),
                _selection_json(report, role="intel"),
                _selection_json(report, role="response"),
            ]
        )

        result = build_graph(llm=model).invoke(_initial_state(report))

        self.assertEqual(len(model.calls), 3)
        intel_prompt = _content(model.calls[1][1])
        response_prompt = _content(model.calls[2][1])
        self.assertIn("## Triage Agent", intel_prompt)
        self.assertIn("## Triage Agent", response_prompt)
        self.assertIn("## Intel Agent", response_prompt)
        self.assertTrue(
            all(
                message.additional_kwargs["generation_mode"]
                == "llm_selected_validated_facts"
                for message in result["messages"]
            )
        )
        expected_id = str(report.findings[0].finding_id)
        self.assertIn(expected_id, result["playbook"])
        self.assertEqual(
            result["messages"][2].additional_kwargs["validated_selection"]
            ["prioritized_finding_ids"],
            [expected_id],
        )

    def test_offline_report_never_invokes_injected_model(self) -> None:
        model = ForbiddenModel()

        result = build_graph(llm=model).invoke(
            _initial_state(self.public_report.model_copy(deep=True))
        )

        self.assertEqual(model.calls, 0)
        self.assertEqual(len(result["messages"]), 3)
        self.assertTrue(
            all(
                message.additional_kwargs["generation_mode"]
                == "deterministic_fallback"
                for message in result["messages"]
            )
        )
        self.assertIn("GreyNoise", _content(result["messages"][1]))
        self.assertIn("status `offline`", _content(result["messages"][1]))
        self.assertIn("GreyNoise", result["playbook"])
        self.assertIn("SAFETY GATE", result["playbook"])

    def test_missing_key_uses_fallback_without_constructing_chatopenai(self) -> None:
        report = _allow_llm(self.public_report.model_copy(deep=True))
        with patch.dict(os.environ, {}, clear=True):
            with patch(
                "autosoc.agents.nodes.load_setting",
                return_value=None,
            ):
                with patch("autosoc.agents.nodes.ChatOpenAI") as constructor:
                    result = build_graph().invoke(_initial_state(report))

        constructor.assert_not_called()
        self.assertEqual(len(result["messages"]), 3)
        self.assertTrue(
            all(
                message.additional_kwargs["generation_mode"]
                == "deterministic_fallback"
                for message in result["messages"]
            )
        )
        self.assertIn("OPENAI_API_KEY", _content(result["messages"][0]))
        self.assertTrue(result["playbook"])

    def test_provider_failure_is_suppressed_and_graph_completes(self) -> None:
        report = _allow_llm(self.public_report.model_copy(deep=True))
        model = RecordingModel([RuntimeError("secret provider detail")])

        result = build_graph(llm=model).invoke(_initial_state(report))

        self.assertEqual(len(model.calls), 1)
        self.assertEqual(len(result["messages"]), 3)
        for message in result["messages"]:
            self.assertEqual(
                message.additional_kwargs["generation_mode"],
                "deterministic_fallback",
            )
            self.assertNotIn("secret provider detail", _content(message))
        self.assertIn("PENDING HUMAN APPROVAL", result["playbook"])

    def test_prompts_exclude_raw_log_and_bound_evidence(self) -> None:
        repeated_attack = "/?q=" + "%20".join(
            ["UNION%20SELECT%201"] * (MAX_EVIDENCE_PER_FINDING + 3)
        )
        repeated_attack += "Z" * (MAX_FACT_TEXT * 3)
        report = _allow_llm(
            _analyze_records(
                [
                    _record(
                        request_path=repeated_attack,
                        raw_only_value=RAW_LOG_SENTINEL,
                    )
                ]
            )
        )
        self.assertIn(RAW_LOG_SENTINEL, report.events[0].raw_log)
        self.assertGreater(
            len(report.findings[0].evidence),
            MAX_EVIDENCE_PER_FINDING,
        )
        model = RecordingModel([_selection_json(report, role="triage")])

        triage_node(_initial_state(report), llm=model)

        prompt = _content(model.calls[0][1])
        self.assertNotIn(RAW_LOG_SENTINEL, prompt)
        self.assertNotIn('"raw_log"', prompt)
        longest_run = max((len(run) for run in re.findall(r"Z+", prompt)), default=0)
        self.assertLessEqual(longest_run, MAX_FACT_TEXT)
        omitted = len(report.findings[0].evidence) - MAX_EVIDENCE_PER_FINDING
        self.assertIn(f'"evidence_omitted": {omitted}', prompt)
        self.assertEqual(prompt.count('"evidence_id"'), MAX_EVIDENCE_PER_FINDING)

    def test_prompt_caps_number_of_findings(self) -> None:
        report = _allow_llm(
            _analyze_records(
                [
                    _record(request_path=f"/?id={index}%20UNION%20SELECT%201")
                    for index in range(MAX_FINDINGS_FOR_LLM + 3)
                ]
            )
        )
        self.assertEqual(len(report.findings), MAX_FINDINGS_FOR_LLM + 3)
        model = RecordingModel([_selection_json(report, role="triage")])

        triage_node(_initial_state(report), llm=model)

        prompt = _content(model.calls[0][1])
        self.assertIn(
            f'"findings_in_packet": {MAX_FINDINGS_FOR_LLM}',
            prompt,
        )
        self.assertIn('"findings_omitted": 3', prompt)
        self.assertEqual(prompt.count('"finding_id"'), MAX_FINDINGS_FOR_LLM)

    def test_long_report_summary_is_bounded_before_model_invocation(self) -> None:
        report_values = self.public_report.model_dump()
        report_values["offline_mode"] = False
        report_values["summary"] = "S" * (MAX_FACT_TEXT * 8)
        report = IncidentReport.model_validate(report_values)
        model = RecordingModel([_selection_json(report, role="triage")])

        triage_node(_initial_state(report), llm=model)

        prompt = _content(model.calls[0][1])
        longest_run = max((len(run) for run in re.findall(r"S+", prompt)), default=0)
        self.assertLessEqual(longest_run, 1_000)

    def test_non_json_prose_commands_urls_and_oversize_are_rejected(self) -> None:
        report = _allow_llm(self.public_report.model_copy(deep=True))
        candidates = {
            "prose": "The source is associated with a known threat campaign.",
            "command": "Run sudo iptables -A INPUT -s 8.8.8.8 -j DROP.",
            "URL": "Review intelligence at https://malicious.example/report.",
            "oversize": "X" * (MAX_MODEL_OUTPUT + 1),
        }

        for label, candidate in candidates.items():
            with self.subTest(label=label):
                result = triage_node(
                    _initial_state(report),
                    llm=RecordingModel([candidate]),
                )
                message = result["messages"][0]
                self.assertEqual(
                    message.additional_kwargs["generation_mode"],
                    "deterministic_fallback",
                )
                self.assertNotIn(candidate, _content(message))
                self.assertIn(
                    "failed schema or grounding validation",
                    _content(message),
                )

    def test_unknown_ids_iocs_mitre_focus_and_extra_keys_are_rejected(self) -> None:
        report = _allow_llm(self.public_report.model_copy(deep=True))
        valid = json.loads(_selection_json(report, role="triage"))
        mutations: dict[str, object] = {
            "unknown finding": {
                **valid,
                "prioritized_finding_ids": [str(uuid4())],
            },
            "unknown evidence": {
                **valid,
                "referenced_evidence_ids": [str(uuid4())],
            },
            "unknown MITRE": {
                **valid,
                "referenced_mitre_technique_ids": ["T1059"],
            },
            "unknown IP": {
                **valid,
                "referenced_ip_addresses": ["203.0.113.77"],
            },
            "domain IOC is not an IP": {
                **valid,
                "referenced_ip_addresses": ["malicious.example.com"],
            },
            "triage response focus": {
                **valid,
                "response_focus": ["network_containment"],
            },
            "unknown focus": {
                **valid,
                "response_focus": ["execute_commands"],
            },
            "extra prose field": {
                **valid,
                "narrative": "invented attribution",
            },
        }

        for label, payload in mutations.items():
            with self.subTest(label=label):
                result = triage_node(
                    _initial_state(report),
                    llm=RecordingModel([json.dumps(payload)]),
                )
                message = result["messages"][0]
                self.assertEqual(
                    message.additional_kwargs["generation_mode"],
                    "deterministic_fallback",
                )
                self.assertIn(
                    "failed schema or grounding validation",
                    _content(message),
                )

    def test_public_command_targets_come_only_from_finding_sources(self) -> None:
        report = self.public_report.model_copy(deep=True)

        result = response_node(_initial_state(report), llm=ForbiddenModel())
        playbook = result["playbook"]

        self.assertIn("SAFETY GATE — DRY RUN / RECOMMENDATION ONLY", playbook)
        self.assertIn("PENDING HUMAN APPROVAL", playbook)
        self.assertIn("No action has been executed", playbook)
        self.assertIn(
            "sudo iptables -I INPUT 1 -s 8.8.8.8/32",
            playbook,
        )
        self.assertIn(f'--comment "AutoSOC:{report.report_id}"', playbook)
        self.assertNotIn("9.9.9.9/32", playbook)
        self.assertNotIn("1.1.1.1/32", playbook)

    def test_private_source_withholds_targeted_containment_commands(self) -> None:
        result = response_node(
            _initial_state(self.private_report.model_copy(deep=True)),
            llm=ForbiddenModel(),
        )
        playbook = result["playbook"]

        self.assertIn("No publicly routable source IP", playbook)
        self.assertIn("192.168.10.25", playbook)
        self.assertIn("Command generation was withheld", playbook)
        self.assertNotIn("sudo iptables", playbook)
        self.assertNotIn("sudo ip6tables", playbook)
        self.assertNotIn("192.168.10.25/32", playbook)

    def test_no_findings_withholds_all_mutating_command_previews(self) -> None:
        result = response_node(
            _initial_state(self.clean_report.model_copy(deep=True)),
            llm=ForbiddenModel(),
        )
        playbook = result["playbook"]

        self.assertIn("No deterministic findings", playbook)
        self.assertIn("No block command is proposed", playbook)
        self.assertNotIn("sudo iptables", playbook)
        self.assertNotIn("sudo ip6tables", playbook)
        self.assertNotIn("revoke-security-group-ingress", playbook)

    def test_tls_protocol_only_playbook_uses_exact_observed_version(self) -> None:
        record = _safe_record(source_ip="8.8.8.8")
        record["tls_version"] = "TLSv1.1"
        report = _analyze_records([record])

        result = response_node(_initial_state(report), llm=ForbiddenModel())
        playbook = result["playbook"]

        self.assertIn("`TLS.DEPRECATED_PROTOCOL`", playbook)
        self.assertIn("`TLS 1.1`", playbook)
        self.assertNotIn("Remove only the weak cipher families", playbook)
        self.assertNotIn("sudo iptables", playbook)
        self.assertNotIn("revoke-security-group-ingress", playbook)

    def test_tls_cipher_only_playbook_does_not_invent_protocol_finding(self) -> None:
        record = _safe_record(source_ip="8.8.8.8")
        record["cipher"] = "TLS_RSA_WITH_RC4_128_MD5"
        report = _analyze_records([record])

        result = response_node(_initial_state(report), llm=ForbiddenModel())
        playbook = result["playbook"]

        self.assertIn("Remove only the weak cipher families", playbook)
        self.assertNotIn("`TLS.DEPRECATED_PROTOCOL`", playbook)
        self.assertNotIn("sudo iptables", playbook)

    def test_command_previews_are_capped_with_an_omission_count(self) -> None:
        extra = 3
        report = _analyze_records(
            [
                _record(source_ip=f"8.8.8.{index}")
                for index in range(1, MAX_COMMAND_TARGETS + extra + 1)
            ]
        )

        result = response_node(_initial_state(report), llm=ForbiddenModel())
        playbook = result["playbook"]

        self.assertEqual(playbook.count("### Candidate `"), MAX_COMMAND_TARGETS)
        self.assertIn(
            f"{extra} additional public target(s) were omitted",
            playbook,
        )

    def test_graph_does_not_mutate_incident_report(self) -> None:
        report = self.public_report.model_copy(deep=True)
        before = report.model_dump_json()

        result = build_graph(llm=None).invoke(_initial_state(report))

        self.assertEqual(report.model_dump_json(), before)
        self.assertEqual(result["incident_report"].model_dump_json(), before)
        self.assertEqual(report.containment_recommendations, [])


if __name__ == "__main__":
    unittest.main()
