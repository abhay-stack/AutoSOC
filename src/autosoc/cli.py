"""Typer commands for deterministic analysis and agent orchestration."""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from enum import StrEnum
from pathlib import Path
from typing import Annotated

from rich import print_json
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.text import Text
import typer

from autosoc.agents.graph import build_graph
from autosoc.detectors.sqli import detect_sqli
from autosoc.detectors.weak_tls import detect_weak_tls
from autosoc.integrations.abuseipdb import AbuseIPDBClient
from autosoc.integrations.greynoise import GreyNoiseClient
from autosoc.models import (
    DecisionTraceEntry,
    DetectionFinding,
    Evidence,
    GreyNoiseClassification,
    GreyNoiseLookupStatus,
    GreyNoiseResult,
    IncidentReport,
    IncidentStatus,
    MitreAttackMapping,
    ScoreContribution,
    SecurityEvent,
    ThreatIntelMode,
    ThreatIntelResult,
    TraceOutcome,
    TraceStage,
)
from autosoc.parsers.log_parser import (
    LogFormat,
    LogParseError,
    parse_json_log,
    parse_log_lines,
)
from autosoc.scoring.risk import calculate_risk_score

app = typer.Typer(
    name="autosoc",
    help="Deterministic SOC log triage with offline-safe enrichment.",
    no_args_is_help=True,
    add_completion=False,
)
error_console = Console(stderr=True)
output_console = Console()


class CLIFormat(StrEnum):
    AUTO = "auto"
    JSON = "json"
    APACHE = "apache"
    NGINX = "nginx"


class AnalysisError(RuntimeError):
    """Raised for user-facing input or pipeline failures."""


@app.callback()
def _main() -> None:
    """AutoSOC command group."""


def _parse_events(
    log_path: Path,
    *,
    log_format: LogFormat,
) -> list[SecurityEvent]:
    try:
        raw_text = log_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise AnalysisError(f"unable to read {log_path}: {exc}") from exc
    if not raw_text.strip():
        raise AnalysisError(f"log file is empty: {log_path}")

    # A complete JSON object may be pretty-printed across multiple lines. JSONL
    # falls through to record-by-record parsing when the whole-file parse fails.
    if log_format in ("auto", "json") and raw_text.lstrip().startswith("{"):
        try:
            return [parse_json_log(raw_text, source=str(log_path))]
        except LogParseError:
            pass

    try:
        return parse_log_lines(
            raw_text.splitlines(),
            log_format=log_format,
            source=str(log_path),
        )
    except LogParseError as exc:
        raise AnalysisError(str(exc)) from exc


def _run_detectors(events: list[SecurityEvent]) -> list[DetectionFinding]:
    findings: list[DetectionFinding] = []
    for event in events:
        findings.extend(detect_sqli(event))
        findings.extend(detect_weak_tls(event))
    return findings


def _abuseipdb_trace_outcome(result: ThreatIntelResult) -> TraceOutcome:
    if result.mode == ThreatIntelMode.LIVE:
        return TraceOutcome.COMPLETED
    if result.retrieval_reason == (
        "AbuseIPDB request or response validation failed"
    ):
        return TraceOutcome.FAILED
    return TraceOutcome.SKIPPED


def _greynoise_trace_outcome(result: GreyNoiseResult) -> TraceOutcome:
    if result.mode == ThreatIntelMode.LIVE:
        return TraceOutcome.COMPLETED
    if result.lookup_status == GreyNoiseLookupStatus.PROVIDER_ERROR:
        return TraceOutcome.FAILED
    return TraceOutcome.SKIPPED


def _rescore_finding(
    finding: DetectionFinding,
    abuse_intel: ThreatIntelResult,
    greynoise_intel: GreyNoiseResult,
) -> DetectionFinding:
    original_evidence_ids = [item.evidence_id for item in finding.evidence]
    abuse_evidence = Evidence(
        event_id=finding.event_id,
        source_field="threat_intelligence.abuseipdb.abuse_confidence_score",
        observed_value=abuse_intel.abuse_confidence_score,
        description=(
            f"AbuseIPDB {abuse_intel.mode.value} enrichment returned score "
            f"{abuse_intel.abuse_confidence_score}/100 for "
            f"{str(abuse_intel.ip_address) if abuse_intel.ip_address else 'a missing IP'}; "
            f"reason: {abuse_intel.retrieval_reason}."
        ),
    )
    greynoise_evidence = Evidence(
        event_id=finding.event_id,
        source_field="threat_intelligence.greynoise.noise_filter",
        observed_value={
            "noise": greynoise_intel.noise,
            "riot": greynoise_intel.riot,
            "classification": (
                greynoise_intel.classification.value
                if greynoise_intel.classification is not None
                else None
            ),
            "mode": greynoise_intel.mode.value,
            "lookup_status": greynoise_intel.lookup_status.value,
        },
        description=(
            f"GreyNoise {greynoise_intel.mode.value} enrichment returned "
            f"status {greynoise_intel.lookup_status.value} for "
            f"{str(greynoise_intel.ip_address) if greynoise_intel.ip_address else 'a missing IP'}; "
            f"reason: {greynoise_intel.retrieval_reason}."
        ),
    )
    risk = calculate_risk_score(
        finding.severity,
        finding.confidence_score,
        abuse_intel.abuse_confidence_score,
        evidence_ids=original_evidence_ids,
        ip_reputation_evidence_ids=[abuse_evidence.evidence_id],
        greynoise_result=greynoise_intel,
        greynoise_evidence_ids=[greynoise_evidence.evidence_id],
    )
    trace = list(finding.decision_trace)
    trace.extend(
        [
            DecisionTraceEntry(
                sequence=len(trace) + 1,
                stage=TraceStage.ENRICHMENT,
                component="abuseipdb_client",
                operation="retrieve or safely mock source-IP reputation",
                outcome=_abuseipdb_trace_outcome(abuse_intel),
                rule_id=finding.rule_id,
                evidence_ids=[abuse_evidence.evidence_id],
                details={
                    "provider": abuse_intel.provider,
                    "mode": abuse_intel.mode.value,
                    "retrieval_reason": abuse_intel.retrieval_reason,
                    "country_code": abuse_intel.country_code,
                    "usage_type": abuse_intel.usage_type,
                },
            ),
            DecisionTraceEntry(
                sequence=len(trace) + 2,
                stage=TraceStage.ENRICHMENT,
                component="greynoise_client",
                operation="classify source IP as scanner noise or benign traffic",
                outcome=_greynoise_trace_outcome(greynoise_intel),
                rule_id=finding.rule_id,
                evidence_ids=[greynoise_evidence.evidence_id],
                details={
                    "provider": greynoise_intel.provider,
                    "mode": greynoise_intel.mode.value,
                    "lookup_status": greynoise_intel.lookup_status.value,
                    "noise": greynoise_intel.noise,
                    "riot": greynoise_intel.riot,
                    "classification": (
                        greynoise_intel.classification.value
                        if greynoise_intel.classification is not None
                        else None
                    ),
                    "risk_reduction_eligible": (
                        greynoise_intel.risk_reduction_eligible
                    ),
                    "retrieval_reason": greynoise_intel.retrieval_reason,
                },
            ),
            DecisionTraceEntry(
                sequence=len(trace) + 3,
                stage=TraceStage.SCORING,
                component="risk_scorer",
                operation="recalculate risk with reputation and noise filtering",
                outcome=TraceOutcome.CALCULATED,
                rule_id=finding.rule_id,
                evidence_ids=original_evidence_ids
                + [abuse_evidence.evidence_id, greynoise_evidence.evidence_id],
                details=risk.trace_details(),
            ),
        ]
    )

    values = finding.model_dump()
    values.update(
        risk_score=risk.score,
        risk_score_components=list(risk.components),
        evidence=[*finding.evidence, abuse_evidence, greynoise_evidence],
        decision_trace=trace,
    )
    return DetectionFinding.model_validate(values)


async def _enrich_findings(
    events: list[SecurityEvent],
    findings: list[DetectionFinding],
    abuse_client: AbuseIPDBClient,
    greynoise_client: GreyNoiseClient,
) -> tuple[
    list[DetectionFinding],
    list[ThreatIntelResult],
    list[GreyNoiseResult],
]:
    events_by_id = {event.event_id: event for event in events}
    source_keys: list[str | None] = []
    for finding in findings:
        source_ip = events_by_id[finding.event_id].source_ip
        key = str(source_ip) if source_ip is not None else None
        if key not in source_keys:
            source_keys.append(key)

    # Deliberately sequential to respect provider rate limits; results are cached
    # by source IP and reused for every finding from that event.
    abuse_by_ip: dict[str | None, ThreatIntelResult] = {}
    greynoise_by_ip: dict[str | None, GreyNoiseResult] = {}
    for source_ip in source_keys:
        abuse_by_ip[source_ip] = await abuse_client.check_ip(source_ip)
        greynoise_by_ip[source_ip] = await greynoise_client.check_ip(source_ip)

    enriched_findings: list[DetectionFinding] = []
    for finding in findings:
        event = events_by_id[finding.event_id]
        key = str(event.source_ip) if event.source_ip is not None else None
        enriched_findings.append(
            _rescore_finding(
                finding,
                abuse_by_ip[key],
                greynoise_by_ip[key],
            )
        )
    return (
        enriched_findings,
        list(abuse_by_ip.values()),
        list(greynoise_by_ip.values()),
    )


def _aggregate_mitre_mappings(
    findings: list[DetectionFinding],
) -> list[MitreAttackMapping]:
    mappings: list[MitreAttackMapping] = []
    seen: set[tuple[str, object]] = set()
    for finding in findings:
        for mapping in finding.mitre_attack_mappings:
            key = (mapping.technique_id, mapping.tactic)
            if key not in seen:
                seen.add(key)
                mappings.append(mapping)
    return mappings


def _build_report(
    log_path: Path,
    *,
    log_format: LogFormat,
    offline: bool,
    events: list[SecurityEvent],
    findings: list[DetectionFinding],
    threat_intelligence: list[ThreatIntelResult],
    greynoise_intelligence: list[GreyNoiseResult],
) -> IncidentReport:
    abuse_live_count = sum(
        result.mode == ThreatIntelMode.LIVE for result in threat_intelligence
    )
    abuse_mock_count = len(threat_intelligence) - abuse_live_count
    abuse_failure_count = sum(
        _abuseipdb_trace_outcome(result) == TraceOutcome.FAILED
        for result in threat_intelligence
    )
    greynoise_live_count = sum(
        result.mode == ThreatIntelMode.LIVE
        for result in greynoise_intelligence
    )
    greynoise_mock_count = len(greynoise_intelligence) - greynoise_live_count
    greynoise_failure_count = sum(
        result.lookup_status == GreyNoiseLookupStatus.PROVIDER_ERROR
        for result in greynoise_intelligence
    )
    greynoise_status_counts = {
        status.value: sum(
            result.lookup_status == status
            for result in greynoise_intelligence
        )
        for status in GreyNoiseLookupStatus
        if any(
            result.lookup_status == status
            for result in greynoise_intelligence
        )
    }
    live_count = abuse_live_count + greynoise_live_count
    mock_count = abuse_mock_count + greynoise_mock_count
    all_evidence_ids = [
        evidence.evidence_id
        for finding in findings
        for evidence in finding.evidence
    ]
    detection_evidence_ids = [
        evidence.evidence_id
        for finding in findings
        for evidence in finding.evidence
        if not evidence.source_field.startswith("threat_intelligence.")
    ]

    if findings:
        overall_risk_score = max(finding.risk_score for finding in findings)
        highest_risk_evidence_ids = [
            evidence.evidence_id
            for finding in findings
            if finding.risk_score == overall_risk_score
            for evidence in finding.evidence
        ]
        overall_confidence_score = round(
            sum(finding.confidence_score for finding in findings) / len(findings),
            3,
        )
        summary = (
            f"Analyzed {len(events)} event(s) and produced {len(findings)} "
            f"deterministic finding(s). Highest risk score: "
            f"{overall_risk_score}/100. Threat-intelligence provider results: "
            f"{live_count} live, {mock_count} mocked."
        )
        confidence_basis = (
            "Arithmetic mean of deterministic detector confidence scores; no LLM "
            "confidence was used."
        )
        risk_reason = "Maximum final risk score across all enriched findings."
    else:
        overall_risk_score = 0
        highest_risk_evidence_ids = []
        overall_confidence_score = 0.0
        summary = (
            f"Analyzed {len(events)} event(s); no deterministic detections were "
            "triggered."
        )
        confidence_basis = "No findings were available for confidence aggregation."
        risk_reason = "No deterministic findings were triggered."

    report_risk_components = [
        ScoreContribution(
            component="maximum_finding_risk",
            points=overall_risk_score,
            reason=risk_reason,
            evidence_ids=highest_risk_evidence_ids,
        )
    ]
    abuse_evidence_ids = [
        evidence.evidence_id
        for finding in findings
        for evidence in finding.evidence
        if evidence.source_field.startswith("threat_intelligence.abuseipdb.")
    ]
    greynoise_evidence_ids = [
        evidence.evidence_id
        for finding in findings
        for evidence in finding.evidence
        if evidence.source_field.startswith("threat_intelligence.greynoise.")
    ]
    report_trace = [
        DecisionTraceEntry(
            sequence=1,
            stage=TraceStage.INGESTION,
            component="log_parser",
            operation="parse and validate input records",
            outcome=TraceOutcome.COMPLETED,
            details={"event_count": len(events), "log_format": str(log_format)},
        ),
        DecisionTraceEntry(
            sequence=2,
            stage=TraceStage.DETECTION,
            component="deterministic_detectors",
            operation="run SQLi and weak-TLS rules",
            outcome=TraceOutcome.COMPLETED,
            evidence_ids=detection_evidence_ids,
            details={"finding_count": len(findings)},
        ),
        DecisionTraceEntry(
            sequence=3,
            stage=TraceStage.ENRICHMENT,
            component="abuseipdb_client",
            operation="enrich unique source IPs with AbuseIPDB reputation",
            outcome=(
                TraceOutcome.FAILED
                if abuse_failure_count
                else (
                    TraceOutcome.COMPLETED
                    if abuse_live_count
                    else TraceOutcome.SKIPPED
                )
            ),
            evidence_ids=abuse_evidence_ids,
            details={
                "unique_ip_count": len(threat_intelligence),
                "live_result_count": abuse_live_count,
                "mock_result_count": abuse_mock_count,
                "failed_result_count": abuse_failure_count,
            },
        ),
        DecisionTraceEntry(
            sequence=4,
            stage=TraceStage.ENRICHMENT,
            component="greynoise_client",
            operation="classify unique source IPv4 addresses with GreyNoise",
            outcome=(
                TraceOutcome.FAILED
                if greynoise_failure_count
                else (
                    TraceOutcome.COMPLETED
                    if greynoise_live_count
                    else TraceOutcome.SKIPPED
                )
            ),
            evidence_ids=greynoise_evidence_ids,
            details={
                "unique_ip_count": len(greynoise_intelligence),
                "live_result_count": greynoise_live_count,
                "mock_result_count": greynoise_mock_count,
                "failed_result_count": greynoise_failure_count,
                "lookup_status_counts": greynoise_status_counts,
                "risk_reduction_eligible_count": sum(
                    result.risk_reduction_eligible
                    for result in greynoise_intelligence
                ),
                "malicious_noise_override_count": sum(
                    result.noise
                    and result.classification
                    == GreyNoiseClassification.MALICIOUS
                    for result in greynoise_intelligence
                ),
            },
        ),
        DecisionTraceEntry(
            sequence=5,
            stage=TraceStage.TRIAGE,
            component="report_builder",
            operation="aggregate validated findings into an incident report",
            outcome=TraceOutcome.COMPLETED,
            evidence_ids=all_evidence_ids,
            details={"overall_risk_score": overall_risk_score},
        ),
    ]
    return IncidentReport(
        status=IncidentStatus.TRIAGED,
        title=f"AutoSOC analysis: {log_path.name}",
        summary=summary,
        events=events,
        findings=findings,
        overall_risk_score=overall_risk_score,
        overall_risk_score_components=report_risk_components,
        overall_confidence_score=overall_confidence_score,
        overall_confidence_basis=confidence_basis,
        mitre_attack_mappings=_aggregate_mitre_mappings(findings),
        decision_trace=report_trace,
        threat_intelligence=threat_intelligence,
        greynoise_intelligence=greynoise_intelligence,
        offline_mode=offline,
        metadata={
            "input_file": str(log_path),
            "log_format": str(log_format),
            "detectors": ["sqli", "weak_tls"],
            "threat_intel_providers": ["AbuseIPDB", "GreyNoise"],
        },
    )


async def analyze_file(
    log_path: Path,
    *,
    log_format: LogFormat = "auto",
    offline: bool = False,
    env_file: str | Path = ".env",
    intel_client: AbuseIPDBClient | None = None,
    greynoise_client: GreyNoiseClient | None = None,
) -> IncidentReport:
    """Analyze one log file and return a fully validated incident report."""

    events = _parse_events(log_path, log_format=log_format)
    findings = _run_detectors(events)
    if not findings:
        return _build_report(
            log_path,
            log_format=log_format,
            offline=offline,
            events=events,
            findings=[],
            threat_intelligence=[],
            greynoise_intelligence=[],
        )

    async with AsyncExitStack() as stack:
        if offline:
            selected_abuse_client = await stack.enter_async_context(
                AbuseIPDBClient(
                    offline=True,
                    mock_score=(
                        intel_client.mock_score
                        if intel_client is not None
                        else 0
                    ),
                )
            )
            selected_greynoise_client = await stack.enter_async_context(
                GreyNoiseClient(offline=True)
            )
        else:
            selected_abuse_client = intel_client
            if selected_abuse_client is None:
                selected_abuse_client = await stack.enter_async_context(
                    AbuseIPDBClient.from_env(
                        env_file=env_file,
                        offline=False,
                    )
                )
            selected_greynoise_client = greynoise_client
            if selected_greynoise_client is None:
                selected_greynoise_client = await stack.enter_async_context(
                    GreyNoiseClient.from_env(
                        env_file=env_file,
                        offline=False,
                    )
                )

        findings, intel_results, greynoise_results = await _enrich_findings(
            events,
            findings,
            selected_abuse_client,
            selected_greynoise_client,
        )

    return _build_report(
        log_path,
        log_format=log_format,
        offline=offline,
        events=events,
        findings=findings,
        threat_intelligence=intel_results,
        greynoise_intelligence=greynoise_results,
    )


@app.command("analyze")
def analyze(
    log_path: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
            help="Path to a JSON/JSONL or Apache/Nginx access log.",
        ),
    ],
    log_format: Annotated[
        CLIFormat,
        typer.Option(
            "--format",
            "-f",
            help="Input format. Auto distinguishes JSON from combined access logs.",
        ),
    ] = CLIFormat.AUTO,
    offline: Annotated[
        bool,
        typer.Option(
            "--offline",
            help="Force mocked threat intelligence and make no API requests.",
        ),
    ] = False,
) -> None:
    """Parse, detect, enrich, re-score, and print a JSON incident report."""

    try:
        report = asyncio.run(
            analyze_file(
                log_path,
                log_format=log_format.value,
                offline=offline,
            )
        )
    except AnalysisError as exc:
        error_console.print(f"[bold red]Analysis failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    print_json(json=report.model_dump_json(indent=2))


def _message_content(message: object) -> str:
    content = getattr(message, "content", "")
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return str(content)

    parts: list[str] = []
    for block in content:
        if isinstance(block, str):
            parts.append(block)
        elif isinstance(block, dict):
            text = block.get("text")
            if isinstance(text, str):
                parts.append(text)
    return "".join(parts)


def _render_orchestration(report: IncidentReport, *, offline: bool) -> str:
    output_console.print(
        Panel(
            Text(
                f"{report.summary}\n"
                f"Report ID: {report.report_id}\n"
                f"Risk: {report.overall_risk_score}/100\n"
                f"Findings: {len(report.findings)}",
                overflow="fold",
            ),
            title="Deterministic Incident Report",
            border_style="cyan",
        )
    )

    graph = build_graph(llm=None) if offline else build_graph()
    initial_state = {
        "incident_report": report,
        "playbook": "",
        "messages": [],
    }
    playbook = ""
    titles = {
        "triage_node": "Triage Agent Update",
        "intel_node": "Intel Agent Update",
        "response_node": "Response Agent Update",
    }
    colours = {
        "triage_node": "yellow",
        "intel_node": "magenta",
        "response_node": "red",
    }
    for chunk in graph.stream(
        initial_state,
        stream_mode="updates",
        version="v2",
    ):
        if chunk.get("type") != "updates":
            continue
        updates = chunk.get("data", {})
        if not isinstance(updates, dict):
            continue
        for node_name, update in updates.items():
            if not isinstance(update, dict):
                continue
            for message in update.get("messages", []):
                output_console.print(
                    Panel(
                        Text(_message_content(message), overflow="fold"),
                        title=titles.get(node_name, node_name),
                        border_style=colours.get(node_name, "white"),
                    )
                )
            candidate = update.get("playbook")
            if isinstance(candidate, str):
                playbook = candidate

    if not playbook:
        raise AnalysisError("agent graph completed without a containment playbook")
    output_console.print(
        Panel(
            Markdown(playbook),
            title="Final Containment Playbook",
            border_style="bold green",
        )
    )
    return playbook


@app.command("orchestrate")
def orchestrate(
    log_path: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
            help="Path to a JSON/JSONL or Apache/Nginx access log.",
        ),
    ],
    log_format: Annotated[
        CLIFormat,
        typer.Option(
            "--format",
            "-f",
            help="Input format. Auto distinguishes JSON from combined access logs.",
        ),
    ] = CLIFormat.AUTO,
    offline: Annotated[
        bool,
        typer.Option(
            "--offline",
            help=(
                "Disable external threat-intelligence and LLM calls; use local "
                "fallbacks."
            ),
        ),
    ] = False,
) -> None:
    """Run deterministic analysis, stream agent updates, and print a playbook."""

    try:
        report = asyncio.run(
            analyze_file(
                log_path,
                log_format=log_format.value,
                offline=offline,
            )
        )
        _render_orchestration(report, offline=offline)
    except AnalysisError as exc:
        error_console.print(f"[bold red]Orchestration failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        error_console.print(
            "[bold red]Orchestration failed safely.[/bold red] "
            "No containment action was executed."
        )
        raise typer.Exit(code=1) from exc


@app.command("serve")
def serve(
    port: Annotated[
        int,
        typer.Option(
            "--port",
            min=1,
            max=65535,
            help="Loopback TCP port for the local AutoSOC dashboard.",
        ),
    ] = 8000,
) -> None:
    """Serve the local FastAPI dashboard on the loopback interface."""

    import uvicorn

    dashboard_url = f"http://localhost:{port}"
    output_console.print(
        Panel(
            Text(
                f"Dashboard: {dashboard_url}\n"
                "Listening on loopback only. Press Ctrl+C to stop.",
                overflow="fold",
            ),
            title="AutoSOC Web Dashboard",
            border_style="cyan",
        )
    )
    uvicorn.run(
        "autosoc.web.app:app",
        host="127.0.0.1",
        port=port,
        log_level="info",
    )


if __name__ == "__main__":
    app()


__all__ = ["AnalysisError", "analyze_file", "app", "orchestrate", "serve"]
