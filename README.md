# AutoSOC

**Deterministic-first, offline-safe SOC triage with auditable agent-assisted
response planning.**

AutoSOC is a local portfolio project for analyzing JSON, Apache, and Nginx logs.
It detects concrete security signals with versioned Python rules, enriches source
IPs through AbuseIPDB when it is safe to do so, and passes only validated incident
facts through a LangGraph workflow that produces a human-reviewable containment
playbook. A FastAPI dashboard visualizes the report, decision trace, agent
summaries, and approval-gated response locally or as a hardened public demo.

> AutoSOC never executes a containment command. Firewall and cloud actions are
> inert previews marked `PENDING HUMAN APPROVAL`.

## Why AutoSOC

Tier-1 SOC analysts often spend their shifts moving between noisy alerts, raw
logs, threat-intelligence portals, and response runbooks. This creates alert
fatigue and makes it difficult to explain why an alert was escalated.

AutoSOC demonstrates a safer hybrid approach:

1. Normalize the source event.
2. Detect threats with explicit signatures and exact configuration deny-lists.
3. Record the evidence, confidence, score contributions, and MITRE mapping.
4. Enrich only eligible public IP addresses, with a labeled mock fallback.
5. Let agents prioritize existing facts—not invent new ones.
6. Render a dry-run containment playbook for human approval.

## What it detects

| Signal | Deterministic behavior | ATT&CK handling |
| --- | --- | --- |
| SQL injection | URL-decodes request targets and form data, including bounded repeated decoding; detects `UNION SELECT`, boolean inference, time-based payloads, and stacked queries | Maps evidence-backed exploitation attempts to `T1190` — Exploit Public-Facing Application |
| Deprecated TLS | Canonicalizes and denies SSLv2, SSLv3, TLS 1.0, and TLS 1.1 | No technique is invented for a configuration weakness |
| Weak TLS cipher | Matches explicit weak families such as NULL, export, RC2/RC4, DES/3DES, MD5, anonymous DH, and IDEA | No attacker behavior is inferred without evidence |

Risk is transparent and reproducible:

```text
risk = clamp(severity baseline + confidence adjustment + IP reputation, 0, 100)
```

Every contribution and its supporting evidence IDs are included in the report.

## Architecture

AutoSOC has two trust tiers:

```text
Untrusted logs
    │
    ▼
Parse → deterministic detection → transparent scoring → safe enrichment
    │                     validated IncidentReport
    ▼
Triage agent → Intel agent → Response agent → approval-gated playbook
```

The agent tier receives a bounded fact packet derived from the validated
`IncidentReport`. Model output is schema-checked against allow-listed finding,
evidence, technique, and IP identifiers. Python—not the model—renders all final
narrative and command previews.

See the detailed [architecture guide](docs/architecture.md) and standalone
[Mermaid source](docs/architecture.mermaid).

### Safety properties

- Detection is deterministic; an LLM cannot create or suppress findings.
- Raw logs are excluded from agent prompts. Bounded evidence values are labeled
  as untrusted data.
- SQLi is mapped to ATT&CK `T1190` in detector code. Weak TLS is deliberately
  left unmapped unless adversarial evidence exists.
- Private, reserved, loopback, link-local, multicast, and other non-global IPs
  are never sent to AbuseIPDB.
- Missing keys, network failures, invalid provider responses, and `--offline`
  mode fall back locally and remain explicitly labeled.
- Firewall previews are limited to globally routable IPs associated with SQLi
  findings and include an exact report-specific rollback rule.
- AWS Security Group changes use fail-closed environment variables and retain
  `--dry-run` until approval.
- No agent has command-execution or infrastructure credentials.

## Repository layout

```text
AutoSOC/
├── data/samples/attack_simulation.json  # 12-record synthetic JSONL fixture
├── docs/
│   ├── architecture.md                  # design and trust-boundary guide
│   └── architecture.mermaid             # standalone Mermaid diagram
├── src/autosoc/
│   ├── agents/                           # state, grounded nodes, graph
│   ├── detectors/                        # SQLi and weak-TLS rules
│   ├── integrations/                     # offline-safe AbuseIPDB client
│   ├── parsers/                          # JSON/Apache/Nginx normalization
│   ├── scoring/                          # deterministic risk formula
│   ├── web/                              # FastAPI app and Jinja dashboard
│   ├── cli.py
│   ├── config.py
│   └── models.py
├── tests/
├── .env.example
├── .python-version                    # Render-compatible Python 3.12 pin
├── render.yaml                        # Render Blueprint deployment contract
└── pyproject.toml
```

## Quickstart

### Requirements

- Python 3.12
- macOS, Linux, or another environment with a POSIX-compatible shell

From the project root:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
cp .env.example .env
```

Both provider keys are optional. An empty `.env` still supports the complete
offline workflow.

```dotenv
ABUSEIPDB_API_KEY=
OPENAI_API_KEY=
AUTOSOC_OPENAI_MODEL=gpt-5-nano
AUTOSOC_ENABLE_LIVE_PROVIDERS=false
```

Process environment variables take precedence over `.env` values. Never commit
the populated `.env` file.

### Run deterministic analysis

Offline mode makes no AbuseIPDB or OpenAI requests:

```bash
autosoc analyze data/samples/attack_simulation.json --offline
```

The command writes a colorized, schema-validated `IncidentReport` as JSON. When
redirected, Rich automatically emits plain JSON:

```bash
autosoc analyze data/samples/attack_simulation.json --offline > incident.json
```

### Run the agent workflow

```bash
autosoc orchestrate data/samples/attack_simulation.json --offline
```

This first runs the same deterministic pipeline, then streams Triage, Intel, and
Response updates before printing the final playbook. Offline orchestration uses
the deterministic local agent fallback.

### Launch the web dashboard

Start the loopback-only FastAPI server:

```bash
autosoc serve --port 8000
```

Then open [http://localhost:8000](http://localhost:8000). The dashboard accepts
pasted logs or one UTF-8 file up to 2 MiB, defaults to offline operation, and
shows the deterministic decision trace alongside auditable Triage, Intel, and
Response summaries. Agent summaries are not hidden chain-of-thought.

The same backend is available programmatically:

```bash
curl --fail-with-body http://localhost:8000/api/orchestrate \
  -H 'Content-Type: application/json' \
  --data '{"raw_log":"{\"timestamp\":\"2026-08-27T09:00:00Z\",\"source_ip\":\"192.0.2.10\",\"method\":\"GET\",\"request_path\":\"/?id=1%20UNION%20SELECT%20password\"}","offline":true,"log_format":"json"}'
```

The endpoint also accepts `multipart/form-data` with exactly one `raw_log` text
field or `file` upload. Responses contain `incident_report`, `agent_thread`, and
`playbook`.

Web provider calls are separately disabled by server policy. This means a
browser visitor cannot activate paid APIs merely by submitting
`"offline": false`; see the authenticated live-mode instructions below.

### Deploy to Render

The repository includes a production install command, Python 3.12 pin, HTTP
health check, public request budget, and fail-closed provider policy in
[`render.yaml`](render.yaml).

1. Commit this project and push it to a GitHub, GitLab, or Bitbucket repository.
2. In Render, choose **New → Blueprint** and connect that repository.
3. Review the `autosoc-dashboard` web service and apply the Blueprint.
4. Wait for `GET /healthz` to pass, then open the assigned HTTPS URL.

Render supplies its `onrender.com` hostname through
`RENDER_EXTERNAL_HOSTNAME`; AutoSOC trusts that exact hostname automatically.
For a custom domain, add every exact hostname in the Render environment:

```dotenv
AUTOSOC_ALLOWED_HOSTS=soc.example.com,www.soc.example.com
```

The committed Blueprint is suitable for a public portfolio demonstration:

- Provider mode is forced offline.
- No API key is present in source or in `render.yaml`.
- Orchestration is limited to 12 POST requests per minute per service process.
- Uploads remain limited to 2 MiB and are handled in temporary storage.
- Reports and playbooks remain non-executing recommendations.

The `autosoc serve` command remains intentionally loopback-only. Render instead
starts Uvicorn on `0.0.0.0:$PORT` behind Render's managed HTTPS proxy.

### Live mode

For CLI use, add either or both keys to `.env`, then omit `--offline`:

```bash
autosoc analyze path/to/access.json
autosoc orchestrate path/to/access.json
```

- `ABUSEIPDB_API_KEY` enables reputation lookups only for globally routable
  source IPs.
- `OPENAI_API_KEY` enables constrained fact selection through ChatOpenAI.
- If either service is unavailable, its corresponding stage degrades safely.

To enable live providers in the web dashboard, configure all of the following
as Render environment variables. Use Render's secret controls for the password
and provider keys:

```dotenv
AUTOSOC_ENABLE_LIVE_PROVIDERS=true
AUTOSOC_WEB_USERNAME=autosoc
AUTOSOC_WEB_PASSWORD=<a-random-value-of-at-least-16-characters>
ABUSEIPDB_API_KEY=<optional-live-key>
OPENAI_API_KEY=<optional-live-key>
```

When web live mode is enabled, AutoSOC refuses to start without the dashboard
password. HTTP Basic authentication then protects the dashboard and API while
`/healthz` remains available to Render. Provider keys by themselves never open
live web access. Keep `AUTOSOC_RATE_LIMIT_PER_MINUTE` nonzero for any public
deployment. The CLI's live behavior is unchanged by these web-only safeguards.

The bundled fixture uses RFC documentation and private address ranges. Those
addresses are intentionally never sent to AbuseIPDB, even in live mode.

### Apache and Nginx logs

Auto-detection handles standard JSONL and combined access logs. A format can also
be selected explicitly:

```bash
autosoc analyze /var/log/nginx/access.log --format nginx --offline
autosoc orchestrate ./apache-access.log --format apache --offline
```

Use `autosoc --help`, `autosoc analyze --help`, or
`autosoc orchestrate --help` for all options.

## Demonstration

The synthetic fixture contains four SQLi attempts, three weak-TLS conditions,
and five benign baseline events. The benign records independently produce zero
findings.

An offline analysis produces the following stable result; IDs and timestamps are
generated per run:

```text
Analyzed 12 event(s) and produced 7 deterministic finding(s).
Highest risk score: 65/100.
Threat intelligence: 0 live, 7 mocked.

Rules:
  SQLI.UNION_SELECT          2
  SQLI.BOOLEAN_INFERENCE     2
  TLS.DEPRECATED_PROTOCOL    2
  TLS.WEAK_CIPHER            1

Evidence-backed ATT&CK mappings: T1190
Offline mode: true
```

The orchestrated terminal output is intentionally explicit about authority:

```text
╭─ Deterministic Incident Report ─────────────────────────────────────╮
│ Risk: 65/100                         Findings: 7                     │
╰─────────────────────────────────────────────────────────────────────╯

Triage Agent Update
Generation mode: deterministic_fallback
Reason: incident report requested offline operation

Intel Agent Update
AbuseIPDB: mock/non-authoritative fallback
ATT&CK T1190: Exploit Public-Facing Application

Final Containment Playbook
SAFETY GATE — DRY RUN / RECOMMENDATION ONLY
Approval status: PENDING HUMAN APPROVAL
No action has been executed.
```

Because the fixture contains only documentation-range attacker addresses,
AutoSOC correctly withholds an `iptables` target. It still demonstrates the
human-approval gate with a fail-closed AWS preview:

```bash
# PREVIEW ONLY — DO NOT RUN UNTIL AN APPROVER VALIDATES THE EXACT RULE
aws ec2 revoke-security-group-ingress \
  --group-id "${AUTOSOC_SG_ID:?set AUTOSOC_SG_ID}" \
  --security-group-rule-ids \
  "${AUTOSOC_SG_RULE_ID:?set AUTOSOC_SG_RULE_ID}" \
  --region "${AWS_REGION:?set AWS_REGION}" \
  --dry-run
```

For an authorized, globally routable source tied to a SQLi finding, the generated
playbook contains three separate `iptables` previews: a non-mutating `-C` check,
an approval-gated `-I` proposal, and an exact report-tagged `-D` rollback. AutoSOC
does not run any of them.

## Testing

Install the development extra and run the full suite:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

Expected result:

```text
80 passed, 55 subtests passed
```

The suite covers model integrity, parser normalization, URL-decoding and SQLi
signatures, TLS deny-lists, risk scoring, threat-intelligence safety gates, CLI
behavior, grounded agent selections, provider failure, command targeting,
FastAPI input boundaries, dashboard safety headers, Render deployment contracts,
provider-access policy, rate limiting, and human-approval playbooks.

The standard library runner remains supported:

```bash
python -m unittest discover -s tests -v
```

## Operational boundaries

AutoSOC is a defensive portfolio project, not an autonomous enforcement system
or a replacement for a SIEM. Validate parser compatibility, detection policy,
asset ownership, provider terms, change-control procedures, and rollback plans
before adapting it to production data.
