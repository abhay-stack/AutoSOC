# AutoSOC

**Deterministic-first, offline-safe SOC triage with auditable agent-assisted
response planning.**

AutoSOC is a local portfolio project for analyzing JSON, Apache, and Nginx logs.
It detects concrete security signals with versioned Python rules, enriches source
IPs through AbuseIPDB and GreyNoise when it is safe to do so, and passes only
validated incident facts through a LangGraph workflow that produces a
human-reviewable containment playbook. A FastAPI dashboard visualizes the
report, decision trace, agent summaries, and approval-gated response locally or
as a hardened public demo.

> AutoSOC never executes a containment command. Firewall and cloud actions are
> inert previews marked `PENDING HUMAN APPROVAL`. Approval can generate a local,
> comment-only evidence artifact; it cannot change the host firewall.

## Why AutoSOC

Tier-1 SOC analysts often spend their shifts moving between noisy alerts, raw
logs, threat-intelligence portals, and response runbooks. This creates alert
fatigue and makes it difficult to explain why an alert was escalated.

AutoSOC demonstrates a safer hybrid approach:

1. Normalize the source event.
2. Detect threats with explicit signatures and exact configuration deny-lists.
3. Record the evidence, confidence, score contributions, and MITRE mapping.
4. Enrich only eligible public IP addresses through two independent providers,
   with labeled, neutral fallbacks.
5. Let agents prioritize existing facts—not invent new ones.
6. Render a dry-run containment playbook for human approval.
7. Optionally record approval and generate an inert remediation handoff without
   executing it.

## What it detects

| Signal | Deterministic behavior | ATT&CK handling |
| --- | --- | --- |
| SQL injection | URL-decodes request targets and form data, including bounded repeated decoding; detects `UNION SELECT`, boolean inference, time-based payloads, and stacked queries | Maps evidence-backed exploitation attempts to `T1190` — Exploit Public-Facing Application |
| Deprecated TLS | Canonicalizes and denies SSLv2, SSLv3, TLS 1.0, and TLS 1.1 | No technique is invented for a configuration weakness |
| Weak TLS cipher | Matches explicit weak families such as NULL, export, RC2/RC4, DES/3DES, MD5, anonymous DH, and IDEA | No attacker behavior is inferred without evidence |

Risk is transparent and reproducible. AbuseIPDB can add at most 20 reputation
points. An authoritative GreyNoise result can then reduce scanner noise without
removing the underlying finding:

```text
subtotal = clamp(severity baseline + confidence adjustment + IP reputation, 0, 100)
risk = 25% of subtotal for eligible live GreyNoise noise; otherwise subtotal
```

The 75% reduction applies only to a live benign classification or live scanner
noise with an unknown classification. A malicious classification always
overrides `noise=true` and receives no reduction. Every contribution and its
supporting evidence IDs are included in the report.

## Architecture

AutoSOC has two trust tiers:

```text
Untrusted logs
    │
    ▼
Parse → deterministic detection → transparent scoring → dual-provider enrichment
    │                     validated IncidentReport
    ▼
Triage agent → Intel agent → Response agent → approval-gated playbook
    │
    ▼
Explicit approval receipt → re-derived SQLi targets → comment-only artifact
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
  are never sent to either threat-intelligence provider. GreyNoise Community is
  additionally restricted to globally routable IPv4 addresses.
- Missing keys, network failures, invalid provider responses, and `--offline`
  mode return explicitly labeled, neutral results that cannot reduce risk.
- GreyNoise changes prioritization only: it cannot create, remove, or rewrite a
  deterministic finding, its evidence, or its ATT&CK mapping.
- Firewall previews are limited to globally routable IPs associated with SQLi
  findings and include an exact report-specific rollback rule.
- AWS Security Group changes use fail-closed environment variables and retain
  `--dry-run` until approval.
- No agent has command-execution or infrastructure credentials.
- `POST /api/execute-playbook` re-derives normalized unicast targets from
  deterministic SQLi findings; it never trusts agent prose or command previews
  as executable input.
- Approval writes only `data/remediation/firewall_remediation.sh`: an atomic,
  non-executable `0600` file whose command proposals are all comments.

## Repository layout

```text
AutoSOC/
├── data/
│   ├── rules/sqli.yml                   # sample Sigma detection-as-code rule
│   └── samples/attack_simulation.json   # 12-record synthetic JSONL fixture
├── docs/
│   ├── architecture.md                  # design and trust-boundary guide
│   └── architecture.mermaid             # standalone Mermaid diagram
├── src/autosoc/
│   ├── agents/                           # state, grounded nodes, graph
│   ├── detectors/                        # Python and Sigma detection engines
│   ├── integrations/                     # offline-safe AbuseIPDB + GreyNoise clients
│   ├── parsers/                          # JSON/Apache/Nginx normalization
│   ├── scoring/                          # deterministic risk formula
│   ├── web/                              # dashboard + inert remediation writer
│   ├── cli.py
│   ├── config.py
│   └── models.py
├── tests/
├── .dockerignore
├── .env.example
├── Dockerfile                           # non-root multi-stage runtime
├── docker-compose.yml                   # hardened local container service
├── .python-version                      # Render-compatible Python 3.12 pin
├── render.yaml                          # Render Blueprint deployment contract
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

All provider keys are optional. An empty `.env` still supports the complete
offline workflow.

```dotenv
ABUSEIPDB_API_KEY=
GREYNOISE_API_KEY=
OPENAI_API_KEY=
AUTOSOC_OPENAI_MODEL=gpt-5-nano
AUTOSOC_ENABLE_LIVE_PROVIDERS=false
AUTOSOC_RATE_LIMIT_PER_MINUTE=0
```

Process environment variables take precedence over `.env` values. Never commit
the populated `.env` file.

### Run deterministic analysis

Offline mode makes no AbuseIPDB, GreyNoise, or OpenAI requests:

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

After reviewing that output, the dashboard exposes **Approve & Execute**. In
AutoSOC, “execute” is deliberately limited to generating an inert local
artifact. The browser sends the returned report, a matching report ID, literal
approval confirmation, the approver identity, and an optional single-line note
to `POST /api/execute-playbook`.

The server ignores agent-authored commands and independently re-derives targets
from normalized unicast source IPs attached to deterministic SQLi findings.
Private enterprise and RFC documentation ranges remain eligible for this inert
handoff; loopback, link-local, multicast, unspecified, and reserved non-host
addresses do not. TLS-only reports and reports without an eligible target fail
safely. Success returns `201 Created` with an approval receipt containing
`executed: false`, receipt/report IDs, approval facts, targets, and artifact
integrity metadata. The fixed output is:

```text
<project>/data/remediation/firewall_remediation.sh
```

When `AUTOSOC_DATA_DIR` is configured, that absolute directory replaces
`<project>/data`. The file is atomically written with mode `0600`, has no
executable bit, and every command and rollback line begins with `#`. AutoSOC
never runs it. A second approval atomically replaces only the same regular
artifact; symlinked paths are refused.

Web provider calls are separately disabled by server policy. This means a
browser visitor cannot activate paid APIs merely by submitting
`"offline": false`; see the authenticated live-mode instructions below.

### Run with Docker Compose

Docker Desktop or Docker Engine with the Compose plugin can run the dashboard
without installing Python on the host. The service uses a read-only root
filesystem, drops all Linux capabilities, runs as a non-root UID/GID, and mounts
only `./data` as writable persistent storage.

On macOS or Linux, pass your host IDs so files created in the bind mount remain
owned by your account:

```bash
AUTOSOC_UID="$(id -u)" AUTOSOC_GID="$(id -g)" \
  docker compose up --build
```

Open [http://localhost:8000](http://localhost:8000). Stop the service with:

```bash
docker compose down
```

Compose maps `${AUTOSOC_PORT:-8000}` to container port 8000 and sets
`AUTOSOC_DATA_DIR=/app/data`. Uploaded logs remain temporary, while checked-in
sample/rule data and generated approval artifacts are visible through the host
bind mount. After an eligible approval, inspect the artifact at
`data/remediation/firewall_remediation.sh` on the host.

If `./data` is not writable, fix its ownership for the UID/GID selected above;
do not run the container as root or make the directory world-writable. You may
persist the IDs and port in `.env`:

```dotenv
AUTOSOC_UID=501
AUTOSOC_GID=20
AUTOSOC_PORT=8000
```

Use the values returned by `id -u` and `id -g`; the example IDs are illustrative
only. Compose defaults to `1000:1000` when they are unset.

Container live-provider access remains opt-in. The default
`AUTOSOC_ENABLE_LIVE_PROVIDERS=false` wins even when API keys are present. To
enable web provider calls, set it to `true`, configure the required dashboard
password and exact allowed hosts, retain a nonzero rate limit, and then add only
the provider keys you intend to use. Do not bake secrets into the image.

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
- `GREYNOISE_API_KEY` enables the [GreyNoise Community API](https://docs.greynoise.io/reference/getcommunityip)
  only for globally routable IPv4 source addresses. Missing keys and ineligible
  addresses produce neutral, non-authoritative results.
- `OPENAI_API_KEY` enables constrained fact selection through ChatOpenAI.
- If any service is unavailable, its corresponding stage degrades safely.

To enable live providers in the web dashboard, configure all of the following
as Render environment variables. Use Render's secret controls for the password
and provider keys:

```dotenv
AUTOSOC_ENABLE_LIVE_PROVIDERS=true
AUTOSOC_WEB_USERNAME=autosoc
AUTOSOC_WEB_PASSWORD=<a-random-value-of-at-least-16-characters>
ABUSEIPDB_API_KEY=<optional-live-key>
GREYNOISE_API_KEY=<optional-live-key>
OPENAI_API_KEY=<optional-live-key>
```

When web live mode is enabled, AutoSOC refuses to start without the dashboard
password. HTTP Basic authentication then protects the dashboard and API while
`/healthz` remains available to Render. Provider keys by themselves never open
live web access. Keep `AUTOSOC_RATE_LIMIT_PER_MINUTE` nonzero for any public
deployment. The CLI's live behavior is unchanged by these web-only safeguards.

The bundled fixture uses RFC documentation and private address ranges. Those
addresses are intentionally never sent to AbuseIPDB or GreyNoise, even in live
mode.

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
Threat-intelligence provider results: 0 live, 14 mocked.

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
GreyNoise: mock/non-authoritative neutral fallback
ATT&CK T1190: Exploit Public-Facing Application

Final Containment Playbook
SAFETY GATE — DRY RUN / RECOMMENDATION ONLY
Approval status: PENDING HUMAN APPROVAL
No action has been executed.
```

Because the fixture contains only documentation-range attacker addresses,
the agent playbook correctly withholds an immediately copyable `iptables`
target. It still demonstrates the human-approval gate with a fail-closed AWS
preview:

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

If a named analyst explicitly approves artifact generation in the dashboard,
the API returns a receipt like this (IDs, digest, time, and size vary):

```json
{
  "status": "artifact_generated",
  "executed": false,
  "report_id": "6f75b4ca-3aa1-4e02-a507-3c661ba75f2f",
  "receipt_id": "e53b0762-4947-4489-9354-cec731f9ef11",
  "approved_by": "analyst@example.com",
  "approved_at": "2026-08-27T12:15:00Z",
  "targets": ["8.8.8.8"],
  "artifact": {
    "path": "remediation/firewall_remediation.sh",
    "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "size_bytes": 742,
    "file_mode": "0600",
    "command_lines_inert": true,
    "replaced_existing": false
  },
  "safety_notice": "No firewall command was executed; the generated artifact is an inert, comment-only preview."
}
```

This receipt proves only that the bounded handoff file was generated. It is not
evidence that a firewall change was reviewed through external change control or
applied to any system. Unlike the agent playbook's stricter public-target command
preview, the inert artifact may include normalized private enterprise or RFC
documentation-range sources after explicit approval.

## Testing

Install the development extra and run the full suite:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

Current verified result:

```text
122 passed, 111 subtests passed
```

The suite covers model integrity, parser normalization, URL-decoding and SQLi
signatures, Sigma parsing/evaluation, TLS deny-lists, risk scoring, dual-provider
threat-intelligence safety gates, GreyNoise suppression and malicious overrides,
CLI behavior, grounded agent selections, provider failure, command targeting,
approval binding, atomic comment-only remediation generation, symlink refusal,
FastAPI input boundaries, dashboard safety headers, Render and Docker deployment
contracts, provider-access policy, rate limiting, and human-approval playbooks.

The standard library runner remains supported:

```bash
python -m unittest discover -s tests -v
```

## Operational boundaries

AutoSOC is a defensive portfolio project, not an autonomous enforcement system
or a replacement for a SIEM. Validate parser compatibility, detection policy,
asset ownership, provider terms, change-control procedures, and rollback plans
before adapting it to production data.
