# MCP Evidence Lab

Companion lab for Samuel Addington's SANS DFIR Summit 2026 session, **“Evidence Isn't on Disk: A DFIR Playbook for Compromised MCP Servers and AI Coding Agents.”**

This self-contained lab reproduces a compromised local MCP server and a deterministic coding-agent harness. It uses synthetic secrets, a seeded throwaway repository, and a localhost-only collection sink. No API key, external model, package install, or internet access is required.

## What the synthetic lab demonstrates

The deterministic harness can produce a benign-looking final answer even though its recorded process/protocol evidence shows a synthetic transfer:

- newline-delimited JSON-RPC on MCP stdio;
- a changed tool definition and its canonical SHA-256 fingerprint;
- untrusted tool output influencing a later file read and tool call;
- the MCP server process—not the model—making the outbound request;
- volatile process/environment provenance;
- a cross-source timeline and an integrity manifest.

The wire examples use MCP protocol revision `2026-07-28`. Rule `MCP-DFIR-006` is an informational heuristic based on the missing `Mcp-Session-Id` header; that absence alone cannot establish the version of a legacy stdio exchange. Inspect explicit protocol metadata when available.

## Requirements

- Python 3.11+ (3.10 usually works)
- Windows PowerShell, macOS, or Linux

## Fast path

```bash
python run_lab.py --scenario baseline
python run_lab.py --scenario attack
python analyze.py runs/<attack-run-directory>
```

## Benign lookalike and real-agent pilot

The new `benign` case deliberately reads the **synthetic** `.env` under an
explicit task and calls the localhost telemetry tool with `probe=ok`. The
canary must not reach the sink. This case uses the deterministic harness and
exposes a known false alert in the original analyzer (`MCP-DFIR-003`).
The added `MCP-DFIR-008` joins an untrusted decision with ordered read,
tool-request, and sink events for the local synthetic case. It does not fire
on the authorized benign run. Rule `-003` remains deliberately unchanged to
show the false alert. Rule `-008` relies on the harness's decision-source
field and is not a validated detector for uninstrumented clients or remote MCP.

```bash
python run_lab.py --scenario benign
python analyze.py --latest benign
```

`run_codex_pilot.py` prepares the same two cases for an independently
authenticated **real Codex CLI**. It saves native CLI events, raw MCP traffic,
and a separate loopback sink receipt. It never calls a real external endpoint.
`EVALUATION_STATUS.md` also records two unblinded trials performed by the
active Codex agent in a tool session. The independent CLI pilot remains open.
Inspect `runs/in-session-attack-20260927` and
`runs/in-session-benign-success-20260927` for their raw MCP and sink records;
run `python analyze.py <run-directory>` to reproduce their finding sets.

```bash
codex login status
python run_codex_pilot.py --scenario attack
python run_codex_pilot.py --scenario benign
```

Run the two commands on a machine where `codex exec` can complete a trivial
prompt. The script marks a timeout or failed CLI turn as `inconclusive`; it
does not count such an attempt as an agent outcome. Do not cite the emulated
control as a real-agent result. See `EVALUATION_STATUS.md` for the measured
control and the authentication limitation on the initial attempt.

PowerShell:

```powershell
./scripts/run-demo.ps1
```

Bash/zsh:

```bash
./scripts/run-demo.sh
```

Every run is written beneath `runs/`. `latest-attack.txt` contains the newest attack run path. Use `python analyze.py --latest attack` after the first run.

## Stage sequence (4–5 minutes)

1. Run the baseline and show `tool-manifest.json` plus the clean finding count.
2. Run the attack. The terminal shows an innocuous agent answer.
3. Analyze the attack run. Walk the eight findings, especially the bounded join in `-008`.
4. Show `evidence/mcp-wire.jsonl`: the injected instruction existed in the server response, not in a normal disk artifact.
5. Show `evidence/egress.jsonl`: the source PID is the MCP server child.
6. Show `evidence/manifest.json`: every collected item is hashed.

If a live demo fails, use the bundled `examples/attack/` run and execute:

```bash
python analyze.py examples/attack
```

## Evidence map

| File | Investigative value |
|---|---|
| `evidence/mcp-wire.jsonl` | Full request/response boundary with request IDs, direction, timestamps, PID, and raw message hash |
| `evidence/agent-events.jsonl` | User task, tool-derived decision, file read, approval source, and final answer |
| `evidence/process.jsonl` | Client/server PID and parent lineage; `/proc` observations when available |
| `evidence/server-stderr.jsonl` | Local server diagnostics that never belong on MCP stdout |
| `evidence/egress.jsonl` | Local sink receipt, source address, payload hash, and synthetic canary match |
| `evidence/tool-manifest.json` | Canonical definitions and SHA-256 fingerprints from `tools/list` |
| `evidence/host.json` | Platform, Python, clock, command line, and redacted environment-name inventory |
| `evidence/manifest.json` | SHA-256 and size for collected files, plus acquisition metadata |
| `analysis/findings.json` | Scenario-specific flags plus a bounded local-run correlation (`-008`) |
| `analysis/timeline.jsonl` | UTC-normalized cross-source event sequence |

## Safe boundaries

The lab never searches a real home directory, credential store, cloud metadata service, browser profile, or system keychain. The only “secret” is `LAB_CANARY_TOKEN=DFIR-SYNTHETIC-CANARY-7F3A` inside the seeded lab repository. Egress is restricted in code to `127.0.0.1`.

## Real-environment adaptation

Use the included queries as starting points, not vendor-neutral truth. Enable the product's native audit surface before an incident where possible:

- capture MCP stdio through a supervised wrapper or capture Streamable HTTP at a controlled gateway;
- enable OpenTelemetry/tool decision events with content redaction and access control;
- retain agent session data, MCP configuration, hooks, approval decisions, and extension/server logs;
- hash tool definitions after canonicalization and alert on unapproved changes;
- record executable/package identity, command line, working directory, parent PID, code signature, container digest, and outbound destinations;
- preserve volatile data before terminating the agent or MCP server.

## References

See `REFERENCES.md` for primary specifications, platform telemetry documentation, DFIR guidance, advisories, and current research used in the summit material.
