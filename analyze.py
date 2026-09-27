from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from lab.common import append_jsonl


ROOT = Path(__file__).resolve().parent


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def add(findings: list[dict[str, Any]], rule: str, severity: str, title: str, evidence: list[str], detail: str) -> None:
    findings.append({"rule": rule, "severity": severity, "title": title, "evidence": evidence, "detail": detail})


def correlate_synthetic_flow(wire: list[dict[str, Any]], agent: list[dict[str, Any]], egress: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Join the lab's observed repo result, decision, read, tool request and loopback receipt.

    This is a case-specific evidence correlation, not a general injection detector.
    Monotonic timestamps and PIDs are comparable only within the same local run.
    """
    def clock(row: dict[str, Any]) -> int:
        return row.get("monotonic_ns") if isinstance(row.get("monotonic_ns"), int) else -1

    responses = [row for row in wire if row.get("direction") == "server_to_client"
                 and row.get("method") == "tools/call" and clock(row) >= 0]
    requests = [row for row in wire if row.get("direction") == "client_to_server"
                and row.get("method") == "tools/call" and clock(row) >= 0]
    for source in responses:
        trace = source.get("trace_id")
        if not trace or not any(
            request.get("trace_id") == trace
            and request.get("request_id") == source.get("request_id")
            and request.get("server_pid") == source.get("server_pid")
            and request.get("message", {}).get("params", {}).get("name") == "repo.search"
            and clock(request) <= clock(source)
            for request in requests
        ):
            continue
        for decision in agent:
            if not (decision.get("event") == "agent.decision"
                    and decision.get("action") == "file.read"
                    and decision.get("source") == "untrusted_mcp_tool_result"
                    and decision.get("approval") != "user"
                    and decision.get("trace_id") == trace
                    and clock(source) <= clock(decision)):
                continue
            for read in agent:
                if not (read.get("event") == "file.read"
                        and read.get("trace_id") == trace
                        and read.get("synthetic_canary_present") is True
                        and Path(str(read.get("path", ""))).name == Path(str(decision.get("target", ""))).name
                        and isinstance(read.get("content_sha256"), str)
                        and clock(decision) <= clock(read)):
                    continue
                for send_decision in agent:
                    if not (send_decision.get("event") == "agent.decision"
                            and send_decision.get("action") == "mcp.tools/call"
                            and send_decision.get("tool") == "telemetry.healthcheck"
                            and send_decision.get("source") == "untrusted_mcp_tool_result"
                            and send_decision.get("trace_id") == trace
                            and send_decision.get("argument_sha256") == read["content_sha256"]
                            and clock(read) <= clock(send_decision)):
                        continue
                    for request in requests:
                        if (request.get("trace_id") != trace
                                or request.get("server_pid") != source.get("server_pid")
                                or request.get("message", {}).get("params", {}).get("name") != "telemetry.healthcheck"
                                or clock(send_decision) > clock(request)):
                            continue
                        blob = request.get("message", {}).get("params", {}).get("arguments", {}).get("diagnostic_blob")
                        if not isinstance(blob, str) or hashlib.sha256(blob.encode()).hexdigest() != read["content_sha256"]:
                            continue
                        for receipt in egress:
                            if (receipt.get("event") != "network.egress_received"
                                    or receipt.get("synthetic_canary_present") is not True
                                    or receipt.get("payload", {}).get("server_pid") != source.get("server_pid")
                                    or receipt.get("payload", {}).get("diagnostic_blob") != blob
                                    or not 0 <= clock(receipt) - clock(request) <= 60_000_000_000):
                                continue
                            return {"trace_id": trace, "source_request_id": source.get("request_id"),
                                    "sink_request_id": request.get("request_id"), "server_pid": source.get("server_pid"),
                                    "content_sha256": read["content_sha256"],
                                    "event_order": [row["event"] for row in (source, decision, read, send_decision, request, receipt)]}
    return None


def analyze(run_dir: Path) -> dict[str, Any]:
    evidence = run_dir / "evidence"
    wire = load_jsonl(evidence / "mcp-wire.jsonl")
    agent = load_jsonl(evidence / "agent-events.jsonl")
    egress = load_jsonl(evidence / "egress.jsonl")
    process = load_jsonl(evidence / "process.jsonl")
    stderr = load_jsonl(evidence / "server-stderr.jsonl")
    findings: list[dict[str, Any]] = []

    manifest = json.loads((evidence / "tool-manifest.json").read_text(encoding="utf-8"))
    defs = {item["name"]: item for item in manifest["tools"]}
    repo_desc = defs.get("repo.search", {}).get("definition", {}).get("description", "")
    if "diagnostic note" in repo_desc:
        add(findings, "MCP-DFIR-001", "high", "Tool definition contains instruction-like hidden content", ["evidence/tool-manifest.json"], "Hash the full canonical definition, not the displayed title or name.")
    if any("[AGENT_INSTRUCTION]" in json.dumps(row) for row in wire):
        add(findings, "MCP-DFIR-002", "critical", "MCP tool result carried an agent-directed instruction", ["evidence/mcp-wire.jsonl"], "The instruction existed on the stdio wire and may not survive server shutdown.")
    if any(row.get("event") == "file.read" and row.get("synthetic_canary_present") for row in agent):
        add(findings, "MCP-DFIR-003", "high", "Tool-derived decision crossed into a sensitive file read", ["evidence/agent-events.jsonl"], "Correlate the decision source, approval source, path, and content hash.")
    if any(row.get("synthetic_canary_present") for row in egress):
        add(findings, "MCP-DFIR-004", "critical", "Synthetic secret reached an MCP-server egress sink", ["evidence/egress.jsonl", "evidence/process.jsonl"], "Attribute the connection to the MCP server/helper process, not merely to the host agent.")
    if any(row.get("role") == "mcp_helper" for row in process) or any('process.spawn' in row.get("line", "") for row in stderr):
        add(findings, "MCP-DFIR-005", "medium", "Ephemeral MCP child process observed", ["evidence/process.jsonl", "evidence/server-stderr.jsonl"], "Corroborate server diagnostics with EDR or live process telemetry; a later disk image will not reconstruct a short-lived process tree.")
    if wire and all("Mcp-Session-Id" not in json.dumps(row) for row in wire):
        add(findings, "MCP-DFIR-006", "info", "Modern stateless MCP traffic detected", ["evidence/mcp-wire.jsonl"], "Use per-request protocol metadata, JSON-RPC IDs, trace IDs, PID lineage, and time—not a removed protocol session header.")
    if any(row.get("event") == "agent.final" and not row.get("disclosure_of_validation_step", True) for row in agent) and egress:
        add(findings, "MCP-DFIR-007", "high", "Agent narrative diverges from trace evidence", ["evidence/agent-events.jsonl", "evidence/egress.jsonl"], "Treat the final answer as a claim, not as the audit record.")

    chain = correlate_synthetic_flow(wire, agent, egress)
    if chain:
        findings.append({"rule": "MCP-DFIR-008", "severity": "high",
                         "title": "Matched untrusted decision, file content and loopback receipt",
                         "evidence": ["evidence/mcp-wire.jsonl", "evidence/agent-events.jsonl", "evidence/egress.jsonl"],
                         "detail": "Local-run correlation by trace, event order, server PID and SHA-256 of the read content. The decision-source label comes from the lab harness; this is not an independently validated production detector.",
                         "correlation": chain})

    timeline = sorted(wire + agent + egress + process + stderr, key=lambda row: (row.get("ts_utc", ""), row.get("monotonic_ns", 0)))
    analysis_dir = run_dir / "analysis"
    analysis_dir.mkdir(exist_ok=True)
    (analysis_dir / "findings.json").write_text(json.dumps({"run": str(run_dir), "finding_count": len(findings), "findings": findings}, indent=2, sort_keys=True), encoding="utf-8")
    (analysis_dir / "timeline.jsonl").write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in timeline), encoding="utf-8")
    return {"findings": findings, "timeline": timeline}


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze MCP Evidence Lab output")
    parser.add_argument("run_dir", nargs="?", type=Path)
    parser.add_argument("--latest", choices=("baseline", "attack", "benign"))
    args = parser.parse_args()
    run_dir = args.run_dir
    if args.latest:
        run_dir = Path((ROOT / f"latest-{args.latest}.txt").read_text(encoding="utf-8").strip())
    if run_dir is None:
        parser.error("provide run_dir or --latest")
    result = analyze(run_dir)
    print(f"RUN       {run_dir}")
    print(f"FINDINGS  {len(result['findings'])}")
    for finding in result["findings"]:
        print(f"{finding['severity'].upper():8} {finding['rule']}  {finding['title']}")
    print("\nCORRELATED TIMELINE")
    for row in result["timeline"]:
        marker = row.get("event", "event")
        detail = row.get("method") or row.get("action") or row.get("role") or row.get("path", "")
        print(f"{row.get('ts_utc', '')}  {marker:24} {detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
