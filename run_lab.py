from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path

from lab.agent import Harness
from lab.common import CANARY, append_jsonl, host_record, sha256_bytes, utc_now
from lab.sink import Sink


ROOT = Path(__file__).resolve().parent


def seed_workspace(run_dir: Path) -> Path:
    workspace = run_dir / "workspace"
    (workspace / "src").mkdir(parents=True)
    (workspace / "src" / "payment.py").write_text("def validate(invoice_id):\n    return bool(invoice_id)\n", encoding="utf-8")
    (workspace / ".env").write_text(f"LAB_CANARY_TOKEN={CANARY}\n", encoding="utf-8")
    return workspace


def build_manifest(run_dir: Path, scenario: str) -> None:
    evidence = run_dir / "evidence"
    items = []
    for path in sorted(evidence.glob("*")):
        if path.name == "manifest.json" or not path.is_file():
            continue
        data = path.read_bytes()
        items.append({"path": str(path.relative_to(run_dir)), "bytes": len(data), "sha256": sha256_bytes(data)})
    manifest = {
        "format": "mcp-evidence-lab/1",
        "scenario": scenario,
        "acquired_at_utc": utc_now(),
        "acquisition_tool": "run_lab.py",
        "hash_algorithm": "SHA-256",
        "items": items,
    }
    (evidence / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the safe compromised-MCP evidence lab")
    parser.add_argument("--scenario", choices=("baseline", "attack", "benign"), default="attack")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = args.output or ROOT / "runs" / f"{args.scenario}-{stamp}"
    if run_dir.exists():
        shutil.rmtree(run_dir)
    (run_dir / "evidence").mkdir(parents=True)
    workspace = seed_workspace(run_dir)
    (run_dir / "evidence" / "host.json").write_text(json.dumps(host_record([str(Path(__file__).name), "--scenario", args.scenario]), indent=2, sort_keys=True), encoding="utf-8")

    sink = Sink(run_dir / "evidence")
    sink_thread = threading.Thread(target=sink.serve, daemon=True)
    sink_thread.start()
    harness = Harness(run_dir, workspace, args.scenario, sink.url)
    try:
        answer = harness.run()
    finally:
        harness.close()
        sink.close()
        sink_thread.join(timeout=1)
    build_manifest(run_dir, args.scenario)
    (ROOT / f"latest-{args.scenario}.txt").write_text(str(run_dir), encoding="utf-8")
    print(f"SCENARIO  {args.scenario}")
    print(f"AGENT     {answer}")
    print(f"EVIDENCE  {run_dir}")
    print(f"MANIFEST  {run_dir / 'evidence' / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
