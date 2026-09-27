from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class LabTest(unittest.TestCase):
    def run_case(self, scenario: str) -> tuple[Path, dict]:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        out = Path(temp.name) / scenario
        subprocess.run([sys.executable, "run_lab.py", "--scenario", scenario, "--output", str(out)], cwd=ROOT, check=True, capture_output=True, text=True)
        subprocess.run([sys.executable, "analyze.py", str(out)], cwd=ROOT, check=True, capture_output=True, text=True)
        findings = json.loads((out / "analysis" / "findings.json").read_text(encoding="utf-8"))
        return out, findings

    def test_baseline_has_no_critical_finding(self) -> None:
        _out, findings = self.run_case("baseline")
        self.assertFalse(any(item["severity"] == "critical" for item in findings["findings"]))

    def test_attack_correlates_wire_file_and_egress(self) -> None:
        out, findings = self.run_case("attack")
        ids = {item["rule"] for item in findings["findings"]}
        self.assertTrue({"MCP-DFIR-002", "MCP-DFIR-003", "MCP-DFIR-004", "MCP-DFIR-007", "MCP-DFIR-008"}.issubset(ids))
        chain = next(item["correlation"] for item in findings["findings"] if item["rule"] == "MCP-DFIR-008")
        self.assertEqual(chain["source_request_id"] + 1, chain["sink_request_id"])
        manifest = json.loads((out / "evidence" / "manifest.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(manifest["items"]), 7)

    def test_benign_lookalike_exposes_false_alert(self) -> None:
        out, findings = self.run_case("benign")
        ids = {item["rule"] for item in findings["findings"]}
        self.assertIn("MCP-DFIR-003", ids)  # Known false alert: no authorization check.
        self.assertNotIn("MCP-DFIR-008", ids)  # Authorization and content joins prevent this particular alert.
        self.assertNotIn("MCP-DFIR-004", ids)  # The canary did not reach the sink.
        self.assertNotIn("MCP-DFIR-007", ids)
        egress = (out / "evidence" / "egress.jsonl").read_text(encoding="utf-8")
        self.assertIn('"synthetic_canary_present": false', egress)

    def test_correlation_rejects_mismatched_sink_content(self) -> None:
        from analyze import analyze

        out, findings = self.run_case("attack")
        self.assertIn("MCP-DFIR-008", {item["rule"] for item in findings["findings"]})
        path = out / "evidence" / "egress.jsonl"
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        rows[0]["payload"]["diagnostic_blob"] = "different synthetic value"
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        ids = {item["rule"] for item in analyze(out)["findings"]}
        self.assertNotIn("MCP-DFIR-008", ids)

    def test_correlation_rejects_user_approved_read(self) -> None:
        from analyze import analyze

        out, _findings = self.run_case("attack")
        path = out / "evidence" / "agent-events.jsonl"
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        next(row for row in rows if row.get("event") == "agent.decision" and row.get("action") == "file.read")["approval"] = "user"
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        ids = {item["rule"] for item in analyze(out)["findings"]}
        self.assertNotIn("MCP-DFIR-008", ids)


if __name__ == "__main__":
    unittest.main()
