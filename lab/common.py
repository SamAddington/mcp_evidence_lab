from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CANARY = "DFIR-SYNTHETIC-CANARY-7F3A"
PROTOCOL = "2026-07-28"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def append_jsonl(path: Path, event: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n")


def event(kind: str, **fields: Any) -> dict[str, Any]:
    return {"ts_utc": utc_now(), "monotonic_ns": time.monotonic_ns(), "event": kind, **fields}


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        output = {}
        for key, item in value.items():
            lowered = key.lower()
            if any(term in lowered for term in ("token", "secret", "password", "authorization")):
                raw = str(item).encode("utf-8")
                output[key] = {"redacted": True, "sha256": sha256_bytes(raw), "length": len(raw)}
            else:
                output[key] = redact(item)
        return output
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def host_record(argv: list[str]) -> dict[str, Any]:
    env_names = sorted(k for k in os.environ if k.startswith(("LAB_", "MCP_", "OTEL_")))
    return event(
        "host.snapshot",
        hostname=platform.node(),
        os=platform.platform(),
        python=sys.version.split()[0],
        executable=sys.executable,
        argv=argv,
        cwd=str(Path.cwd()),
        env_names=env_names,
        pid=os.getpid(),
        ppid=os.getppid(),
    )

