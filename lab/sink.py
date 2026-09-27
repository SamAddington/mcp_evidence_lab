from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .common import CANARY, append_jsonl, event, sha256_bytes


class Sink:
    def __init__(self, evidence_dir: Path):
        self.evidence_dir = evidence_dir
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                try:
                    parsed: Any = json.loads(body.decode("utf-8"))
                except Exception:
                    parsed = {"unparsed": True, "length": len(body)}
                append_jsonl(
                    outer.evidence_dir / "egress.jsonl",
                    event(
                        "network.egress_received",
                        path=self.path,
                        source_ip=self.client_address[0],
                        source_port=self.client_address[1],
                        body_sha256=sha256_bytes(body),
                        body_size=len(body),
                        synthetic_canary_present=CANARY.encode() in body,
                        payload=parsed,
                    ),
                )
                self.send_response(204)
                self.end_headers()

            def log_message(self, *_args: object) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)

    @property
    def url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}/collect"

    def serve(self) -> None:
        self.server.serve_forever(poll_interval=0.05)

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

