#!/usr/bin/env python3
"""MCP stdio client proving mcp-visor enforcement against the real
Qwen-MM-Plugins core MCP server (examples/qwen-mm-plugins-demo).

Spawns `mcp-visor serve` wrapping the Qwen core server (uvx, git tag
qwen-mm-plugins-core-v1.0.2), then:
  1. initialize
  2. tools/list                       -> expect the 7 core tools
  3. tools/call read_image (allowed)  -> relayed, real result
  4. tools/call media_info (allowed)  -> relayed, real result
  5. tools/call crop (denied)         -> JSON-RPC error before relay
  6. tools/call visualize (denied)    -> JSON-RPC error before relay

Run:  python3 examples/qwen-mm-plugins-demo/demo-client.py
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

Json = dict[str, Any]

REPO = Path(__file__).resolve().parents[2]
VISOR = REPO / "mcp-visor"
POLICY = REPO / "examples" / "policies" / "qwen-mm-plugins.yaml"
AUDIT = "/tmp/qwen-demo/audit.jsonl"
UVX = shutil.which("uvx") or "/home/mayur/.local/bin/uvx"  # requires uv; see README
SRC = ("qwen-mm-plugins[core] @ git+https://github.com/QwenLM/"
       "Qwen-MM-Plugins.git@qwen-mm-plugins-core-v1.0.2")

CMD = [
    str(VISOR), "serve",
    "-server", UVX,
    "-server-arg", "--from",
    "-server-arg", SRC,
    "-server-arg", "qwen-mm-plugins-core",
    "-server-name", "qwen-mm-plugins-core",
    "-policy", str(POLICY),
    "-audit-log", AUDIT,
    "-session-id", "demo-qwen",
    "-client-id", "demo-client",
    "-log-level", "warn",
]

proc = subprocess.Popen(
    CMD, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL, text=True, bufsize=1,
)
assert proc.stdin is not None and proc.stdout is not None
_id = 0


def send(msg: Json) -> int:
    global _id
    if "id" not in msg:
        _id += 1
        msg["id"] = _id
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()
    return int(msg["id"])


def recv_until(expect_id: int, timeout: float = 240) -> Json:
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line == "":
            if proc.poll() is not None:
                raise RuntimeError(f"visor exited rc={proc.returncode}")
            time.sleep(0.1)
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("id") == expect_id:
            return msg
    raise RuntimeError(f"timeout waiting for id {expect_id}")


def call(method: str, params: Json | None = None) -> Json:
    msg: Json = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    return recv_until(send(msg))


def text_of(r: Json) -> str:
    result = r.get("result")
    if not isinstance(result, dict):
        return ""
    return " ".join(
        c.get("text", "") for c in result.get("content", [])
        if isinstance(c, dict) and c.get("type") == "text"
    )


def main() -> int:
    init = call("initialize", {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "visor-demo-client", "version": "1.0"},
    })
    print("== initialize ==")
    print("  server:", init.get("result", {}).get("serverInfo"))
    time.sleep(1.0)  # let the server finish the handshake before tools/list
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    tl = call("tools/list")
    names = sorted(t["name"] for t in tl.get("result", {}).get("tools", []))
    print("== tools/list ==")
    print(f"  {len(names)} tools: {', '.join(names)}")

    r = call("tools/call", {"name": "read_image",
                            "arguments": {"image_path": "/tmp/qwen-demo/red.png",
                                          "budget": "small"}})
    print("== read_image (ALLOWED) ==")
    print("  isError:", r.get("result", {}).get("isError"), "|", text_of(r)[:120])

    r = call("tools/call", {"name": "media_info",
                            "arguments": {"path": "/tmp/qwen-demo/test.mp4"}})
    print("== media_info (ALLOWED) ==")
    print("  isError:", r.get("result", {}).get("isError"), "|", text_of(r)[:140])

    for denied_tool, args in [
        ("crop", {"image_path": "/tmp/qwen-demo/red.png"}),
        ("visualize", {"path": "/tmp/qwen-demo/red.png"}),
    ]:
        r = call("tools/call", {"name": denied_tool, "arguments": args})
        err = r.get("error") or {}
        print(f"== {denied_tool} (DENIED) ==")
        print(f"  error: {err.get('code')} {err.get('message')}")

    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
