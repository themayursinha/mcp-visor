#!/usr/bin/env python3
"""Fail-closed proof that mcp-visor enforces the Qwen-MM-Plugins allowlist.

Spawns `mcp-visor serve` wrapping the Qwen core server (uvx, git commit
ec9fbd1e11a30841685b949863e9d9d30cd7a4d8 = tag qwen-mm-plugins-core-v1.0.2).

Exits 0 only when all of these hold:
  1. initialize returns a result
  2. tools/list advertises the 7 core tools (including denied names)
  3. read_image and media_info return JSON-RPC results (not errors)
  4. crop and visualize return JSON-RPC -32000 containing "not registered"
  5. the durable audit ledger records tool_call_allowed for (3) and
     tool_call_denied for (4), with hash-chain linkage

This client does not wrap the third-party server with an observe-log.
Non-relay of denied calls is visor's deny-before-relay invariant, evidenced
here by a visor JSON-RPC error (not a tool result) plus tool_call_denied.

Run:  python3 examples/qwen-mm-plugins-demo/demo-client.py
"""
from __future__ import annotations

import json
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from pathlib import Path
from typing import Any, IO

Json = dict[str, Any]

REPO = Path(__file__).resolve().parents[2]
VISOR = REPO / "mcp-visor"
POLICY = REPO / "examples" / "policies" / "qwen-mm-plugins.yaml"
# Annotated tag qwen-mm-plugins-core-v1.0.2 -> commit (not a movable tag name).
QWEN_COMMIT = "ec9fbd1e11a30841685b949863e9d9d30cd7a4d8"
SRC = (
    "qwen-mm-plugins[core] @ git+https://github.com/QwenLM/"
    f"Qwen-MM-Plugins.git@{QWEN_COMMIT}"
)
CORE_TOOLS = {
    "crop",
    "draw_bbox",
    "media_info",
    "read_image",
    "read_video",
    "save_view",
    "visualize",
}
DENIED_CODE = -32000


class ProofError(Exception):
    """Proof client failed closed."""


def write_png(path: Path) -> None:
    """Write a 1x1 red PNG with stdlib only."""

    def chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    raw = b"\x00\xff\x00\x00"  # filter 0 + RGB red
    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )
    path.write_bytes(png)


def write_mp4(path: Path) -> None:
    ffmpeg = shutil.which("ffmpeg")
    if ffmpeg is None:
        raise ProofError("ffmpeg not found on PATH (required for media_info fixture)")
    result = subprocess.run(
        [
            ffmpeg, "-y", "-hide_banner", "-loglevel", "error",
            "-f", "lavfi", "-i", "color=c=red:s=32x32:d=1",
            "-pix_fmt", "yuv420p", str(path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 or not path.is_file():
        err = (result.stderr or result.stdout or "").strip()
        raise ProofError(f"ffmpeg failed to write {path}: {err}")


def require_visor() -> None:
    if VISOR.is_file():
        return
    raise ProofError(
        f"visor binary not found at {VISOR}; run `make build` from the repo root"
    )


def require_uvx() -> str:
    uvx = shutil.which("uvx")
    if uvx is None:
        raise ProofError("uvx not found on PATH - install uv (https://docs.astral.sh/uv/)")
    return uvx


def drain_stderr(stream: IO[str], lines: list[str]) -> None:
    for line in stream:
        lines.append(line.rstrip("\n"))


class VisorClient:
    def __init__(self, proc: subprocess.Popen[str]) -> None:
        self.proc = proc
        self._id = 0
        assert proc.stdin is not None and proc.stdout is not None
        self.stdin = proc.stdin
        self.stdout = proc.stdout

    def notify(self, method: str, params: Json | None = None) -> None:
        msg: Json = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.stdin.write(json.dumps(msg) + "\n")
        self.stdin.flush()

    def call(self, method: str, params: Json | None = None, timeout: float = 240) -> Json:
        self._id += 1
        expect_id = self._id
        msg: Json = {"jsonrpc": "2.0", "id": expect_id, "method": method}
        if params is not None:
            msg["params"] = params
        self.stdin.write(json.dumps(msg) + "\n")
        self.stdin.flush()
        return self._recv_until(expect_id, timeout)

    def _recv_until(self, expect_id: int, timeout: float) -> Json:
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = self.stdout.readline()
            if line == "":
                if self.proc.poll() is not None:
                    raise ProofError(f"visor exited rc={self.proc.returncode}")
                time.sleep(0.05)
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") == expect_id:
                return msg
        raise ProofError(f"timeout waiting for id {expect_id}")


def text_of(r: Json) -> str:
    result = r.get("result")
    if not isinstance(result, dict):
        return ""
    return " ".join(
        c.get("text", "") for c in result.get("content", [])
        if isinstance(c, dict) and c.get("type") == "text"
    )


def require_result(r: Json, tool: str) -> Json:
    if r.get("error"):
        raise ProofError(f"{tool} must be allowed, got error: {r.get('error')}")
    result = r.get("result")
    if not isinstance(result, dict):
        raise ProofError(f"{tool} missing result: {r}")
    if result.get("isError"):
        raise ProofError(f"{tool} result isError=true: {text_of(r)[:200]}")
    return result


def require_denied(r: Json, tool: str) -> None:
    err = r.get("error")
    if not isinstance(err, dict):
        raise ProofError(f"{tool} must be denied by visor, got: {r}")
    if err.get("code") != DENIED_CODE:
        raise ProofError(f"{tool} deny code want {DENIED_CODE}, got {err}")
    message = str(err.get("message", ""))
    if "not registered" not in message or tool not in message:
        raise ProofError(
            f"{tool} deny message must cite unregistered tool, got {message!r}"
        )


def read_audit(path: Path) -> list[Json]:
    if not path.is_file():
        raise ProofError(f"audit ledger missing: {path}")
    events: list[Json] = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ProofError(f"corrupt audit line: {line!r}") from exc
    return events


def require_audit(events: list[Json], allowed: list[str], denied: list[str]) -> None:
    if not events:
        raise ProofError("audit ledger is empty")
    by_type_tool: dict[tuple[str, str], int] = {}
    for ev in events:
        key = (str(ev.get("event_type", "")), str(ev.get("tool", "")))
        by_type_tool[key] = by_type_tool.get(key, 0) + 1
    for tool in allowed:
        if by_type_tool.get(("tool_call_allowed", tool), 0) < 1:
            raise ProofError(f"audit missing tool_call_allowed for {tool}")
        if by_type_tool.get(("tool_call_denied", tool), 0) != 0:
            raise ProofError(f"audit has unexpected tool_call_denied for allowed {tool}")
    for tool in denied:
        if by_type_tool.get(("tool_call_denied", tool), 0) < 1:
            raise ProofError(f"audit missing tool_call_denied for {tool}")
        if by_type_tool.get(("tool_call_allowed", tool), 0) != 0:
            raise ProofError(f"audit has unexpected tool_call_allowed for denied {tool}")
        reasons = [
            str(ev.get("reason", ""))
            for ev in events
            if ev.get("event_type") == "tool_call_denied" and ev.get("tool") == tool
        ]
        if not any("not registered" in reason for reason in reasons):
            raise ProofError(
                f"audit deny for {tool} must cite unregistered tool, got {reasons}"
            )
    if any(not ev.get("hash") for ev in events):
        raise ProofError("audit record missing hash")
    if len(events) < 2:
        raise ProofError("audit hash chain missing (need at least two records)")
    prev = events[0]
    for ev in events[1:]:
        if ev.get("prev_hash") != prev.get("hash"):
            raise ProofError(
                f"audit prev_hash mismatch at chain_index={ev.get('chain_index')}"
            )
        prev = ev


def stop_proc(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def run() -> None:
    require_visor()
    uvx = require_uvx()
    if not POLICY.is_file():
        raise ProofError(f"policy missing: {POLICY}")

    workdir = Path(tempfile.mkdtemp(prefix="qwen-demo-"))
    audit = workdir / "audit.jsonl"
    png = workdir / "red.png"
    mp4 = workdir / "test.mp4"
    write_png(png)
    write_mp4(mp4)
    print(f"workdir: {workdir}")

    cmd = [
        str(VISOR), "serve",
        "-server", uvx,
        "-server-arg", "--from",
        "-server-arg", SRC,
        "-server-arg", "qwen-mm-plugins-core",
        "-server-name", "qwen-mm-plugins-core",
        "-policy", str(POLICY),
        "-audit-log", str(audit),
        "-session-id", "demo-qwen",
        "-client-id", "demo-client",
        "-log-level", "warn",
    ]
    stderr_lines: list[str] = []
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    assert proc.stderr is not None
    threading.Thread(target=drain_stderr, args=(proc.stderr, stderr_lines), daemon=True).start()
    client = VisorClient(proc)
    try:
        init = client.call("initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "visor-demo-client", "version": "1.0"},
        })
        if init.get("error") or not isinstance(init.get("result"), dict):
            raise ProofError(f"initialize failed: {init}")
        print("== initialize ==")
        print("  server:", init["result"].get("serverInfo"))
        client.notify("notifications/initialized")

        tl = client.call("tools/list")
        if tl.get("error"):
            raise ProofError(f"tools/list failed: {tl.get('error')}")
        tools = (tl.get("result") or {}).get("tools") or []
        names = sorted(t["name"] for t in tools if isinstance(t, dict) and "name" in t)
        print("== tools/list ==")
        print(f"  {len(names)} tools: {', '.join(names)}")
        missing = CORE_TOOLS.difference(names)
        if missing:
            raise ProofError(f"tools/list missing {sorted(missing)}; got {names}")

        r = client.call("tools/call", {
            "name": "read_image",
            "arguments": {"image_path": str(png), "budget": "small"},
        })
        require_result(r, "read_image")
        print("== read_image (ALLOWED) ==")
        print("  ", text_of(r)[:120])

        r = client.call("tools/call", {
            "name": "media_info",
            "arguments": {"path": str(mp4)},
        })
        require_result(r, "media_info")
        print("== media_info (ALLOWED) ==")
        print("  ", text_of(r)[:140])

        for denied_tool, args in [
            ("crop", {"image_path": str(png)}),
            ("visualize", {"path": str(png)}),
        ]:
            r = client.call("tools/call", {"name": denied_tool, "arguments": args})
            require_denied(r, denied_tool)
            err = r["error"]
            print(f"== {denied_tool} (DENIED) ==")
            print(f"  error: {err.get('code')} {err.get('message')}")

        time.sleep(0.2)
        require_audit(read_audit(audit), ["read_image", "media_info"], ["crop", "visualize"])
        print(f"PASS audit ledger {audit}")
    except ProofError:
        if stderr_lines:
            print("== visor stderr ==", file=sys.stderr)
            print("\n".join(stderr_lines[-80:]), file=sys.stderr)
        raise
    finally:
        stop_proc(proc)


if __name__ == "__main__":
    try:
        run()
    except ProofError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
    except BrokenPipeError:
        print("FAIL: visor pipe closed", file=sys.stderr)
        sys.exit(1)
