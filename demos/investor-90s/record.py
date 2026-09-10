#!/usr/bin/env python3
"""Record go run ./examples/demo-runner -investor into a branded 1280x720 mp4.

The frames are the real process stdout. Captions are keyed off printed lines,
not invented allow/deny decisions.
"""

from __future__ import annotations

import os
import pty
import select
import subprocess
import sys
import time
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent / "investor-90s.mp4"

W, H, FPS = 1280, 720, 12
BG = (18, 16, 12)
INK = (242, 237, 228)
DIM = (181, 172, 157)
ACCENT = (195, 159, 119)
DENY = (208, 101, 90)
ALLOW = (143, 174, 126)
RULE = (51, 45, 36)

CAPTIONS = (
    ("Building local Visor", "The agent can request any tool. Visor decides before the server sees it."),
    ("PROOF", "Local synthetic server. Real Visor proxy. No LLM in the loop."),
    ("POLICY", "After a sensitive read, egress is forbidden for the session."),
    ("1  ALLOW", "Benign read. Allowed and relayed."),
    ("2  ALLOW + TAINT", "Secrets read. Allowed — and the session is now tainted."),
    ("3  DENY", "Egress. Denied. Zero relay."),
    ("4  SERVER OBSERVED", "The server saw both reads. It never saw the post."),
    ("5  DECISION EVIDENCE", "Deny is in the audit log. Deterministic."),
    ("Model proposed.", "Model proposed. Policy authorized. Proxy enforced."),
)


def font(size: int, mono: bool = False) -> ImageFont.FreeTypeFont:
    path = (
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
        if mono
        else "/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf"
    )
    return ImageFont.truetype(path, size)


def caption_for(text: str) -> str:
    chosen = CAPTIONS[0][1]
    for needle, line in CAPTIONS:
        if needle in text:
            chosen = line
    return chosen


def draw_frame(lines: list[str], caption: str) -> Image.Image:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    serif, mono, small = font(22), font(18, True), font(14, True)
    d.text((48, 36), "MCP Visor", font=serif, fill=ACCENT)
    d.text((200, 42), "90-second action-boundary proof", font=small, fill=DIM)
    d.rectangle((48, 72, W - 48, 73), fill=RULE)

    y = 100
    body = lines[-18:]
    for raw in body:
        line = raw.rstrip("\n")[:92]
        fill = INK
        if line.startswith("3  DENY") or "decision=deny" in line or line.startswith("   http_post"):
            fill = DENY
        elif "ALLOW" in line[:12] or line.startswith("1  ") or line.startswith("2  "):
            fill = ALLOW
        elif line.startswith("PROOF") or line.startswith("POLICY") or line == "MCP Visor":
            fill = ACCENT
        d.text((56, y), line, font=mono, fill=fill)
        y += 26
        if y > H - 140:
            break

    d.rectangle((48, H - 118, W - 48, H - 117), fill=RULE)
    d.text((56, H - 96), caption, font=serif, fill=INK)
    d.text((56, H - 52), "Recording of  go run ./examples/demo-runner -investor", font=small, fill=DIM)
    return img


def main() -> int:
    os.chdir(ROOT)
    env = os.environ.copy()
    env["TERM"] = "xterm-256color"

    master, slave = pty.openpty()
    proc = subprocess.Popen(
        ["go", "run", "./examples/demo-runner", "-investor"],
        cwd=ROOT,
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env=env,
        close_fds=True,
    )
    os.close(slave)

    ffmpeg = subprocess.Popen(
        [
            "ffmpeg",
            "-y",
            "-f",
            "rawvideo",
            "-pix_fmt",
            "rgb24",
            "-s",
            f"{W}x{H}",
            "-r",
            str(FPS),
            "-i",
            "-",
            "-an",
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            "-crf",
            "20",
            "-movflags",
            "+faststart",
            str(OUT),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    assert ffmpeg.stdin is not None

    buf = ""
    lines: list[str] = [""]
    caption = CAPTIONS[0][1]
    interval = 1.0 / FPS
    start = time.monotonic()
    next_frame = start
    max_s = 95.0
    eof = False

    def blit() -> None:
        frame = draw_frame(lines, caption)
        ffmpeg.stdin.write(frame.tobytes())

    try:
        while True:
            now = time.monotonic()
            if now - start > max_s:
                proc.kill()
                break
            timeout = max(0.0, next_frame - now)
            ready, _, _ = select.select([master], [], [], timeout)
            if ready:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    chunk = b""
                if not chunk:
                    eof = True
                else:
                    buf += chunk.decode("utf-8", errors="replace")
                    while "\n" in buf:
                        line, buf = buf.split("\n", 1)
                        lines.append(line)
                        caption = caption_for("\n".join(lines[-30:]))
            now = time.monotonic()
            if now >= next_frame:
                blit()
                next_frame += interval
            dead = proc.poll() is not None
            if dead and (eof or not ready):
                if buf.strip():
                    lines.append(buf)
                    buf = ""
                caption = caption_for("\n".join(lines[-30:]))
                for _ in range(FPS * 3):
                    blit()
                break
    finally:
        try:
            os.close(master)
        except OSError:
            pass
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        ffmpeg.stdin.close()
        ffmpeg.wait()

    if ffmpeg.returncode not in (0, None) and ffmpeg.returncode != 0:
        print(f"ffmpeg failed: {ffmpeg.returncode}", file=sys.stderr)
        return 1
    if not OUT.is_file() or OUT.stat().st_size < 1000:
        print("record failed: empty mp4", file=sys.stderr)
        return 1
    probe = subprocess.check_output(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(OUT)],
        text=True,
    ).strip()
    duration = float(probe)
    if duration < 60 or duration > 95:
        print(f"record failed: duration {duration:.1f}s not in 60-95s", file=sys.stderr)
        return 1
    print(f"{OUT}  {duration:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
