"""
wireshark-claude-bridge: MCP server
-----------------------------------
Two halves:
  1. Analysis  - runs tshark against the same capture file the GUI has open.
  2. GUI control - queues commands in a bridge folder; the companion Lua plugin
     (claude_bridge.lua) executes them inside Wireshark when you click
     Tools > Claude > Sync.

Requires: Python 3.10+, `pip install "mcp<2"`, Wireshark (tshark) installed.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# --------------------------------------------------------------------------
# Locations
# --------------------------------------------------------------------------

def _wireshark_conf_dir() -> Path:
    if os.environ.get("WS_CLAUDE_CONF_DIR"):
        return Path(os.environ["WS_CLAUDE_CONF_DIR"])
    if sys.platform.startswith("win"):
        return Path(os.environ["APPDATA"]) / "Wireshark"
    if sys.platform == "darwin":
        return Path.home() / ".config" / "wireshark"
    return Path.home() / ".config" / "wireshark"


CONF_DIR = _wireshark_conf_dir()
BRIDGE_DIR = CONF_DIR / "claude_bridge"
COMMANDS_FILE = BRIDGE_DIR / "commands.txt"
STATE_FILE = BRIDGE_DIR / "state.txt"
CONTEXT_FILE = BRIDGE_DIR / "context.txt"
SESSION_FILE = BRIDGE_DIR / "session.json"
PROFILE_NAME = "Claude"
PROFILE_DIR = CONF_DIR / "profiles" / PROFILE_NAME

BRIDGE_DIR.mkdir(parents=True, exist_ok=True)


def _find_tshark() -> str:
    if os.environ.get("TSHARK_PATH"):
        return os.environ["TSHARK_PATH"]
    found = shutil.which("tshark")
    if found:
        return found
    win_default = Path(r"C:\Program Files\Wireshark\tshark.exe")
    if win_default.exists():
        return str(win_default)
    raise RuntimeError("tshark not found. Install Wireshark or set TSHARK_PATH.")


TSHARK = _find_tshark()
MAX_OUTPUT_CHARS = 20000

mcp = FastMCP("wireshark-claude-bridge")

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _load_session() -> dict:
    try:
        return json.loads(SESSION_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_session(data: dict) -> None:
    SESSION_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _capture_path(path: str | None = None) -> str:
    p = path or _load_session().get("capture")
    if not p:
        raise ValueError("No capture selected. Call set_capture(path) first.")
    if not Path(p).exists():
        raise FileNotFoundError(f"Capture not found: {p}")
    return p


def _run_tshark(args: list[str], timeout: int = 120) -> str:
    proc = subprocess.run(
        [TSHARK, *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"tshark exited {proc.returncode}")
    out = proc.stdout
    if len(out) > MAX_OUTPUT_CHARS:
        out = out[:MAX_OUTPUT_CHARS] + f"\n... [truncated, {len(proc.stdout)} chars total]"
    return out


def _validate_filter(expr: str) -> None:
    """Fail fast on a bad display filter before it reaches the GUI."""
    _run_tshark(["-r", _capture_path(), "-Y", expr, "-c", "1", "-T", "fields", "-e", "frame.number"])


_SAFE_TEXT = re.compile(r"^[^\t\r\n]*$")


def _queue(*parts: str) -> None:
    """Append one tab-separated command line for the Lua plugin."""
    for p in parts:
        if not _SAFE_TEXT.match(p):
            raise ValueError("Command arguments may not contain tabs or newlines.")
    line = "\t".join(parts) + "\n"
    existing = COMMANDS_FILE.read_text(encoding="utf-8") if COMMANDS_FILE.exists() else ""
    tmp = COMMANDS_FILE.with_suffix(".tmp")
    tmp.write_text(existing + line, encoding="utf-8")
    os.replace(tmp, COMMANDS_FILE)


SYNC_HINT = " Queued. Click Tools > Claude > Sync in Wireshark to apply."

# --------------------------------------------------------------------------
# Analysis tools (tshark)
# --------------------------------------------------------------------------

@mcp.tool()
def set_capture(path: str, open_in_gui: bool = True) -> str:
    """Select the capture file to analyse. Optionally queue opening it in the Wireshark GUI
    so Claude and the GUI are looking at the same file."""
    p = str(Path(path).expanduser().resolve())
    if not Path(p).exists():
        raise FileNotFoundError(p)
    s = _load_session()
    s["capture"] = p
    _save_session(s)
    if open_in_gui:
        _queue("open", p)
        return f"Capture set to {p}." + SYNC_HINT
    return f"Capture set to {p}."


@mcp.tool()
def capture_summary() -> str:
    """Packet count, duration, protocol hierarchy and top IP conversations."""
    cap = _capture_path()
    phs = _run_tshark(["-r", cap, "-q", "-z", "io,phs"])
    conv = _run_tshark(["-r", cap, "-q", "-z", "conv,ip"])
    conv_lines = conv.splitlines()[:35]
    return phs + "\n" + "\n".join(conv_lines)


@mcp.tool()
def query_packets(
    display_filter: str = "",
    fields: list[str] | None = None,
    limit: int = 200,
) -> str:
    """Return a tab-separated table of packets matching a Wireshark display filter.
    `fields` are Wireshark field names (e.g. ip.src, ip.ttl, dns.qry.name).
    frame.number and frame.time_relative are always included first."""
    cap = _capture_path()
    cols = ["frame.number", "frame.time_relative"] + [f for f in (fields or ["_ws.col.Source", "_ws.col.Destination", "_ws.col.Protocol", "_ws.col.Info"]) if f not in ("frame.number", "frame.time_relative")]
    args = ["-r", cap, "-T", "fields", "-E", "header=y", "-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=,"]
    if display_filter:
        args += ["-Y", display_filter]
    for c in cols:
        args += ["-e", c]
    out = _run_tshark(args)
    lines = out.splitlines()
    total = max(len(lines) - 1, 0)
    if total > limit:
        lines = lines[: limit + 1] + [f"... {total - limit} more rows (raise limit or narrow the filter)"]
    return f"{total} matching packets\n" + "\n".join(lines)


@mcp.tool()
def frame_detail(frame_number: int, layers: str = "") -> str:
    """Full protocol tree (like the Packet Details pane) for one frame.
    Optionally restrict to layers, e.g. 'ip,udp,mdns'."""
    cap = _capture_path()
    args = ["-r", cap, "-Y", f"frame.number == {int(frame_number)}", "-V"]
    if layers:
        args += ["-O", layers]
    return _run_tshark(args)


@mcp.tool()
def stats(kind: str) -> str:
    """Run a tshark -z statistic, e.g. 'conv,udp', 'endpoints,ip', 'io,stat,1',
    'dns,tree', 'http,tree', 'expert'."""
    if not re.fullmatch(r"[A-Za-z0-9_.,:()=\- ]+", kind):
        raise ValueError("Unexpected characters in stat name.")
    return _run_tshark(["-r", _capture_path(), "-q", "-z", kind])


@mcp.tool()
def compare_captures(other_path: str, display_filter: str, fields: list[str]) -> str:
    """Run the same filter/fields against the current capture and another one,
    returning both tables for side-by-side comparison (e.g. working vs non-working)."""
    a = query_packets(display_filter, fields, 100)
    current = _capture_path()
    s = _load_session()
    try:
        s_tmp = dict(s, capture=str(Path(other_path).resolve()))
        _save_session(s_tmp)
        b = query_packets(display_filter, fields, 100)
    finally:
        _save_session(s)
    return f"=== {current} ===\n{a}\n\n=== {other_path} ===\n{b}"

# --------------------------------------------------------------------------
# GUI control tools (executed by claude_bridge.lua)
# --------------------------------------------------------------------------

@mcp.tool()
def gui_apply_filter(display_filter: str) -> str:
    """Apply a display filter in the Wireshark GUI (validated with tshark first).
    Use an empty string to clear the filter."""
    if display_filter:
        _validate_filter(display_filter)
    _queue("filter", display_filter)
    return f"Filter '{display_filter}'." + SYNC_HINT


@mcp.tool()
def gui_goto_frame(frame_number: int) -> str:
    """Mark a frame in the GUI (colour slot 10) and copy its number to the clipboard.
    Wireshark's Lua API cannot move the selection, so the user presses
    Ctrl+G, Ctrl+V, Enter to jump. Use highlight slots 1-9 for other highlights."""
    _queue("goto", str(int(frame_number)))
    return f"Go to frame {frame_number}." + SYNC_HINT


@mcp.tool()
def gui_highlight(display_filter: str, slot: int = 1) -> str:
    """Colour every packet matching the filter using temporary colouring slot 1-9
    (the same slots as View > Colorize Conversation). Lasts until cleared or Wireshark restarts."""
    if not 1 <= slot <= 9:
        raise ValueError("slot must be 1-9 (slot 10 is reserved for gui_goto_frame)")
    _validate_filter(display_filter)
    _queue("color", str(slot), display_filter)
    return f"Highlight slot {slot} = '{display_filter}'." + SYNC_HINT


@mcp.tool()
def gui_clear_highlights() -> str:
    """Clear all ten temporary colouring slots."""
    _queue("clear_colors")
    return "Clear highlights." + SYNC_HINT


@mcp.tool()
def gui_set_columns(columns: list[dict]) -> str:
    """Define the packet-list columns in a dedicated 'Claude' configuration profile.
    columns: [{"title": "TTL", "field": "ip.ttl"}, ...]. Built-ins allowed via
    field values like "%m" (No.), "%Rt" (relative time), "%s", "%d", "%p", "%i" (Info).
    Wireshark reads profiles on switch, so switch to the 'Claude' profile (status bar,
    bottom right) - or away and back - to see changes."""
    builtin = {"%m", "%t", "%Rt", "%At", "%Yt", "%Tt", "%Gt", "%s", "%d", "%p", "%L", "%i",
               "%uh", "%us", "%ud", "%rs", "%rd"}
    entries = []
    for col in columns:
        title = str(col["title"]).replace('"', "'")
        field = str(col["field"])
        fmt = field if field in builtin else f"%Cus:{field}:0:R"
        entries.append(f'"{title}", "{fmt}"')
    PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    prefs = PROFILE_DIR / "preferences"
    lines = []
    if prefs.exists():
        skip = False
        for ln in prefs.read_text(encoding="utf-8").splitlines():
            if ln.startswith("gui.column.format:"):
                skip = True
                continue
            if skip and (ln.startswith(" ") or ln.startswith("\t")):
                continue
            skip = False
            lines.append(ln)
    lines.append("gui.column.format:\n\t" + ",\n\t".join(entries))
    prefs.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return (f"Wrote {len(entries)} columns to profile '{PROFILE_NAME}' at {prefs}. "
            "Switch to that profile in Wireshark (or switch away and back) to load them.")


@mcp.tool()
def gui_get_context() -> str:
    """What the user is looking at: the last Sync state (active filter, applied commands)
    and any frame sent via right-click > Claude > Send frame to Claude."""
    parts = []
    for label, f in (("GUI state", STATE_FILE), ("Selected frame", CONTEXT_FILE)):
        parts.append(f"--- {label} ---")
        parts.append(f.read_text(encoding="utf-8") if f.exists() else "(nothing yet)")
    pending = COMMANDS_FILE.read_text(encoding="utf-8") if COMMANDS_FILE.exists() else ""
    parts.append("--- Pending commands (not yet synced) ---")
    parts.append(pending or "(none)")
    return "\n".join(parts)


if __name__ == "__main__":
    mcp.run()
