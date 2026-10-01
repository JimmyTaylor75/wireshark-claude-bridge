# wireshark-claude-bridge

Work with Claude directly on the capture you have open in Wireshark. Claude can analyse the
capture with `tshark`, and it can change what you see in the Wireshark GUI: apply display
filters, highlight packets, mark frames, and define packet-list columns. You can also send
Claude the packet you are looking at with a right-click.

It has two parts:

| File | Runs in | What it does |
|---|---|---|
| `wireshark_claude_mcp.py` | Claude Desktop (local MCP server) | Runs `tshark` against the capture file for analysis, and queues GUI commands in a bridge folder |
| `claude_bridge.lua` | Wireshark (Lua plugin) | Adds a **Tools > Claude** menu. **Sync** applies the queued commands inside the GUI |

```
 Claude Desktop ──MCP──► wireshark_claude_mcp.py ──► tshark ──► capture file (analysis)
                                   │
                                   └──► %APPDATA%\Wireshark\claude_bridge\commands.txt
                                                     │
                     Wireshark ◄── claude_bridge.lua ┘  (you click Tools > Claude > Sync)
```

Wireshark's Lua API has no timers or sockets, so the plugin cannot pick up Claude's commands
on its own. One click on **Sync** is the trade-off.

---

## Requirements

- Windows 10/11 (macOS and Linux should work but are untested; see [Other platforms](#other-platforms))
- Wireshark 3.6 or newer, which includes `tshark` and Lua support
- Python 3.10 or newer
- Claude Desktop

---

## Installation

### 1. Get the files

```
git clone https://github.com/JimmyTaylor75/wireshark-claude-bridge.git
```

Or download the repository as a ZIP and extract it somewhere permanent, for example
`C:\Tools\wireshark-claude-bridge`. Claude Desktop runs the server from this location, so
don't leave it in Downloads.

### 2. Install the Python dependency

Use the same Python you will point Claude Desktop at in step 4:

```
"C:\Path\To\python.exe" -m pip install -r requirements.txt
```

To find your Python's full path, run `where python` (Windows) or `py -0p`.

### 3. Install the Wireshark plugin

1. In Wireshark, open **Help > About Wireshark > Folders** and note the **Personal Lua Plugins**
   path. On Windows it is usually `%APPDATA%\Wireshark\plugins`.
2. Copy `claude_bridge.lua` into that folder (create it if it doesn't exist).
3. Restart Wireshark, or use **Analyze > Reload Lua Plugins** (Ctrl+Shift+L).
4. Check that **Tools > Claude** now has **Sync** and **Show bridge log**. **Show bridge log**
   should say `Claude bridge v1.1 loaded`.

### 4. Register the server in Claude Desktop

Open `%APPDATA%\Claude\claude_desktop_config.json` (in Claude Desktop: **Settings > Developer >
Edit Config**) and add a `wireshark` entry under `mcpServers`:

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "C:\\Path\\To\\python.exe",
      "args": ["C:\\Tools\\wireshark-claude-bridge\\wireshark_claude_mcp.py"],
      "env": { "TSHARK_PATH": "C:\\Program Files\\Wireshark\\tshark.exe" }
    }
  }
}
```

- Every backslash in a JSON path must be doubled (`\\`).
- `command` must be the full path to the Python from step 2. A bare `python` may resolve to a
  different interpreter that doesn't have `mcp` installed.
- If the file already has other servers, add `wireshark` alongside them inside the same
  `mcpServers` object.

### 5. Restart Claude Desktop fully

Closing the window isn't enough, because Claude Desktop keeps running in the system tray.
Right-click the tray icon and choose **Quit**, then start it again.

In **Settings > Developer**, the `wireshark` server should show as running. Start a **new**
chat so the tools are available in it.

---

## Usage

### Open a capture

Ask Claude to set the capture, using the full Windows path:

> Set my capture to "C:\Users\me\Downloads\trace.pcapng"

Claude can now analyse the file. It also queues the file to open in the GUI, so click
**Tools > Claude > Sync** to load it. Opening is asynchronous: if other commands were queued
after the open, click **Sync** a second time once the file has loaded.

You can also open the file yourself with **File > Open**. Claude reads the file from disk, so
you are both looking at the same frames either way. Claude still needs `set_capture` to know
which file to analyse.

### Ask questions

Analysis needs no Sync click. Examples:

> Give me a summary of this capture.
>
> Show every mDNS query for _googlecast with source, TTL and query name.
>
> Which hosts send SSDP M-SEARCH, and does anything answer them?
>
> Compare DHCP traffic between this capture and C:\caps\working.pcapng.
>
> Show me the full decode of frame 1130.

### Change the Wireshark view

GUI changes are queued, then applied when you click **Tools > Claude > Sync**:

> Filter to mDNS and SSDP, highlight the queries from 192.0.2.10, and mark frame 1234.

- **Filters** are checked with `tshark` before they are queued, so a typo is rejected instead
  of turning your filter bar red.
- **Highlights** use Wireshark's temporary colouring slots 1–9, the same slots as
  **View > Colorize Conversation**. They last until cleared or until Wireshark restarts.
  Sync repaints the packet list automatically.
- **Go to frame** can't move your selection, because the Lua API has no function for it.
  Instead, the frame is marked in colour slot 10 and its number is copied to your clipboard.
  Press **Ctrl+G, Ctrl+V, Enter** to jump to it.
- **Columns** are written to a dedicated Wireshark configuration profile called **Claude**.
  Wireshark only reads columns when a profile loads, so switch to the **Claude** profile
  (status bar, bottom right) after Claude sets them. If it's already active, switch away and
  back.

### Show Claude a packet

Right-click a packet and choose **Claude > Send frame to Claude**, then ask your question:

> What's wrong with the frame I just sent?

Claude can't see your selection unless you send it this way, or tell it the frame number.

### Check what happened

- **Tools > Claude > Show bridge log** in Wireshark lists every command applied or failed.
- Ask Claude *"what's the GUI state?"*. It reads the last Sync result, any frame you sent, and
  any commands still waiting for a Sync.

---

## Tools reference

### Analysis (runs immediately)

| Tool | Purpose |
|---|---|
| `set_capture(path, open_in_gui=True)` | Select the capture to analyse, and optionally queue opening it in the GUI |
| `capture_summary()` | Protocol hierarchy and top IPv4 conversations |
| `query_packets(display_filter, fields, limit)` | Table of matching packets with any Wireshark fields; frame number and relative time are always included |
| `frame_detail(frame_number, layers)` | Full protocol tree for one frame, optionally limited to some layers |
| `stats(kind)` | Any `tshark -z` statistic, e.g. `conv,udp`, `endpoints,ip`, `io,stat,1`, `dns,tree`, `expert` |
| `compare_captures(other_path, display_filter, fields)` | Same query against the current capture and another one, side by side |

### GUI (applied on Sync)

| Tool | Purpose |
|---|---|
| `gui_apply_filter(display_filter)` | Apply a display filter (validated first). Empty string clears it |
| `gui_highlight(display_filter, slot)` | Colour matching packets using slot 1–9 |
| `gui_clear_highlights()` | Clear all ten colour slots |
| `gui_goto_frame(frame_number)` | Mark the frame (slot 10) and copy its number for Ctrl+G |
| `gui_set_columns(columns)` | Write packet-list columns to the **Claude** profile |
| `gui_get_context()` | Last Sync state, the frame you sent, and pending commands |

`gui_set_columns` takes a list like
`[{"title": "TTL", "field": "ip.ttl"}, {"title": "Info", "field": "%i"}]`. Built-in columns
use Wireshark's format codes: `%m` (No.), `%t` (Time), `%Rt` (relative time), `%s` (Source),
`%d` (Destination), `%p` (Protocol), `%L` (Length), `%i` (Info).

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Claude says it has no Wireshark tools | Check **Settings > Developer** in Claude Desktop. Quit fully from the tray and restart, then start a new chat |
| Server shows an error in Claude Desktop | Read `%APPDATA%\Claude\logs\mcp-server-wireshark.log`. Usual causes: single backslashes in the JSON, `mcp` not installed in the configured Python, wrong script path |
| `tshark not found` | Set `TSHARK_PATH` in the config to the full path of `tshark.exe` |
| No **Tools > Claude** menu | The plugin isn't loaded. Check the folder in **Help > About Wireshark > Folders**, then Ctrl+Shift+L. **Help > About Wireshark > Plugins** shows load errors |
| Sync says "nothing queued" | The commands were already applied by an earlier Sync. Ask Claude for the GUI state |
| Highlights don't show | Toggle **View > Colorize Packet List** off and on. The bridge log says whether the automatic repaint ran |
| Columns don't change | Switch to the **Claude** profile, or away and back if it's already active |
| Commands after an `open` didn't apply | The file was still loading. Click Sync again |

To test the server outside Claude Desktop, run it in a terminal:

```
"C:\Path\To\python.exe" "C:\Tools\wireshark-claude-bridge\wireshark_claude_mcp.py"
```

It should sit silently, waiting for MCP input (press Ctrl+C to stop). A traceback shows what's
wrong.

---

## Other platforms

The server finds Wireshark's configuration folder at `%APPDATA%\Wireshark` on Windows and
`~/.config/wireshark` on macOS and Linux. If your Wireshark uses a different folder (check
**Help > About Wireshark > Folders > Personal configuration**), set `WS_CLAUDE_CONF_DIR` to it
in the server's `env` block. On macOS, `tshark` usually lives at
`/Applications/Wireshark.app/Contents/MacOS/tshark`.

## Environment variables

| Variable | Purpose |
|---|---|
| `TSHARK_PATH` | Full path to `tshark`, if it isn't on `PATH` or in the default install location |
| `WS_CLAUDE_CONF_DIR` | Wireshark personal configuration folder, if not the default |

---

## Limitations

- GUI changes need a click on **Sync**.
- The plugin can't move the packet selection. **Go to frame** marks the frame and copies its
  number instead.
- Columns only load on a profile switch.
- Command output is capped at 20,000 characters per call, so very broad queries are truncated.
  Narrow the filter or lower the row limit.

## Privacy and data handling

Packet contents reach Claude through tool results in your conversation. Captures can contain
IP and MAC addresses, hostnames, credentials and other personal or confidential data. Check
your organisation's data-handling rules before using this on production or customer captures.

## Changelog

**v1.1**
- **Go to frame** now marks the frame in colour slot 10 and copies its number to the
  clipboard. The previous version called a function that doesn't exist in Wireshark's Lua API.
- Sync repaints the packet list after colour changes.
- Highlight slots are limited to 1–9; slot 10 is reserved for go-to-frame.

**v1.0**
- Initial release.
