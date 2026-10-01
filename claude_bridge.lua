-- claude_bridge.lua  (v1.1)
-- Companion plugin for wireshark_claude_mcp.py.
-- Install: copy to %APPDATA%\Wireshark\plugins\ (Windows), then
-- Analyze > Reload Lua Plugins (Ctrl+Shift+L) or restart Wireshark.
--
-- Adds:
--   Tools > Claude > Sync              - run commands Claude has queued
--   Tools > Claude > Show bridge log   - see what was applied
--   Right-click packet > Claude > Send frame to Claude
--
-- v1.1 changes:
--   * "goto" no longer calls goto_frame (not in Wireshark's Lua API). It marks the
--     frame in colour slot 10 and copies its number to the clipboard instead:
--     press Ctrl+G, Ctrl+V, Enter to jump.
--   * Sync repaints the packet list after colour changes (redissect_packets),
--     so highlights show without toggling View > Colorize Packet List.

if not gui_enabled() then return end

local SEP = package.config:sub(1, 1)
local BRIDGE = persconffile_path("claude_bridge")
pcall(Dir.make, BRIDGE)

local CMD_FILE   = BRIDGE .. SEP .. "commands.txt"
local STATE_FILE = BRIDGE .. SEP .. "state.txt"
local CTX_FILE   = BRIDGE .. SEP .. "context.txt"

local GOTO_SLOT = 10  -- colour slot reserved for "go to frame" marking

local log_lines = {}

local function log(msg)
    table.insert(log_lines, os.date("%H:%M:%S") .. "  " .. msg)
    if #log_lines > 200 then table.remove(log_lines, 1) end
end

local function split_tabs(line)
    local out = {}
    for part in (line .. "\t"):gmatch("([^\t]*)\t") do table.insert(out, part) end
    return out
end

local function read_lines(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local lines = {}
    for l in f:lines() do
        l = l:gsub("\r$", "")
        if l ~= "" then table.insert(lines, l) end
    end
    f:close()
    return lines
end

local function write_file(path, text)
    local f = io.open(path, "w")
    if f then f:write(text); f:close() end
end

local function write_state(applied)
    local s = {
        "synced_at=" .. os.date("%Y-%m-%d %H:%M:%S"),
        "display_filter=" .. (get_filter and (get_filter() or "") or "(unknown)"),
        "applied:",
    }
    for _, a in ipairs(applied) do table.insert(s, "  " .. a) end
    write_file(STATE_FILE, table.concat(s, "\n") .. "\n")
end

-- Commands that change colouring and need a repaint afterwards.
local RECOLOR_CMDS = { color = true, clear_colors = true, ["goto"] = true }

-- Execute one command; returns true if remaining commands must wait for the next Sync.
local function run(parts)
    local cmd = parts[1]
    if cmd == "filter" then
        set_filter(parts[2] or "")
        apply_filter()
    elseif cmd == "goto" then
        local n = tonumber(parts[2])
        if not n then error("bad frame number") end
        set_color_filter_slot(GOTO_SLOT, "frame.number == " .. n)
        if copy_to_clipboard then copy_to_clipboard(tostring(n)) end
        log("Frame " .. n .. " marked (slot " .. GOTO_SLOT .. ") and copied - press Ctrl+G, Ctrl+V, Enter")
    elseif cmd == "color" then
        set_color_filter_slot(tonumber(parts[2]), parts[3] or "")
    elseif cmd == "clear_colors" then
        for i = 1, 10 do set_color_filter_slot(i, "") end
    elseif cmd == "open" then
        open_capture_file(parts[2], "")
        return true -- file loads asynchronously; run the rest on the next Sync
    else
        error("unknown command '" .. tostring(cmd) .. "'")
    end
    return false
end

local function sync()
    local lines = read_lines(CMD_FILE)
    if not lines or #lines == 0 then
        log("Sync: nothing queued")
        write_state({})
        return
    end
    os.remove(CMD_FILE)
    local applied, remaining = {}, {}
    local deferred = false
    local needs_recolor = false
    for _, line in ipairs(lines) do
        if deferred then
            table.insert(remaining, line)
        else
            local parts = split_tabs(line)
            local ok, res = pcall(run, parts)
            if ok then
                table.insert(applied, line)
                log("OK   " .. line)
                deferred = res
                if RECOLOR_CMDS[parts[1]] then needs_recolor = true end
            else
                log("FAIL " .. line .. "  -> " .. tostring(res))
                table.insert(applied, "FAILED: " .. line .. " (" .. tostring(res) .. ")")
            end
        end
    end
    if needs_recolor then
        if redissect_packets then
            local ok, err = pcall(redissect_packets)
            if ok then
                log("Recoloured packet list")
            else
                log("Recolour failed (" .. tostring(err) .. ") - toggle View > Colorize Packet List")
            end
        else
            log("Colours set - toggle View > Colorize Packet List to show them")
        end
    end
    if #remaining > 0 then
        write_file(CMD_FILE, table.concat(remaining, "\n") .. "\n")
        log(#remaining .. " command(s) waiting - click Sync again once the file has loaded")
    end
    write_state(applied)
end

local function show_log()
    local w = TextWindow.new("Claude bridge log")
    w:set(#log_lines > 0 and table.concat(log_lines, "\n") or "(empty)")
end

-- Right-click a packet: dump its fields so Claude can see what you selected.
local function send_frame(...)
    local fields = { ... }
    local out = { "sent_at=" .. os.date("%Y-%m-%d %H:%M:%S") }
    for _, fi in ipairs(fields) do
        local ok, line = pcall(function()
            local name = fi.name or "?"
            local val = fi.display or tostring(fi.value)
            return name .. " = " .. val
        end)
        table.insert(out, ok and line or tostring(fi))
        if #out > 400 then table.insert(out, "... truncated"); break end
    end
    write_file(CTX_FILE, table.concat(out, "\n") .. "\n")
    log("Sent selected frame (" .. #fields .. " fields) to Claude")
end

register_menu("Claude/Sync", sync, MENU_TOOLS_UNSORTED)
register_menu("Claude/Show bridge log", show_log, MENU_TOOLS_UNSORTED)
if register_packet_menu then
    register_packet_menu("Claude/Send frame to Claude", send_frame)
end
log("Claude bridge v1.1 loaded. Bridge folder: " .. BRIDGE)
