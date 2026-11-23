# Exposed Diagnostic Command Execution Endpoint (`mtk/webcmd`) in WAVLINK WL-WN586X3-A (`M86X3A_V250118`)

## 1. Summary
Production firmware `M86X3A_V250118` for the WAVLINK WL-WN586X3-A (AX3000 Wi-Fi 6 Router) ships with an active, unguarded diagnostic command execution endpoint at `/cgi-bin/luci/admin/mtk/webcmd` (**CWE-78 / CWE-749**). Notice in `/usr/lib/lua/luci/controller/mtkwifi.lua` line `1`: *"This module is a demo to configure MTK' proprietary WiFi driver."* Rather than disabling or restricting the demo `webcmd` route in production firmware, the controller exposes `entry({"admin", "mtk", "webcmd"}, call("webcmd"))` over HTTP `GET` and `POST` without command allowlisting or CSRF token enforcement, passing `http.formvalue("cmd")` straight into Lua `io.popen()` and returning full command output to the caller.

## 2. Firmware & Target Identification

| Field | Value |
|---|---|
| **Vendor** | Shenzhen Wavlink Technology Co., Ltd. (WAVLINK) |
| **Device Model** | WL-WN586X3-A (AX3000 Wi-Fi 6 Router) |
| **Firmware Version** | `M86X3A_V250118` (`WAVLINK-AX3000-M86X3A-V250118.bin`) |
| **Image Size** | `13,894,458` bytes |
| **Image MD5** | `878bec34f661779d08d6d5f919b1830f` |
| **Image SHA-256** | `4a3845f8b3d1d5181289ac21fd24bf87bd3bfd4dc37de5cceeddabc4ec6e97d8` |
| **SquashFS Offset / Size** | Offset `3,145,728` (`0x300000`), `10,678,017` bytes |
| **Base OS / Target SoC** | OpenWrt `21.02-SNAPSHOT` (`r17218-fb2551a`), `mediatek/mt7981` (`aarch64_cortex-a53`) |
| **Related / Distinct Advisories** | Distinct product codebase from TOTOLINK A6000R (`CVE-2024-41319`); distinct component and root cause from WAVLINK WL-WN586X3-A `host_black` (`CVE-2024-57366`) and `ExportAllSettings.cgi` (`CVE-2025-55847`). |

## 3. Static Root-Cause Proof

### 3.1 Route Registration (`/usr/lib/lua/luci/controller/mtkwifi.lua`, lines 89–90)
```lua
-- /usr/lib/lua/luci/controller/mtkwifi.lua
89:     entry({"admin", "mtk", "console"}, template("admin_mtk/mtk_web_console"), _("Web Console"), 4)
90:     entry({"admin", "mtk", "webcmd"}, call("webcmd"))
```

### 3.2 Controller Handler (`/usr/lib/lua/luci/controller/mtkwifi.lua`, lines 1677–1686)
```lua
-- /usr/lib/lua/luci/controller/mtkwifi.lua (lines 1677-1686)
1677: function webcmd()
1678:     local cmd = http.formvalue("cmd")
1679:     if cmd then
1680:         local result = mtkwifi.read_pipe(tostring(cmd).." 2>&1")
1681:         result = result:gsub("<", "&lt;")
1682:         http.write(tostring(result))
1683:     else
1684:         http.write_json(http.formvalue())
1685:     end
1686: end
```

### 3.3 Underlying `io.popen` Sink (`/usr/lib/lua/mtkwifi.lua`, lines 163–173)
```lua
-- /usr/lib/lua/mtkwifi.lua (lines 163-173)
163: function mtkwifi.read_pipe(pipe)
164:     local retry_count = 10
165:     local fp, txt, err
166:     repeat  -- fp:read() may return error, "Interrupted system call", and can be recovered by doing it again
167:         fp = io.popen(pipe)
168:         txt, err = fp:read("*a")
169:         fp:close()
170:         retry_count = retry_count - 1
171:     until err == nil or retry_count == 0
172:     return txt
173: end
```

**Dataflow Chain (`path_id = c39afd6d5995a711`)**:
1. **Source**: `http.formvalue("cmd")` at `/usr/lib/lua/luci/controller/mtkwifi.lua:1678`.
2. **Propagation**: Concatenated with `" 2>&1"` at line `1680` and passed to `mtkwifi.read_pipe(pipe)`.
3. **Sink**: `io.popen(pipe)` at `/usr/lib/lua/mtkwifi.lua:167` executes `pipe` via `/bin/sh -c` and streams the full output back into the HTTP response at line `1682`.

## 4. Dynamic Verification & Reproducibility Proof (Non-Destructive Loopback Sandbox)

Dynamic verification was executed in an isolated local loopback testbed (`127.0.0.1` ephemeral port `39019`, `bwrap --unshare-net` sandbox) running the extracted firmware's LuCI `mtkwifi.lua` controller and library under `lua5.1`.

### 4.1 Benign Verification Request Structure
```http
GET /cgi-bin/luci/admin/mtk/webcmd?cmd=<URL_ENCODED_BENIGN_DIAGNOSTIC_MARKER> HTTP/1.1
Host: 127.0.0.1:39019
Cookie: sysauth=<VALID_ADMIN_SESSION_TOKEN>
```

### 4.2 Observed Sandbox Execution Evidence
- **Finding Key**: `ax3000:cgi_bin_luci_admin_mtk_webcmd:cmd:command_execution`
- **Backend / Execution Mode**: `luci_mtk` (`native` Lua execution of extracted firmware controller & `mtkwifi.read_pipe`)
- **HTTP Response Status**: `200 OK`
- **Independent Replay Verification (`3/3` reproduced)**:
  - Replay #1 (`marker = /tmp/iotvuln_framework_ax3000_0260029839ab9fb3_replay_1`): `status_code = 200`, `reproduced = true`, `marker_present = true`, Request SHA-256: `4ff7856cc00266c42e1f1736b52a54651b6de080e090e591a51088264b42ef38`
  - Replay #2 (`marker = /tmp/iotvuln_framework_ax3000_0260029839ab9fb3_replay_2`): `status_code = 200`, `reproduced = true`, `marker_present = true`, Request SHA-256: `022b2426f4e969d75020348a839a490c7d8d077a93ef602b9a2e58ddca9516e4`
  - Replay #3 (`marker = /tmp/iotvuln_framework_ax3000_0260029839ab9fb3_replay_3`): `status_code = 200`, `reproduced = true`, `marker_present = true`, Request SHA-256: `1c1aca05bc41d29c3500e7321938f220f3a1136b9843efa5163e1b659e70f1d6`

## 5. Remediation Recommendations
1. **Remove Demo Diagnostic Endpoints in Production Builds**: Comment out or strip `entry({"admin", "mtk", "console"}, ...)` and `entry({"admin", "mtk", "webcmd"}, call("webcmd"))` (along with `function webcmd()`) from release firmware images.
2. **Strict Subcommand Allowlisting**: If diagnostic queries (`iwpriv`, `ated`, etc.) are required by the web UI, replace free-form `cmd` execution with a strict server-side command map and `nixio.execp` argument arrays, enforced via `POST` + CSRF token verification.
