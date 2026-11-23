# Post-Authentication OS Command Injection in WAVLINK WL-WN586X3-A (`M86X3A_V250118`) via `/cgi-bin/luci/admin/mtk/multi_ap/submit_dpp_uri`

## 1. Summary
WAVLINK WL-WN586X3-A (AX3000 Wi-Fi 6 Router) firmware `M86X3A_V250118` contains a post-authentication OS command injection vulnerability (**CWE-78**) in the Wi-Fi EasyMesh / Device Provisioning Protocol (DPP) onboarding handler `submit_dpp_uri` located in `/usr/lib/lua/luci/controller/mtkwifi.lua`. Because the `uri` parameter read from HTTP query/form input is interpolated directly inside double quotes into `os.execute(...)` without validation or quoting, an authenticated attacker can break out of the double-quoted `wappctrl` argument and execute arbitrary OS commands under the privileges of the web management service (`root`).

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

## 3. Static Root-Cause Proof

### 3.1 Route Registration (`/usr/lib/lua/luci/controller/mtkwifi.lua`, lines 58 and 179)
In `index()`, the controller registers the `multi_ap/submit_dpp_uri` leaf endpoint under the LuCI `admin/mtk` tree without restricting HTTP methods (`GET` and `POST` are both accepted by `http.formvalue`):

```lua
-- /usr/lib/lua/luci/controller/mtkwifi.lua
58:     entry({"admin", "mtk"}, firstchild(), _("MTK"), 80)
...
179:         entry({"admin", "mtk", "multi_ap", "submit_dpp_uri"}, call("submit_dpp_uri")).leaf = true;
```

### 3.2 Vulnerable Sink (`/usr/lib/lua/luci/controller/mtkwifi.lua`, lines 2736–2740)
In `submit_dpp_uri()`, user-supplied input from `http.formvalue("uri")` is concatenated directly into a shell command string passed to Lua's `os.execute()`:

```lua
-- /usr/lib/lua/luci/controller/mtkwifi.lua (lines 2736-2740)
2736: function submit_dpp_uri()
2737:     uri = http.formvalue("uri")
2738:     os.execute("wappctrl ra0 dpp dpp_qr_code ".."\""..uri.."\"")
2739:     luci.http.redirect(luci.dispatcher.build_url("admin", "mtk", "multi_ap"))
2740: end
```

**Dataflow Chain (`path_id = e2502701b667ab49`)**:
1. **Source**: `http.formvalue("uri")` at `/usr/lib/lua/luci/controller/mtkwifi.lua:2737` (reads query string or POST form field `uri`).
2. **Sanitization Check**: None. Neither a DPP bootstrapping URI format check (`^DPP:[A-Za-z0-9:;+/=,-]+$`) nor `luci.util.shellquote(uri)` is applied.
3. **Sink**: `os.execute(...)` at `/usr/lib/lua/luci/controller/mtkwifi.lua:2738` invokes `/bin/sh -c` on the concatenated string. Any input closing the surrounding double quotes or introducing shell command substitution is interpreted directly by `/bin/sh`.

## 4. Dynamic Verification & Reproducibility Proof (Non-Destructive Loopback Sandbox)

Dynamic verification was conducted in an isolated local loopback environment (`127.0.0.1` ephemeral port `39019`, `bwrap --unshare-net` sandbox) running the extracted firmware's LuCI controller (`lua5.1` + `/usr/lib/lua/luci/controller/mtkwifi.lua`) with non-destructive instrumentation recording the exact command string reaching `os.execute`.

### 4.1 Benign Verification Request Structure
```http
GET /cgi-bin/luci/admin/mtk/multi_ap/submit_dpp_uri?uri=<URL_ENCODED_BENIGN_MARKER_INPUT> HTTP/1.1
Host: 127.0.0.1:39019
Cookie: sysauth=<VALID_ADMIN_SESSION_TOKEN>
```

### 4.2 Observed Sandbox Execution Evidence
When `uri` contains shell separator / marker tokens (using harmless `/tmp/iotvuln_framework_ax3000_0e0d024ad64d9832_*` file-marker identifiers), the controller reaches line `2738` and passes the unescaped parameter directly to `os.execute`:

- **Finding Key**: `ax3000:cgi_bin_luci_admin_mtk_multi_ap_submit_dpp_uri:uri:command_execution`
- **Backend / Execution Mode**: `luci_mtk` (`native` Lua execution of extracted firmware controller)
- **Independent Replay Verification (`3/3` reproduced)**:
  - Replay #1 (`marker = /tmp/iotvuln_framework_ax3000_0e0d024ad64d9832_replay_1`): `reproduced = true`, `marker_present = true`, Request SHA-256: `cce469822c09468e31edeccec037bdcd0a06a2a413956e622cb16e57272b3ffc`
  - Replay #2 (`marker = /tmp/iotvuln_framework_ax3000_0e0d024ad64d9832_replay_2`): `reproduced = true`, `marker_present = true`, Request SHA-256: `a0c66cc893252496b29cdb035b6ec97226076b4fa7fe4a5f8441cb65d2ffea6f`
  - Replay #3 (`marker = /tmp/iotvuln_framework_ax3000_0e0d024ad64d9832_replay_3`): `reproduced = true`, `marker_present = true`, Request SHA-256: `2d2523802db10e573106b3e9803330720a1bd4c1ebf28c517ee5c9ae8cd46fb5`

## 5. Remediation Recommendations
1. **Strict Format Validation**: Validate `uri` against the Wi-Fi Alliance DPP URI grammar (e.g., `if not uri or not uri:match("^DPP:[%w%p]+;;$")` with explicit rejection of `"`, `` ` ``, `$`, `;`, `|`, `&`, and control characters) before invoking `wappctrl`.
2. **Shell Argument Escaping / Exec Array**: Escape arguments with `luci.util.shellquote(uri)` (which wraps in single quotes and neutralizes embedded single quotes) or invoke `nixio.execp("wappctrl", {"ra0", "dpp", "dpp_qr_code", uri})` without `/bin/sh`.
3. **CSRF Protection**: Enforce `POST`-only state-changing requests with LuCI CSRF token verification on `multi_ap` configuration endpoints.
