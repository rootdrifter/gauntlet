# Steel Mountain — TryHackMe

> **Preparation stub.** Based on publicly documented information about this retired room — not an
> original solve, and no live flag values are recorded. Complete the bracketed fields when working
> the room under your own account.

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

A Windows server running **Rejetto HttpFileServer (HFS) 2.3**, vulnerable to unauthenticated
remote code execution. Exploitation gives a user shell; privilege escalation abuses an
**insecure/unquoted Windows service** (identified with PowerUp) to run a malicious binary as
SYSTEM. Teaches Windows service-misconfiguration privesc.

## Key vulnerability class

- **Foothold:** Rejetto **HFS 2.3** RCE via the `{.exec.}` macro in the search parameter —
  **CVE-2014-6287**. *Verify CVE when citing.*
- **Privesc:** insecure Windows **service** — commonly the bundled `AdvancedSystemCareService9`
  (Advanced SystemCare) with a **writable binary path** (and/or **unquoted service path**),
  exploitable by replacing the service executable and restarting it (CWE-732 / CWE-428 unquoted
  search path).

## Attack chain summary

1. **Recon** — scan identifies the HFS web service (often port **8080**) banner "HttpFileServer
   2.3".
2. **Exploit (HFS RCE)** — use the HFS 2.3 RCE (Metasploit `rejetto_hfs_exec`, or a manual
   `{.exec.}` payload hosting a Netcat/PowerShell reverse shell) to land a user shell; collect the
   user flag.
3. **Privesc enumeration** — run **PowerUp.ps1**; it flags a service whose executable path is
   writable by the current user (and/or unquoted).
4. **Privesc exploit** — generate a malicious replacement binary (`msfvenom`), overwrite the
   service executable, then **restart the service** so it runs the payload as **SYSTEM**; collect
   the root/admin flag.

## Tools used

| Phase | Tools |
|-------|-------|
| Recon | `nmap` (`-sC -sV -p-`) |
| Exploitation | Metasploit (`rejetto_hfs_exec`) or manual `{.exec.}` payload + `nc`/PowerShell |
| Privesc enumeration | **PowerUp.ps1** (PowerSploit), `sc qc`, `accesschk` |
| Privesc exploitation | `msfvenom` (payload), `sc stop/start`, meterpreter |

## Lessons learned

- **Service-binary permissions are a top Windows privesc vector** — if a low-priv user can write the
  service's executable (or exploit an unquoted path), they can run code as SYSTEM on restart.
- **PowerUp/winPEAS pay for themselves** — automated checks surface writable services, unquoted
  paths, and `AlwaysInstallElevated` quickly.
- **Know both routes** — Metasploit *and* a manual `{.exec.}` payload; the manual path builds
  understanding and works when Metasploit is disallowed.
- **Blue-team transfer:** MITRE **T1574.009 (unquoted path)** / **T1543.003 (Windows Service)**;
  detect via service-binary modification and unexpected service restarts.

## References

- Rejetto HFS 2.3 CVE-2014-6287 (verify).
- PowerSploit / PowerUp documentation; unquoted-service-path guidance.
