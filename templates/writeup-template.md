<!--
gauntlet writeup template
Copy this file to writeups/<platform>/<machine>/README.md and fill in each section.
Delete guidance comments before committing. Only document legally authorised CTF activity.
-->

# <Machine / Challenge name> — <Platform>

## Engagement metadata

| Field | Value |
|-------|-------|
| Platform | TryHackMe / HackTheBox |
| Room / challenge name | <name> |
| Difficulty | Easy / Medium / Hard / Insane |
| Category | Linux / Windows / Web / Crypto / Pwn / Forensics / OSINT |
| Target IP | 10.x.x.x (lab-assigned) |
| Date completed | YYYY-MM-DD |

## Executive summary

> Two or three sentences: what the target was, the key vulnerability/path used to compromise it,
> and the final outcome (user + root, or flag captured). Written so a non-specialist can grasp
> the result; detail belongs in the sections below.

## 1. Reconnaissance

### Passive

- OSINT, public records, or platform-provided hints reviewed before touching the target.
- Anything inferred about the tech stack without active interaction.

### Active

- Initial scan command(s) and the rationale for each flag.

```
nmap -sC -sV -oN nmap/initial 10.x.x.x
```

- Open ports / services / versions:

| Port | Service | Version | Notes |
|------|---------|---------|-------|
| | | | |

- First hypotheses about the likely attack surface.

## 2. Enumeration

- Service-by-service probing (web, SMB, DNS, FTP, etc.).
- Directory / vhost / user enumeration.

```
gobuster dir -u http://10.x.x.x/ -w <wordlist> -o gobuster.txt
```

- **What was found** and, importantly, **what was ruled out** — dead ends are evidence.

## 3. Exploitation

- The chosen vector and **why** it was chosen over the alternatives.
- Alternatives considered and what failed first.
- Steps to initial foothold, with command(s) and trimmed output excerpts.
- Any payload / exploit code (referenced, not pasted wholesale if large).

```
# foothold command(s)
```

- **User flag:** `THM{...}` / `HTB{...}` (redact or note as captured).

## 4. Post-exploitation

- Local enumeration (`linpeas` / `winpeas` / `pspy` / manual).
- Privilege-escalation path, with the reasoning that identified it.
- Lateral movement / persistence, where in scope.

```
# privesc command(s)
```

- **Root / system flag:** `THM{...}` / `HTB{...}` (redact or note as captured).

## 5. Flags captured

| Flag | Location | Value |
|------|----------|-------|
| User | <path> | `redacted / captured` |
| Root | <path> | `redacted / captured` |

## 6. Tools used

| Phase | Tools |
|-------|-------|
| Reconnaissance | nmap, whatweb |
| Enumeration | gobuster, ffuf, enum4linux, nikto |
| Exploitation | burpsuite, sqlmap, manual / custom scripts |
| Privilege escalation | linpeas, winpeas, pspy, GTFOBins |
| Post-exploitation | manual shell stabilisation, metasploit (where appropriate) |

## 7. Lessons learned

- Transferable technique(s) this box demonstrated.
- Tooling notes (flags, gotchas, faster alternatives).
- What prior knowledge would have shortened the path.

## 8. References

- CVE / advisory links, exploit-DB IDs, GTFOBins entries.
- Relevant documentation or writeups consulted (cited, not copied).
