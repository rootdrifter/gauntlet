# gauntlet

CTF writeups from TryHackMe and HackTheBox. Methodology-first — each writeup documents the
reasoning process, not just the commands. Updated as rooms and challenges are completed.

---

## Overview

Capture the Flag competitions provide controlled, legally-authorised environments for practising
offensive security techniques against machines configured to be vulnerable. This repository
collects writeups for completed challenges, with an emphasis on transferable methodology rather
than solution shortcuts.

The format is consistent across all writeups: what was observed, what was inferred, what was
tried, what failed, and what worked. The failure documentation is deliberate — understanding
why a technique did not apply is as important as knowing when it does.

---

## Platforms

**TryHackMe** — structured learning paths and guided rooms. Useful for building systematic
knowledge of specific techniques (privilege escalation, web exploitation, cryptography) with
immediate feedback.

**HackTheBox** — competitive CTF environment with harder, less guided machines. Closer to a
realistic engagement: the attack surface is defined, but the path from reconnaissance to root
is not signposted.

---

## Writeup Structure

Every writeup follows this structure:

### 1. Reconnaissance
Initial information gathering — what the target exposes without active interaction. Passive
enumeration, OSINT where applicable, and initial network mapping.

### 2. Enumeration
Active probing of the identified attack surface. Port scanning, service fingerprinting,
directory enumeration, user enumeration. Documenting what was found and what was ruled out.

### 3. Exploitation
The specific vulnerability or misconfiguration used to gain initial access. Includes the
decision process: why this vector was chosen, what alternatives were considered, and what
failed before the successful approach.

### 4. Post-Exploitation
Actions taken after initial access: privilege escalation, lateral movement, persistence,
data exfiltration (within scope). Each step documented with the reasoning, not just the output.

### 5. Lessons Learned
What this machine demonstrated that is applicable beyond the specific challenge. Technique
generalisation, tooling notes, and anything that would have shortened the path with better
prior knowledge.

### Writeup template

Every writeup file follows this exact skeleton, committed as
`writeups/<platform>-<machine>.md` (template at
[templates/writeup-template.md](templates/writeup-template.md)):

```markdown
# <Machine name> — <Platform>

| Field | Value |
|-------|-------|
| Platform | TryHackMe / HackTheBox |
| Difficulty | Easy / Medium / Hard |
| OS | Linux / Windows |
| Target IP | 10.x.x.x (lab-assigned) |
| Date completed | YYYY-MM-DD |

## 1. Reconnaissance
- Initial scan command(s) and rationale
- Open ports / services / versions
- Observations and first hypotheses

## 2. Enumeration
- Service-by-service probing (web, SMB, DNS, etc.)
- Directory / user / vhost enumeration
- What was found and what was ruled out

## 3. Exploitation
- Chosen vector and *why* it was chosen
- Alternatives considered and what failed first
- Steps to initial foothold (commands + output excerpts)
- User flag

## 4. Post-Exploitation
- Local enumeration (linpeas/winpeas/pspy/manual)
- Privilege-escalation path with reasoning
- Lateral movement / persistence (within scope)
- Root flag

## 5. Lessons Learned
- Transferable technique(s)
- Tooling notes
- What prior knowledge would have shortened the path
```

---

## Tool Stack

Reconnaissance and enumeration: `nmap`, `gobuster`, `ffuf`, `whatweb`, `nikto`, `enum4linux`

Web exploitation: `burpsuite`, `sqlmap`, manual injection testing

Password and credential attacks: `hashcat`, `john`, `hydra`

Privilege escalation: `linpeas`, `winpeas`, `pspy`, manual enumeration

Binary exploitation and reversing: `gdb`, `pwndbg`, `ghidra`, `objdump`

Post-exploitation: `metasploit` (where appropriate), manual shell stabilisation

---

## Writeup index

Seven structured writeups are in place. Each is honestly labelled: where a machine has not yet
been solved under my own account, it is marked a **preparation stub** — a study scaffold built
from publicly documented information, with no live flag values recorded. Stubs become full
writeups as each box is worked.

| Machine | Platform | Difficulty | OS | Attack path |
|---------|----------|------------|-----|-------------|
| [Blue](writeups/thm-blue.md) | TryHackMe | Easy | Windows | EternalBlue / MS17-010 → SMBv1 → SYSTEM → hashdump |
| [Kenobi](writeups/thm-kenobi.md) | TryHackMe | Easy | Linux | SMB + NFS enum → ProFTPD mod_copy → SUID privesc |
| [Steel Mountain](writeups/thm-steel-mountain.md) | TryHackMe | Easy | Windows | Rejetto HFS 2.3 RCE (CVE-2014-6287) → unquoted service path |
| [Alfred](writeups/thm-alfred.md) | TryHackMe | Easy | Windows | Jenkins default creds → Groovy console RCE → token impersonation |
| [Basic Pentesting](writeups/thm-basic-pentesting.md) | TryHackMe | Easy | Linux | SMB user disclosure → SSH brute-force → SUID + sudo privesc |
| [Lame](writeups/htb-lame.md) | HackTheBox | Easy | Linux | Samba 3.0.20 usermap_script (CVE-2007-2447) → direct root |
| [Jerry](writeups/htb-jerry.md) | HackTheBox | Easy | Windows | Tomcat Manager default creds → WAR deploy → SYSTEM |

Methodology spine: [methodology/ctf-methodology.md](methodology/ctf-methodology.md) — enumeration
discipline, OWASP→CTF mapping, privilege-escalation triage order, and evidence standards.

The repository is active — new rooms are added as they are completed; check commit history for the
most recent.

---

*Part of the [rootdrifter](https://github.com/rootdrifter) security portfolio — built and maintained by a security-cleared candidate. UK-issued clearance held now, not pending vetting: deployable to cleared work from day one.*
