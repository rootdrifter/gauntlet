# gauntlet

**Active CTF practice that connects offensive technique to defensive detection.** Methodology-first
TryHackMe and HackTheBox writeups — every box is worked *and* turned into the question a SOC analyst
actually asks: "what log would have caught this, and what rule fires?" Each writeup now carries a
box-specific **Wazuh detection rule** that feeds directly into the [watchtower](../watchtower) SIEM
lab. Updated as rooms are completed.

---

## Overview

This repository is the offensive half of a deliberate offence→detection loop. CTF competitions give
controlled, legally-authorised environments for practising offensive techniques against intentionally
vulnerable machines; the writeups here capture the *reasoning* — what was observed, inferred, tried,
ruled out, and what finally worked — and then **cross the bridge to the blue team**: each attack step
is mapped to MITRE ATT&CK and paired with the detection logic (Event IDs, auditd/Sysmon, and a Wazuh
rule sketch) that would surface it in a monitored estate.

That second half is the point. Retired easy boxes are solved thousands of times over; the
differentiator for a SOC-analyst target role is being able to exploit a technique *and* engineer the
detection for it. The failure documentation is equally deliberate — understanding why a technique did
not apply is as important as knowing when it does, and it is what makes the work reproducible.

**Connection to [spectre](../spectre):** gauntlet builds the methodology and enumeration discipline in
isolated lab boxes; spectre applies the same discipline end-to-end in a scoped grey-box engagement
(PTES-structured, SHA-256 evidence chain, scope-halt at the ethical boundary). gauntlet is the drill;
spectre is the engagement. **Connection to [watchtower](../watchtower):** the ATT&CK techniques
demonstrated here map one-to-one to watchtower's Wazuh detection scenarios — the loop closes there.

---

## Platforms

**TryHackMe** — structured learning paths and guided rooms. Useful for building systematic
knowledge of specific techniques (privilege escalation, web exploitation, cryptography) with
immediate feedback.

**HackTheBox** — competitive CTF environment with harder, less guided machines. Closer to a
realistic engagement: the attack surface is defined, but the path from reconnaissance to root
is not signposted.

**Why both?** They train different muscles. TryHackMe's guided structure builds *coverage* — a
systematic, named technique catalogue (the foundation you can map to Sec+ objectives). HackTheBox's
unguided machines build *judgement* — choosing a path with no signposts, which is what a real
engagement demands. Practising on both means the methodology is neither rote (THM-only) nor
unstructured (HTB-only); the writeups deliberately apply the *same* discipline to both so the
transferable skill, not the platform, is what shows.

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
writeups as each box is worked. Every writeup carries command-backed recon/enumeration/
exploitation sections and a per-machine **MITRE ATT&CK technique mapping** — tying the offensive
steps to the framework a defender would use to detect them.

| Machine | Platform | Difficulty | OS | Attack path |
|---------|----------|------------|-----|-------------|
| [Blue](writeups/thm-blue.md) | TryHackMe | Easy | Windows | EternalBlue / MS17-010 → SMBv1 → SYSTEM → hashdump |
| [Kenobi](writeups/thm-kenobi.md) | TryHackMe | Easy | Linux | SMB + NFS enum → ProFTPD mod_copy → SUID/PATH privesc |
| [Steel Mountain](writeups/thm-steel-mountain.md) | TryHackMe | Easy | Windows | Rejetto HFS 2.3 RCE (CVE-2014-6287) → insecure service binary |
| [Alfred](writeups/thm-alfred.md) | TryHackMe | Easy | Windows | Jenkins default creds → Groovy console RCE → token impersonation |
| [Basic Pentesting](writeups/thm-basic-pentesting.md) | TryHackMe | Easy | Linux | SMB user disclosure → SSH key recovery / crack → sudo privesc |
| [Lame](writeups/htb-lame.md) | HackTheBox | Easy | Linux | Samba 3.0.20 usermap_script (CVE-2007-2447) → direct root |
| [Jerry](writeups/htb-jerry.md) | HackTheBox | Easy | Windows | Tomcat Manager default creds → WAR deploy → SYSTEM |

Methodology spine: [methodology/ctf-methodology.md](methodology/ctf-methodology.md) — enumeration
discipline, OWASP→CTF mapping, privilege-escalation triage order, and evidence standards.

The repository is active — new rooms are added as they are completed; check commit history for the
most recent.

---

## Skills Demonstrated

The value of this repository for a security employer is not the flags — retired easy boxes are
solved thousands of times over — but the **discipline and transferability** the writeups show:

- **Methodology over shortcuts.** A consistent recon → enumeration → exploitation → post-exploitation
  → lessons structure applied to every box, with failed paths and ruled-out rabbit holes documented
  (e.g. the vsftpd 2.3.4 decoy on Lame, distcc as the slower alternate route). Knowing *why* a
  technique does not apply is the skill that scales to real engagements.
- **Version-to-vulnerability mapping.** Reading a service banner (`smbd 3.0.20`, `HttpFileServer 2.3`,
  `ProFTPD 1.3.5`) and cross-referencing it to a known CVE before touching anything noisy.
- **Both Linux and Windows privilege escalation.** SUID/PATH interception and NFS-staged key theft on
  Linux; unquoted/writable service paths and `SeImpersonatePrivilege` token impersonation on Windows.
- **Tool fluency and the manual fallback.** Metasploit where appropriate, but the manual path
  (AutoBlue, `{.exec.}` payloads, `ssh2john`, hand-built reverse shells) documented alongside it —
  because the manual route builds understanding and works when tooling is disallowed.
- **Blue-team transferability (SOC relevance).** Every writeup maps its offensive steps to
  **MITRE ATT&CK** (sub-technique level) and ships a **box-specific Wazuh detection rule** plus the
  Event IDs / auditd / Sysmon artefacts a defender would see — the same framework an L1/L2 SOC
  analyst uses to recognise the activity in logs and EDR telemetry. Those rules are the input to the
  [watchtower](../watchtower) SIEM lab, so the offence→detection loop is demonstrated end-to-end, not
  asserted. This deliberately bridges the offensive practice to the #1 target role.
- **Cert-to-hands-on mapping.** Each writeup carries a Sec+ SY0-701 *exam-relevance* table — the box
  made concrete against specific objectives — so the practice doubles as applied certification study.

**Relevant to:** penetration testing / security consulting (offensive methodology and reporting) and
SOC analyst roles (attack-technique recognition, ATT&CK fluency, detection mindset).

---

*Part of the [rootdrifter](https://github.com/rootdrifter) security portfolio — built and maintained by a security-cleared candidate. UK-issued clearance held now, not pending vetting: deployable to cleared work from day one.*
