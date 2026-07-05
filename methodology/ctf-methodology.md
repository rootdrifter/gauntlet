# CTF / Lab Methodology

A systematic, repeatable methodology for boxes and lab targets. The principle throughout: **work in
order, document as you go, and record dead ends** — a missed enumeration step is the most common
reason a box stalls. Applies only to legally authorised CTF/lab activity.

---

## 1. Initial enumeration checklist (what to run, in what order, why)

Enumeration is breadth-first then depth-first. Map the whole surface before committing to a vector.

### 1.1 Network / port scan (always first)

```bash
# Fast full-port sweep to find everything, then targeted service scan on what's open
nmap -p- --min-rate=1000 -T4 -oN nmap/allports 10.x.x.x
nmap -sC -sV -p<comma,sep,ports> -oN nmap/services 10.x.x.x
# UDP (selective — slow): top ports only
sudo nmap -sU --top-ports 50 -oN nmap/udp 10.x.x.x
```

- **Why full ports first:** services on non-standard high ports are the classic "I was stuck for an
  hour" miss. `-p-` finds them; the second scan adds `-sC -sV` only where needed.
- **Why `-oN` (and ideally `-oA`):** keep evidence and re-reference without rescanning.
- **Order rationale:** ports → services/versions → version-specific known exploits. Note the OS.

### 1.2 Per-service enumeration (depth, by what's open)

| Service / port | First moves |
|----------------|-------------|
| **HTTP/HTTPS** (80/443/8080/8000) | `whatweb`; browse + view source; `gobuster`/`feroxbuster` dir + vhost; check `robots.txt`, `/.git`, default creds, CMS version |
| **SMB** (139/445) | `enum4linux -a`; `smbclient -L`; null-session shares; user enumeration |
| **FTP** (21) | Banner/version; **anonymous login**; version-specific exploits (e.g. ProFTPD mod_copy) |
| **SSH** (22) | Version; usually *not* the foothold — note for later credential reuse |
| **NFS / rpcbind** (111/2049) | `showmount -e`; mount exports; look for keys/creds |
| **DNS** (53) | Zone transfer attempt (`dig axfr`), subdomain discovery |
| **SMTP/POP/IMAP** | User enumeration (`VRFY`), version |
| **Databases** (3306/5432/1433/6379) | Default creds, unauth access, version exploits |

- **Document what you ruled out.** "FTP anonymous = denied" is evidence that narrows the path.
- **Map every version to known exploits** (searchsploit / vendor advisories) *before* exploiting.

### 1.3 Note-taking from the first command

Keep a running log per target (see §4). Record: open ports, versions, creds/usernames found,
hypotheses, and what failed.

---

## 2. Web application testing checklist (OWASP Top 10 → common CTF vulns)

Map the OWASP Top 10 to what actually appears on boxes:

| OWASP (2021) | Common CTF manifestation | First checks |
|--------------|--------------------------|--------------|
| **A01 Broken Access Control** | IDOR, forced browsing, dir listing, `/admin` reachable | Change IDs/params; `gobuster`; check auth on each path |
| **A02 Cryptographic Failures** | Cleartext creds, weak hashes, exposed keys/backups | Inspect responses, JS, `/.git`, backup files |
| **A03 Injection** | SQLi, command injection, LFI/RFI, SSTI | Test inputs with `'`, `;`, `{{7*7}}`, `../`; `sqlmap`; Burp |
| **A04 Insecure Design** | Logic flaws, password-reset abuse | Manual workflow testing |
| **A05 Security Misconfiguration** | Default creds, verbose errors, dir indexing, exposed admin panels | Default logins, error messages, `/server-status` |
| **A06 Vulnerable Components** | Outdated CMS/library with public exploit | Version → searchsploit |
| **A07 Auth Failures** | Weak/brute-forceable creds, no lockout | `hydra`/`ffuf` against forms (after narrowing user) |
| **A08 Integrity Failures** | Insecure deserialization, unsigned updates | Inspect serialized blobs, file-upload handling |
| **A09 Logging/Monitoring** | (Mostly a defence gap; less common as a CTF vector) | — |
| **A10 SSRF** | Internal-resource fetch via a URL parameter | Point parameters at `127.0.0.1`/metadata endpoints |

**Web workflow:** fingerprint (`whatweb`) → content discovery (`gobuster`/`feroxbuster`) → manual
review (source, JS, comments, cookies) → targeted injection/auth testing in **Burp** → exploit. Use
a wordlist appropriate to scope (`dirb/common.txt` for quick, SecLists `*-medium` for thorough).

---

## 3. Privilege-escalation checklist

After a foothold, **stabilise the shell** first (`python3 -c 'import pty; pty.spawn("/bin/bash")'`,
`stty raw -echo`, set `TERM`), then enumerate.

### 3.1 Linux

Run an automated scan **and** check the high-yield vectors manually:

```bash
sudo -l                       # sudo misconfig — single highest-yield check
find / -perm -4000 2>/dev/null   # SUID binaries → GTFOBins
getcap -r / 2>/dev/null       # capabilities
crontab -l; cat /etc/crontab; ls -la /etc/cron.*   # cron jobs / writable scripts
ls -la /  ; find / -writable -type d 2>/dev/null    # writable paths
cat /etc/passwd; ls -la /home/*; find / -name id_rsa 2>/dev/null  # creds/keys
uname -a                      # kernel (last resort: kernel exploits)
```

### 3.2 Interpreting LinPEAS output

LinPEAS colour-codes risk — **red/yellow = highly likely escalation vector**. Triage in this order:

1. **`sudo -l` / sudo version** — NOPASSWD entries and dangerous allowed binaries (GTFOBins) are the
   fastest win.
2. **SUID/SGID + capabilities** — cross-reference every non-standard SUID binary against **GTFOBins**.
3. **Cron jobs** — writable scripts run by root, wildcard/`PATH` injection.
4. **Writable files in sensitive locations** — service unit files, `/etc/passwd` writable, writable
   `PATH` dirs used by SUID binaries.
5. **Credentials** — passwords in config/history/backup files; reused creds (DB → SSH).
6. **Kernel exploits** — *last*, because they are unstable; only after the above are exhausted.

> Don't drown in LinPEAS output — scan the red/yellow highlights, then verify each candidate
> manually. An automated finding is a lead, not a confirmed exploit.

### 3.3 Windows

```
whoami /priv                  # SeImpersonatePrivilege/SeBackup etc. → Potato/token abuse
whoami /groups
```

- **winPEAS / PowerUp** for unquoted service paths, writable service binaries,
  `AlwaysInstallElevated`, stored creds.
- **`whoami /priv` first** — impersonation privileges are a direct SYSTEM path (see thm-alfred).
- Service misconfig (writable binary / unquoted path) — see thm-steel-mountain.

### 3.4 Common-vector quick map

| Vector | Tell-tale | Exploit route |
|--------|-----------|---------------|
| sudo misconfig | NOPASSWD / risky binary in `sudo -l` | GTFOBins sudo entry |
| SUID | unusual binary in `find -perm -4000` | GTFOBins SUID entry / PATH hijack |
| Cron | writable script run by root | inject payload; wait for run (`pspy` to observe) |
| Writable service (Win) | service exe writable | replace exe, restart service |
| Token (Win) | `SeImpersonatePrivilege` | Incognito / Potato family |
| Credential reuse | password in file/history | try across SSH/DB/other users |

---

## 4. Evidence capture standards

Discipline here makes a writeup defensible and a real engagement auditable (mirrors the
[../../spectre](../../spectre) repo's SHA-256 evidence approach).

### 4.1 Command logging

- Log the whole session: `script -a session.log` (or `tmux` logging) from the start.
- Keep scan output files (`nmap -oA`), not just terminal scrollback.
- Maintain a running notes file per target with timestamped findings, hypotheses, and **dead ends**.

### 4.2 Screenshot naming

Use a consistent, sortable scheme so screenshots map to the writeup sections:

```
<machine>_<NN>_<phase>_<short-desc>.png
# e.g. blue_01_recon_nmap.png, blue_04_privesc_hashdump.png
```

- `NN` is a zero-padded sequence so screenshots sort in attack order.
- One screenshot per meaningful step (the command + its result), not a wall of duplicates.

### 4.3 Hash verification (integrity)

Hash artefacts on capture so you can prove nothing changed afterwards:

```bash
sha256sum *.png nmap/* session.log notes.md > evidence.sha256
sha256sum -c evidence.sha256        # re-verify before writing up / archiving
```

- This proves **integrity of collected evidence** (not full forensic chain of custody — see the
  spectre methodology-context note on the distinction).

### 4.4 Flag handling

- In published writeups, **redact or note "captured"** rather than pasting live flag values — posting
  flags spoils the room and can breach platform rules. The *method* is the deliverable.

---

## 5. The repeatable loop (summary)

```
Scan all ports → service-scan open ports → enumerate each service (note ruled-out paths)
   → map versions to known exploits → pick a vector (record why, and what you tried first)
   → foothold → stabilise shell → privesc enumeration (sudo/SUID/cron/creds, then kernel)
   → escalate → capture evidence (logs + named screenshots + hashes) → write up (incl. dead ends)
```

> Document the reasoning, not just the commands. "Why this vector, and what failed first" is the
> part that transfers to real engagements and to interviews.

---

## 6. How CTF practice maps to a real pentest (PTES)

CTF boxes are a *subset* of a professional engagement — they exercise the technical core but skip the
process wrapper. Knowing the mapping (and the gaps) is what turns "I do CTFs" into "I understand
engagements". The seven PTES phases vs what a CTF actually covers:

| PTES phase | CTF coverage | What CTFs leave out (and you must learn separately) |
|------------|--------------|------------------------------------------------------|
| **Pre-engagement / scoping** | None — scope is the box | Rules of engagement, authorisation, scope boundaries, emergency contacts |
| **Intelligence gathering** | Partial — active recon on one host | Real OSINT, multi-host attack surface, client-specific intel |
| **Threat modelling** | Implicit | Mapping findings to the client's actual business risk |
| **Vulnerability analysis** | Strong — version→CVE mapping, enumeration | Authenticated scanning at scale, asset criticality weighting |
| **Exploitation** | Strong — the core CTF skill | Production-safety (don't crash the client), change windows |
| **Post-exploitation** | Strong — privesc, loot, pivot | Scoped data handling, "prove impact without exfiltrating real data" |
| **Reporting** | This is where the gauntlet writeups add the most | Exec summary in business language, prioritised remediation, retest |

**The honest framing for interviews:** "CTFs build the methodology and enumeration discipline; the
process wrapper — scoping, client comms, production safety, business-language reporting — is what I'd
learn on the job. I practise the reporting half deliberately, because that's the part most CTF players
skip." Scope discipline is the bridge: in [../../spectre](../../spectre) I halted enumeration at the
agreed ethical boundary and documented what I chose *not* to do — the single most transferable habit.

## 7. MITRE ATT&CK mapping approach

Every writeup maps its steps to ATT&CK because it is the **bridge from offence to detection** — the
same framework a SOC analyst uses to recognise the activity in logs (directly relevant to the
SOC-analyst target role; see [../../sec-plus-notes](../../sec-plus-notes) Domain 4).

How to map a step, consistently:
1. **Identify the tactic** (the *why* / the adversary's goal): Initial Access, Execution, Privilege
   Escalation, Credential Access, Lateral Movement, etc.
2. **Pin the technique/sub-technique** (the *how*) to a specific ID — e.g. SSH brute force →
   **T1110**, EternalBlue → **T1210**, token impersonation → **T1134.001**, unquoted/writable service
   → **T1543.003 / T1574.009**, SUID/PATH privesc → **T1548.001 / T1574.007**.
3. **Add the detection note** (the blue-team transfer): which log/telemetry would catch this step
   (e.g. Windows Event 7045 for service creation, `auth.log` for SSH brute force). This is what makes
   the mapping useful rather than decorative.
4. **Map per-step, not per-box** — a single box touches several tactics; a one-line-per-box label
   loses the chain.

Pitfall to avoid: don't force an ID where none fits, and don't confuse a *tool* (nmap) with a
*technique* (T1046 Network Service Discovery) — ATT&CK describes behaviour, not software.

## 8. Writeup discipline — a writeup vs a tool dump

A tool dump is "here are my commands and their output". A writeup is "here is how I *reasoned*". The
difference is what an employer is actually buying. A good gauntlet writeup:

- **Leads with reasoning, not commands.** Every command answers a stated question ("is SMB
  exposed?"), and the output is interpreted, not just pasted.
- **Documents the dead ends.** The ruled-out vsftpd decoy on *Lame*, the 403 on *spectre*'s
  `/server-status` — recognising a rabbit hole quickly is itself a skill, and hiding failures makes
  the work unreproducible.
- **Explains vector choice.** "I chose the Samba path over distcc because it yields root in one step
  with no privesc" beats silently running the winning exploit.
- **Maps findings to a framework** (CWE for the weakness type, ATT&CK for the behaviour) so the work
  connects to detection and remediation.
- **Is honest about provenance.** Where a box is a study scaffold rather than an original solve, it's
  labelled a **preparation stub** with no fabricated flag values. Under-claim and be trusted.
- **Captures evidence to the §4 standard** (logs, named screenshots, hashes) so it's auditable.

> Test for a good writeup: could a peer reproduce the solve *and* understand why each decision was
> made, from the writeup alone? If yes, it's a writeup. If they only get a list of commands, it's a
> dump.

---

## 9. Enumeration philosophy and tool selection

Enumeration is where engagements are won or lost — most "I'm stuck" moments are missed enumeration,
not a missing exploit. The discipline is **breadth before depth, and a stated reason for every tool**.

**The philosophy in four rules:**
1. **Enumerate wide, then deep.** Sweep all ports/services first so you know the whole surface before
   committing to one path — committing early to port 80 while a writable SMB share sits on 445 is the
   classic time-sink.
2. **Let the result pick the next tool, not habit.** A port is a question, not an answer: 445 open →
   "is this SMB signed? null-session enumerable? a known CVE version?" — the *answer* selects
   enumeration vs exploitation.
3. **Quiet first, loud only when justified.** Start with the least-noisy technique that answers the
   question; escalate noise only when you need to. (On a CTF this is practice for the real-engagement
   habit of not tripping every alarm.)
4. **Record what you ruled out.** A negative result is data — "no anonymous FTP, SMB signing on, web
   root clean" narrows the path and is half of a reproducible writeup.

**Tool-selection rationale (why this tool for this job):**

| Situation | Tool + key flags | Why this and not the alternative |
|-----------|------------------|----------------------------------|
| Find every open port fast | `nmap -p- --min-rate 1000 -T4` | Full range first; rate-limited SYN is fast and reliable — a top-1000 scan *misses* high-port services (the trap) |
| Identify services on open ports | `nmap -sC -sV -p<list>` | Targeted version+default-scripts only on the *known-open* ports — don't `-sV` all 65k, it's wasteful |
| UDP (only when relevant) | `nmap -sU --top-ports 20` | UDP is slow; scan selectively (SNMP/DNS/TFTP) rather than full-range |
| Web content discovery | `feroxbuster`/`gobuster` + a sane wordlist | Directory brute force after a manual look; pick the wordlist to the stack (raft/seclists), not the biggest list blindly |
| Web fingerprint | `whatweb`, `nikto` | Quick tech + low-hanging misconfig (the spectre CWE-548 class) before heavier tooling |
| SMB enumeration | `smbclient -L`, `enum4linux-ng` | Null-session shares/users before reaching for an exploit |
| Linux privesc survey | `linpeas.sh` (interpret, don't trust) | Fast surface; **§3.2** says read the *highlighted* findings critically, don't run the first "95% PE" suggestion blindly |
| Windows privesc survey | `winPEAS`, `Seatbelt` | Service/permission/credential misconfig enumeration |

> The interview-grade sentence: "I scan all ports first because a top-1000 scan would have missed the
> service that actually mattered, then I let each open port dictate the next tool rather than running
> a fixed script." That is the whole philosophy in one line.

## 10. Exploitation and post-exploitation discipline

**Exploitation — minimal footprint:**
- **Pick the path with the fewest moving parts.** If two vectors reach the goal, prefer the one that
  is most reliable and least destructive (e.g. a documented auth bypass over a memory-corruption
  exploit that may crash the service). Record *why* you chose it.
- **Understand the exploit before you run it.** Know what it changes on the target (files dropped,
  service restarted, ports opened) so you can clean up and so the writeup is honest about impact.
- **One change at a time.** Make a single change, observe, record — so cause and effect stay clear
  and the run is reproducible.
- **Capture evidence at the moment of impact** (§4): the proof screenshot, the command, the hash —
  not reconstructed afterward.

**Post-exploitation checklist (run in this order):**
1. **Stabilise** the shell (`python3 -c 'import pty; pty.spawn("/bin/bash")'`, then upgrade the TTY) —
   an unstable shell loses work.
2. **Situational awareness** — `id`/`whoami`, `hostname`, OS/kernel, network position (`ip a`,
   `ss -tulpn`), what other hosts/segments are reachable.
3. **Loot, scoped** — collect *proof* (flags, a screenshot of access) but, in the real-engagement
   mindset, **prove impact without exfiltrating real data** (§6 PTES note). On a CTF the flag is the
   proof; in production you'd document access, not hoover up the database.
4. **Privesc enumeration** — sudo/SUID/cron/capabilities/credentials *before* kernel exploits (less
   risky, more reliable).
5. **Persistence/pivot — only if in scope** and only documented. On CTFs this is rarely needed; the
   habit to build is *asking whether it's in scope at all*.
6. **Note cleanup** — what you'd remove to leave the host as found (dropped binaries, added users).
7. **Record the chain** for the writeup — every tactic touched, in order, with the ATT&CK ID (§7).

## 11. From offence to detection — building the blue-team half

The target role is **SOC analyst**, so every offensive step is studied for *how it would be caught*.
This is the deliberate differentiator: most CTF players stop at the flag; this practice continues to
"what alert should have fired?".

For each technique in a writeup, answer three blue-team questions:
1. **What log/telemetry records it?** (e.g. SSH brute force → `auth.log` / Windows 4625; service
   install → Windows **7045**; new process → Sysmon **Event 1**; SMB exploit → SMB audit + IDS sig.)
2. **What would the detection rule look like?** A threshold (N failures in M seconds), a signature
   (known exploit bytes), or an anomaly (a service binary running from `%TEMP%`).
3. **What's the mitigation** that removes the vector (patch, config, least privilege)?

This is exactly the **GAUNTLET_BRIDGE** to [../../watchtower](../../watchtower): each ATT&CK technique
demonstrated here maps to a Wazuh detection scenario there. Offence proves the technique works;
detection engineering proves you can catch it. Demonstrating *both halves* of the same technique is
the portfolio's core SOC argument — and the reason the writeups carry detection notes, not just
exploitation steps.

> Interview framing: "I don't just want to know how to pop the box — I want to know what I'd look for
> in the SIEM to catch someone doing it to me. That's why each writeup has a detection section, and
> why the techniques map straight into my Wazuh lab."
