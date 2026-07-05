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
