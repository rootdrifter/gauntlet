# Kenobi — TryHackMe

> **Preparation stub.** Based on publicly documented information about this retired room — not an
> original solve, and no live flag values are recorded. Complete the bracketed fields when working
> the room under your own account.

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

A Linux host running a vulnerable **ProFTPD 1.3.5**, an exposed **Samba** share, and an
NFS export. The chain abuses ProFTPD's `mod_copy` to stage an SSH key into an NFS-mounted path,
gains a foothold over SSH, then escalates to root via a **SUID binary with an unsafe `PATH`**
dependency. Teaches service-chaining and SUID/PATH privilege escalation.

## Key vulnerability class

- **Foothold:** ProFTPD **1.3.5 `mod_copy`** arbitrary file copy — **CVE-2015-3306** (the
  `SITE CPFR`/`CPTO` commands allow copying files without authentication). *Verify CVE when citing.*
- **Privesc:** insecure **SUID** binary (`/usr/bin/menu`) that calls system utilities **by relative
  name**, exploitable via **`PATH` manipulation** (CWE-426 Untrusted Search Path / CWE-732
  permissions).
- **Enabler:** **NFS** export and Samba misconfiguration exposing file paths.

## Attack chain summary

1. **Recon** — full scan: FTP (ProFTPD 1.3.5), SSH, HTTP, Samba (139/445), `rpcbind`/NFS (111/2049).
2. **Enumerate** — `enum4linux`/`smbclient` on Samba; `showmount -e` reveals the NFS export and a
   writable/mountable path.
3. **Exploit (mod_copy)** — use `SITE CPFR`/`CPTO` to copy the user's SSH **private key** into the
   NFS-exported directory.
4. **Foothold** — mount the NFS share, retrieve the private key, SSH in as the user; collect the
   user flag.
5. **Privesc** — find SUID `/usr/bin/menu`; it runs commands by relative path. Prepend a malicious
   `PATH` entry (a fake `curl`/`ifconfig` etc.) so the SUID binary executes attacker code as **root**;
   collect the root flag.

## Tools used

| Phase | Tools |
|-------|-------|
| Recon | `nmap` (`-sC -sV -p-`) |
| Enumeration | `enum4linux`, `smbclient`, `showmount`, `nmap` NSE (`nfs-*`) |
| Exploitation | netcat/FTP client for `mod_copy` `SITE CPFR/CPTO`; `mount` for NFS |
| Privilege escalation | `find / -perm -4000` (SUID hunt), `PATH` hijack, GTFOBins reference |

## Lessons learned

- **Service chaining** — no single bug was sufficient; the solve came from combining mod_copy +
  NFS + SSH. Enumerate *all* services and think about how they connect.
- **SUID + relative command = privesc** — always check what a SUID binary calls and whether it
  trusts `PATH`. Classic, recurring real-world misconfiguration.
- **`showmount -e` is cheap and high-value** — exposed NFS exports are an easy win and easy to miss.
- **Blue-team transfer:** detect via anomalous FTP `SITE` commands, unexpected NFS mounts, and SUID
  execution with a tampered environment.

## References

- ProFTPD mod_copy CVE-2015-3306 (verify).
- GTFOBins (SUID/PATH abuse patterns).
