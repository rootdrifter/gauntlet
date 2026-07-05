# Blue — TryHackMe

> **Preparation stub.** Based on publicly documented information about this well-known retired
> room — not an original solve, and no live flag values are recorded. Use this as a study scaffold;
> complete the bracketed fields when working the room under your own account.

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

## Key vulnerability class

- **CWE/Class:** Remote code execution via memory corruption in SMBv1 (`srv.sys`).
- **Identifier:** **MS17-010** (CVEs in the 2017-0143…0148 range; EternalBlue is commonly tied to
  **CVE-2017-0144**). *Verify the exact CVE when citing.*
- **Why it matters:** the same flaw weaponised by WannaCry/NotPetya in 2017 — the textbook example
  of why legacy SMBv1 must be disabled and patches applied promptly.

## Attack chain summary

1. **Recon** — full TCP scan; identify SMB (445) and the Windows version. A vuln script flags
   MS17-010.
2. **Verify** — confirm MS17-010 exposure (`nmap --script smb-vuln-ms17-010` or the Metasploit
   scanner module).
3. **Exploit** — run the EternalBlue module (`exploit/windows/smb/ms17_010_eternalblue`), landing a
   shell typically already as **SYSTEM**.
4. **Post-exploitation** — migrate to a stable process; `hashdump`; optionally crack an NTLM hash;
   collect the three flags placed around the filesystem.

## Tools used

| Phase | Tools |
|-------|-------|
| Recon | `nmap` (`-sC -sV -p-`, `--script smb-vuln-ms17-010`) |
| Exploitation | Metasploit (`ms17_010_eternalblue`) |
| Post-exploitation | meterpreter (`migrate`, `hashdump`), `john`/`hashcat` (optional NTLM crack) |

## Lessons learned

- **SMBv1/MS17-010 is a kill shot** — full SYSTEM from a single unpatched service; demonstrates why
  patch management and disabling legacy SMB are non-negotiable.
- **Process migration matters** — the initial EternalBlue process can be unstable; migrate before
  doing further work.
- **Detection note (blue-team transfer):** MS17-010 exploitation is loud — anomalous SMB traffic and
  the spawned SYSTEM process are detectable; map to MITRE **T1210 (Exploitation of Remote Services)**.

## References

- MS17-010 / EternalBlue (verify exact CVE before citing).
- Metasploit `ms17_010_eternalblue` module documentation.
