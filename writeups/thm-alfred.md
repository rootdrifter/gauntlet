# Alfred — TryHackMe

> **Preparation stub.** Based on publicly documented information about this retired room — not an
> original solve, and no live flag values are recorded. Complete the bracketed fields when working
> the room under your own account.

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

## Key vulnerability class

- **Foothold:** **Jenkins** exposed with weak/default credentials → authenticated **Groovy Script
  Console RCE** (CWE-1188 insecure default / CWE-78 command execution via an admin feature). This is
  a *configuration/exposure* issue, not a single CVE.
- **Privesc:** **token impersonation** via **`SeImpersonatePrivilege`** held by the service account —
  the classic "Potato" family (e.g. Incognito token-stealing / JuicyPotato-style) to obtain a SYSTEM
  token (CWE-269 improper privilege management).

## Attack chain summary

1. **Recon** — scan finds a web service; identify **Jenkins** (often on port **8080**).
2. **Access** — log in with weak/guessable creds (commonly `admin:admin`; brute-force with Hydra if
   needed).
3. **Exploit (Groovy RCE)** — in **Manage Jenkins → Script Console**, run a Groovy one-liner that
   executes a command / fetches and runs a reverse-shell payload (e.g. a Netcat or PowerShell
   payload hosted on the attacker box); catch the shell; collect the user flag.
4. **Enumerate privileges** — `whoami /priv` shows **`SeImpersonatePrivilege` = Enabled**.
5. **Privesc (token impersonation)** — use Metasploit **Incognito** (`load incognito` →
   `impersonate_token`) or a Potato-style tool to impersonate `NT AUTHORITY\SYSTEM`; collect the
   root/admin flag.

## Tools used

| Phase | Tools |
|-------|-------|
| Recon | `nmap` (`-sC -sV -p-`) |
| Access | browser, `hydra` (if brute-forcing Jenkins login) |
| Exploitation | Jenkins Groovy Script Console; `nc`/PowerShell reverse shell; `msfvenom` |
| Privesc | meterpreter `incognito` (`impersonate_token`) / Potato-family token abuse; `whoami /priv` |

## Lessons learned

- **CI/CD systems are high-value footholds** — an exposed Jenkins with a Script Console is effectively
  RCE-as-a-feature; never expose Jenkins without auth and never leave default creds.
- **`SeImpersonatePrivilege` is a SYSTEM ticket** — service accounts holding it are routinely
  escalated via the Potato/Incognito techniques; always run `whoami /priv` early on Windows.
- **`whoami /priv` first** — privilege enumeration is faster than blind kernel-exploit hunting on
  Windows.
- **Blue-team transfer:** MITRE **T1078 (Valid/Default Accounts)**, **T1059 (Command/Scripting)**,
  **T1134 (Access Token Manipulation)**; detect anomalous Jenkins console use and token-impersonation
  events.

## References

- Jenkins Script Console RCE technique (configuration exposure, not a single CVE).
- Potato / Incognito `SeImpersonatePrivilege` abuse references.
