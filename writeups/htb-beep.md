# Beep — HackTheBox

> **Preparation stub.** Based on publicly documented information about this retired machine — not an
> original solve, and no live flag values are recorded. Use this as a study scaffold; complete the
> bracketed fields when working the box under your own account. Only document legally authorised
> activity.

## Engagement metadata

| Field | Value |
|-------|-------|
| Platform | HackTheBox |
| Machine | Beep |
| Difficulty | Easy |
| Category | Linux |
| Target IP | 10.10.x.x (lab-assigned) |
| Date completed | [YYYY-MM-DD] |

## Executive summary

A Linux host running **Elastix** (a FreePBX/Asterisk VoIP distribution) on Apache. A **Local File
Inclusion** in the bundled vtigerCRM (`graph.php`) reads server config files; `/etc/amportal.conf`
discloses the **AMP/manager admin password** in cleartext. That password is **reused for the root SSH
account**, so a direct SSH login (over a legacy key-exchange the old daemon requires) yields root.
The box is the canonical "LFI → credential disclosure → password reuse → root" chain.

## Key vulnerability class

- **CWE:** CWE-98 (LFI) → CWE-312 (cleartext credentials in config) → CWE-521/CWE-262 (password
  reuse across services).
- **Why it matters:** none of the steps is a memory-corruption exploit — it is enumeration, an
  inclusion bug, and the single most common real-world failure (**password reuse**). Highly
  transferable.

## 1. Reconnaissance

```
nmap -sC -sV -p- --min-rate 1000 -oA nmap/beep 10.10.x.x
```

Expected exposed surface (confirm on completion):

| Port | Service | Note |
|------|---------|------|
| 22/tcp | SSH (old OpenSSH) | **root login + reused password** (needs legacy KexAlgorithms) |
| 25/110/143 | SMTP/POP3/IMAP | mail stack (PBX voicemail) |
| 80/443 | http/https (Elastix) | **The LFI vector** |
| 3306 | MySQL | backend |
| 4445/5038/10000 | Asterisk mgmt / Webmin | alternate surfaces |

**nmap flag rationale:**
- `-p-` — this box exposes *many* services; a full scan shows the breadth (PBX + mail + Webmin) and
  avoids tunnel-vision on 443.
- `-sV` — pins the **Elastix** stack and the **old OpenSSH** (the version that forces a legacy
  key-exchange — a detail you need for the final SSH login).
- `-sC` — `http-title`/ssl scripts identify Elastix quickly.

**What to look for:** an Elastix login page (the LFI target) and an old SSH banner (foreshadows the
legacy-cipher login). Many open ports = enumerate breadth before committing.

## 2. Enumeration

```
# Browse https://10.10.x.x/  -> Elastix login (don't brute it; find the LFI)
# Known LFI in the bundled vtigerCRM graph.php:
curl -sk "https://10.10.x.x/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action="
```
- The LFI + **null-byte (`%00`) truncation** (old PHP) reads `/etc/amportal.conf`, which contains
  `AMPDBPASS` / `AMPMGRPASS` in **cleartext**.
- *Tool selection:* manual `curl` over a scanner — the vector is a *known* path; reading one config
  file beats noisy directory brute-forcing. Searchsploit `elastix` confirms the LFI path.

## 3. Exploitation

- Recover the admin/manager password from `amportal.conf`.
- Test **password reuse** against SSH as **root** (the box's design flaw). The old daemon needs an
  explicit legacy key-exchange/cipher:
  ```
  ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-rsa root@10.10.x.x
  ```
- *Vector choice:* SSH-as-root via reused creds is the cleanest single step; record the alternative
  (Elastix RCE / Shellshock on the web stack) as a considered route. **One step to root because the
  admin password was reused** — that's the lesson.
- [Both flags on completion — root login means user + root together.]

## 4. Post-exploitation

- Already root via the SSH login. Confirm `id`, capture proof, and (real-engagement mindset) note
  what you would *not* exfiltrate.
- [Root flag on completion.]

## 5. Tools used

`nmap`, `curl`, `searchsploit`, `ssh` (with legacy `-oKexAlgorithms`/`-oHostKeyAlgorithms`).

## 6. MITRE ATT&CK mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Reconnaissance | Active scanning | T1595 |
| Initial Access / Execution | Exploit public-facing app (LFI) | T1190 |
| Credential Access | Unsecured credentials in files | T1552.001 |
| Defense Evasion / Discovery | File and directory discovery (via LFI) | T1083 |
| Lateral Movement / Privilege Escalation | Valid accounts (password reuse) → SSH | T1078 / T1021.004 |

## 7. Key learnings

- **Password reuse is the whole box** — one cleartext credential in a config, reused for root SSH.
- **Cleartext secrets in config files** (`amportal.conf`) are a CWE-312 finding in their own right.
- **Legacy SSH crypto** (`diffie-hellman-group1-sha1`) — you must know the override flags *and*
  recognise that a server requiring them is itself a hardening finding (weak/deprecated algorithms).

## 8. Defender perspective — logs & detection

- **Apache access log:** the LFI request — `../` traversal sequences and `amportal.conf`/`%00` in a
  query string are an unmistakable inclusion signature.
- **auth.log:** a **root** SSH login (root login should be disabled) — and one negotiating a
  **deprecated key-exchange** (`diffie-hellman-group1-sha1`), which is itself alert-worthy.
- **Correlation:** the LFI read of a credential file followed shortly by a successful SSH login is
  the chain — credential disclosure → reuse.

### Wazuh detection rule (→ [watchtower](../../watchtower))

```xml
<group name="web,apache,sshd,attack,">
  <!-- LFI: traversal + sensitive config file in the request -->
  <rule id="100600" level="13">
    <decoded_as>web-accesslog</decoded_as>
    <url type="pcre2">(\.\./){2,}|amportal\.conf|%00</url>
    <description>Local File Inclusion / path traversal to a config file (T1190/T1083)</description>
    <mitre><id>T1190</id><id>T1083</id></mitre>
  </rule>
  <!-- Root SSH login (should be disabled) — high signal -->
  <rule id="100601" level="12">
    <if_sid>5715</if_sid>
    <field name="srcuser">root</field>
    <description>Successful SSH login as root — policy violation / credential reuse (T1078)</description>
    <mitre><id>T1078</id></mitre>
  </rule>
</group>
```
**Validation:** fire the LFI request and confirm 100600; SSH as root and confirm 100601; verify the
two correlate within a short window. Sub-techniques: **T1190**, **T1552.001**, **T1078**,
**T1021.004**.

## Exam relevance — Sec+ SY0-701

| SY0-701 objective | How Beep makes it concrete |
|-------------------|-----------------------------|
| **2.2** Application attacks — inclusion/traversal | LFI is the "malicious file inclusion" class. |
| **2.2 / 4.6** Unsecured & reused credentials | Cleartext config password reused for root = the exam's password-reuse + insecure-storage answers. |
| **1.4 / 3.1** Weak/deprecated cryptography | The forced `diffie-hellman-group1-sha1` is a deprecated-algorithm finding. |
| **4.1** Hardening | Disable root SSH login, remove deprecated KEX, encrypt/secret-manage config creds. |
| **2.4** Indicators | `../`+`amportal.conf` reads and a root SSH login are the indicators (§8). |

**Interview line:** "Beep is a password-reuse box — one cleartext credential in a config, reused for
root over SSH. It's why I argue for secret management, disabling root login, and retiring deprecated
crypto as separate, compounding controls."

## 9. References

- Elastix / vtigerCRM `graph.php` LFI (verify the exact advisory/CVE before citing).
- OpenSSH legacy key-exchange (`diffie-hellman-group1-sha1`) deprecation notes.
- MITRE ATT&CK T1190 / T1552.001 / T1078 / T1021.004.
