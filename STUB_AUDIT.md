# Writeup Audit & Scoring

An honest internal quality audit of all 11 writeups, scored 1–10 against a fixed rubric. The point is
to find the genuinely weakest material and say *why* — not to flatter the repo. Where a writeup is
labelled a **preparation stub** (built from public documentation, not yet solved under my own
account), that is a completeness ceiling by design, not a defect: a stub can be a 9/10 *stub* while
still awaiting live flag values.

> Audited 2026-06-12. Re-run when a stub is completed under my own account (flag values + real output
> replace bracketed fields) or when a writeup gains content.

## Rubric (10 points)

| Criterion | Weight | What earns the points |
|-----------|--------|------------------------|
| Recon/enum command-fidelity | 2 | Exact commands + flag rationale, not hand-waving |
| Exploitation reasoning | 2 | *Why this vector*, alternatives considered, what failed first |
| Privesc depth | 1 | Triage order shown, not just the winning command |
| ATT&CK mapping | 1 | Sub-technique level, accurate tactic placement |
| Defender perspective | 2 | Log sources + a working Wazuh rule that ties to watchtower |
| Sec+ exam relevance | 1 | Objective-mapped, makes the cert concrete |
| Honesty / reproducibility | 1 | Stub labelled, no fabricated flags, ruled-out paths documented |

## Scores

| # | Writeup | Diff | OS | Lines | Uniq ATT&CK | Score | One-line verdict |
|---|---------|------|-----|-------|-------------|-------|------------------|
| 1 | thm-alfred | Easy | Win | 262 | 6 | **9** | Deepest Windows box; Jenkins→Groovy→token impersonation fully reasoned |
| 2 | thm-kenobi | Easy | Lin | 260 | 5 | **9** | Strong multi-service chain (SMB+NFS+ProFTPD), clean SUID/PATH privesc |
| 3 | thm-steel-mountain | Easy | Win | 255 | 4 | **8** | Solid HFS CVE→insecure-service; could add the manual (non-MSF) path detail |
| 4 | thm-basic-pentesting | Easy | Lin | 238 | 9 | **9** | Best ATT&CK breadth; SMB→SSH-key→sudo well documented |
| 5 | thm-blue | Easy | Win | 242 | 5 | **9** | Canonical EternalBlue; excellent defender pairing (IDS + host) |
| 6 | htb-jerry | Easy | Win | 226 | 5 | **8** | Tomcat→WAR→SYSTEM; short box, writeup appropriately complete |
| 7 | htb-lame | Easy | Lin | 224 | 2 | **8** | Single-CVE direct-root; 2 techniques is *correct* for this box, not thin |
| 8 | thm-skynet | Easy | Lin | 172 | 7 | **7** | Good cred-chain→RFI→tar-wildcard; **stub**, bracketed flags |
| 9 | thm-relevant | Med | Win | 170 | 7 | **8** | Best stub: writable-share→aspx→SeImpersonate, two-misconfig narrative |
| 10 | htb-bashed | Easy | Lin | 160 | 6 | **7** | phpbash→sudo→cron→root; **stub**, solid but shortest |
| 11 | htb-beep | Easy | Lin | 164 | 6 | **7** | Elastix LFI→cred-reuse→root; **stub**, multiple-paths box under-explored |

**Distribution:** 9×4 · 8×4 · 7×3. Mean ≈ 8.0. No writeup below 7 — the repo is genuinely solid,
not a pile of thin stubs. The honest read is that the depth gap is small and is concentrated in the
four newest additions (skynet, relevant, bashed, beep), which are well-structured but await live
solves and could carry more *alternative-path* discussion.

## The 3 lowest-scoring writeups (C2 targets)

Scoring ties at 7 → ranked by remaining headroom: **htb-beep (7), htb-bashed (7), thm-skynet (7).**
These are the ones where added depth buys the most. They are already ~85% complete; the enhancement
queue below takes them to ~90% without running the machine (live flags still require a solve).

### htb-beep — Elastix
- **Box is multi-path** (the famous "many ways to root" box). Currently documents the LFI→cred-reuse
  route only. *Add:* the alternative `webmin` LFI and the `shellshock` route as ruled-out/alternate
  vectors with the reasoning for choosing the SSH cred-reuse path — this is exactly the judgement the
  README claims the repo trains.
  > **Addressed 2026-06-19:** §3 now carries the full quietest-first contingency tree (SSH cred-reuse
  > chosen; Elastix LFI→RCE, Shellshock, and Webmin:10000 documented as ruled-out/fallback vectors
  > with reasoning). The remaining headroom is the live solve (flag values + real output).
- **Recon precision:** note the SSL-cert CN leak and the FreePBX version banner as the version→CVE
  pivot. `nmap -sC -sV -p- --min-rate 1000` then the targeted Elastix LFI path.
- **Detection add:** an LFI signature on the Apache access log (`?file=../` / `amportal` path traversal)
  → Wazuh rule keyed on the web-log pattern; pair with an auth log rule for the reused SSH password.

### htb-bashed — phpbash
- **Currently shortest (160 lines).** *Add:* the enumeration that *finds* `/dev/phpbash.php` (gobuster
  wordlist choice + why `dev/` is the giveaway) and the `sudo -l` → `scriptmanager` reasoning.
- **Privesc depth:** the writable-cron-as-scriptmanager step deserves the `pspy` evidence (catching the
  root-run cron without credentials) — the canonical "watch for scheduled tasks" lesson.
- **Detection add:** Wazuh rule for a web shell spawning `python`/`bash` (web-server parent → shell
  child), plus a `pspy`-equivalent auditd rule on cron execution as root.
  > **Addressed 2026-06-22:** §4 now carries the `pspy64 -pf` step (confirms the root cron without
  > credentials, with the explicit "`crontab -l` shows only your jobs" rationale); §8 adds the
  > web-server→interpreter process-lineage detection (rule `100522`, flagged higher-fidelity than the
  > URL match because it survives the shell being renamed). Remaining headroom: the live solve.

### thm-skynet — SMB→SquirrelMail→Cuppa RFI→tar-wildcard
- **Longest technique chain of the three** but thin on the **tar-wildcard cron** privesc, which is a
  high-value, frequently-tested technique (`--checkpoint-action`). *Add:* the exact malicious-filename
  payload mechanics and *why* the wildcard expands into argument injection.
- **Recon:** the `/etc/hosts`-style vhost / SMB share that leaks the SquirrelMail path.
- **Detection add:** auditd rule on `tar` executed by root with `--checkpoint` in a cron context;
  Wazuh correlation of the web RFI fetch (outbound HTTP from the web user) preceding it.
  > **Addressed 2026-06-22:** §4 now explains the *mechanism* — shell glob expansion places
  > `--checkpoint*` filenames on tar's argument vector as options (no `--` end-of-options guard), and
  > generalises it to any privileged command over a user-writable glob (`rsync -e`, `chown
  > --reference`, `zip --unzip-command`). The "why", not just the payload. Remaining headroom: the live solve.

## What the audit deliberately does **not** recommend

- **No padding.** Lame at 2 ATT&CK techniques is correct — it is a one-CVE direct-root box. Adding
  fabricated steps to inflate the count would be dishonest and is rejected.
- **No fake flags.** Stubs keep bracketed flag fields until solved under my own account.
- **No new boxes here** — new machines are tracked in [WEEKLY_WORKFLOW.md](WEEKLY_WORKFLOW.md); this
  audit is about depth of existing material.

## Cross-references
- ATT&CK coverage and gaps → [ATT&CK_GAP_MATRIX.md](ATT&CK_GAP_MATRIX.md)
- Machine-of-the-week process + next picks → [WEEKLY_WORKFLOW.md](WEEKLY_WORKFLOW.md)
- Detection rules these writeups feed → [watchtower](../watchtower)
