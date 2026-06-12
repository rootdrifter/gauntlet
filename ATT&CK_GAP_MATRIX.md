# MITRE ATT&CK Gap Matrix — gauntlet × watchtower

The offence→detection loop only closes where an offensive technique (demonstrated in a **gauntlet**
writeup) has a corresponding **watchtower** detection. This matrix maps that across all 14 enterprise
tactics, exposes where the loop is *open*, and names the next machines that would close it. It is
deliberately honest about gaps: easy retired CTF boxes end at root, so whole tactics (Collection,
Exfiltration, Impact) are barely touched on the offensive side even where watchtower already has the
detection built.

> Generated 2026-06-12 from `writeups/*.md` (29 unique techniques) and
> `watchtower/scenarios|rules` (≈50 techniques). Re-run after each new writeup or scenario.

## Legend
- **Off** = demonstrated offensively in a gauntlet writeup
- **Det** = detection engineered in watchtower (scenario + Wazuh rule)
- **Loop** = ✅ closed (both) · ◐ half (one side) · ⬜ open (neither)

## Tactic-level coverage

| Tactic | gauntlet techniques (Off) | watchtower detection (Det) | Loop |
|--------|---------------------------|----------------------------|------|
| Reconnaissance (TA0043) | T1595 | T1595, T1046 | ✅ |
| Resource Development (TA0042) | — | — | ⬜ (N/A for CTF; out of scope) |
| Initial Access (TA0001) | T1190, T1078, T1078.001 | T1190 (via T1210), T1566/.001, T1078.003 | ✅ |
| Execution (TA0002) | T1059, T1059.004 | T1059/.001/.004 | ✅ |
| Persistence (TA0003) | T1505.003, T1543.003, T1053.003, T1078 | T1136/.001/.002, T1543.003, T1078.003 | ✅ |
| Privilege Escalation (TA0004) | T1134/.001, T1548.001/.003, T1574.007/.009, T1543.003, T1053.003, T1055/.012 | T1134.001, T1548/.001/.002/.003, T1055/.001/.003/.012 | ✅ |
| Defense Evasion (TA0005) | T1078, T1134, T1055 (incidental) | T1070/.001/.003/.006, T1027/.002/.010, T1140, T1562/.001/.002/.004 | ◐ **det-heavy, off-light** |
| Credential Access (TA0006) | T1003.002, T1110/.001/.002, T1552.001/.004 | T1003/.001/.002/.008, T1110/.003 | ✅ |
| Discovery (TA0007) | T1083, T1087, T1135 | T1046, T1057, T1083 | ✅ |
| Lateral Movement (TA0008) | T1021.001, T1021.004, T1210 | T1021/.001/.002/.004, T1210 | ✅ |
| Collection (TA0009) | — | — | ⬜ **open both sides** |
| Command and Control (TA0011) | reverse shells (undocumented as C2) | — | ⬜ **open both sides** |
| Exfiltration (TA0010) | — | — | ⬜ **open both sides** |
| Impact (TA0040) | — | T1485, T1486, T1561, T1490(impl.) | ◐ **det-only** |

## The open / half-open loops — and why

1. **Defense Evasion (◐ det-heavy).** watchtower has rich detections for log-clearing (T1070),
   obfuscation (T1027), and impair-defenses (T1562) because those are what a SOC must catch. gauntlet
   barely demonstrates them offensively — easy boxes don't require the attacker to clear logs or
   disable AV. *This asymmetry is correct and honest:* the detection is built proactively; the
   offensive demonstration is the gap.

2. **Impact (◐ det-only).** watchtower scenario-19 (T1485 data destruction) and the ransomware/disk-wipe
   rules exist; no gauntlet box performs destructive impact (nor should a learner). The detection is
   validated in the lab against synthetic activity, documented in watchtower — not against a CTF box.

3. **Collection / C2 / Exfiltration (⬜ open).** Retired easy boxes terminate at root and don't model
   data staging, C2 channels, or exfil. Reverse shells *are* used throughout gauntlet but are not
   documented as ATT&CK C2 techniques (T1071 application-layer, T1572 protocol tunnelling) — an honest
   labelling gap as much as a coverage gap.

## Next machines to close the gaps (offensive side)

Ranked by how much ATT&CK ground each one opens that gauntlet does not yet cover. All are free or
retired and legally workable; honest stubs first, full solves as worked.

| Priority | Machine | Platform | Opens (new tactics/techniques) | Closes which gap |
|----------|---------|----------|--------------------------------|------------------|
| 1 | **Attacktive Directory** | THM | T1558.003 Kerberoasting, T1003.006 DCSync, T1087.002, T1021.002 | Credential Access (AD), Lateral Movement depth — the #1 enterprise gap |
| 2 | **Wreath** (network) | THM | T1090 internal proxy, T1572 tunnelling, T1021, T1547 persistence | **Command and Control**, Lateral Movement pivoting |
| 3 | **Forest** / **Active** | HTB | T1558.003, T1003.006, T1482 domain trust, T1550 | AD Credential Access + Discovery (T1482/T1069) |
| 4 | **Internal** / pivot box | HTB/THM | T1071 app-layer C2, T1041 exfil-over-C2, T1074 staging | **Collection + Exfiltration**, the fully-open loop |

**Detection-build follow-through:** each new offensive technique above must spawn a matching watchtower
scenario+rule, or the loop stays half-open. The backlog of watchtower scenarios needed is tracked in
[watchtower/GAUNTLET_BRIDGE.md](../watchtower/GAUNTLET_BRIDGE.md).

## How to read this for an interview

> "My CTF practice covers the front half of the kill chain well — initial access through privilege
> escalation and lateral movement, all mapped to ATT&CK and paired with Wazuh detections in my SIEM
> lab. The honest gap is the back half — C2, collection, exfiltration, impact — because easy retired
> boxes end at root. I close that two ways: AD/pivoting boxes (Attacktive Directory, Wreath) for the
> offensive demonstration, and the watchtower lab for the destructive techniques you can't safely
> practise on someone else's CTF box. I'd rather show you exactly where my coverage ends than claim
> the whole matrix."

## Cross-references
- Per-writeup quality → [STUB_AUDIT.md](STUB_AUDIT.md)
- Next-machine selection process → [WEEKLY_WORKFLOW.md](WEEKLY_WORKFLOW.md)
- Detection backlog → [watchtower/GAUNTLET_BRIDGE.md](../watchtower/GAUNTLET_BRIDGE.md)
