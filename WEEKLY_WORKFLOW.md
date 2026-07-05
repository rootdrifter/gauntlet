# Weekly Workflow — Machine of the Week

A repeatable cadence that turns one CTF box per week into a published, detection-backed writeup. The
goal is not volume — it is the **offence→detection loop**, run end-to-end, every week, so the portfolio
compounds with evidence a SOC employer recognises.

> One box → one writeup → one Wazuh rule → one blog post. Each artefact feeds the next.

## The weekly loop

```
   SELECT ──▶ SOLVE ──▶ WRITE UP ──▶ ENGINEER DETECTION ──▶ PUBLISH ──▶ (back to SELECT)
   (gap-     (own       (repo, full   (watchtower scenario   (Ghost blog
    driven)   account)   skeleton)     + Wazuh rule)          teaser → post)
```

### Day-by-day (≈4–5 focused hours total across the week)

| Day | Step | Output | Time |
|-----|------|--------|------|
| Mon | **Select** the box from the gap matrix (not by popularity) | chosen machine + the tactic it opens | 15 min |
| Tue–Wed | **Solve** under my own account; keep raw notes + screenshots | working notes, real flag values (private) | 2–3 h |
| Thu | **Write up** into the repo skeleton: recon→enum→exploit→privesc→lessons | `writeups/<plat>-<machine>.md` | 1 h |
| Fri | **Engineer detection**: map each step to ATT&CK, write the Wazuh rule, add the watchtower scenario | rule XML + scenario md | 45 min |
| Sat | **Publish**: defender section + exam-relevance table; draft the Ghost teaser | committed writeup + blog draft | 30 min |
| Sun | **Review**: update STUB_AUDIT score, ATT&CK_GAP_MATRIX, README index | updated trackers | 15 min |

## Selection rule (why this box, this week)

Pick by **gap, not by fame**. Consult [ATT&CK_GAP_MATRIX.md](ATT&CK_GAP_MATRIX.md) and choose the box
that opens the most uncovered ATT&CK ground. A box that re-demonstrates EternalBlue for the fifth time
adds nothing; a box that introduces Kerberoasting or C2 pivoting closes a real loop. Secondary tie-break:
alternate OS (don't do three Windows boxes in a row) and alternate difficulty (mix Easy for cadence with
Medium for judgement).

## Definition of done (a writeup is "published" only when all are true)

- [ ] Recon/enum commands are exact, with flag rationale (not "I scanned it")
- [ ] Exploitation documents the chosen vector **and** an alternative considered/ruled out
- [ ] Privesc shows the triage order, not just the winning command
- [ ] Every offensive step mapped to an ATT&CK sub-technique
- [ ] A **working** Wazuh rule exists in watchtower and is referenced from the writeup
- [ ] Defender section names the real log sources (Event IDs / auditd / Sysmon)
- [ ] Sec+ exam-relevance table maps to specific SY0-701 objectives
- [ ] No fabricated flags; stub fields replaced with real (private) values or honestly bracketed
- [ ] STUB_AUDIT score + README index updated

## Recommended next 4 machines (with rationale)

Ordered to maximise new ATT&CK coverage per the gap matrix; honest about why each is next.

| Order | Machine | Platform | Why this one next | New ground |
|-------|---------|----------|-------------------|------------|
| 1 | **Attacktive Directory** | THM (Easy) | The single biggest gap is Active Directory — every enterprise SOC role assumes it. Kerberoasting + AS-REP roasting + DCSync in one guided box. | T1558.003, T1003.006, T1087.002, T1021.002 |
| 2 | **Wreath** | THM (network) | Introduces **Command and Control** and pivoting — the open loop. A 3-host network, not a single box: lateral movement + internal proxying + persistence. | T1090, T1572, T1547, T1021 |
| 3 | **Forest** | HTB (Easy) | Reinforces AD from the unguided side (judgement, not a walkthrough); DCSync to Domain Admin. Validates that AD skill transfers off-rails. | T1003.006, T1482, T1550 |
| 4 | **Internal** | HTB (Medium) | Steps up difficulty and opens **Collection/Exfiltration** via a pivot + data-staging path; the back half of the kill chain. | T1071, T1041, T1074 |

After these four, the matrix is materially fuller: AD credential access, C2, and exfil all gain at
least one demonstrated technique with a paired detection. Re-audit at that point.

## Anti-patterns (explicitly avoided)

- **Box farming** — solving many easy boxes for a streak without writing the detection half. The
  detection is the differentiator; a solve without a rule is half-finished.
- **Walkthrough copying** — a writeup that reproduces someone else's steps without the *reasoning*
  (why this vector, what failed) is worthless for an interview.
- **Fame-driven selection** — picking the trending box instead of the box that closes a gap.

## Cross-references
- Quality scores → [STUB_AUDIT.md](STUB_AUDIT.md)
- Coverage gaps → [ATT&CK_GAP_MATRIX.md](ATT&CK_GAP_MATRIX.md)
- Detection lab → [watchtower](../watchtower) · content pipeline → rootdrifter.io blog
