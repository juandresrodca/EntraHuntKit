# Contributing to EntraHuntKit

Thanks for helping M365 defenders hunt better. Contributions of new queries, tuning improvements, and sourced IOCs are all welcome.

## The one hard rule: accuracy

**Every query must be accurate and paste-ready.** That means:

- Real tables and **real columns** — no invented schema. If you're unsure a column exists, verify it in the [Defender XDR schema reference](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables) or the [Sentinel/Entra table docs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/tables-category).
- Correct **table dialect** — label the query as **Defender XDR** (`CloudAppEvents`, `AADSignInEventsBeta`, `EmailEvents`, `DeviceEvents`) or **Sentinel** (`SigninLogs`, `AuditLogs`, `OfficeActivity`, `IntuneAuditLogs`, `MicrosoftGraphActivityLogs`). If you know both, add an "Also in" note.
- It **runs** — paste it into Advanced Hunting or Sentinel Logs and confirm it executes without a schema error before you open the PR.

An inaccurate query that throws an error, or worse silently returns nothing, costs an analyst trust and time. We'd rather have 16 solid queries than 60 shaky ones.

## Query format

Add your query to the right ATT&CK-tactic folder under [`hunting/`](hunting/), following the existing template:

```markdown
## N. Short descriptive title

**ATT&CK:** [Txxxx.xxx — Technique Name](https://attack.mitre.org/techniques/Txxxx/xxx/) · **Platform:** Sentinel | Defender XDR · **License:** <what it needs>
**What it catches:** One sentence — the attacker behaviour, in plain English.

​```kql
<your query>
​```

**Tuning / false positives:** What generates noise, how to baseline it, and what the high-fidelity version of the signal looks like.
**Also in:** <the other table/platform, if applicable>
```

Every query needs all five: title, ATT&CK ID, "what it catches", the KQL, and a tuning note. The tuning note is not optional — a detection with no false-positive guidance isn't finished.

## Contributing IOCs

IOC lists live in [`ioc/`](ioc/). For **confirmed-malicious** indicators (OAuth app IDs, sender domains, etc.):

- **Cite a source.** A public report, advisory, or your own IR writeup — a link or reference. PRs adding "known-bad" indicators without a source will be rejected.
- Never add an indicator you can't stand behind. Falsely flagging a legitimate app or domain is worse than omitting it.

## Submitting

1. Fork, branch, add your query/IOC.
2. Update the query count and ATT&CK coverage table in [README.md](README.md) if you added a new technique.
3. Add a line to [CHANGELOG.md](CHANGELOG.md) under **Unreleased**.
4. Open a PR describing what the detection catches and where you tested it (Defender XDR / Sentinel).

## Scope

Defensive / blue-team hunting for Entra ID, Intune, and M365 only. This repo is detection logic — not exploitation tooling, not red-team payloads.
