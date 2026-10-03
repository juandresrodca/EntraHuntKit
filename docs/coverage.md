# Coverage index

Sixteen queries across seven tactic folders. This page is the index a SOC lead wants
before adopting any of it: what is covered, **what you have to be ingesting to run
it**, which queries work on your platform, and — the part that matters most — what is
not covered at all.

The [ATT&CK Navigator layer](attack-navigator/) shows the same coverage on the matrix.
This page adds the two dimensions the matrix cannot show: the table and licence each
query needs, and the gaps written out as candidate detections rather than as dark cells.

Every figure here is derived from the `**ATT&CK:**`, `**Platform:**` and
`**License:**` lines of the queries themselves — see
[Regenerating this page](#regenerating-this-page).

## By tactic

| Tactic | Queries | Techniques |
|---|---|---|
| [Initial Access](../hunting/initial-access/) | 3 | `T1078` · `T1078.004` |
| [Credential Access](../hunting/credential-access/) | 2 | `T1110` · `T1110.003` · `T1621` |
| [Persistence](../hunting/persistence/) | 5 | `T1098` · `T1098.001` · `T1098.003` · `T1114` · `T1114.003` · `T1137` · `T1137.005` · `T1484` · `T1484.002` · `T1528` |
| Privilege Escalation | **0** | reached indirectly by `T1098.003` (query 7), which ATT&CK lists under both tactics — see [gaps](#gaps-worth-filling) |
| [Defense Evasion](../hunting/defense-evasion/) | 3 | `T1556` · `T1556.009` · `T1562` · `T1562.001` · `T1562.007` · `T1562.008` |
| [Discovery](../hunting/discovery/) | 1 | `T1069` · `T1069.003` · `T1087` · `T1087.004` |
| [Collection](../hunting/collection/) | 1 | `T1114` · `T1114.003` · `T1564` · `T1564.008` |
| [Exfiltration](../hunting/exfiltration/) | 1 | `T1530` · `T1567` |
| Execution | **0** | [gap](#gaps-worth-filling) |
| Lateral Movement | **0** | [gap](#gaps-worth-filling) |
| Impact | **0** | [gap](#gaps-worth-filling) |

Twenty distinct techniques, counting sub-techniques separately and parents only where a
query names the parent directly. `T1114.003` is reached twice — the forwarding rule in
query 6 and the hide-and-delete rule in query 15 — so the query count per tactic adds up
to sixteen while the technique list does not.

Three tactics have no query and no indirect coverage. That is not an oversight to be
embarrassed about, it is where the next pull request should go, so each one is written
out below with named candidates.

## What you need to be ingesting

The first question about any query set is which of it you can actually run today. Eight
of the sixteen need nothing beyond the M365 unified audit log, which every tenant has.

| Source table | Queries | Needs |
|---|---|---|
| `AuditLogs` | 4, 5, 7, 8, 9 | M365 unified audit log → Sentinel |
| `OfficeActivity` | 6, 11, 15, 16 | M365 unified audit log, **mailbox auditing on** for 6, 11 and 15 |
| `SigninLogs` | 1, 2, 3, 12, 13 | Entra ID **P1** — sign-in logs are not in the free tier |
| `AADUserRiskEvents` | 3 | Entra ID **P2** — risk detections |
| `IntuneAuditLogs` | 10 | Intune, **plus a diagnostic setting shipping it to Log Analytics** |
| `MicrosoftGraphActivityLogs` | 14 | Entra ID P1 **and** Graph activity logs explicitly enabled |
| `CloudAppEvents` | 16 | Defender XDR, or Defender for Cloud Apps for the richer fields |

By licence, rather than by table:

| Licence floor | Queries | Count |
|---|---|---|
| M365 audit only — any tenant | 4, 5, 6, 7, 8, 9, 11, 15 | 8 |
| Entra ID P1 | 1, 2, 12, 13, 14 | 5 |
| Entra ID P2 | 3 | 1 |
| Intune with diagnostics configured | 10 | 1 |
| Defender XDR / Defender for Cloud Apps | 16 | 1 |

Two of these are configuration rather than licence, and both are silent when missing:
`IntuneAuditLogs` and `MicrosoftGraphActivityLogs` return nothing at all until their
diagnostic settings are on. A query that returns no rows because the table is empty looks
exactly like a query that returns no rows because nothing happened. Check the table
exists before you conclude you are clean:

```kql
union withsource=T IntuneAuditLogs, MicrosoftGraphActivityLogs
| summarize Rows = count(), Latest = max(TimeGenerated) by T
```

## Platform portability

Fourteen of the sixteen carry an **Also in** line giving the equivalent on the other
surface, usually `CloudAppEvents` in Defender XDR Advanced Hunting where Sentinel uses
`AuditLogs` or `OfficeActivity`. Two do not, for reasons worth knowing:

| Query | Only on | Why |
|---|---|---|
| 3 — impossible / atypical travel | Sentinel | `AADUserRiskEvents` has no Advanced Hunting equivalent; Defender surfaces the same risk as an incident, not a table |
| 16 — anomalous mass file download | Defender XDR | Written against `CloudAppEvents` natively; the `OfficeActivity` fallback in the same query is the Sentinel route |

Everything else runs on either platform with the substitution the query names. Translating
by hand is not recommended: `CloudAppEvents` nests the interesting fields under
`RawEventData`, so a column that exists in `AuditLogs` is usually a `parse_json` away
rather than a rename.

## Gaps worth filling

Each of these is a tactic with no query, a reason it is reachable in M365 telemetry, and
candidate techniques. Pick one and open a pull request — [CONTRIBUTING.md](../CONTRIBUTING.md)
has the accuracy bar, and the [Navigator layer](attack-navigator/) has to be updated in
the same pull request.

### Privilege Escalation

The Navigator column is not dark — `T1098.003` from query 7 lights it, because ATT&CK
lists privileged role assignment under Persistence *and* Privilege Escalation. But no
query was written **for** escalation, and the obvious one is missing: a PIM eligible role
being **activated**, rather than assigned. Assignment is a change an admin makes once;
activation is the moment privilege is actually held, and it is the event an attacker with
an eligible account generates.

Candidates: `T1548` — Abuse Elevation Control Mechanism. Source: `AuditLogs`,
`OperationName` on the PIM activation operations, baselined against the actor's normal
activation pattern and the change window.

### Execution

The gap that should close first, because the table is already proven: query 10 reads
`IntuneAuditLogs`, and the same table records **device scripts, remediations and Win32
app assignments**. Intune is a remote-execution platform with an audit trail, and an
attacker with Intune Administrator does not need malware — they need a PowerShell script
targeted at a device group.

Candidates: `T1059.009` — Cloud Administration Command. Source: `IntuneAuditLogs` on
script and remediation create/assign operations, and on an assignment whose target group
suddenly widens.

### Lateral Movement

Entra lateral movement is token movement, not network movement. An access token stolen
from one resource replayed against another leaves a sign-in with a familiar session and an
unfamiliar resource; internal phishing from an already-compromised mailbox leaves an
`OfficeActivity` send with internal recipients and an external reply-to.

Candidates: `T1550.001` — Application Access Token; `T1021.007` — Cloud Services;
`T1534` — Internal Spearphishing. Sources: `SigninLogs` correlated on session identifier
across `ResourceDisplayName`, and `OfficeActivity` / `CloudAppEvents` for the mail path.

### Impact

Nothing here detects the end of the attack. Mass file deletion or encryption in
SharePoint and OneDrive, and mass account disable or password reset — the move that locks
the defenders out while the attacker still holds a token — are both plainly visible in
audit telemetry.

Candidates: `T1485` — Data Destruction; `T1486` — Data Encrypted for Impact; `T1531` —
Account Access Removal. Sources: `CloudAppEvents` or `OfficeActivity` for file operations
at volume by one actor; `AuditLogs` for `Disable account` and `Reset user password` in
bursts.

### Thin rather than absent

Discovery, Collection and Exfiltration have one query each. Two named gaps in the covered
tactics, for anyone who would rather deepen than broaden:

- **Initial Access** has no query for `T1199` — Trusted Relationship. Delegated admin
  (GDAP) access from a partner tenant is a route into a tenant that the tenant's own
  Conditional Access does not necessarily constrain, and it is recorded in `AuditLogs`.
- **Persistence** has no query for `T1136.003` — Create Account: Cloud Account. A guest
  invitation, or a new cloud-only account created by a compromised admin, is cheaper for
  an attacker than any of the five credential paths that *are* covered.

## Out of scope, deliberately

Reconnaissance, Resource Development and Command and Control have no rows above and will
not get any. They happen outside the tenant: an attacker registering a look-alike domain
or standing up infrastructure generates no Entra, Intune or Exchange audit event, so there
is nothing in these tables to hunt. Treating them as gaps would mean writing queries
against telemetry that does not exist, which fails the one hard rule in
[CONTRIBUTING.md](../CONTRIBUTING.md) — real tables, real columns, no invented schema.

Endpoint execution and host-based tactics are out of scope for the same reason the repo is
called EntraHuntKit: `DeviceProcessEvents` is a different kit.

## Regenerating this page

The tables are derived from the queries, so they can be rebuilt rather than remembered.
From the repository root:

```bash
# query count and technique list per tactic folder
for d in hunting/*/; do
  n=$(grep -cE '^## [0-9]+\. ' "$d/README.md")
  t=$(grep -oE 'T[0-9]{4}(\.[0-9]{3})?' "$d/README.md" | sort -u | paste -sd' ')
  printf '%-20s %2s  %s\n' "$(basename "$d")" "$n" "$t"
done

# every source table, and how many query blocks open with it
# (a `let` row is query 12's variable preamble, not a table)
grep -A1 -h '^```kql' hunting/*/README.md | grep -oE '^[A-Za-z]+' | sort | uniq -c
```

Run both after adding a query and reconcile the three places coverage is stated: this
page, the table in the [README](../README.md#attck-coverage), and the
[Navigator layer](attack-navigator/entrahuntkit-layer.json) with its `metadata` counts.
A query added without updating all three leaves the repository claiming coverage it has
or hiding coverage it does not — both of which cost a reader more than the missing query
did.

## Related

- [ATT&CK Navigator layer](attack-navigator/) — the same coverage on the Enterprise matrix
- [CONTRIBUTING.md](../CONTRIBUTING.md) — the accuracy bar a new query has to clear
- [`ioc/`](../ioc/) — the indicator lists the queries cross-reference
