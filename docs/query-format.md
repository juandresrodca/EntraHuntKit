# Query format

[`CONTRIBUTING.md`](../CONTRIBUTING.md) shows the shape of a query block in five
lines. This page is the long version: every field the
[submission form](../.github/ISSUE_TEMPLATE/new_query.yml) asks for, where it lands
in the tree, and the exact syntax, derived from the sixteen queries already in
[`hunting/`](../hunting/) rather than imposed on them.

It exists because the form asks for two things the repository had never written
down — which number a new query takes, and where the *tested where and when* answer
goes. Both are settled below.

A reviewer should be able to accept or reject a submission against this page alone,
and the planned metadata lint should be able to enforce it without a judgement call.

---

## The template

Copy this block into the right tactic README, replacing the content but not the
punctuation:

~~~markdown
## N. Short descriptive title

**ATT&CK:** [Txxxx.xxx — Technique Name](https://attack.mitre.org/techniques/Txxxx/xxx/) · **Platform:** Sentinel · **License:** M365 audit
**What it catches:** One sentence — the attacker behaviour, in plain English.

```kql
TableName
| where TimeGenerated > ago(7d)
| where OperationName has "Something"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, OperationName, Actor, Result, CorrelationId
| order by TimeGenerated desc
```

**Tuning / false positives:** What generates the noise, how to baseline it, and what the high-fidelity version of the signal looks like.
**Also in:** Defender XDR — `CloudAppEvents` where `ActionType has "Something"`.
**Tested:** Microsoft Sentinel Logs, 2026-10-06.
~~~

Separate every query from the next with a `---` on its own line, blank line either
side.

## The same thing filled in

This is [query 4](../hunting/persistence/README.md) reproduced verbatim. It is here
because a format page should demonstrate the format with a detection that has
already passed review — inventing a seventeenth query inside a document about the
submission process would be the wrong place to introduce one, and the repository's
one hard rule applies to examples too.

~~~markdown
## 4. Illicit OAuth application consent

**ATT&CK:** [T1528 — Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) · also [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/) · **Platform:** Sentinel · **License:** M365 audit (all tenants)
**What it catches:** A user (or admin) granting OAuth permissions to an app — the core of consent-phishing / "illicit consent grant" attacks that hand an app persistent Graph access.

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has "Consent to application"
    or OperationName has "Add OAuth2PermissionGrant"
    or OperationName has "Add delegated permission grant"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetApp = tostring(TargetResources[0].displayName)
| extend Props = TargetResources[0].modifiedProperties
| project TimeGenerated, OperationName, Actor, TargetApp, Result, Props, CorrelationId
| order by TimeGenerated desc
```

**Tuning / false positives:** Legitimate SaaS onboarding generates consent events. Triage by (a) *who* consented … and (b) *what scopes* …
**Also in:** Defender XDR — `CloudAppEvents` where `ActionType has "Consent to application"`.
~~~

Note what the real query does *not* have: a `**Tested:**` line. None of the sixteen
do. See [the tested-on convention](#the-tested-on-convention).

---

## Field reference

| Field | Form id | Required | Lands as |
|---|---|---|---|
| Detection title | `title` | yes | the `## N.` heading |
| ATT&CK technique ID | `technique` | yes | the `**ATT&CK:**` line |
| ATT&CK tactic | `tactic` | yes | which `hunting/<tactic>/README.md` the block goes in |
| Platform | `platform` | yes | the `**Platform:**` field |
| License tier it needs | `license` | yes | the `**License:**` field |
| What it catches | `catches` | yes | the `**What it catches:**` line |
| The query | `kql` | yes | the ` ```kql ` fenced block |
| Primary table | `table` | yes | first line of the query; not repeated in prose |
| Tuning / false positives | `tuning` | yes | the `**Tuning / false positives:**` line |
| Also in | `also-in` | no | the `**Also in:**` line |
| Tested where and when | `tested` | yes | the `**Tested:**` line — new, see below |

`table` is the one field with no slot of its own, and deliberately so: the query's
first line already states it, and a prose copy is a second thing to keep in step.
[`docs/coverage.md`](coverage.md) derives its table column from the query text for
the same reason.

### The heading number

**`N` is a single sequence across the whole repository, not per folder.** The
sixteen existing queries run 1 to 16 continuously: initial-access holds 1–3,
persistence 4–8, defense-evasion 9–11, credential-access 12–13, discovery 14,
collection 15, exfiltration 16. **A new query takes 17**, whichever folder it lands
in.

This is the convention a contributor is most likely to get wrong, because numbering
from 1 inside your own folder is the obvious reading of `## N`. It matters because
the queries are cited by number — `coverage.md` refers to *query 7* and *query 15*,
and the [ATT&CK Navigator layer](attack-navigator/) keys its comments the same way.
Renumbering a query silently breaks those references.

Numbers are never reused. If a query is removed, its number retires with it.

### The ATT&CK line

```
**ATT&CK:** [Txxxx.xxx — Technique Name](https://attack.mitre.org/techniques/Txxxx/xxx/) · **Platform:** … · **License:** …
```

- The ID pattern is `T` followed by four digits, optionally `.` and three more:
  `T1528`, `T1098.001`. Nothing else is valid.
- The URL is `https://attack.mitre.org/techniques/Txxxx/` for a parent and
  `https://attack.mitre.org/techniques/Txxxx/xxx/` for a sub-technique — the dot
  becomes a slash, and the trailing slash is required.
- ID and name are joined by an em dash with spaces either side: `T1528 — Steal
  Application Access Token`. Use the technique's name as MITRE spells it.
- Additional techniques follow the first, each introduced by ` · also `. Cite a
  second technique only when the query genuinely detects it; the coverage index
  counts what is written here.
- The three fields are separated by ` · ` (U+00B7, space either side). Not a pipe,
  not a comma.

### Platform and table

`**Platform:**` takes exactly one of `Sentinel`, `Defender XDR`, or both names
joined by ` | ` when the query runs unchanged on either. If the two surfaces need
different queries, give the primary one here and the other under `**Also in:**`.

The platform fixes the table vocabulary, and mixing the two dialects is the most
common way a submitted query fails to run:

| Platform | Tables in use here |
|---|---|
| Sentinel | `SigninLogs`, `AuditLogs`, `OfficeActivity`, `IntuneAuditLogs`, `MicrosoftGraphActivityLogs` |
| Defender XDR | `CloudAppEvents`, `AADSignInEventsBeta`, `EmailEvents`, `DeviceEvents` |

A table outside these lists is fine if it is real — verify it in the
[Defender XDR schema reference](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
or the [Sentinel table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/tables-category)
and say so in the pull request.

### License

What a tenant must actually have for the data to exist, in the tenant's own terms,
not a marketing SKU. The phrasings already in use are `M365 audit (all tenants)`,
`M365 audit`, `M365 audit (mailbox auditing on)` and the Entra ID P2 tier for
risk-based signals. Add the enabling condition in brackets when the data is off by
default — mailbox auditing is the case that catches people out.

All sixteen queries carry this field. It is what `coverage.md` uses to tell a SOC
lead which half of the kit they can actually run.

### What it catches

One sentence, the attacker behaviour, in plain English. Not the query mechanics:
*an attacker adding a second credential to an app so access survives a password
reset* is the field done right; *looks for OperationName in a list of values* is
the field done wrong, because the reader can see the query underneath.

### The KQL block

Fenced with ` ```kql `. House conventions, visible in all sixteen:

- Table name alone on the first line, then one `|` operator per line.
- A `| where TimeGenerated > ago(Nd)` bound immediately after the table. Seven days
  is the default; thirty is used where the behaviour is rare and high-impact, such
  as the federation-trust change in query 8.
- `extend` to flatten dynamic columns, then `project` the analyst-facing set, then
  `order by TimeGenerated desc`.
- A wrapped line is indented four spaces under its operator.
- Keep `CorrelationId` in the projection where the table has it. It is what joins a
  hit to the rest of the incident.
- No tenant identifiers, real user principal names, domains or customer data.
  Placeholders belong in the tuning note, not the query.

Two trailing spaces are a hard line break in markdown and
[`.editorconfig`](../.editorconfig) deliberately leaves them alone, so do not
"tidy" the ends of lines in a query page.

### Tuning / false positives

Not optional, and the form says so. The bar is three things:

1. **What generates the noise** — the legitimate activity that fires the same query.
2. **How to baseline it** — what a reviewer should compare against to tell the two
   apart.
3. **What the high-fidelity version looks like** — the narrower condition worth
   alerting on rather than hunting.

A note that only says *this may produce false positives* fails all three and the
detection is not finished. Query 6's note is the shape to copy: external domain,
shortly after a risky sign-in, paired with a hiding rule.

Link sideways where it helps. The consent query sends the reader to
[`ioc/malicious-oauth-app-ids.md`](../ioc/malicious-oauth-app-ids.md); a tuning note
that can hand over a concrete list should.

### Also in

The equivalent on the other surface, named precisely enough to paste:

```
**Also in:** Defender XDR — `CloudAppEvents` where `ActionType has "Consent to application"`.
```

Thirteen of the sixteen carry it. The three that do not are the exfiltration query
and two of the three initial-access queries, where the other surface has no
equivalent the author could verify. Omitting the field is better than guessing one,
and [issue #3](https://github.com/juandresrodca/EntraHuntKit/issues/3) tracks adding
the Defender XDR versions of the Sentinel-only queries properly.

Where the field names a column that lives at a different path on the other surface,
say so — query 6 does: *parameters live under `RawEventData.Parameters`*.

### The tested-on convention

The submission form has required *tested where and when* since it was written. The
rendered format never had a slot for it, so the answer has only ever existed in
issue threads and pull request descriptions. Searching `hunting/` for `Tested`
returns nothing.

**From 6 October 2026 a new query carries a `**Tested:**` line**, last in the block,
after `**Also in:**`:

```
**Tested:** Defender XDR Advanced Hunting, 2026-09-14.
```

Surface first, then an ISO date, `YYYY-MM-DD`. The surface is where the query was
actually executed, spelled as the product spells it — *Microsoft Sentinel Logs* or
*Defender XDR Advanced Hunting* — and the date is when it ran, not when the pull
request opened. A month is acceptable where that is honestly all the author
remembers; a fabricated day is worse than a vague month.

It is there because these schemas move. `AADSignInEventsBeta` carries *Beta* in its
name for a reason, `modifiedProperties` indexing already varies enough for query 7
to warn about it, and a reader deciding whether to trust a query needs to know
whether it was last run this quarter or two years ago.

**The sixteen existing queries are not being backfilled.** Their test dates are
recoverable only from commit history, and a date reconstructed from a commit is not
the same claim as a date the author stood behind. They stay without the line, which
means the metadata lint must require `**Tested:**` only on queries numbered 17 and
above. That asymmetry is deliberate and is the one rule on this page that cannot be
checked by pattern alone.

---

## The reviewer's checklist

What a merge is checked against, and what the planned metadata lint should
automate — every line but the last two is checkable by pattern:

- [ ] The heading is `## N. Title`, `N` is the next number in the repository-wide
      sequence, and no existing number changed.
- [ ] The block sits in the folder matching its ATT&CK tactic.
- [ ] Every technique ID matches `T\d{4}(\.\d{3})?` and its link resolves to the
      matching MITRE path.
- [ ] `**Platform:**` is one of the three accepted values and the query's tables
      belong to that platform's dialect.
- [ ] `**License:**` is present and names a real prerequisite.
- [ ] `**What it catches:**` is one sentence about behaviour.
- [ ] The query is fenced as `kql`, bounded by `ago()`, ends in an `order by`, and
      contains no tenant data.
- [ ] `**Tuning / false positives:**` covers noise, baseline and the high-fidelity
      signal.
- [ ] `**Tested:**` is present for query 17 and above, with a real surface and an
      ISO date.
- [ ] The query count and ATT&CK coverage table in [`README.md`](../README.md),
      [`docs/coverage.md`](coverage.md) and the
      [Navigator layer](attack-navigator/) are updated in the same change.
- [ ] A line is added to [`CHANGELOG.md`](../CHANGELOG.md) under **Unreleased**.

The accuracy rule sits above all of it: a query that throws a schema error, or
silently returns nothing, costs an analyst trust and time. Sixteen solid queries
beat sixty shaky ones, and that trade has already been made here.

---

*This page is derived from the queries, so the queries win. If a block in
`hunting/` disagrees with something stated above, check whether the block is wrong
or the page is — and fix whichever it turns out to be, in the same sitting.*
