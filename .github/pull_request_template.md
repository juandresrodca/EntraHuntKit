<!--
Thanks for contributing to EntraHuntKit.

Two things worth knowing before you read the checklists:

1. **There is no CI here.** `.github/` holds issue forms and nothing else, so no
   tick on this pull request means a machine checked anything. Every box below is
   checked by a person reading the diff — which is why the sections ask you to say
   where you ran the query rather than to trust a green light.
2. **Most of this template is deletable.** A typo fix, a broken link or a tuning
   note that got clearer needs **What this changes** and nothing else. Delete the
   rest.

The long reference for all of it is
[docs/query-format.md](https://github.com/juandresrodca/EntraHuntKit/blob/main/docs/query-format.md),
and its [reviewer's checklist](https://github.com/juandresrodca/EntraHuntKit/blob/main/docs/query-format.md#the-reviewers-checklist)
is what the boxes below are taken from. Where this template and that page disagree,
the page wins.
-->

## What this changes

<!-- One or two sentences on why it matters rather than a restatement of the diff. -->

Closes #

## Adding a hunting query?

<!-- Delete this whole section if you are not. -->

The accuracy rule sits above everything else on this list: a query that throws a
schema error, or silently returns nothing, costs an analyst trust and time. Sixteen
solid queries beat sixty shaky ones, and that trade is already made.

**Where it goes**

- [ ] The block is in `hunting/<tactic>/README.md`, the folder matching its ATT&CK tactic
- [ ] The heading is `## N. Title`, and `N` is the next number in the **repository-wide** sequence — not the next one in that folder
- [ ] No existing query's number changed. They are cited by number from `docs/coverage.md` and the Navigator layer, and numbers are never reused

**The metadata line**

- [ ] Every technique ID matches `T\d{4}(\.\d{3})?`, and each link resolves to the matching `https://attack.mitre.org/techniques/…/` path with its trailing slash
- [ ] ID and name are joined by ` — ` and the name is spelled as MITRE spells it; extra techniques follow with ` · also `
- [ ] The three fields are separated by ` · ` — not a pipe, not a comma
- [ ] `**Platform:**` is `Sentinel`, `Defender XDR`, or both joined by ` | `, and the query's tables belong to that platform's dialect
- [ ] `**License:**` names what a tenant must actually have, in the tenant's own terms, with the enabling condition in brackets where the data is off by default
- [ ] `**What it catches:**` is one sentence about attacker behaviour, not about query mechanics

**The query**

- [ ] Fenced as ` ```kql `, table name alone on the first line, one `|` operator per line, wrapped lines indented four spaces
- [ ] Bounded by `| where TimeGenerated > ago(Nd)` immediately after the table
- [ ] `extend` to flatten, then `project` the analyst-facing set, then `order by TimeGenerated desc`, keeping `CorrelationId` where the table has it
- [ ] No tenant identifiers, real user principal names, domains or customer data anywhere in it
- [ ] I did not strip trailing whitespace from an existing query page. Two trailing spaces are a hard line break and `.editorconfig` leaves them alone deliberately

**Tuning, and where you ran it**

- [ ] `**Tuning / false positives:**` covers all three: what generates the noise, how to baseline it, and what the high-fidelity version of the signal looks like. "This may produce false positives" is none of the three
- [ ] `**Tested:**` is present, last in the block, naming the surface as the product spells it and an ISO date — the date it ran, not the date this pull request opened
- [ ] **I pasted it into Advanced Hunting or Sentinel Logs and it executed without a schema error.** Say below what came back, even if the answer is "no rows in this tenant"

**Coverage — all three places, by the same rule**

`README.md`, `docs/coverage.md` and the Navigator layer each state coverage, and
three different counting rules coexisting in them is what
[#8](https://github.com/juandresrodca/EntraHuntKit/issues/8) was. Regenerate the
figures with the commands in
[Regenerating this page](https://github.com/juandresrodca/EntraHuntKit/blob/main/docs/coverage.md#regenerating-this-page)
rather than editing them by hand; those commands strip the MITRE link targets before
counting, which hand-editing does not.

- [ ] The query count and coverage table in [`README.md`](https://github.com/juandresrodca/EntraHuntKit/blob/main/README.md#attck-coverage) are updated
- [ ] [`docs/coverage.md`](https://github.com/juandresrodca/EntraHuntKit/blob/main/docs/coverage.md) is regenerated, not hand-edited
- [ ] [`docs/attack-navigator/entrahuntkit-layer.json`](https://github.com/juandresrodca/EntraHuntKit/blob/main/docs/attack-navigator/) is updated, including its `metadata` counts
- [ ] All three agree with what the regeneration commands print, and with [the counting rule](https://github.com/juandresrodca/EntraHuntKit/blob/main/docs/coverage.md#the-counting-rule)

## Adding an indicator?

<!-- Delete this whole section if you are not. -->

Indicators here get pasted into other people's hunts, so the bar is a public,
checkable source. Falsely flagging a legitimate app or domain is worse than omitting
it.

- [ ] It goes in the right list under `ioc/`, in that file's existing column order
- [ ] **A public source is cited and linked** — an advisory, a vendor write-up, or your own incident report. "Known bad" with no source is rejected
- [ ] The source is readable today. A dead link is not a citation
- [ ] I can stand behind this indicator being malicious rather than merely unusual
- [ ] If a query's tuning note should now hand the reader this list, it does

If you own an app or domain listed here and believe it is listed in error, this is
not the route — the dispute process is in
[SECURITY.md](https://github.com/juandresrodca/EntraHuntKit/blob/main/SECURITY.md).

## Everything

- [ ] A line under **Unreleased** in [`CHANGELOG.md`](https://github.com/juandresrodca/EntraHuntKit/blob/main/CHANGELOG.md)
- [ ] This change stays on the defensive side of [scope](https://github.com/juandresrodca/EntraHuntKit/blob/main/CONTRIBUTING.md#scope): detection logic for Entra ID, Intune and M365 — not exploitation tooling, not red-team payloads

## Anything a reviewer should know

<!--
The output you got, a schema reference that says something surprising, a technique
mapping you went back and forth on, or a tuning note you are not happy with yet.
With no CI to lean on, this is the most useful part of the description.

Arguing that a detection is wrong is the point of this project and is always
welcome. House style, for reference: British spelling in prose, UTF-8 and LF per
.editorconfig, and Conventional Commit subjects in the imperative.
-->
