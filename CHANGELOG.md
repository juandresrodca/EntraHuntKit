# Changelog

All notable changes to EntraHuntKit are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/); this is a data/reference repo, so "releases" are curation milestones.

## [Unreleased]

### Added

- **A pull request template** — `.github/pull_request_template.md`. The checklists are the reviewer's checklist from [`docs/query-format.md`](docs/query-format.md#the-reviewers-checklist), reordered to the way a submission is read, with the coverage section naming all three places a count lives and pointing at the regeneration commands rather than at hand-editing. The repository had two issue forms and a format reference but nothing in front of someone opening a pull request, and with no CI here every box is checked by a person — so the template asks for the query's actual output rather than for a green tick. Cross-linked from the README and from `CONTRIBUTING.md`'s submission steps. Relates to #7.
- **A written query format** — [`docs/query-format.md`](docs/query-format.md). The submission form had always asked for a tested-on answer and a tactic number, and neither had a written home: nothing under `hunting/` used the word *Tested*, and a heading of `## N` never said the sequence runs once across all seven tactic folders rather than restarting inside each — the obvious reading breaks every by-number citation in [`docs/coverage.md`](docs/coverage.md) and in the Navigator layer. The page derives the format from the sixteen queries already in the tree rather than prescribing a new one, fixes the next number at 17, defines a `**Tested:**` line from that date without backfilling the sixteen, and ends in [the reviewer's checklist](docs/query-format.md#the-reviewers-checklist). The nine rules a metadata lint would enforce are cited from #7 rather than restated here, so the page and the automation cannot drift apart.
- **The ATT&CK coverage index** — [`docs/coverage.md`](docs/coverage.md). Seven tactic folders and no way to see what the sixteen queries reach without walking the tree. The page indexes coverage by tactic and technique, and adds the two dimensions the Navigator layer cannot show — the source table and licence floor each query needs, with eight of the sixteen running on the unified audit log alone — then writes the four uncovered tactics out as named candidate detections rather than leaving dark cells. It is the page the *Changed* and *Fixed* entries below are about, and it had never been recorded as arriving.
- **A code of conduct** — [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md), the Contributor Covenant 2.1 verbatim with one added note under *Enforcement* routing wrong-query reports and IOC disputes to [`SECURITY.md`](SECURITY.md), so that an argument about whether a detection is correct is not misfiled as a conduct complaint. EntraHuntKit was the last of these repositories without one, and GitHub's community profile shows its absence to anyone weighing up whether to contribute a detection.
- **ATT&CK Navigator layer** — `docs/attack-navigator/entrahuntkit-layer.json`, a layer-format 4.5 file covering the 20 techniques these 16 queries reach, loadable straight from a URL. Closes #4.
- **Issue forms for both kinds of submission** — `.github/ISSUE_TEMPLATE/`. The repository had no `.github/` at all, so every contribution started from a blank box that asked for none of the five things [`CONTRIBUTING.md`](CONTRIBUTING.md) says a query needs. `new_query.yml` collects the tactic folder, ATT&CK technique, platform, table, licence tier, KQL and a mandatory tuning note, and makes *I ran this and it executed* a required tick. `new_ioc.yml` asks for a public source URL and separates confirmed-malicious from abused-legitimate, so that a listing never quietly blocks a real product. `config.yml` keeps blank issues open for *this query is wrong*, which [`SECURITY.md`](SECURITY.md) treats as the priority report, and routes private disclosure to the advisory form.
- **A security policy** — [`SECURITY.md`](SECURITY.md). A repository of paste-ready hunting queries and IOC lists has two failure modes an ordinary bug report handles badly: a query that runs clean and silently returns nothing, and an indicator that names a legitimate application. The policy carries the private reporting route, the sourcing rule `CONTRIBUTING.md` already enforced, and a dispute path targeting acknowledgement in 72 hours and resolution in 7 days for anyone who owns an app or domain listed under [`ioc/`](ioc/).

### Changed

- **One ATT&CK counting rule, stated once and cited from the other three places.** `docs/coverage.md` now carries a named [counting rule](docs/coverage.md#the-counting-rule); the README table, the Navigator layer's README and the reviewer's checklist in `docs/query-format.md` cite it instead of each restating a rule of their own. Closes #8.
- **Line endings are settled by the repository rather than by whichever editor a contributor uses** — `.gitattributes`. A CRLF checkout could still turn a one-line query edit into a whole-file diff; [Enterprise-Onboarding-Platform#12](https://github.com/juandresrodca/Enterprise-Onboarding-Platform/issues/12) is the case that cost 1,341 lines. The entries are written from `git ls-files` rather than copied from a sibling, which is why no query file type is declared — the queries and the IOC lists are markdown with fenced KQL, and have no extension of their own. `git add --renormalize .` produced no change, so nothing tracked here carried CRLF; the one binary file, `docs/demo/demo.mp4`, is now marked binary explicitly so that neither that renormalisation nor a later one can rewrite it.
- **First-party Microsoft application IDs are cited upstream instead of restated here.** [`ioc/malicious-oauth-app-ids.md`](ioc/malicious-oauth-app-ids.md) points at [`merill/microsoft-info`](https://github.com/merill/microsoft-info), which regenerates daily and resolves names at query time, rather than carrying a hand-maintained table of its own. That table had already drifted — `de8bc8b5` was labelled Graph Command Line Tools when it is Graph Explorer, and `14d82eec` the reverse — and a wrong name on a right GUID is precisely what [`SECURITY.md`](SECURITY.md) treats as a security bug rather than an ordinary one. The `externaldata` form is flagged Sentinel-only so the section stays paste-ready in Defender XDR. It is a position as much as a fix: where another project maintains a dataset better than this one can, this one links to it.

### Fixed

- **`docs/coverage.md`'s By tactic table counted nine techniques no query declares** — `T1069`, `T1087`, `T1110`, `T1114`, `T1137`, `T1484`, `T1556`, `T1562` and `T1564` were read out of the path segments of the MITRE links (`.../techniques/T1562/007/`), not out of any query's `**ATT&CK:**` declaration. The regeneration command had the same defect and is now anchored with the link targets stripped.
- **The README's Persistence row omitted `T1114.003`**, which query 6 declares, so the table showed one query for mail-collection coverage where there are two.

- _Your next detection here — see [CONTRIBUTING.md](CONTRIBUTING.md)._

## [0.1.0] — 2026-08-04

Initial public release. 16 ATT&CK-mapped hunting queries across 7 tactics, plus 3 IOC reference lists.

### Added

- **Initial Access** (3): legacy authentication sign-ins, anonymized-IP sign-ins, impossible/atypical travel.
- **Persistence** (5): illicit OAuth consent, app/service-principal credential add, BEC forwarding rules, privileged Entra role assignment, federation/domain-auth tampering.
- **Defense Evasion** (3): Conditional Access policy changes, Intune compliance/config policy tampering, mailbox audit disable.
- **Credential Access** (2): MFA-fatigue / push-bombing, password spray.
- **Discovery** (1): directory enumeration via Microsoft Graph.
- **Collection** (1): inbox rules that hide/delete/move mail.
- **Exfiltration** (1): anomalous mass file download.
- **IOC lists**: abused/malicious OAuth app IDs, suspicious inbox-rule patterns, high-risk Graph permission scopes.
- Scaffold: MIT license, scout-aesthetic README with ATT&CK coverage table, contributing guide.
