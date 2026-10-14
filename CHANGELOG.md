# Changelog

All notable changes to EntraHuntKit are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/); this is a data/reference repo, so "releases" are curation milestones.

## [Unreleased]

### Added

- **A pull request template** — `.github/pull_request_template.md`. The checklists are the reviewer's checklist from [`docs/query-format.md`](docs/query-format.md#the-reviewers-checklist), reordered to the way a submission is read, with the coverage section naming all three places a count lives and pointing at the regeneration commands rather than at hand-editing. The repository had two issue forms and a format reference but nothing in front of someone opening a pull request, and with no CI here every box is checked by a person — so the template asks for the query's actual output rather than for a green tick. Cross-linked from the README and from `CONTRIBUTING.md`'s submission steps. Relates to #7.
- **ATT&CK Navigator layer** — `docs/attack-navigator/entrahuntkit-layer.json`, a layer-format 4.5 file covering the 20 techniques these 16 queries reach, loadable straight from a URL. Closes #4.

### Changed

- **One ATT&CK counting rule, stated once and cited from the other three places.** `docs/coverage.md` now carries a named [counting rule](docs/coverage.md#the-counting-rule); the README table, the Navigator layer's README and the reviewer's checklist in `docs/query-format.md` cite it instead of each restating a rule of their own. Closes #8.

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
