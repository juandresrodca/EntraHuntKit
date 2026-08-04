# Changelog

All notable changes to EntraHuntKit are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/); this is a data/reference repo, so "releases" are curation milestones.

## [Unreleased]

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
