# IOC — OAuth App IDs & Consent-Phishing Reference

Use this list to enrich the **illicit OAuth consent** hunt ([`hunting/persistence`](../hunting/persistence/README.md#4-illicit-oauth-application-consent)). Two kinds of entries:

1. **First-party app IDs commonly abused / impersonated** in consent-phishing and token attacks. These IDs are *legitimate Microsoft apps* — attackers piggyback on or spoof them to look trustworthy. They are **not** enumerated here; see [below](#microsoft-first-party-app-ids--resolve-them-upstream) for the maintained source.
2. A **contribution template** for genuinely malicious app IDs sourced from your own IR or public threat intel. **Do not add an app ID here unless you have a citation.** Falsely flagging a legitimate SaaS app is worse than no entry.

> ⚠️ **Accuracy over volume.** An IOC list that names innocent apps burns the analyst's trust. Every malicious entry must carry a source.

---

## Microsoft first-party app IDs — resolve them upstream

This repository does **not** keep its own table of Microsoft first-party app IDs. Microsoft
publishes thousands of them and the set moves; a copy pasted here goes stale quietly, and a
stale name attached to the right GUID is exactly the kind of wrong that survives review.

Use **[merill/microsoft-info](https://github.com/merill/microsoft-info)** instead — a
daily-regenerated list of Microsoft first-party app names and their GUIDs, built from
Microsoft Graph, the Entra docs `known-guids.json`, and the *Verify first-party Microsoft
applications in sign-in reports* Learn article. It is community-run, MIT-licensed, and
designed to be consumed by scripts and KQL rather than read.

| Feed | Raw URL |
|---|---|
| First-party apps | `https://raw.githubusercontent.com/merill/microsoft-info/main/_info/MicrosoftApps.csv` (also `.json`) |
| Graph **application** permissions | `https://raw.githubusercontent.com/merill/microsoft-info/main/_info/GraphAppRoles.csv` |
| Graph **delegated** permissions | `https://raw.githubusercontent.com/merill/microsoft-info/main/_info/GraphDelegateRoles.csv` |

`MicrosoftApps.csv` columns: `AppId`, `AppDisplayName`, `AppOwnerOrganizationId`, `Source`.

### Resolving names at query time

**Platform: Sentinel / Log Analytics.** `externaldata` is not available in Defender XDR
advanced hunting — there, paste the handful of IDs a given hunt needs into a `dynamic()`
list, or load the feed as a watchlist.

```kql
let firstParty = externaldata(AppId: string, AppDisplayName: string, AppOwnerOrganizationId: string, Source: string)
    [@"https://raw.githubusercontent.com/merill/microsoft-info/main/_info/MicrosoftApps.csv"]
    with (format="csv", ignoreFirstRecord=true);
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has "Consent to application"
| extend AppId = tostring(TargetResources[0].id)
| lookup kind=leftouter firstParty on AppId
| project TimeGenerated, AppId, AppDisplayName, InitiatedBy, Result
```

A first-party ID in a consent event is **not a finding on its own**. Several of the
highest-volume ones — Microsoft Office, Azure CLI, Azure PowerShell, the Graph command-line
tools — are ordinary admin tooling *and* the clients that recon and token-replay scripts
reach for. Alert on the **context**: who consented, from which IP, to which scopes.

---

## Confirmed-malicious app IDs (community-contributed — cite your source)

<!-- Add entries in this format. PRs without a source link will be rejected. -->

| App ID | First seen | Campaign / notes | Source |
|---|---|---|---|
| _example — remove_ `00000000-0000-0000-0000-000000000000` | 2026-01-01 | Consent-phishing app requesting `Mail.ReadWrite` + `offline_access` | https://example.com/report |

---

## How to use in a hunt

```kql
// paste your confirmed-bad IDs into the dynamic list
let maliciousApps = dynamic(["00000000-0000-0000-0000-000000000000"]);
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has "Consent to application"
| extend AppId = tostring(TargetResources[0].id)
| where AppId in (maliciousApps)
```

**References worth watching for fresh IOCs:** Microsoft Threat Intelligence blog, CISA advisories, the Huntress / Volexity / Proofpoint BEC writeups, and `microsoft/Microsoft-365-Defender-Hunting-Queries`.
