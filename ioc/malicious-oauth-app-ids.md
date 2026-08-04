# IOC — OAuth App IDs & Consent-Phishing Reference

Use this list to enrich the **illicit OAuth consent** hunt ([`hunting/persistence`](../hunting/persistence/README.md#4-illicit-oauth-application-consent)). Two kinds of entries:

1. **First-party app IDs commonly abused / impersonated** in consent-phishing and token attacks. These IDs are *legitimate Microsoft apps* — they are listed so you can recognise them, not because the app itself is malicious. Attackers frequently piggyback on or spoof these to look trustworthy.
2. A **contribution template** for genuinely malicious app IDs sourced from your own IR or public threat intel. **Do not add an app ID here unless you have a citation.** Falsely flagging a legitimate SaaS app is worse than no entry.

> ⚠️ **Accuracy over volume.** An IOC list that names innocent apps burns the analyst's trust. Every malicious entry must carry a source.

---

## Well-known Microsoft first-party app IDs (recognition reference)

| App ID | App | Why it matters in hunts |
|---|---|---|
| `d3590ed6-52b3-4102-aeff-aad2292ab01c` | Microsoft Office | Extremely common; used as a client for token replay. High baseline volume. |
| `1b730954-1685-4b74-9bfd-dac224a7b894` | Azure Active Directory PowerShell | Legit admin tooling **and** a favourite of recon/attack scripts. |
| `1950a258-227b-4e31-a9cf-717495945fc2` | Microsoft Azure PowerShell | Same — legit automation and offensive tooling both use it. |
| `04b07795-8ddb-461a-bbee-02f9e1bf7b46` | Microsoft Azure CLI | Common in automation; watch for interactive use from odd IPs. |
| `de8bc8b5-d9f9-48b1-a8ad-b748da725064` | Microsoft Graph Command Line Tools | Delegated Graph access; abused by GraphRunner-style tooling. |
| `14d82eec-204b-4c2f-b7e8-296a70dab67e` | Microsoft Graph | The resource most consent-phishing scopes target. |

*These are reference/benign. Alert on the **context** (who, which IP, which scopes), not the ID alone.*

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
