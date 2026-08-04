# Discovery

After access, attackers map the tenant — enumerating users, groups, roles, and service principals through Microsoft Graph before choosing their next move.

> **Table dialects:** `MicrosoftGraphActivityLogs` lives in **Microsoft Sentinel** and requires the *Microsoft Graph activity logs* diagnostic setting to be enabled (Entra ID P1/P2).

---

## 14. Directory enumeration via Microsoft Graph

**ATT&CK:** [T1087.004 — Account Discovery: Cloud Account](https://attack.mitre.org/techniques/T1087/004/) · also [T1069.003](https://attack.mitre.org/techniques/T1069/003/) · **Platform:** Sentinel · **License:** Entra ID P1 + Graph activity logs enabled
**What it catches:** A single identity or app making a high volume of Graph reads against `/users`, `/groups`, `/directoryRoles`, and `/servicePrincipals` — the fingerprint of recon tooling (AADInternals, ROADrecon, GraphRunner).

```kql
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(1d)
| where RequestMethod == "GET"
| where RequestUri has_any ("/users", "/groups", "/directoryRoles", "/servicePrincipals",
    "/applications", "/roleManagement", "/memberOf")
| summarize Requests = count(), DistinctUris = dcount(RequestUri),
    Targets = make_set(tostring(parse_url(RequestUri).Path), 30)
    by AppId, UserId = tostring(UserId), IPAddress = tostring(IPAddress), bin(TimeGenerated, 1h)
| where Requests > 100 and DistinctUris > 20
| order by Requests desc
```

**Tuning / false positives:** Governance/reporting tools (identity lifecycle, access reviews, your own IntuneGraph-style exports) legitimately sweep the directory — baseline those app IDs and exclude them. The suspicious profile is a *user-delegated* token or an unfamiliar app suddenly enumerating at volume, especially from a fresh IP or right after a risky sign-in. Tune `Requests`/`DistinctUris` thresholds to your tenant's normal Graph traffic.
**Also in:** No direct Defender XDR equivalent — `MicrosoftGraphActivityLogs` is the authoritative source. Some Graph calls also surface in `CloudAppEvents` but without full URI granularity.
