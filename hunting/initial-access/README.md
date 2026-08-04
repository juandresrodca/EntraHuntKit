# Initial Access

Queries for spotting the *first foothold* — how an attacker gets a valid session into your tenant.

> **Table dialects:** `SigninLogs` / `AADUserRiskEvents` live in **Microsoft Sentinel** (Log Analytics). In **Defender XDR Advanced Hunting** the closest equivalent is `AADSignInEventsBeta`. Each query names the table it's written for; the "Also in" note points at the other surface.

---

## 1. Legacy authentication sign-ins

**ATT&CK:** [T1078.004 — Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) · **Platform:** Sentinel · **License:** Entra ID P1 (sign-in logs)
**What it catches:** Successful sign-ins over legacy protocols (IMAP/POP/SMTP/EAS/"Other clients") that silently bypass Conditional Access and MFA.

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ClientAppUsed in ("Other clients", "IMAP4", "POP3", "SMTP", "Authenticated SMTP",
    "Exchange ActiveSync", "MAPI Over HTTP", "Offline Address Book",
    "Outlook Anywhere (RPC over HTTP)", "AutoDiscover", "Exchange Web Services",
    "Exchange Online PowerShell")
| where ResultType == 0            // 0 = success
| summarize SignIns = count(), IPs = make_set(IPAddress, 50), Protocols = make_set(ClientAppUsed, 20)
    by UserPrincipalName, AppDisplayName
| order by SignIns desc
```

**Tuning / false positives:** Line-of-business apps, legacy scanners/MFPs, and some CRM connectors still use basic auth. Baseline the known service accounts, then alert on *interactive user* accounts. The real win is a successful legacy sign-in for a user who normally authenticates with a modern client — that's often a token/password replay. Block legacy auth with CA once you've cleared the baseline.
**Also in:** Defender XDR — `AADSignInEventsBeta` (filter `ErrorCode == 0`).

---

## 2. Successful sign-in from an anonymizing IP (Tor / VPN / proxy)

**ATT&CK:** [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/) · **Platform:** Sentinel · **License:** Entra ID P1 (risk surfaced with P2)
**What it catches:** A *successful* sign-in that Entra risk-tagged as coming from an anonymized IP address — a common step right after credential phishing.

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| where RiskEventTypes_V2 has "anonymizedIPAddress"
    or RiskLevelDuringSignIn in ("high", "medium")
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName,
    ClientAppUsed, RiskLevelDuringSignIn, RiskEventTypes_V2, ConditionalAccessStatus
| order by TimeGenerated desc
```

**Tuning / false positives:** Corporate VPN egress and privacy-conscious users trip `anonymizedIPAddress`. Exclude your known VPN ranges, then focus on sign-ins that were *not* challenged (`ConditionalAccessStatus != "success"`) or that hit high-value apps.
**Also in:** Defender XDR — `AADSignInEventsBeta` carries `RiskLevelDuringSignIn`.

---

## 3. Impossible / atypical travel

**ATT&CK:** [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/) · **Platform:** Sentinel · **License:** Entra ID P2 (risk detections)
**What it catches:** Entra's own impossible-travel / unlikely-travel risk detections — two sign-ins too far apart to be the same human.

```kql
AADUserRiskEvents
| where TimeGenerated > ago(7d)
| where RiskEventType in ("impossibleTravel", "unlikelyTravel", "unfamiliarFeatures")
| project TimeGenerated, UserPrincipalName, RiskEventType, RiskLevel, RiskState,
    IpAddress, Location, Source, DetectionTimingType
| order by TimeGenerated desc
```

**No P2? Heuristic fallback on `SigninLogs` (multiple countries in one hour):**

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0 and isnotempty(Location)
| summarize Countries = make_set(Location, 20), SignIns = count()
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(Countries) > 1
| order by SignIns desc
```

**Tuning / false positives:** VPN hopping, mobile carriers, and cross-border commuters generate noise. Treat `impossibleTravel` at `RiskLevel == "high"` as the highest-fidelity signal; the heuristic version needs an allow-list of expected country pairs.
