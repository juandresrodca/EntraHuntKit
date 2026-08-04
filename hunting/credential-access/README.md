# Credential Access

Getting the keys: spraying passwords, and hammering MFA until a tired user taps "Approve".

> **Table dialects:** `SigninLogs` lives in **Microsoft Sentinel**. Defender XDR equivalent is `AADSignInEventsBeta`.

---

## 12. MFA-fatigue / push-bombing

**ATT&CK:** [T1621 — Multi-Factor Authentication Request Generation](https://attack.mitre.org/techniques/T1621/) · **Platform:** Sentinel · **License:** Entra ID P1
**What it catches:** A burst of MFA prompts against one user — the attacker has the password and is spamming push notifications hoping for an accidental approval.

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType in (50074, 500121)   // 50074 = MFA required; 500121 = MFA failed/denied/timed-out
| summarize MfaPrompts = count(), Apps = make_set(AppDisplayName, 20), IPs = make_set(IPAddress, 20)
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where MfaPrompts >= 5
| order by MfaPrompts desc
```

**Correlate with a follow-on success (the dangerous case):**

```kql
let bombed = SigninLogs
    | where TimeGenerated > ago(1d)
    | where ResultType in (50074, 500121)
    | summarize Prompts = count() by UserPrincipalName, bin(TimeGenerated, 1h)
    | where Prompts >= 5
    | distinct UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0 and UserPrincipalName in (bombed)
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ClientAppUsed
| order by TimeGenerated asc
```

**Tuning / false positives:** Flaky mobile networks and users who ignore prompts create low-count noise — the `>= 5` threshold filters most of it. A `500121` storm followed by a `ResultType == 0` from a *new* IP is the compromise pattern; treat it as high severity. Move users to number-matching MFA to kill this technique.
**Also in:** Defender XDR — `AADSignInEventsBeta` (`ErrorCode`).

---

## 13. Password spray

**ATT&CK:** [T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/) · **Platform:** Sentinel · **License:** Entra ID P1
**What it catches:** One source hitting *many* accounts with a *few* passwords — low-and-slow credential guessing that stays under per-account lockout thresholds.

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType in (50126, 50053, 50055, 50056)   // bad password / locked / expired / invalid
| summarize FailedUsers = dcount(UserPrincipalName), Attempts = count(),
    Users = make_set(UserPrincipalName, 100)
    by IPAddress, bin(TimeGenerated, 1h)
| where FailedUsers >= 10
| order by FailedUsers desc
```

**Tuning / false positives:** A misconfigured app or expired service-account password can spike failures from one IP against one account — that's not spray. The signature here is **high distinct-user count from a single IP** (`FailedUsers >= 10`). Tune the threshold to your tenant size, and enrich `IPAddress` with geo/ASN — sprays often come from hosting/VPS ranges. A spray IP that later produces a `ResultType == 0` is a confirmed breach.
**Also in:** Defender XDR — `AADSignInEventsBeta` (`ErrorCode in (50126, 50053, 50055, 50056)`).
