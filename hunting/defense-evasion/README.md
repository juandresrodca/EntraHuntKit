# Defense Evasion

Attackers who reach admin turn the lights off: weakening Conditional Access, gutting Intune compliance, and disabling mailbox audit so the rest of the kill chain goes unseen.

> **Table dialects:** `AuditLogs`, `IntuneAuditLogs`, and `OfficeActivity` live in **Microsoft Sentinel**. Defender XDR equivalent for directory/audit events is `CloudAppEvents`.

---

## 9. Conditional Access policy created, weakened, or disabled

**ATT&CK:** [T1562.007 — Disable or Modify Cloud Firewall](https://attack.mitre.org/techniques/T1562/007/) · also [T1556.009](https://attack.mitre.org/techniques/T1556/009/) · **Platform:** Sentinel · **License:** M365 audit
**What it catches:** Any change to a Conditional Access policy — the control that enforces MFA and device compliance. Disabling or scoping-out a policy is a favourite pre-attack move.

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("Add conditional access policy",
    "Update conditional access policy", "Delete conditional access policy")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend PolicyName = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, Actor, PolicyName, Result,
    Changes = TargetResources[0].modifiedProperties, CorrelationId
| order by TimeGenerated desc
```

**Tuning / false positives:** Identity teams tune CA policies regularly. Pair with change control. The alerts that matter: a policy set to `disabled`, a grant control dropped from `mfa` to `none`, an exclusion group added, or a delete — expand `Changes` to see the before/after `state` and `grantControls`.
**Also in:** Defender XDR — `CloudAppEvents` where `ActionType has "conditional access policy"`.

---

## 10. Intune compliance or configuration policy deleted / weakened

**ATT&CK:** [T1562.001 — Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) · **Platform:** Sentinel · **License:** Intune + diagnostic settings to Log Analytics
**What it catches:** Deletion or patching of a device compliance / configuration policy — undermining the "compliant device" signal that Conditional Access trusts.

```kql
IntuneAuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("Delete", "Patch", "Set")
| where OperationName has_any ("Compliance", "Configuration", "DeviceConfiguration",
    "CompliancePolicy", "DeviceCompliancePolicy")
| extend Actor = tostring(parse_json(tostring(Properties)).Actor.UPN)
| project TimeGenerated, OperationName, Actor, Identity,
    Target = tostring(parse_json(tostring(Properties)).TargetDisplayNames), ResultType
| order by TimeGenerated desc
```

**Tuning / false positives:** Intune admins edit policies daily. Focus on **Delete** operations and on changes that *loosen* posture (e.g. compliance policy set to not require encryption/PIN). The `Properties` JSON shape varies by event — if `Actor`/`Target` parse empty, inspect the raw `Properties` column. Baseline your MDM admins and alert on anyone outside that set.
**Also in:** Defender XDR does not surface Intune audit; this one is Sentinel-only (or Graph `deviceManagement/auditEvents`).

---

## 11. Mailbox audit logging disabled

**ATT&CK:** [T1562.008 — Disable or Modify Cloud Logs](https://attack.mitre.org/techniques/T1562/008/) · **Platform:** Sentinel · **License:** M365 audit
**What it catches:** `Set-Mailbox` turning off per-mailbox audit logging — an attacker blinding the very telemetry that would reveal mail theft.

```kql
OfficeActivity
| where TimeGenerated > ago(30d)
| where Operation == "Set-Mailbox"
| extend P = parse_json(Parameters)
| mv-apply p = P on (
    where p.Name == "AuditEnabled"
    | project AuditEnabled = tostring(p.Value)
)
| where AuditEnabled =~ "False"
| project TimeGenerated, UserId, ClientIP, Operation, TargetMailbox = OfficeObjectId, AuditEnabled
| order by TimeGenerated desc
```

**Tuning / false positives:** Very rarely legitimate — org-wide mailbox auditing should stay on. A `Set-Mailbox … -AuditEnabled $false` against a user mailbox, especially by a non-standard admin or from an unusual IP, is a strong evasion signal. Also watch for `Set-AdminAuditLogConfig` disabling admin audit.
**Also in:** Defender XDR — `CloudAppEvents` where `ActionType == "Set-Mailbox"`.
