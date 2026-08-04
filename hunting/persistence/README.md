# Persistence

Once an attacker has access, these are the moves that let them *keep* it — new credentials, consented apps, forwarding rules, role grants, and federation backdoors.

> **Table dialects:** `AuditLogs` and `OfficeActivity` live in **Microsoft Sentinel**. In **Defender XDR Advanced Hunting** the directory/audit equivalent is `CloudAppEvents`. Each query names its table.

---

## 4. Illicit OAuth application consent

**ATT&CK:** [T1528 — Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) · also [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/) · **Platform:** Sentinel · **License:** M365 audit (all tenants)
**What it catches:** A user (or admin) granting OAuth permissions to an app — the core of consent-phishing / "illicit consent grant" attacks that hand an app persistent Graph access.

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has "Consent to application"
    or OperationName has "Add OAuth2PermissionGrant"
    or OperationName has "Add delegated permission grant"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetApp = tostring(TargetResources[0].displayName)
| extend Props = TargetResources[0].modifiedProperties
| project TimeGenerated, OperationName, Actor, TargetApp, Result, Props, CorrelationId
| order by TimeGenerated desc
```

**Tuning / false positives:** Legitimate SaaS onboarding generates consent events. Triage by (a) *who* consented — user self-consent to an unknown app is far more suspicious than admin consent, and (b) *what scopes* — expand `Props` and flag high-impact delegated scopes like `Mail.ReadWrite`, `Mail.Send`, `MailboxSettings.ReadWrite`, `Files.ReadWrite.All`, `offline_access`. Cross-reference the app ID against [`ioc/malicious-oauth-app-ids.md`](../../ioc/malicious-oauth-app-ids.md).
**Also in:** Defender XDR — `CloudAppEvents` where `ActionType has "Consent to application"`.

---

## 5. Credential or certificate added to an app / service principal

**ATT&CK:** [T1098.001 — Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/) · **Platform:** Sentinel · **License:** M365 audit
**What it catches:** A new client secret or certificate attached to an app registration or service principal — a stealthy backdoor that survives password resets and MFA.

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("Add service principal credentials",
    "Update application – Certificates and secrets management",
    "Update application", "Add key to application")
| extend Actor = tostring(iff(isnotempty(InitiatedBy.user.userPrincipalName),
    InitiatedBy.user.userPrincipalName, InitiatedBy.app.displayName))
| extend TargetApp = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, Actor, TargetApp, Result,
    Details = TargetResources[0].modifiedProperties, CorrelationId
| order by TimeGenerated desc
```

**Tuning / false positives:** CI/CD pipelines and app owners rotate secrets legitimately. Baseline the apps and identities that normally add credentials; alert hard when the actor is a *user* account acting on a high-privilege app (e.g. one holding `Application.ReadWrite.All` or a Graph app role), or when a secret is added to an app that has never had one.
**Also in:** Defender XDR — `CloudAppEvents` where `ActionType has "Add service principal credentials"`.

---

## 6. New mailbox forwarding / redirect rule (BEC)

**ATT&CK:** [T1137.005 — Outlook Rules](https://attack.mitre.org/techniques/T1137/005/) · also [T1114.003](https://attack.mitre.org/techniques/T1114/003/) · **Platform:** Sentinel · **License:** M365 audit (mailbox auditing on)
**What it catches:** An inbox rule that auto-forwards or redirects mail externally — the classic Business Email Compromise persistence + exfil move.

```kql
OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in ("New-InboxRule", "Set-InboxRule")
| extend RuleParams = parse_json(Parameters)
| mv-apply p = RuleParams on (
    where p.Name in ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
    | project ParamName = tostring(p.Name), ParamValue = tostring(p.Value)
)
| project TimeGenerated, UserId, ClientIP, Operation, ParamName, ParamValue, OriginatingServer
| order by TimeGenerated desc
```

**Tuning / false positives:** Users legitimately forward to personal or delegate mailboxes. The high-fidelity signal is a rule forwarding to an *external* domain, created shortly after a risky sign-in, often paired with a subject/body filter that hides replies (see query 15). Check `ParamValue` for domains outside your tenant.
**Also in:** Defender XDR — `CloudAppEvents` where `ActionType in ("New-InboxRule", "Set-InboxRule")`; parameters live under `RawEventData.Parameters`.

---

## 7. Privileged Entra role assignment

**ATT&CK:** [T1098.003 — Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/) · **Platform:** Sentinel · **License:** M365 audit
**What it catches:** A user being added to a privileged directory role (Global Admin, Privileged Role Admin, Application Admin, etc.) — privilege escalation and durable persistence.

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("Add member to role", "Add eligible member to role",
    "Add member to role in PIM requested (permanent)")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend RoleName = tostring(TargetResources[0].modifiedProperties[1].newValue)
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| where RoleName has_any ("Global Administrator", "Privileged Role Administrator",
    "Privileged Authentication Administrator", "Application Administrator",
    "Cloud Application Administrator", "Exchange Administrator", "User Administrator",
    "Security Administrator", "Hybrid Identity Administrator")
| project TimeGenerated, Actor, TargetUser, RoleName, Result, CorrelationId
| order by TimeGenerated desc
```

**Tuning / false positives:** Legitimate admin onboarding and PIM activations show up here. Correlate with a change ticket; alert immediately on self-assignment, on assignment by a newly created account, or on Global Admin grants outside a change window. `modifiedProperties` indexing can vary — inspect the raw record if `RoleName` comes back empty.
**Also in:** Defender XDR — `CloudAppEvents` where `ActionType has "Add member to role"`.

---

## 8. Federation trust / domain authentication change

**ATT&CK:** [T1484.002 — Domain Trust Modification](https://attack.mitre.org/techniques/T1484/002/) · **Platform:** Sentinel · **License:** M365 audit
**What it catches:** A domain switched to federated auth or a new federation trust added — the "AADFSpoof" / golden-SAML style backdoor that lets an attacker mint tokens for any user.

```kql
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in ("Set domain authentication", "Set federation settings on domain",
    "Add unverified domain", "Add domain to company", "Add partner to company")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend Domain = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, Actor, Domain, Result,
    Details = TargetResources[0].modifiedProperties, CorrelationId
| order by TimeGenerated desc
```

**Tuning / false positives:** Rare and high-value — most tenants change federation settings a handful of times a year. Every hit deserves a look. Legitimate changes come from identity admins during ADFS/third-party IdP migrations; anything else, especially a *new* federated domain or a change to `IssuerUri`/signing cert, is a red flag.
**Also in:** Defender XDR — `CloudAppEvents` where `ActionType has "Set domain authentication"`.
