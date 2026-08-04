# IOC — High-Risk Microsoft Graph Permission Scopes

When triaging an OAuth consent ([hunt #4](../hunting/persistence/README.md#4-illicit-oauth-application-consent)), the *scopes* the app requested tell you the blast radius. These are the permissions that let an app read mail, send as the user, exfiltrate files, or escalate — the ones consent-phishing apps ask for.

> Delegated = acts as the signed-in user. Application = acts tenant-wide with no user. **Application-level grants of these are near-nuclear** — treat any unexpected admin consent to them as an incident.

## Tier 1 — mailbox takeover / BEC

| Scope | Risk |
|---|---|
| `Mail.ReadWrite` | Read + modify the user's mail. |
| `Mail.Read` | Read all the user's mail. |
| `Mail.Send` | Send mail **as the user** — fraud, lateral phishing. |
| `MailboxSettings.ReadWrite` | Create forwarding rules programmatically. |
| `IMAP.AccessAsUser.All` / `POP.AccessAsUser.All` / `SMTP.Send` | Legacy-protocol mail access, bypasses many controls. |

## Tier 1 — data exfiltration

| Scope | Risk |
|---|---|
| `Files.ReadWrite.All` | Read/write **all** files the user can reach. |
| `Files.Read.All` | Read all OneDrive/SharePoint content. |
| `Sites.ReadWrite.All` / `Sites.Read.All` | Whole-SharePoint access. |
| `Notes.ReadWrite.All` | OneNote, often full of secrets. |

## Tier 0 — privilege escalation / tenant takeover

| Scope | Risk |
|---|---|
| `Application.ReadWrite.All` | Create/modify apps + **add credentials to any app** → persistence. |
| `AppRoleAssignment.ReadWrite.All` | Grant app roles — self-escalation path. |
| `RoleManagement.ReadWrite.Directory` | Assign directory roles → Global Admin. |
| `Directory.ReadWrite.All` | Broad directory write. |
| `PrivilegedAccess.ReadWrite.AzureADGroup` | Manipulate PIM-managed groups. |
| `User.ReadWrite.All` | Reset attributes / MFA methods across users. |

## Always paired with the above

| Scope | Why it matters |
|---|---|
| `offline_access` | Grants a **refresh token** — persistent access after the session ends. Almost every malicious consent asks for it. |

## Use in a hunt

```kql
let riskyScopes = dynamic([
  "Mail.ReadWrite","Mail.Send","MailboxSettings.ReadWrite","Files.ReadWrite.All",
  "Application.ReadWrite.All","RoleManagement.ReadWrite.Directory","Directory.ReadWrite.All",
  "AppRoleAssignment.ReadWrite.All","offline_access"]);
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has "Consent to application" or OperationName has "OAuth2PermissionGrant"
| mv-expand mp = TargetResources[0].modifiedProperties
| extend newVal = tostring(mp.newValue)
| where newVal has_any (riskyScopes)
| project TimeGenerated, OperationName, Actor = tostring(InitiatedBy.user.userPrincipalName),
    App = tostring(TargetResources[0].displayName), GrantedScopes = newVal
```
