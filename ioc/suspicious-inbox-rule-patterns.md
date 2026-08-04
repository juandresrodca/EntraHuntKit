# IOC — Suspicious Inbox-Rule Patterns

Feeds the BEC inbox-rule hunts ([forwarding](../hunting/persistence/README.md#6-new-mailbox-forwarding--redirect-rule-bec) and [hide/delete](../hunting/collection/README.md#15-inbox-rule-that-hides-deletes-or-moves-mail)). These are the tell-tale shapes of attacker-created rules seen across real BEC intrusions.

## Rule *name* patterns

Attackers name rules to be forgettable — often a single character or blank so they blend in and are easy to overlook in Outlook.

```
.            (single dot)
..           (double dot)
,            (single comma)
;
_            (single underscore)
" "          (a single space or empty name)
a
1
rule
temp
```

## Rule *behaviour* patterns (the real signal)

| Pattern | Why it's suspicious |
|---|---|
| `ForwardTo` / `RedirectTo` an **external** domain | Exfil of every inbound mail. Top BEC indicator. |
| `DeleteMessage = true` | Hides attacker replies / security alerts from the victim. |
| `MoveToFolder` → `RSS Feeds`, `Conversation History`, `Archive`, `Junk` | Classic "hide the evidence" folders users never check. |
| Body/subject filter on `invoice`, `payment`, `bank`, `wire`, `ACH`, `remittance` | Financial-fraud targeting. |
| Body/subject filter on `phish`, `fraud`, `suspicious`, `hacked`, `helpdesk`, `security`, `password` | Suppressing the victim's view of the incident. |
| Rule created within minutes of a risky / foreign sign-in | Timing correlation with account takeover. |

## Keyword list for `SubjectContainsWords` / body filters

```
invoice
payment
wire transfer
bank
ACH
remittance
account details
password
verify
suspicious
phishing
fraud
report
helpdesk
```

## Use in a hunt

```kql
let sketchyFolders = dynamic(["RSS Feeds","Conversation History","Archive","Junk Email","Deleted Items"]);
let fraudKeywords  = dynamic(["invoice","payment","wire","bank","ACH","phish","fraud","suspicious","password"]);
OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in ("New-InboxRule","Set-InboxRule")
| where Parameters has_any (fraudKeywords) or Parameters has_any (sketchyFolders) or Parameters has "DeleteMessage"
| project TimeGenerated, UserId, ClientIP, Operation, Parameters
```
