# Collection

Staging the data before it leaves — inbox rules that quietly file away or delete mail so the victim never notices the theft in progress.

> **Table dialects:** `OfficeActivity` lives in **Microsoft Sentinel**. Defender XDR equivalent is `CloudAppEvents`.

---

## 15. Inbox rule that hides, deletes, or moves mail

**ATT&CK:** [T1114.003 — Email Collection: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003/) · also [T1564.008](https://attack.mitre.org/techniques/T1564/008/) · **Platform:** Sentinel · **License:** M365 audit (mailbox auditing on)
**What it catches:** Rules that auto-delete or shove messages into `RSS Feeds`, `Archive`, `Conversation History`, or `Deleted Items` — used in BEC to hide the attacker's own replies and the victim's security alerts.

```kql
OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in ("New-InboxRule", "Set-InboxRule")
| extend RuleParams = parse_json(Parameters)
| mv-apply p = RuleParams on (
    summarize Params = make_bag(bag_pack(tostring(p.Name), tostring(p.Value)))
)
| where Params has "DeleteMessage"
    or (Params has "MoveToFolder" and tostring(Params.MoveToFolder)
        has_any ("RSS", "Archive", "Conversation History", "Deleted Items", "Junk"))
| project TimeGenerated, UserId, ClientIP, Operation, Params
| order by TimeGenerated desc
```

**Tuning / false positives:** Plenty of users file newsletters into folders — that alone isn't malicious. The strong signals: a rule that **deletes** mail, or one that filters on security keywords (`phish`, `fraud`, `suspicious`, `helpdesk`) and moves matches out of the Inbox, created soon after a risky sign-in. Combine with the forwarding rule hunt (query 6) — attackers often set both.
**Also in:** Defender XDR — `CloudAppEvents` where `ActionType in ("New-InboxRule", "Set-InboxRule")`; rule params under `RawEventData.Parameters`.
