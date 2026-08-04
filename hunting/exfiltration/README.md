# Exfiltration

The data leaving the building — anomalous bulk downloads from SharePoint / OneDrive that signal an account being drained.

> **Table dialects:** `CloudAppEvents` lives in **Defender XDR Advanced Hunting**. Sentinel equivalent is `OfficeActivity` (SharePoint/OneDrive file operations).

---

## 16. Anomalous mass file download

**ATT&CK:** [T1567 — Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/) · also [T1530 — Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/) · **Platform:** Defender XDR · **License:** Defender for Cloud Apps / M365 audit
**What it catches:** A user pulling an unusual volume of files from SharePoint/OneDrive in a short window — bulk collection before exfil, or a compromised account being scraped.

```kql
CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileDownloaded", "FileSyncDownloadedFull")
| summarize Downloads = count(),
    Files = dcount(tostring(RawEventData.SourceFileName)),
    Apps = make_set(Application, 10)
    by AccountDisplayName, AccountObjectId, IPAddress, bin(Timestamp, 1h)
| where Downloads > 100 or Files > 50
| order by Downloads desc
```

**Sentinel equivalent (`OfficeActivity`):**

```kql
OfficeActivity
| where TimeGenerated > ago(1d)
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull")
| summarize Downloads = count(), Files = dcount(OfficeObjectId)
    by UserId, ClientIP, bin(TimeGenerated, 1h)
| where Downloads > 100 or Files > 50
| order by Downloads desc
```

**Tuning / false positives:** OneDrive sync clients on a new device legitimately download large batches (`FileSyncDownloadedFull`) — exclude first-time device syncs and known migration/backup accounts. The real signal is a *browser-based* mass `FileDownloaded` from an unfamiliar IP, or downloads spanning many distinct SharePoint sites the user doesn't normally touch. Set thresholds from your own per-user baseline rather than the placeholder `100` / `50`.
