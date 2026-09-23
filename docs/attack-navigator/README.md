# ATT&CK Navigator layer

`entrahuntkit-layer.json` is a [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
layer showing exactly which techniques the 16 hunting queries in this repo cover. Load it and the
Enterprise matrix lights up in EntraHuntKit lime — one look tells you where you are covered and,
more usefully, where you are not.

| | |
|---|---|
| **File** | [`entrahuntkit-layer.json`](entrahuntkit-layer.json) |
| **Layer format** | 4.5 (Navigator 5.x) |
| **Domain** | `enterprise-attack`, ATT&CK v19 |
| **Techniques highlighted** | 20, from 16 queries |

---

## Load it

**From a URL** — nothing to download:

1. Open the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
2. **Open Existing Layer → Load from URL**.
3. Paste:

   ```
   https://raw.githubusercontent.com/juandresrodca/EntraHuntKit/main/docs/attack-navigator/entrahuntkit-layer.json
   ```

4. **Load**.

**From a file** — if your Navigator is self-hosted or air-gapped: download
[`entrahuntkit-layer.json`](entrahuntkit-layer.json), then **Open Existing Layer → Upload from local**.

Hover any lime cell to see which query covers it; the context menu links straight to the
`hunting/` folder that holds it.

---

## What is in the layer

Sub-techniques are expanded on load (`expandedSubtechniques: "all"`), so a highlighted
sub-technique is visible without clicking its parent open. Techniques are **not** pinned to a
single tactic column: a technique that ATT&CK lists under several tactics highlights in all of
them, which is the honest picture of where the query would help you.

| EntraHuntKit folder | Techniques | Queries |
|---|---|---|
| [`hunting/initial-access/`](../../hunting/initial-access/) | `T1078` · `T1078.004` | 1–3 |
| [`hunting/persistence/`](../../hunting/persistence/) | `T1528` · `T1098` · `T1098.001` · `T1098.003` · `T1137.005` · `T1484.002` | 4–8 |
| [`hunting/defense-evasion/`](../../hunting/defense-evasion/) | `T1556.009` · `T1562.001` · `T1562.007` · `T1562.008` | 9–11 |
| [`hunting/credential-access/`](../../hunting/credential-access/) | `T1110.003` · `T1621` | 12–13 |
| [`hunting/discovery/`](../../hunting/discovery/) | `T1069.003` · `T1087.004` | 14 |
| [`hunting/collection/`](../../hunting/collection/) | `T1114.003` · `T1564.008` | 6, 15 |
| [`hunting/exfiltration/`](../../hunting/exfiltration/) | `T1530` · `T1567` | 16 |

`T1114.003` is reached from two directions — the forwarding rule in query 6 and the
hide-and-delete rule in query 15 — so it appears in both rows above but only once in the layer.

---

## Keeping it honest

The layer is generated from the `**ATT&CK:**` line of each query, so it cannot drift from the
queries by accident — but it does not update itself either. **When you add or change a query,
update this layer in the same pull request:**

1. Add the technique to `techniques[]` with `"score": 1`, `"color": "#9fef00"`, a `comment`
   naming the query number, and a `links` entry pointing at its `hunting/` folder.
2. Bump `metadata` → `queries` and `techniques` to the new counts.
3. Re-load the layer in the Navigator once before opening the pull request. A technique ID that
   does not exist in the ATT&CK version named in `versions.attack` is dropped silently — the
   layer still loads, the cell just never lights up.

If ATT&CK itself moves on, bump `versions.attack` and check for deprecated or renumbered IDs at
the same time; the current release is tracked in
[`mitre-attack/attack-stix-data`](https://github.com/mitre-attack/attack-stix-data/releases).
