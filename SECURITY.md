# Security Policy

EntraHuntKit ships no executable code. It ships **detection logic and indicators that
defenders paste into a production tenant**, which is its own kind of security surface:
a wrong query wastes an incident, and a wrongly listed indicator accuses an innocent
app. This policy covers both, and how to get either fixed.

## Reporting a problem

**Do not open a public issue for anything that names a real, non-public tenant,
identity, IP or campaign.**

Report privately through GitHub:
[Security → Report a vulnerability](https://github.com/juandresrodca/EntraHuntKit/security/advisories/new).
If private reporting is unavailable to you, email **juandresrodca@gmail.com** with
`EntraHuntKit security` in the subject.

Everything else — a query that throws a schema error, a tuning threshold that is too
noisy, a broken link — is a normal [issue](https://github.com/juandresrodca/EntraHuntKit/issues),
and public is better for those.

What to expect:

| Stage | Target |
|---|---|
| Acknowledgement | 72 hours |
| Assessment | 7 days |
| Correction or documented caveat | 30 days; an indicator dispute is handled first (see below) |
| Credit | given unless you ask otherwise |

This is a personal open-source project maintained outside working hours. There is no
bug bounty; there is a genuine commitment to answering you.

## What counts as a security problem here

Three things, in descending order of how badly they hurt an analyst:

**1. A false indicator.** An app ID, domain or pattern in [`ioc/`](ioc/) that names
something benign. This is the most damaging failure mode in the repo — it can put a
legitimate SaaS vendor on a block list at a customer site. Reports of these are
actioned ahead of everything else. See *Disputing an indicator* below.

**2. A query that is silently wrong.** One that runs clean and returns nothing when the
behaviour it claims to catch *is* present — a wrong column, a filter that excludes the
true positives, an operator precedence bug. An analyst reads an empty result as "we are
not compromised". A query that errors loudly is a bug; a query that lies quietly is a
security problem.

**3. A query that is unsafe to run.** Anything here should be read-only telemetry.
A contribution that mutates state, exfiltrates results to a third party, or is expensive
enough to exhaust a workspace's ingestion or query quota is out of scope for this repo
and will be removed.

## Indicator sourcing policy

Every entry in [`ioc/`](ioc/) falls into one of two buckets, and the file says which:

- **Recognition references** — legitimate Microsoft first-party app IDs and normal
  patterns, listed so you can recognise them in a hunt. These are explicitly *benign*.
  Alert on the context around them, never on the ID alone.
- **Confirmed-malicious entries** — accepted only with a citation: a public report, a
  vendor advisory, or a described IR case. As [CONTRIBUTING.md](CONTRIBUTING.md) puts
  it, PRs adding "known-bad" indicators without a source are rejected. Accuracy over
  volume.

No indicator in this repo is derived from a customer tenant, and none should be
contributed from one. If your only evidence is a client's telemetry, publish the
generalised behaviour — the scope combination, the rule shape, the sending pattern —
not their data.

## Disputing an indicator

If you own or operate an application, domain or service listed in [`ioc/`](ioc/) and
believe the listing is wrong or out of date:

1. Open a private report (link above) with `IOC dispute` in the subject, naming the
   indicator and the file it appears in.
2. Say what the entry gets wrong: never malicious, previously compromised and since
   remediated, or a shared identifier that also covers legitimate use.
3. You do not need to prove a negative. The burden sits with the citation that put the
   entry there — if it does not hold up, the entry goes.

Target: **72 hours to acknowledge, 7 days to resolve.** A disputed entry is annotated
as disputed while it is being reviewed, so anyone reading the list in the meantime sees
the doubt. Removals are recorded in [CHANGELOG.md](CHANGELOG.md) with the reason, and
the entry is not re-added without new, stronger sourcing.

## The part that is on you

- **Tune before you alert.** Every query carries a false-positive note because the
  thresholds are starting points against a generic baseline, not yours. Wiring an
  untuned query straight to an automated response is how a hunt becomes an outage.
- **Run it where you are authorised to run it.** Your own tenant, or one you have
  explicit permission to defend. See *Authorized use only* in the
  [README](README.md#authorized-use-only).
- **Do not paste tenant data into this repo.** Issues, PRs and discussions are public.
  Send counts and shape — "≈40 consent grants/day, 3 spike days" — not UPNs, tenant
  IDs, device names or raw result sets.
- **Check the licence tier before you build on a query.** Each one names the table and
  the tier it needs; a detection you cannot actually run is not coverage.

## Out of scope

- Vulnerabilities in Entra ID, Intune, Defender XDR or Sentinel themselves — report
  those to [MSRC](https://msrc.microsoft.com/report).
- Cost or performance of running a query in your workspace. Query cost is a tuning
  matter; open a normal issue and the query gets a scoping note.
- A query returning false positives at the documented rate. That is what the tuning
  note is for — though if the note is wrong or missing, say so, that is a real bug.
- The [demo console](https://juandresrodca.github.io/EntraHuntKit/demo/), which serves
  static, fictional data and holds no credentials.
