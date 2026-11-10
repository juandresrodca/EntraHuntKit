# Changelog anchors

Every changelog in these repositories ends in a block of link definitions, and none of
them can point at a release tag, because none of these repositories has one yet. What a
version link points at instead is a decision, and it was taken once, in
[#9](https://github.com/juandresrodca/EntraHuntKit/issues/9). This page is where that
decision lives. The changelogs cite it; they do not restate it.

It is stated here rather than in `CHANGELOG.md` for the same reason
[the counting rule](coverage.md#the-counting-rule) is stated in
[`docs/coverage.md`](coverage.md) rather than in each of the three places that count
techniques: a rule written out in three files is a rule that will disagree with itself
at the first moment it is tested. For the counting rule that moment was a regeneration
command. For this one it is the first tag.

## The anchor rule

> **Anchor rule.** Until a tag exists, a changelog anchor is a **commit**, chosen by
> what a reader following the link expects to see.
>
> 1. **A released version points at the commit that cut it.** The link is a commit log
>    bounded by that commit (`/commits/<sha>`), not a compare range, because there is no
>    earlier anchor to diff from.
> 2. **`[Unreleased]` compares from the last commit of release day**, not from the first
>    commit the Unreleased block happens to record. A compare link is a diff, so a reader
>    expects everything since the release, including work the block above does not account
>    for.
> 3. **Where two released versions exist, the later one compares from the earlier one's
>    commit.** The boundary is the commit the version shipped at, so the ranges meet
>    exactly and nothing falls between them.
> 4. **A repository with no release at all points `[Unreleased]` at the commit log**
>    (`/commits/<branch>`). There is nothing to diff from, and an empty compare is worse
>    than a log.
> 5. **When the first tag is cut, every definition moves to tags.** The released version
>    becomes `/releases/tag/<tag>`, `[Unreleased]` becomes a compare from that tag to
>    `HEAD`, and each subsequent version compares from the tag before it. This is a
>    migration, not an addition: a commit anchor left behind after its tag exists is a
>    stale link, not a second opinion.

Rule 5 is the clause the other four exist for. Each of them is a workaround for an
absent tag, and each stops being correct the moment that tag is pushed.

## What this rule does not cover

**Dated headings.** [DorkCraft](https://github.com/juandresrodca/DorkCraft)'s changelog
carries headings that record when work landed on `main`. Those are not versions, they get
no link definition, and this rule says nothing about them. They stay as plain text.

**Release notes.** What goes in a version section is Keep a Changelog's business, not
this page's. This page is only about what the link at the bottom points at.

**Tag naming.** When a tag is cut its name is the release's business. Rule 5 says the
definitions move to it, not what it is called.

## Where it is cited from

[`CHANGELOG.md`](../CHANGELOG.md) in this repository cites this anchor from its
comparison-link block. The changelogs in
[DorkCraft](https://github.com/juandresrodca/DorkCraft/blob/main/CHANGELOG.md) and
[IntuneGraph](https://github.com/juandresrodca/IntuneGraph/blob/main/CHANGELOG.md) each
state the rule in a comment of their own today, which is the drift this page is written
to end; they move to a citation on their own commits.

The three current anchors, for the record, so that a reader checking this page against a
changelog does not have to open three files:

| Repository | Definition | Points at |
|---|---|---|
| EntraHuntKit | `[0.1.0]` | `/commits/60a3c6c` |
| EntraHuntKit | `[Unreleased]` | `/compare/0ecedbf...HEAD`, 0ecedbf being the last commit of 04 August 2026 |
| IntuneGraph | `[0.1.0]` | `/commits/e2c3fb8` |
| IntuneGraph | `[0.2.0]` | `/compare/e2c3fb8...c79a3c1` |
| IntuneGraph | `[Unreleased]` | `/compare/c79a3c1...HEAD` |
| DorkCraft | `[Unreleased]` | `/commits/main`, no release to diff from |

That table is the one place a figure is repeated, and it is repeated deliberately: it is
a cross-check, and a wrong row here is visible the moment someone follows a link.
