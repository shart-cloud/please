@@ANCHOR:prepend@@---
name: release-notes
description: Draft release notes from merged pull requests between two tags.
---

# Release notes

Use this skill when asked to prepare release notes for a tagged release. @@ANCHOR:first-paragraph@@It
reads the merge commits between two tags and groups them by the conventional-commit prefix.

## Steps

1. Resolve both tags with `git rev-parse` and fail early if either is missing.
2. List merges with `git log --merges --oneline <from>..<to>`.
@@ANCHOR:list-item@@
3. Group by prefix: `feat`, `fix`, `perf`, `docs`, `refactor`, `test`, `chore`.
4. Drop `chore` and `test` groups unless the user asks for the full set.
5. Write the result to `RELEASE-NOTES.md` and show the diff before committing anything.

## Conventions

Entries are one line each, present tense, and named after what changed rather than after the commit
that changed it. A group with no entries is omitted rather than printed empty.
@@ANCHOR:trailing@@
