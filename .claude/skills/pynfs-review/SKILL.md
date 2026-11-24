---
name: pynfs-review
description: Use when reviewing a change to pynfs, the NFSv4 test suite, before it is committed or sent as a PR. Triggers on a diff touching nfs4.0/servertests/, nfs4.1/server41tests/, nfs4.1/client41tests/, any .x file under nfs4.1/xdrdef/, rpc/, or nfs4.0/lib/rpc/, or the nfs4lib helpers; on questions like "does this test match the RFC", "is a server required to return this error", "can a conformant server fail this test"; and on any request to check a pynfs test against NFSv4.0, 4.1, or 4.2 specifications or their XDR.
---

# pynfs review

## Overview

pynfs tests assert what an NFSv4 server does. A test is wrong when it
requires behavior the specification does not require, or expects an
error the operation cannot return. This review checks every
expectation in a change against the RFC text in a local plaintext
cache and reports each finding with a quote and a line number.

Spec text is read from the files, never recalled from memory. Python
quality is out of scope here; `/code-review` covers it.

## Workflow

0. **Confirm the tree.** This skill runs inside a pynfs checkout:
   `nfs4.1/testmod.py` and `nfs4.0/servertests/` must exist in the
   working directory. If they do not, try in order: a directory
   given as the argument, `$PYNFS_TREE`, and the tree this SKILL.md
   sits in (walk up from its directory), and use the first that
   contains `nfs4.1/testmod.py`. If none does, say which locations
   were tried and stop; do not review from the diff alone, because
   checks 3, 4, 6, and 7 need the tree. In the tree found, find the
   upstream remote with `git remote -v` (the one pointing at
   linux-nfs/pynfs). Below, UPSTREAM stands for that remote's name;
   substitute it in every command. If no remote points there, use
   `origin` and say so in part 3 of the report.

1. **Resolve the target.** Use the argument if given: a commit, a
   range, a PR number (`gh pr diff N`; if `gh` is unavailable, ask
   for a commit range), or a path. A directory step 0 consumed as the
   tree is not a target; with nothing else given, fall through to the
   no-argument case. With no argument, review the working tree diff
   plus the commits on this branch not on `UPSTREAM/master`
   (`git log --oneline UPSTREAM/master..`). List the files in scope
   before reading any of them.

2. **Locate the RFC cache.** `$PYNFS_RFC_DIR` if set, else
   `~/Documents/rfcs`. Resolve it to a literal path once and use that
   path in every command, since the variable may not survive between
   shell calls. Files are `rfcNNNN.txt`. If a needed file is missing,
   fetch it into that directory and say so in the report:

   ```
   curl -sS -O --output-dir /path/to/rfcs https://www.rfc-editor.org/rfc/rfcNNNN.txt
   ```

   with the resolved cache path in place of `/path/to/rfcs`.

3. **Inventory the diff.** For each added or changed test function
   record: the directory (which fixes the minor version), the
   operations used, every status asserted by `check`, `fail`, or
   `t.fail`, the `warnlist` contents, flags and attributes named
   (`OPEN4_*`, `WANT_*`, `FATTR4_*`, `SEQ4_STATUS_*`, `WND4_*`), the
   `CODE:` and `FLAGS:` lines, and any server pin: an implementation
   name in `FLAGS:` (`ganesha`, `linux`) or a docstring sentence that
   names an implementation as the reason for an expectation ("The
   Linux server only accepts ...", "knfsd returns ..."). For a
   `.x` change record each changed type, field, and constant. Read
   `references/checks.md` now; its items name the sections step 4
   must find.

4. **Map each item to the spec** with `references/spec-map.md`, which
   gives the grep patterns for operation chapters, error definitions,
   valid-error table rows, attributes, and XDR. Grep the cache for
   the heading or identifier, then read only that section with
   `sed -n 'A,Bp'`. The protocol RFCs are 18k to 32k lines; reading
   one whole is a defect in the review.

5. **Apply checks.md** to every item. Before writing a finding, test
   it against `references/false-positives.md`.

6. **Write the report** in the shape `references/report.md` gives:
   findings with citations, then what was verified, then open
   questions and the `/code-review` reminder.

## Citations

A conformance finding (checks.md items 1 to 5) cites `RFC NNNN sec
S.S (rfcNNNN.txt line L)` followed by a quoted sentence copied from
that line. The line is where the quoted sentence starts, found with
`grep -n`. A tree finding (checks.md items 6 and 7) has no RFC text;
it cites the test file and line plus the pynfs line that establishes
the fact: the other `CODE:` line for a duplicate, the `createtests`
line in `nfs4.1/testmod.py` for a load-time rule, the maketree line
for a missing object, and for a test that fails rather than reports
unsupported, the test line that raises on the absent option plus the
`unsupported()` or `fail_support` definition it should have used. A
fail or warn with neither is not reported; it
becomes a question in part 3 of the report. A note needs the test
file and line but no RFC citation.

## Quick reference

Summary only; checks.md is authoritative when they differ.

| Test asserts | Backed only when | Severity and fix |
|---|---|---|
| exactly one status | spec says MUST / MUST NOT / REQUIRED, or states in a declarative sentence what the server does (checks.md item 1) | fail; status list or warnlist |
| a delegation was granted | 4.1: a `deleg` flag in `FLAGS:` (the convention's pin); 4.0: never | fail; add the flag (4.1) or use `_get_deleg` / `t.pass_warn` (4.0); see checks.md item 4 |
| a delegation was refused for a given reason | a one-sentence docstring pin | fail; add the pin or accept the grant in the status list |
| one of several statuses | each is in the valid-errors table for that version (checks.md item 2) | fail; drop the one the op cannot return |
| a callback arrived | spec requires the callback for that event | fail; accept the revocation path as an outcome |
| XDR field or constant | matches RFC XDR exactly | fail; fix the .x |
