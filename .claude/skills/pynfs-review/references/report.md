# Report format

The report has three parts, in this order. Keep part 1 complete
whatever its length. Part 2 is bounded: one line per checked
expectation, grouped by test, or for a `.x` change one line per
changed type, field, or constant with the RFC XDR line it matches.
For a test with many checked expectations, give one line per test
naming the sections read (for example "st_foo.py: 18.16.3, 15.2 OPEN
row, 8.2.4"). No prose between the blocks.

## 1. Findings

Ordered by severity (fail, warn, note), then by file and line. Each
finding is one block, shaped like this. All numbers and quotes in the
examples in this file are placeholders; every value in a report comes
from `grep -n` in the current session.

```
**fail** nfs4.1/server41tests/st_example.py:NNN
  Asserts NFS4ERR_DELAY where the server may also return NFS4ERR_LOCKED.
  RFC 8881 sec S.S.S (rfc8881.txt line NNNNN): "In that case, the
  server MAY return NFS4ERR_DELAY or NFS4ERR_LOCKED."
  Suggest: check(res, [NFS4ERR_DELAY, NFS4ERR_LOCKED])
```

Rules:

- The citation names the RFC, the section number, and the line in the
  cache file where the quoted sentence starts. Every quote is a whole
  sentence copied from the file, not paraphrased and not elided with
  `...`.
- One finding per defect. If the same defect repeats in several tests,
  one finding lists the locations.
- A defect the commit inherits rather than introduces keeps its
  severity and says "predates this commit".
- No fail or warn without a citation. If the reviewer suspects a
  problem but cannot find governing text, it goes in part 3 as a
  question. A tree finding (checks.md items 6 and 7) cites the pynfs
  file and line that establishes the fact in place of the RFC. A note
  needs the test file and line but no RFC citation.

## 2. Verified

A short list of the expectations that were checked and hold. A spec
check cites RFC, section, and cache line in the compact form; a tree
check (checks.md items 6 and 7, or an observing line item 1 accepted)
cites the pynfs file and line that established it, for example
"st_foo.py CODE DELEG99 unique: grep found only st_foo.py:12". This
is how a clean review shows it read the spec rather than finding
nothing to say.
Placeholder example:

```
- st_example.py:NN expects NFS4ERR_DELEG_ALREADY_WANTED on a
  second WANT_DELEGATION for the same file: RFC 8881 sec S.S.S.S
  (rfc8881.txt line NNNNN): "The client has requested a delegation
  when it had already registered that it wants that same delegation."
```

## 3. Open questions and next step

Questions for the author that the spec did not settle, if any.

Then the closing line, whenever the diff touches a `.py` file:

```
Python quality was not reviewed here. Run /code-review on the same
target for that.
```
