# What is not a finding

Read this before reporting. Each item below has been a false positive
from a generic reviewer on this codebase.

- **Implementation-defined behavior asserted loosely.** If the spec
  leaves a choice to the server and the test accepts every permitted
  outcome (a status list, a `warnlist`, a branch on the result), there
  is nothing to report. Only a hard assertion of one permitted choice
  is a finding.
- **`warnlist` entries.** These are deliberate tolerances. A status in
  `warnlist` produces a warning result, not a failure, and is how
  pynfs records "the server is within its rights but we would prefer
  otherwise". Do not ask for them to be removed or promoted. The
  entry must still be a status the op may return: apply checks.md
  item 2 to `warnlist` members as to accepted statuses, and report a
  forbidden tolerance.
- **A status list is the assertion.** `check(res, [NFS4ERR_A,
  NFS4ERR_B])` is correct when the spec permits either. Do not ask the
  test to pick one.
- **`check(res)` is the assertion.** A test whose only verification is
  that the compound returned NFS4_OK is testing exactly that. Do not
  report a missing assertion.
- **Implementation-specific expectations behind a flag.** Some tests
  encode behavior a particular server exhibits and are run only when
  the maintainer selects that flag. A test whose `FLAGS:` names the
  implementation is not a finding. A test whose docstring names it but
  whose flags do not: note asking whether a flag should gate it,
  unless that sentence is the per-test refusal pin checks.md item 4
  asks for in a test already under a delegation flag; that pin is
  complete and yields no output. Neither: the finding keeps the severity checks.md gives the unpinned
  assertion (a hard requirement of behavior the spec does not require
  is a fail); suggest the pin or the tolerant status as the fix.
- **Old-fashioned Python.** pynfs predates most modern idioms and
  keeps a consistent style across hundreds of tests. Formatting,
  naming, f-strings, type hints, and similar are out of scope here.
  Tell the user to run `/code-review` for Python quality.
- **Tests that exercise error paths with invalid input.** A test that
  sends a bad stateid, an invalid UTF-8 name, or a malformed XDR on
  purpose is not "buggy input"; check that the expected error is the
  one the spec requires for that input.
- **Duplicated setup code.** Tests open-code client and session
  creation because each test must be independently runnable and
  filterable. Do not suggest fixtures or shared setup.
- **RFC 5661 versus 8881 wording differences.** 8881 obsoletes 5661,
  restructures it, and applies erratum 2006; other errata remain open
  (8881 sec 1.1). A test comment that cites 5661 is not wrong; cite
  8881 in the finding only if the text changed in a way that matters.
- **IMPLEMENTATION sections describing what servers commonly do.** A
  test is not required to accept every behavior IMPLEMENTATION text
  mentions; it is only forbidden from requiring what only that text
  suggests. A requirement stated inside IMPLEMENTATION, with or
  without a key word, is a requirement all the same (checks.md item 1).
- **A grant hard-required under a delegation flag in 4.1.** A
  `server41tests` test under a delegation flag fails when the server
  declines a delegation. That is the suite's long-standing convention
  and the flag is the pin. See checks.md item 4 for which flags
  qualify, why 4.0 is different, and what still needs a per-test pin.
- **Commit-message intent the test does not verify.** When the
  commit message claims the test checks something and the test body
  only does `check(res)`, that is a note asking whether the stronger
  assertion was intended, not a fail. The test is not wrong; it is
  weaker than advertised.
- **A missing test.** Review what the change does, not what it could
  also have covered. A suggestion for an additional case is a note at
  most.
