# Review checks

Run every check against every added or changed test. Each check names
what to look at, what counts as a finding, and its severity. A finding
from items 1 to 5 needs a spec citation (RFC, section, cache line)
and a one-line quote; a finding from items 6 and 7 needs the pynfs
file and line that establishes the fact (the other `CODE:` line, the
`createtests` line in `nfs4.1/testmod.py`, the maketree line, or for
item 7's third bullet the raising test line plus the `unsupported()`
or `fail_support` definition it should have used). Without either it
is a question for the author, not a finding.

Severity: **fail** means the test would fail a conformant server,
pass a non-conformant one, or stop the suite from loading
(`createtests` in `nfs4.1/testmod.py` raises on a duplicate code, a
`DEPEND:` that does not resolve, or a flag that is also a code).
**warn** means it is fragile or
unidiomatic. **note** means a suggestion. A defect the commit inherits
from code it copies, or inside a function it modifies, keeps the
severity its effect earns; say that it predates the commit. A defect
in an unchanged function in the same file is out of scope; if it is
the same defect a finding reports, mention it in one line in part 3. Where an item's stated severity and
these definitions disagree, the definitions win.

pynfs result classes, from `testmod.py`: a test **passes** when it
returns; **warns** on `WarningException` (what `warnlist` and
`t.pass_warn(...)` raise);
reports **unsupported** on `UnsupportedException` (`unsupported()`,
`t.fail_support()`), which means "the server lacks an optional
feature" and is not a failure; **fails** on `FailureException`. A
test that routes a status the spec forbids into the unsupported class
passes a non-conformant server; report it at severity fail.

## 1. The assertion matches the requirement level

Look at every `check(res, STAT)`, `check(res, [STATS])`, `t.fail(...)`,
and `fail(...)` after a compound. `warnlist` belongs to the `check` in
each suite's `environment.py`; the `nfs4lib.check` variant takes no
`warnlist`, so a test importing that one needs a status list instead.

- A hard expectation of a status or a result value must trace to a
  requirement in the operation's DESCRIPTION, an error definition, or
  a state-management section: a MUST, MUST NOT, or REQUIRED, or a
  declarative sentence that states what the server does ("If a
  duplicate exists, NFS4ERR_EXIST is returned", "the server checks
  ..."). RFC 8174 sec 2 says normative text does not require the key
  words, and 7530 and 8881 state many requirements without them.
  SHOULD, MAY, "is free to", and IMPLEMENTATION advice are the weaker
  forms handled below.
- A SHOULD or RECOMMENDED behavior may be asserted only through
  `warnlist=[...]` or a status list that also accepts the
  non-recommended outcome, or after an earlier compound in the same
  test function, checked with `check`, returned a result that shows
  the server performs the recommended behavior, or has checked an
  advertised capability (RFC 9754 sec 3 attributes, EXCHANGE_ID
  flags, `SEQ4_STATUS_*`). Delegation grants are not observed this
  way; item 4 gives their only pins. A loop or sleep that reissues an operation until
  it succeeds is a retry, not an observation, whatever it waits for;
  the backchannel probe is the common case. When accepting this, name
  the observing line in the part 2 entry.
- A MAY, OPTIONAL, or "the server is free to" behavior cannot be a hard
  expectation at all. The test should accept both outcomes or branch.
- Judge the requirement by its words, not by the subsection title.
  IMPLEMENTATION subsections are mostly advice, but they also state
  requirements, with or without key words (8881 sec 18.9.4 requires
  NFS4ERR_XDEV for a named-attribute LINK with a MUST, and for a
  cross-file-system LINK with "the error NFS4ERR_XDEV is returned").
  A MUST, or an unhedged declarative sentence stating what the server
  does whose error appears in the op's valid-errors row, backs a hard
  expectation from IMPLEMENTATION. A hedged sentence ("may",
  "typically", "should", "is free to", "it is expected that") is
  advice and cannot be the sole basis for one.

Finding (fail): hard assertion backed only by SHOULD, MAY,
IMPLEMENTATION advice, or nothing. Suggest the status list or warnlist
form and cite the governing sentence.

## 2. The error code is one the operation may return

For each `NFS4ERR_*` expected:

- It appears in the valid-errors table for that operation (8881 sec
  15.2, 7530 sec 13.2, 7862 sec 11.2, 8276 sec 8.4.5), or a later RFC
  adds it.
- When two errors both apply, the test accepts both unless a sentence
  in the op's DESCRIPTION, the error definition, 16.2.3, or 8.2.4 says
  which is returned first. The order errors appear in a section is not
  an ordering. If no such sentence exists, precedence is undecidable:
  that is the warn finding below, never the fail. Stateid errors: 8881
  sec 8.2.4 lists the BAD_STATEID checks first and the OLD_STATEID
  seqid check last, and does not mention STALE_STATEID; quote the
  bullet that applies rather than this summary. For 4.0 read 7530 sec
  9.1.4 before asserting any order. Session errors precede op errors
  because SEQUENCE is evaluated first (8881 sec 18.46).
- The failing operation is the one the test thinks it is. `check`
  names the last op in `resarray`; a compound that fails earlier
  reports an earlier op.

- A status list is a tolerance, but every member must still be valid
  for the op. A list that includes an error the table omits, or that
  an error definition says the op MUST NOT return, lets a
  non-conformant server pass.
- The same rules apply to result-reason enums, not only statuses:
  `why_no_delegation4` (`WND4_*`), `nfs_lock_denied`, layout and copy
  result codes. When two reasons apply at once and the spec does not
  order them, the test accepts both or states a pin. 8881 sec 18.49.3
  says outright that with multiple conditions "the server MAY return
  any of the mandated error codes".

Finding (fail): expected error not valid for the op, a list member the
op cannot return, or a precedence that one of the four places named
above (this op's DESCRIPTION, the error's definition, 16.2.3, 8.2.4)
states as a requirement under item 1's rule (a MUST, or a declarative
sentence such as "X is returned", "the server will return X", "X is
to be returned") and that the test contradicts. An ordering sentence
found elsewhere, or using SHOULD, MAY, or hedged wording, or the mere
order in which errors are listed, does not decide precedence.
Finding (warn): two errors or
reasons both plausible and the test accepts only one, with no such
sentence choosing.

## 3. The test sits in the right minor version

- Directory decides the version: `nfs4.0/servertests` is 4.0 only;
  `nfs4.1/server41tests` runs at the minor version the runner's
  `--minorversion` option selects (default 2 in `nfs4.1/testserver.py`),
  which `environment.py` passes to `NFS4Client` and every COMPOUND
  uses unless a call overrides it. `new_client()` and
  `create_session()` do not negotiate the minor version. A test that
  needs 4.2 carries `VERS: 2-` (as `st_xattr.py` does); without it
  the test runs under `--minorversion 1` and fails a conformant 4.1
  server. When every neighbouring 4.2 test in the file also omits it,
  say so; the fix may belong at file level. One that must not run at
  4.2 needs `VERS:` too. `nfs4.1/testclient.py` has no
  `--minorversion` option, so this rule does not apply to
  `nfs4.1/client41tests`.
- An op, flag, attribute, or error introduced in 4.1 or 4.2 is not
  tested from a lower version. 8178 sec 8 covers interaction rules.
- Ops 8881 says MUST NOT be implemented in 4.1 (OPEN_CONFIRM,
  RELEASE_LOCKOWNER, RENEW, SETCLIENTID, SETCLIENTID_CONFIRM) are only
  tested in 4.1 for the NOTSUPP response.

Finding (fail): version mismatch.

## 4. State, sequencing, and session rules

- 4.1 compounds begin with SEQUENCE unless the only operation is one
  of BIND_CONN_TO_SESSION, EXCHANGE_ID, CREATE_SESSION,
  DESTROY_SESSION, or DESTROY_CLIENTID (8881 sec 18.46.3, 18.50.3).
  The pynfs `sess.compound()` helper adds SEQUENCE; a raw
  `c.compound()` does not.
- Stateid seqid handling: the test uses the stateid the server
  returned, not a stale copy, unless staleness is what it tests.
  `makeStaleId` and `makeBadID` exist for that.
- 4.0 OPEN confirmation (`nfs4.0/servertests` only): a first open by
  a new owner needs OPEN_CONFIRM when `OPEN4_RESULT_CONFIRM` is set
  (7530 sec 9.1.11). The client method `c.create_confirm()` in
  `nfs4.0/nfs4lib.py` handles it; a raw open that skips it is a
  finding. The same-named helper under `nfs4.1/` does not confirm,
  because 4.1 has no OPEN_CONFIRM.
- Lease and courtesy: a test that expects expiry must wait at least a
  lease period from the client's last renewing operation (8881 sec 8.3)
  or use the server helper that forces expiry; a test that expects a
  courtesy client to survive must not assume a duration the spec does
  not give (8881 sec 8.4.3, 7530 sec 9.6.3).
- Delegations and wants: `OPEN4_SHARE_ACCESS_WANT_*` flags are a
  request, and the server MAY ignore them; only the returned
  `delegation_type` and `why_no_delegation` are facts (8881 sec
  18.16.3, 18.49.3). The spec never requires a grant. The 4.1 suite
  accepts that by convention: a `server41tests` test whose `FLAGS:`
  line names a delegation flag (any flag containing `deleg`; confirm
  with `grep -rhoE 'FLAGS: .*' nfs4.1/server41tests | tr ' ' '\n' |
  grep -i deleg | sort -u`, run only against that directory, since the
  4.0 flag `delegations` also matches) hard-requires a grant so that
  the delegation path gets
  exercised at all, and the flag is the stated pin. Do not report a
  required grant in such a test. The 4.0 suite does not share the
  convention: its `FLAGS: delegations` tests go through `_get_deleg`
  in `st_delegation.py`, which calls `t.pass_warn` when no grant
  arrives, so a 4.0 test that hard-requires one is a fail. A
  required *refusal* (a hard `NONE_EXT` with a specific `WND4_*`
  reason, or a refusal keyed to mode bits, open state, or backchannel
  state) is different: the spec does not require it either, and the
  flag does not cover it, so it needs its own one-sentence pin in the
  docstring or a status that accepts the grant.
- Callbacks: a test that expects a CB_RECALL or CB_NOTIFY must allow
  the server its own timing and must not fail on a conflicting-access
  path the spec lets the server resolve by revoking instead.

Finding (fail) when the test depends on a sequence the spec does not
guarantee; (warn) when the test open-codes a sequencing rule a helper
enforces (OPEN_CONFIRM via `c.create_confirm()`, SEQUENCE via
`sess.compound()`) and gets it wrong or fragile. Open-coded client
and session setup is not this; see false-positives.md.

## 5. XDR fidelity

For any change to a `.x` file (`nfs4.1/xdrdef/`, `rpc/`,
`nfs4.0/lib/rpc/` including `rpcsec/`):

- Field order, types, array bounds, union discriminants and arms, and
  constant values match the RFC XDR (7531, 5662, 7863, 8276 sec 7.2,
  8435 sec 3, 5663 sec 2, 5531 sec 9) character for character apart
  from comments and whitespace.
- A new enum or const value matches the IANA-assigned number the RFC
  gives; no locally invented values.
- Optional data (`*` pointer syntax, 4506 sec 4.19) is not rewritten as
  a variable-length array with a bound other than 1, which changes the
  encoding. 4506 sec 4.19 defines `identifier<1>` as equivalent.
- For a test that hand-builds a wire message (`st_spoof.py`,
  `st_badxdr`-style tests), the deliberately bad encoding is the one the
  comment claims, and the expected error is NFS4ERR_BADXDR or the
  RPC-level reply the spec requires (5531 sec 9 GARBAGE_ARGS).

Finding (fail) on any mismatch with the RFC XDR.

## 6. Test metadata

- `CODE:` present, exactly one, unique among the tests the same
  suite loads (`createtests(testdir)` in `testmod.py` builds one code
  table per suite, so `nfs4.0/servertests` and
  `nfs4.1/server41tests` may reuse a code). Verify with
  `grep -rn 'CODE: XYZ' <testdir>`.
- `FLAGS:` words are existing flags in that tree (`grep -rhoE
  'FLAGS: .*' <testdir> | tr ' ' '\n' | sort -u`) or deliberately new
  ones the commit message explains. Every test should carry the flag
  for the operation it exercises and usually `all` (note when
  missing; `createtests` adds `everything` itself).
- `DEPEND:` tokens each resolve, the way `testmod.py` resolves them,
  to a code in the loaded suite or to a callable in the test's module
  whose boolean result gates the test (`_using_gss` in
  `nfs4.0/servertests/st_gss.py` is one). The dependency is real: the
  named test's outcome or the predicate is a prerequisite. Sharing
  created state is not required.
- `VERS:` only when the test is restricted to a minor-version range.
- Docstring first line is a short description; testmod uses it as the
  test's one-line summary.

Finding (fail) for a duplicate or missing CODE, a `DEPEND:` token that
does not resolve, or a `FLAGS:` word that is also a code (all raise
in `createtests`); (warn) for a `FLAGS:` word that exists nowhere
else in the tree and that neither the commit message nor the test's
docstring or a comment in the diff introduces; with no commit message
yet, ask in part 3 whether the new flag is intended.

## 7. Environment coupling and cleanup

- Objects the test needs from `--maketree` (`env.opts.usefile`,
  `env.home`, special files) are the ones maketree creates.
- State the test creates (clients, sessions, opens, locks,
  delegations, files) is released or removed, or the test is written
  so that a leftover cannot make a later test fail. Use the existing
  helpers (`close_file`, `clean_dir`, `env.c1.new_client` with a
  per-test name via `env.testname(t)`).
- A test that needs a server option (expiry helper, a specific export,
  a uid) says so in its docstring and uses `unsupported()` or a flag
  rather than failing when it is absent.

Finding (warn), except the third bullet: a test that fails rather than
reports unsupported when the option is absent fails a conformant
server, so that is a fail.

## 8. Spec citation in the test

A non-obvious expectation benefits from a comment naming the RFC and
section. Finding (note) when the reviewer had to dig to confirm an
expectation the test states without a pointer.
