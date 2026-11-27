# Spec map: where each pynfs subject is specified

All files are plaintext under `$PYNFS_RFC_DIR` (default
`~/Documents/rfcs`), named `rfcNNNN.txt`. Section headings sit at
column 0 as `N.N.  Title`. Find a section with grep, then read only
that range. Never read a whole file; RFC 8881 is ~32k lines.

## Lookup recipes

Operation chapter (protocol RFCs):

```
grep -nE '^[0-9.]+  Operation [0-9]+: OPEN ' rfc8881.txt
grep -nE '^18\.16\.[0-9]+\.  ' rfc8881.txt        # ARGUMENTS, RESULTS, DESCRIPTION, IMPLEMENTATION
```

Error definition:

```
grep -nE '^[0-9.]+  NFS4ERR_DELAY ' rfc8881.txt    # 15.1.1.3.  NFS4ERR_DELAY (Error Code 10008)
```

Valid errors for an operation (table rows; read the block that begins
at the row):

```
grep -nE '^     \| OPEN  ' rfc8881.txt            # inside 15.2
```

Attribute definition:

```
grep -nE '^5\.8\.[0-9.]+  Attribute [0-9]+: ' rfc8881.txt
```

XDR definition:

```
grep -nE 'struct OPEN4args|union open_claim4|const OPEN4_' rfc5662.txt
```

Two sections most 4.1 state tests need:

```
grep -nE '^16\.2\.3\.1\.2\.  ' rfc8881.txt    # current stateid rules and Figure 6
grep -nE '^8\.2\.4\.  ' rfc8881.txt           # stateid validation: BAD_STATEID checks, then the OLD_STATEID seqid check
```

Read the hit with `sed -n 'A,Bp'` where A is the heading hit and B is
the line before the next heading at the same or higher level, for
example the DESCRIPTION heading through the line before
IMPLEMENTATION. Quote the governing sentence in the finding.

`$PYNFS_RFC_DIR` does not persist between shell commands in most
agent harnesses. Resolve it once into a literal path and use that
path in every later command.

## Which document is authoritative

| Minor version or area | Protocol | XDR | Notes |
|---|---|---|---|
| NFSv4.0 | RFC 7530 | RFC 7531 | Obsoletes 3530. Tests under `nfs4.0/servertests/`. |
| NFSv4.1 | RFC 8881 | RFC 5662 | Obsoletes 5661; 8881 restructures it and applies erratum 2006, with other errata deferred (8881 sec 1.1), so cite 8881 and read 5661 only if a test comment cites it. Tests under `nfs4.1/server41tests/` and `nfs4.1/client41tests/`. |
| NFSv4.2 | RFC 7862 | RFC 7863 | 4.2 ops are tested from `server41tests` with `--minorversion 2` selected (the default). |
| Extended attributes (4.2) | RFC 8276 | 8276 sec 7.2 | GETXATTR, SETXATTR, LISTXATTRS, REMOVEXATTR; sec 8.3 new error definitions, sec 8.4 ops, sec 8.4.5 valid errors. `st_xattr.py`. |
| OPEN extensions (4.2): offline files, OPEN_XOR_DELEGATION, READ_ATTRS_DELEG, time proxying | RFC 9754 | 9754 sec 6 | Sec 3 feature probing, sec 4 open-or-delegation grant, sec 5 proxied times. Used by delegation and WANT tests. |
| Minor versioning rules | RFC 8178 | | What a minor version may add or change; `VERS:` questions. |
| pNFS file layout | RFC 8881 ch 12, 13 | RFC 5662 | `st_getdevicelist.py`, layout tests. |
| pNFS flexible files | RFC 8435 | 8435 sec 3 | `st_flex.py`. |
| pNFS block layout | RFC 5663 | 5663 sec 2 | `st_block.py`, `xdrdef/pnfs_block.x`. |
| Layout type requirements | RFC 8434 | | What any layout type must provide. |
| RPC-with-TLS | RFC 9289 | | AUTH_TLS probe and policy. |
| ONC RPC v2 | RFC 5531 | 5531 sec 9 to 12 | `rpc/rpc.x`. Record marking is sec 11. |
| RPCSEC_GSS | RFC 2203, 5403 | | `rpc/gss.x`, `st_gss.py`. Fetch if absent. |
| XDR language and encoding | RFC 4506 | | Padding, discriminated unions, optional data (sec 4.19). |
| NFSv3 and MOUNT helpers | RFC 1813 | 1813 | `xdrdef/nfs3.x`, `mnt3.x`; only the setup helpers use these. |
| NFSv2 | RFC 1094 | | Legacy; rarely relevant. |

## Section numbers that come up constantly

An empty cell means that document itself has no section for the
subject. For a 4.0 test, an empty 7530 cell means the subject does
not exist in 4.0; do not read 8881 for it. For a 4.1 test, likewise
with 8881. For a 4.2 test, RFC 7862 only amends 8881, so an empty
7862 cell means 4.2 left the 4.1 text unchanged: read the 8881 cell.
A non-empty 7862 cell is read first and 8881 second.

| Subject | RFC 7530 (4.0) | RFC 8881 (4.1) | RFC 7862 (4.2) |
|---|---|---|---|
| Error definitions | 13.1 | 15.1 | 11.1 |
| Operations and their valid errors (table) | 13.2 | 15.2 | 11.2 |
| Callback ops and valid errors | 13.3 | 15.3 | 11.3 |
| Errors and the ops that use them | 13.4 | 15.4 | |
| COMPOUND procedure, evaluation order | 15.2 | 16.2 | |
| Forward operations | 16.x | 18.x | 15.x (new), 14.x (modified 4.1 ops) |
| Callback operations | 18.x | 20.x | 16.x |
| REQUIRED / RECOMMENDED attributes | 5.1, 5.2, 5.6, 5.7 | 5.1, 5.2, 5.6, 5.7 | 12 (new attrs) |
| Attribute definitions | 5.8 | 5.8 | 12 |
| Named attributes, OPENATTR | 5.3 | 5.3 | |
| ACLs | 6 | 6 | |
| Filehandles, volatile FH, FHEXPIRED | 4 | 4 | |
| Client ID, SETCLIENTID, seqid rules | 9.1.1 to 9.1.3 | | |
| Stateid definition and validation | 9.1.4 | 8.2 (8.2.4 lifetime and validation; 8.2.3 special stateids) | |
| Stateid seqid and byte-range locks | 9.1.7 to 9.1.9 | 9.4 | |
| Lock-owner state lifetime, RELEASE_LOCKOWNER, new_lock_owner rule | 9.1.10, 16.10.5, 16.37 | 8.8 (obsolete in 4.1) | |
| Current filehandle and current stateid in COMPOUND | 15.2.4 | 16.2.3.1 (16.2.3.1.2 current stateid, Figure 6) | |
| OPEN confirmation (4.0 only) | 9.1.11, 16.18 | 8.8 says obsolete | |
| Lease renewal | 9.5 | 8.3 | |
| Server reboot, grace, reclaim | 9.6.2 | 8.4.2 | |
| Network partition, courtesy, lock revocation | 9.6.3, 9.8 | 8.4.3, 8.5 | |
| Share reservations, OPEN/CLOSE, upgrade and downgrade | 9.9 to 9.11 | 9.7 to 9.9 | |
| Blocking locks | 9.4 | 9.6 | |
| Open delegation, recall, CB_RECALL | 10.4, 10.2 | 10.4, 10.2 | |
| Directory delegations, CB_NOTIFY | | 10.9, 18.39, 20.4 | |
| WANT_DELEGATION, CB_PUSH_DELEG, CB_WANTS_CANCELLED | | 18.49, 20.5, 20.10, and OPEN 18.16.3 for `OPEN4_SHARE_ACCESS_WANT_*` | |
| Sessions: slots, EOS, replay cache | | 2.10.6 | |
| Session recovery and SEQUENCE status flags | | 2.10.13, 18.46 | |
| Trunking, server scope | | 2.10.4, 2.10.5, 18.35 | |
| EXCHANGE_ID flags and owner matching | | 18.35 | 14.1 (4.2 changes) |
| CREATE_SESSION, channel attrs, backchannel | | 18.36, 18.33, 18.34 | |
| RECLAIM_COMPLETE | | 18.51 | |
| TEST_STATEID, FREE_STATEID | | 18.48, 18.38 | |
| DESTROY_CLIENTID, DESTROY_SESSION | | 18.50, 18.37 | |
| SECINFO, SECINFO_NO_NAME | 16.31 | 18.29, 18.45 | |
| pNFS layout semantics and recall | | 12.5, 20.3 | |
| Server-side COPY, COPY_NOTIFY, OFFLOAD_* | | | 4, 15.2, 15.3, 15.8, 15.9, 16.1 |
| Sparse files: READ_PLUS, SEEK, ALLOCATE, DEALLOCATE | | | 6, 7, 15.10, 15.11, 15.1, 15.4 |
| CLONE | | | 15.13 |
| Labeled NFS | | | 9 |
| Internationalization and UTF-8 errors | 12 (12.7 errors) | 14 | |

## Document conventions to know

- 8881 section 15.2 lists which errors each op may return. An
  `NFS4ERR_*` a test expects but the table omits is a finding unless a
  later RFC adds it (7862 sec 11.2, 8276 sec 8.4.5).
- Error precedence: 8881 has no single ordering table. Use the
  operation's DESCRIPTION, 15.1 definitions, the COMPOUND rules in
  16.2.3 (evaluation stops at the first failing op; 16.2.3.1.2 for the
  current stateid), and the stateid validation order in 8.2.4. 7530 has
  the same in 15.2.4 and 9.1.4.
- `check(res, [A, B])` in pynfs accepts either status. When the spec
  permits more than one outcome, that list is the correct assertion.
- Capitalised MUST, SHOULD, MAY carry RFC 2119 meaning in all these
  documents, but a requirement does not need them (RFC 8174 sec 2): a
  declarative sentence in a DESCRIPTION, an error definition, or a
  state-management section stating what the server does is normative.
  Only SHOULD, MAY, and hedged advice are weaker.
- Each operation chapter ends with an IMPLEMENTATION section. It is
  mostly advisory; a test cannot require what only IMPLEMENTATION
  suggests, but a requirement stated there, with or without a key
  word, is still a requirement (checks.md item 1).
