# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is pynfs?

pynfs is an NFS protocol conformance testing framework written in Python. It tests NFSv4.0 and NFSv4.1/4.2 servers by sending crafted NFS COMPOUND operations over RPC and verifying responses. Tests require a live NFS server with an exported filesystem.

## Build

```bash
# Install dependencies (Fedora)
yum install krb5-devel python3-devel swig python3-gssapi python3-ply
pip install xdrlib3

# Build (generates XDR code from .x files -- must be done before running tests)
./setup.py build
```

Build order matters: xdr → rpc → nfs4.1 → nfs4.0. The top-level setup.py handles this.

## Running Tests

Tests use a **custom test framework** (not pytest). They require a live NFS server.

```bash
cd nfs4.1

# First run: create test directory tree on server
./testserver.py SERVER:/export --maketree -v all

# Run all tests
./testserver.py SERVER:/export -v all

# Run a single test by code
./testserver.py SERVER:/export OPEN1

# Run a flag group
./testserver.py SERVER:/export dirdeleg

# Exclude tests: prefix with "no"
./testserver.py SERVER:/export all nodirdeleg
./testserver.py SERVER:/export dirdeleg noDIRDELEG3

# Run with dependencies auto-resolved
./testserver.py SERVER:/export --rundeps DIRDELEG5

# Skip initial tree cleanup (faster for tests that don't need it)
./testserver.py SERVER:/export --noinit EXID1
```

NFSv4.0 tests work the same way from the `nfs4.0/` directory.

## Architecture

- **`xdr/`** — XDR parser/code generator (`xdrgen.py` uses PLY). Generates `*_const.py`, `*_type.py`, `*_pack.py` from `.x` definition files. These generated files are gitignored.
- **`rpc/`** — Shared RPC client library with AUTH_SYS and RPCSEC_GSS support.
- **`nfs4.1/`** — NFSv4.1/4.2 test suite and utilities. Active development happens here.
- **`nfs4.0/`** — NFSv4.0 test suite. Older codebase with its own copy of rpc/testmod in `lib/`.
- **`nfs4.1/testmod.py`** — The custom test framework engine (discovery, dependencies, execution).
- **`nfs4.1/nfs4client.py`** — NFS4 client implementation built on RPC.
- **`nfs4.1/nfs_ops.py`** — Operation factory (`op.open()`, `op.putfh()`, `op.rename()`, etc.).

## Writing Tests (NFSv4.1)

Tests live in `nfs4.1/server41tests/st_*.py`. Each test is a function:

```python
def testMyFeature(t, env):
    """Describe what this test verifies

    FLAGS: myfeature all
    CODE: MYFEAT1
    DEPEND: MYFEAT0
    """
    sess = env.c1.new_client_session(env.testname(t))
    res = sess.compound([op.putrootfh()])
    check(res)
```

Key conventions:
- Function name starts with `test`, takes `(t, env)`.
- **CODE** (required): unique identifier like `OPEN1`, `DIRDELEG5`.
- **FLAGS**: space-separated group tags. Include `all` for general tests.
- **DEPEND**: test codes that must pass first.
- **VERS**: minor version range (e.g., `1-2`).
- `check(res, NFS4_OK)` is the primary assertion — compares compound result status.
- `t.fail("msg")` signals failure; `t.pass_warn("msg")` for warnings; `t.fail_support("msg")` for unsupported features.
- New test modules must be added to `server41tests/__init__.py`'s `__all__` list.
- Environment helpers in `server41tests/environment.py`: `create_file()`, `open_file()`, `close_file()`, `clean_dir()`, `do_readdir()`, etc.

## Contributing

Patches go to linux-nfs@vger.kernel.org via `git format-patch` / `git send-email`. Commits should be signed off (`git commit -s`). Follow Linux kernel patch submission conventions.

## Notes

- The NFS server under test must allow high-port connections (`insecure` export option on Linux).
- `use_local.py` in each package manipulates `sys.path` so tests can run directly from the source tree without installation.
- Test results are not authoritative protocol statements — consult the RFCs if a server fails a test.
