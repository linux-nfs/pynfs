#!/usr/bin/env python3
"""Fail if a pynfs JSON report is missing, empty, or records failures.

testserver.py exits 0 whatever the test results, so CI gates on the
report written by --json instead.  The totals and the failing tests
go to the log and, when GITHUB_STEP_SUMMARY is set, to the job
summary on the run page.
"""

import json
import os
import sys


def summarize(data, failed):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a") as f:
        f.write("| tests | failed | skipped | time |\n")
        f.write("|---|---|---|---|\n")
        f.write("| %d | %d | %d | %ds |\n\n" % (
            data["tests"], data["failures"], data["skipped"],
            round(data.get("time", 0))))
        for t in failed:
            f.write("- `%s` %s: %s\n" % (t["code"], t["name"],
                                        t["failure"]["message"]))


def main(path):
    try:
        with open(path) as f:
            data = json.load(f)
    except OSError as e:
        print("no results file: %s" % e)
        return 1

    tests = data.get("tests", 0)
    failures = data.get("failures", 0)
    skipped = data.get("skipped", 0)
    print("%d tests, %d failed, %d skipped" % (tests, failures, skipped))

    if tests == 0:
        print("no tests ran")
        return 1

    failed = [t for t in data.get("testcase", []) if "failure" in t]
    for t in failed:
        print("FAIL %s %s: %s" % (t["code"], t["name"],
                                  t["failure"]["message"]))
    summarize(data, failed)

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
