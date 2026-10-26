"""Runs the test suite and turns each failing test into a GitHub annotation (visible on the PR).

Used by the CI workflow only. Exit code is that of the test run.
"""

import re
import subprocess
import sys

proc = subprocess.run([sys.executable, "-m", "unittest", "discover", "tests", "-v"],
                      capture_output=True, text=True, encoding="utf-8", errors="replace")
output = proc.stdout + proc.stderr
print(output)

for block in re.split(r"\n={60,}\n", output)[1:]:
    head, _, body = block.partition("\n")
    # body: optional docstring, a line of dashes, then the traceback; the error is at its end
    traceback = body.split("-" * 60, 1)[-1].lstrip("-")
    detail = traceback.split("\n" + "-" * 60)[0].strip().splitlines()
    message = " | ".join(line.strip() for line in detail[-6:])  # last lines of the traceback
    message = message.replace("%", "%25").replace("\r", "").replace("\n", " ")[:900]
    print(f"::error title={head.strip()[:120]}::{message}")
sys.exit(proc.returncode)
