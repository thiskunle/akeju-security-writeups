# Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
# Security Write-ups by Adekunle Akeju, created by Adekunle Akeju. SPDX-License-Identifier: CC-BY-SA-4.0
"""Blocks a report that is incomplete or still contains a flag or password hash."""
import pathlib
import re
import sys

REQUIRED = ["## Executive summary", "## Findings", "## Attack path", "## Remediation", "## What I learned"]
SECRETS = {
    "a 32-character flag or MD5 hash": re.compile(r"\b[a-f0-9]{32}\b"),
    "an HTB-style flag": re.compile(r"HTB\{[^}\s]+\}"),
    "a CTF-style flag": re.compile(r"\b(?:flag|ctf)\{[^}\s]+\}", re.I),
    "a password hash": re.compile(r"\$(?:2[aby]|6|5|1)\$[./A-Za-z0-9$]{10,}"),
}
PLACEHOLDER = re.compile(r"\[(?:Machine or challenge name|date|Date|Title|Severity|Score|Technique|Hack The Box, or the CTF's name|Easy, Medium, Hard)\]")


def check(text: str) -> list[str]:
    problems = [f"missing section: {s}" for s in REQUIRED if s not in text]
    if "Adekunle Akeju" not in "\n".join(text.splitlines()[:4]):
        problems.append("author credit missing from the top")
    if "Retired on" not in text and "Ended on" not in text:
        problems.append("does not state that the target is retired or the CTF has ended")
    if PLACEHOLDER.search(text):
        problems.append("template placeholders are still in the report")
    problems += [f"contains {name}; redact it" for name, pattern in SECRETS.items() if pattern.search(text)]
    return problems


def main(folder: str = "writeups") -> int:
    failed = False
    for path in sorted(pathlib.Path(folder).glob("*.md")):
        for problem in check(path.read_text(encoding="utf-8")):
            print(f"{path.name}: {problem}")
            failed = True
    print("Failed." if failed else "OK.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
