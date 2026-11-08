# Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
# Security Write-ups by Adekunle Akeju, created by Adekunle Akeju. SPDX-License-Identifier: CC-BY-SA-4.0
import importlib.util
import pathlib

_path = pathlib.Path(__file__).parents[1] / "scripts" / "check_writeup.py"
_spec = importlib.util.spec_from_file_location("check_writeup", _path)
checker = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(checker)

GOOD = """# Sample

*Report by Adekunle Akeju.*

Status: Retired on 2026-01-01

## Executive summary
x
## Findings
x
## Attack path
x
## Remediation
x
## What I learned
x
"""


def test_complete_report_passes():
    assert checker.check(GOOD) == []


def test_untouched_template_fails():
    template = (pathlib.Path(__file__).parents[1] / "TEMPLATE.md").read_text(encoding="utf-8")
    assert any("placeholders" in p for p in checker.check(template))


def test_missing_section_fails():
    assert checker.check(GOOD.replace("## Remediation", "## Other"))


def test_active_target_fails():
    assert checker.check(GOOD.replace("Retired on", "Started on"))


def test_flags_and_hashes_are_blocked():
    for secret in ["d41d8cd98f00b204e9800998ecf8427e", "HTB{s3cret}", "flag{abc}", "$6$abcdefghijkl$mnop"]:
        assert any("redact" in p for p in checker.check(GOOD + secret)), secret


def test_folder_run(tmp_path):
    assert checker.main(str(tmp_path)) == 0
    (tmp_path / "bad.md").write_text("nothing")
    assert checker.main(str(tmp_path)) == 1
