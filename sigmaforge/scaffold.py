"""Scaffold a new rule plus its fixture directory.

Creates rules/windows/<name>.yml and tests/fixtures/windows/<name>/ with
tp_/fp_ template fixtures, pre-filled with a fresh UUID and today's date.
The scaffold deliberately does not pass the test gates as-is: the
metadata gate and rule tests fail until the detection logic, description,
FP story, and fixtures contain real content. Adding a rule the wrong way
takes more effort than adding it the right way.

CLI: python -m sigmaforge.scaffold NAME
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import date

from sigmaforge.loader import FIXTURES_DIR, RULES_DIR

RULE_TEMPLATE = """\
title: TODO one line saying what this detects and where
id: {rule_id}
status: experimental
description: |
    TODO at least 40 characters: what attacker behavior this catches, why
    it matters, and which log source (note the Sysmon EventID) sees it.
references:
    - https://attack.mitre.org/techniques/TXXXX/
author: TODO
date: {today}
tags:
    - attack.TODO-tactic
    - attack.tXXXX
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\TODO.exe'
    condition: selection
falsepositives:
    - TODO describe the benign activity that could fire this rule. "Unknown"
      does not pass the metadata gate.
level: medium
"""

TP_TEMPLATE = {
    "_comment": "TODO describe the attack variant this event represents",
    "EventID": 1,
    "Image": "C:\\TODO\\replace-with-real-attack-event.exe",
    "CommandLine": "TODO",
}

FP_TEMPLATE = {
    "_comment": "TODO describe plausible benign activity a naive rule would catch",
    "EventID": 1,
    "Image": "C:\\TODO\\replace-with-real-benign-event.exe",
    "CommandLine": "TODO",
}


def scaffold(name: str) -> int:
    if not name.replace("_", "").replace("-", "").isalnum():
        print(f"error: rule name '{name}' must be alphanumeric with _ or -", file=sys.stderr)
        return 2
    rule_path = RULES_DIR / "windows" / f"{name}.yml"
    fixture_dir = FIXTURES_DIR / "windows" / name
    if rule_path.exists():
        print(f"error: {rule_path} already exists", file=sys.stderr)
        return 1
    rule_path.write_text(
        RULE_TEMPLATE.format(rule_id=uuid.uuid4(), today=date.today().isoformat()),
        encoding="utf-8",
        newline="\n",
    )
    fixture_dir.mkdir(parents=True, exist_ok=True)
    for filename, template in (
        ("tp_basic.json", TP_TEMPLATE),
        ("tp_variant.json", TP_TEMPLATE),
        ("fp_benign.json", FP_TEMPLATE),
        ("fp_benign_variant.json", FP_TEMPLATE),
    ):
        (fixture_dir / filename).write_text(
            json.dumps(template, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
    print(f"created {rule_path}")
    print(f"created {fixture_dir} with 2 tp_ and 2 fp_ templates")
    print("Fill in the TODOs, then run: make test")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m sigmaforge.scaffold NAME", file=sys.stderr)
        return 2
    return scaffold(args[0])


if __name__ == "__main__":
    sys.exit(main())
