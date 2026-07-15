"""Sigma to Elasticsearch query conversion.

Converts rules to Lucene query strings with the ecs_windows pipeline, the
same field mapping Winlogbeat applies to Windows events. Also exposes
event_to_ecs(), which applies the equivalent mapping to a raw Sysmon
event dict so integration tests can index fixtures the way Winlogbeat
would ship them. Both directions read the mapping out of the installed
pySigma pipeline object at runtime, so they cannot drift from the rule
conversion.

CLI: python -m sigmaforge.convert rules/windows/foo.yml [more.yml ...]
"""

from __future__ import annotations

import copy
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

from sigma.backends.elasticsearch import LuceneBackend
from sigma.pipelines.elasticsearch.windows import (
    ecs_windows,
    ecs_windows_variable_mappings,
)
from sigma.rule import SigmaRule


@lru_cache(maxsize=1)
def _backend() -> LuceneBackend:
    return LuceneBackend(ecs_windows())


def convert_rule_to_lucene(rule: SigmaRule) -> str:
    """Convert a SigmaRule to a Lucene query string.

    Works on a deep copy because pipeline application mutates the rule's
    field names in place, and callers (the offline evaluator) still need
    the original Sysmon field names.
    """
    queries = _backend().convert_rule(copy.deepcopy(rule))
    if len(queries) != 1:
        raise ValueError(
            f"Expected exactly one query from rule '{rule.title}', got {len(queries)}"
        )
    return queries[0]


@lru_cache(maxsize=1)
def _static_field_map() -> dict[str, str]:
    """The ecs_windows static Sysmon-to-ECS field mapping, extracted from
    the installed pipeline so it stays in sync with rule conversion."""
    for item in ecs_windows().items:
        if item.identifier == "ecs_windows_field_mapping":
            return {
                field: mapped if isinstance(mapped, str) else mapped[0]
                for field, mapped in item.transformation.mapping.items()
            }
    raise RuntimeError("ecs_windows pipeline no longer defines ecs_windows_field_mapping")


def _map_field(field: str, category: str | None) -> str:
    for logsrc_field, logsrc, mapped in ecs_windows_variable_mappings.get(field, ()):
        if logsrc_field == "category" and logsrc == category:
            return mapped
    static = _static_field_map()
    if field in static:
        return static[field]
    if "." in field:  # already ECS-style
        return field
    return f"winlog.event_data.{field}"


def event_to_ecs(event: dict[str, Any], category: str | None) -> dict[str, Any]:
    """Map a raw Sysmon-style event dict to flat dotted ECS field names,
    mirroring what the ecs_windows pipeline does to rule field names."""
    return {_map_field(field, category): value for field, value in event.items()}


def main(argv: list[str] | None = None) -> int:
    # windash expansions contain non-ASCII dash variants; don't let a
    # legacy console codepage (Windows cp1252) crash the CLI.
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        sys.stdout.reconfigure(encoding="utf-8")
    args = sys.argv[1:] if argv is None else argv
    if not args:
        print("usage: python -m sigmaforge.convert RULE.yml [RULE.yml ...]", file=sys.stderr)
        return 2
    status = 0
    for arg in args:
        path = Path(arg)
        if not path.is_file():
            print(f"{arg}: no such file", file=sys.stderr)
            status = 1
            continue
        try:
            rule = SigmaRule.from_yaml(path.read_text(encoding="utf-8"))
            query = convert_rule_to_lucene(rule)
        except Exception as e:  # noqa: BLE001 - CLI boundary, report and continue
            print(f"{arg}: conversion failed: {e}", file=sys.stderr)
            status = 1
            continue
        if len(args) > 1:
            print(f"# {arg}")
        print(query)
    return status


if __name__ == "__main__":
    sys.exit(main())
