"""Rule and fixture discovery.

Pairs every rule under rules/ with its fixture directory under
tests/fixtures/ and yields one RuleFixturePair per (rule, fixture)
combination.

Convention, enforced here as hard failures rather than skips:

* A rule at rules/windows/foo.yml has its fixtures in
  tests/fixtures/windows/foo/.
* Fixture files are single JSON objects. Names must start with ``tp_``
  (the rule must match) or ``fp_`` (the rule must not match).
* Every rule needs at least one tp_ and one fp_ fixture. A rule without
  a false positive test is not a tested rule.
* Top-level keys starting with ``_`` (e.g. ``_comment``) are stripped
  before evaluation.
* Fixture directories that do not correspond to a rule are also an
  error, so a renamed rule cannot silently orphan its tests.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sigma.rule import SigmaRule

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"


class LoaderError(Exception):
    """A rule or fixture violates the repository conventions."""


@dataclass(frozen=True)
class RuleFixturePair:
    rule_path: Path
    rule: SigmaRule
    fixture_path: Path
    expect_match: bool  # True for tp_ fixtures, False for fp_

    @property
    def rule_name(self) -> str:
        return self.rule_path.stem

    @property
    def fixture_name(self) -> str:
        return self.fixture_path.stem

    @property
    def test_id(self) -> str:
        return f"{self.rule_name}-{self.fixture_name}"


def discover_rule_paths() -> list[Path]:
    """All rule files under rules/, sorted for stable test ordering."""
    return sorted(p for p in RULES_DIR.rglob("*.yml") if p.is_file())


def load_rule(rule_path: Path) -> SigmaRule:
    return SigmaRule.from_yaml(rule_path.read_text(encoding="utf-8"))


def fixture_dir_for(rule_path: Path) -> Path:
    relative = rule_path.relative_to(RULES_DIR)
    return FIXTURES_DIR / relative.parent / relative.stem


def load_fixture(fixture_path: Path) -> dict[str, Any]:
    """Load a fixture event, stripping top-level keys starting with ``_``."""
    try:
        raw = json.loads(fixture_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise LoaderError(f"{fixture_path}: invalid JSON: {e}") from e
    if not isinstance(raw, dict):
        raise LoaderError(
            f"{fixture_path}: fixture must be a single JSON object representing one event, "
            f"got {type(raw).__name__}"
        )
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def _fixture_paths(rule_path: Path) -> list[tuple[Path, bool]]:
    """Validate a rule's fixture directory and return (path, expect_match) pairs."""
    fixture_dir = fixture_dir_for(rule_path)
    rel_rule = rule_path.relative_to(REPO_ROOT)
    rel_dir = fixture_dir.relative_to(REPO_ROOT)
    if not fixture_dir.is_dir():
        raise LoaderError(
            f"{rel_rule}: no fixture directory at {rel_dir}. "
            "Every rule needs TP and FP fixtures."
        )
    pairs: list[tuple[Path, bool]] = []
    for path in sorted(fixture_dir.iterdir()):
        if not path.is_file() or path.name == ".gitkeep":
            continue
        if path.suffix != ".json":
            raise LoaderError(
                f"{rel_dir}/{path.name}: fixtures must be .json files"
            )
        if path.name.startswith("tp_"):
            pairs.append((path, True))
        elif path.name.startswith("fp_"):
            pairs.append((path, False))
        else:
            raise LoaderError(
                f"{rel_dir}/{path.name}: fixture files must be prefixed tp_ or fp_"
            )
    if not any(expect for _, expect in pairs):
        raise LoaderError(f"{rel_rule}: no tp_ fixtures in {rel_dir}")
    if not any(not expect for _, expect in pairs):
        raise LoaderError(
            f"{rel_rule}: no fp_ fixtures in {rel_dir}. "
            "A rule without a false positive test is not a tested rule."
        )
    return pairs


def _check_orphan_fixture_dirs(rule_paths: list[Path]) -> None:
    if not FIXTURES_DIR.is_dir():
        return
    expected = {fixture_dir_for(p) for p in rule_paths}
    for directory in sorted(FIXTURES_DIR.rglob("*")):
        if not directory.is_dir():
            continue
        has_fixtures = any(
            f.suffix == ".json" and f.is_file() for f in directory.iterdir()
        )
        if has_fixtures and directory not in expected:
            raise LoaderError(
                f"{directory.relative_to(REPO_ROOT)}: fixture directory has no matching rule "
                f"under {RULES_DIR.relative_to(REPO_ROOT)}"
            )


def iter_rule_fixture_pairs() -> list[RuleFixturePair]:
    """Discover all rules and yield one pair per (rule, fixture).

    Raises LoaderError on any convention violation.
    """
    rule_paths = discover_rule_paths()
    _check_orphan_fixture_dirs(rule_paths)
    pairs: list[RuleFixturePair] = []
    for rule_path in rule_paths:
        rule = load_rule(rule_path)
        for fixture_path, expect_match in _fixture_paths(rule_path):
            pairs.append(
                RuleFixturePair(
                    rule_path=rule_path,
                    rule=rule,
                    fixture_path=fixture_path,
                    expect_match=expect_match,
                )
            )
    return pairs
