"""Metadata gate: structural and hygiene checks on every rule.

Operates on the raw YAML (not the parsed SigmaRule) so every violation
produces a message naming the rule file and the specific problem, even
for values pySigma would reject with its own less specific errors.
"""

import re
import uuid
from datetime import date, datetime

import pytest
import yaml
from sigma.data.mitre_attack import mitre_attack_tactics, mitre_attack_techniques

from sigmaforge.loader import discover_rule_paths

RULE_PATHS = discover_rule_paths()
RULE_IDS = [p.stem for p in RULE_PATHS]

VALID_STATUS = {"experimental", "test", "stable"}
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
TECHNIQUE_TAG_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
# ATT&CK IDs for things that are not tactics: techniques, groups, software, mitigations
NON_TACTIC_TAG_RE = re.compile(r"^attack\.[tgsm]\d{4}(\.\d{3})?$")
VALID_TACTIC_NAMES = set(mitre_attack_tactics.values())


def load_raw(rule_path):
    return yaml.safe_load(rule_path.read_text(encoding="utf-8"))


@pytest.fixture(params=RULE_PATHS, ids=RULE_IDS)
def rule(request):
    """(path, raw dict, display name) for each rule in the repo."""
    path = request.param
    return path, load_raw(path), path.name


def test_title(rule):
    path, raw, name = rule
    title = raw.get("title")
    assert title, f"{name}: missing title"
    assert isinstance(title, str), f"{name}: title must be a string"
    assert len(title) < 120, f"{name}: title is {len(title)} chars, must be under 120"
    assert not title.rstrip().endswith("."), f"{name}: title must not end with a period"


def test_id_is_valid_uuid(rule):
    path, raw, name = rule
    rule_id = raw.get("id")
    assert rule_id, f"{name}: missing id"
    try:
        uuid.UUID(str(rule_id))
    except ValueError:
        pytest.fail(f"{name}: id '{rule_id}' is not a valid UUID")


def test_ids_unique_across_repo():
    seen = {}
    for path in RULE_PATHS:
        rule_id = str(load_raw(path).get("id"))
        if rule_id in seen:
            pytest.fail(
                f"Duplicate rule id {rule_id}: used by both {seen[rule_id].name} and {path.name}"
            )
        seen[rule_id] = path


def test_description(rule):
    path, raw, name = rule
    description = raw.get("description")
    assert description, f"{name}: missing description"
    assert len(description.strip()) >= 40, (
        f"{name}: description is {len(description.strip())} chars, needs at least 40. "
        "Explain what the rule detects and why it matters."
    )


def test_status(rule):
    path, raw, name = rule
    status = raw.get("status")
    assert status, f"{name}: missing status"
    assert status in VALID_STATUS, (
        f"{name}: status '{status}' invalid, must be one of {sorted(VALID_STATUS)}"
    )


def test_author(rule):
    path, raw, name = rule
    assert raw.get("author"), f"{name}: missing author"


def test_date(rule):
    path, raw, name = rule
    value = raw.get("date")
    assert value, f"{name}: missing date"
    if isinstance(value, (date, datetime)):
        return  # YAML already parsed it, so it is a valid date
    try:
        date.fromisoformat(str(value))
    except ValueError:
        pytest.fail(f"{name}: date '{value}' is not parseable, use YYYY-MM-DD")


def test_logsource(rule):
    path, raw, name = rule
    logsource = raw.get("logsource")
    assert logsource, f"{name}: missing logsource"
    keys = set(logsource) & {"product", "category", "service"}
    assert keys, (
        f"{name}: logsource must contain at least one of product/category/service, "
        f"got {sorted(logsource)}"
    )


def test_level(rule):
    path, raw, name = rule
    level = raw.get("level")
    assert level, f"{name}: missing level"
    assert level in VALID_LEVELS, (
        f"{name}: level '{level}' invalid, must be one of {sorted(VALID_LEVELS)}"
    )


def test_falsepositives(rule):
    path, raw, name = rule
    falsepositives = raw.get("falsepositives")
    assert falsepositives, (
        f"{name}: missing falsepositives. Every rule needs a documented FP story."
    )
    assert isinstance(falsepositives, list) and len(falsepositives) > 0, (
        f"{name}: falsepositives must be a non-empty list"
    )
    if len(falsepositives) == 1 and str(falsepositives[0]).strip().lower() in ("unknown", "none"):
        pytest.fail(
            f"{name}: falsepositives is just '{falsepositives[0]}'. "
            "That is a placeholder, not an FP story. Describe the benign activity "
            "that could trigger this rule."
        )


def test_has_technique_tag(rule):
    path, raw, name = rule
    tags = raw.get("tags") or []
    technique_tags = [t for t in tags if TECHNIQUE_TAG_RE.match(str(t))]
    assert technique_tags, (
        f"{name}: no ATT&CK technique tag (attack.tNNNN or attack.tNNNN.NNN) in tags={tags}. "
        "A tactic alone does not say what the rule detects."
    )
    for tag in technique_tags:
        technique_id = tag.split(".", 1)[1].upper()
        assert technique_id in mitre_attack_techniques, (
            f"{name}: tag '{tag}' references {technique_id}, which is not a real "
            "ATT&CK technique ID"
        )


def test_tactic_tags_are_real(rule):
    path, raw, name = rule
    tags = raw.get("tags") or []
    for tag in tags:
        tag = str(tag)
        if not tag.startswith("attack.") or NON_TACTIC_TAG_RE.match(tag):
            continue
        tactic = tag.removeprefix("attack.")
        assert tactic in VALID_TACTIC_NAMES, (
            f"{name}: tag '{tag}' is not a real ATT&CK tactic. "
            f"Valid tactics: {sorted(VALID_TACTIC_NAMES)}"
        )


def test_references(rule):
    path, raw, name = rule
    references = raw.get("references")
    assert references, f"{name}: missing references"
    urls = [r for r in references if str(r).startswith(("http://", "https://"))]
    assert urls, f"{name}: references must contain at least one URL, got {references}"
