"""Offline Sigma rule evaluator.

Evaluates a parsed SigmaRule directly against a single JSON event dict,
implementing Sigma matching semantics without any backend conversion.

The heavy lifting (condition parsing, modifier application) is done by
pySigma at rule parse time: ``rule.detection.parsed_condition[n].parse()``
returns a tree of ConditionAND / ConditionOR / ConditionNOT nodes whose
leaves are ConditionFieldEqualsValueExpression (field-bound values) and
ConditionValueExpression (keyword values). Modifiers are already folded
into the leaf value types (SigmaString wildcards, SigmaRegularExpression,
SigmaCIDRExpression, SigmaCompareExpression, SigmaExpansion for
windash / base64offset, ConditionAND linking for ``|all``). This module
only walks that tree and matches leaf values against the event.

Semantics notes, chosen to keep Tier 1 (this evaluator) in agreement with
Tier 2 (the Elasticsearch Lucene backend):

* Plain strings match case-insensitively against the whole field value,
  with ``*`` / ``?`` wildcards (Sigma default semantics).
* ``|re`` regexes must match the WHOLE field value (fullmatch) and are
  case-sensitive, mirroring Lucene ``field:/regex/`` which is anchored.
* Keyword (field-less) values use substring semantics, mirroring the
  Lucene backend's ``*value*`` rendering of unbound values.
* A rule referencing a field the event does not have is not a match,
  except ``field: null`` which matches exactly when the field is absent
  or null (Lucene: ``NOT _exists_:field``).
"""

from __future__ import annotations

import re
from functools import lru_cache
from ipaddress import ip_address
from typing import Any

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    CompareOperators,
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SigmaType,
)

_MISSING = object()


class UnsupportedSigmaFeature(Exception):
    """Raised when a rule uses a Sigma feature this evaluator cannot handle.

    Raising instead of returning False means an unsupported rule fails its
    tests loudly rather than silently never matching.
    """


def match_event(rule: SigmaRule, event: dict[str, Any]) -> bool:
    """Return True if the Sigma rule matches the given event.

    Multiple condition entries in a rule are OR-linked per the Sigma spec.
    """
    return any(
        _eval_node(condition.parse(), event) for condition in rule.detection.parsed_condition
    )


def _eval_node(node: Any, event: dict[str, Any]) -> bool:
    if node is None:  # pySigma postprocessing can collapse a condition to nothing
        return False
    if isinstance(node, ConditionAND):
        return all(_eval_node(arg, event) for arg in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval_node(arg, event) for arg in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval_node(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _match_field(node.field, node.value, event)
    if isinstance(node, ConditionValueExpression):
        return _match_keyword(node.value, event)
    raise UnsupportedSigmaFeature(f"Unsupported condition node type: {type(node).__name__}")


def _get_field(event: dict[str, Any], field: str) -> Any:
    """Look up a field, returning _MISSING if absent.

    Exact key match first; falls back to dotted-path traversal into nested
    objects so ECS-style names like process.name resolve either way.
    """
    if field in event:
        return event[field]
    if "." in field:
        current: Any = event
        for part in field.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return _MISSING
        return current
    return _MISSING


def _match_field(field: str, value: SigmaType, event: dict[str, Any]) -> bool:
    if isinstance(value, SigmaExpansion):  # windash / base64offset variants: OR-linked
        return any(_match_field(field, v, event) for v in value.values)

    event_value = _get_field(event, field)
    if event_value is _MISSING:
        if isinstance(value, SigmaNull):
            return True
        if isinstance(value, SigmaExists):
            return not bool(value)
        return False

    if isinstance(value, SigmaExists):
        return bool(value)
    if isinstance(event_value, list):  # multi-valued event field: any element may match
        return any(_match_value(value, item, event) for item in event_value)
    return _match_value(value, event_value, event)


def _match_value(value: SigmaType, event_value: Any, event: dict[str, Any]) -> bool:
    # SigmaCasedString subclasses SigmaString, so it must be checked first.
    if isinstance(value, SigmaCasedString):
        return _string_match(value, event_value, case_sensitive=True)
    if isinstance(value, SigmaString):
        return _string_match(value, event_value, case_sensitive=False)
    if isinstance(value, SigmaNumber):
        return _number_match(value.number, event_value)
    if isinstance(value, SigmaBool):
        if isinstance(event_value, bool):
            return event_value is bool(value)
        if isinstance(event_value, str):
            return event_value.lower() == str(value).lower()
        return False
    if isinstance(value, SigmaNull):
        return event_value is None
    if isinstance(value, SigmaRegularExpression):
        if event_value is None:
            return False
        # Fullmatch mirrors Lucene's anchored field:/regex/ semantics.
        pattern = _compile(str(value.regexp), _regex_flags(value))
        return pattern.fullmatch(_as_str(event_value)) is not None
    if isinstance(value, SigmaCIDRExpression):
        try:
            return ip_address(str(event_value).strip()) in value.network
        except ValueError:
            return False
    if isinstance(value, SigmaCompareExpression):
        return _compare_match(value, event_value)
    if isinstance(value, SigmaFieldReference):
        other = _get_field(event, value.field)
        if other is _MISSING or event_value is None or other is None:
            return False
        this_s, other_s = _as_str(event_value).lower(), _as_str(other).lower()
        if value.starts_with:
            return this_s.startswith(other_s)
        if value.ends_with:
            return this_s.endswith(other_s)
        return this_s == other_s
    if isinstance(value, SigmaExpansion):
        return any(_match_value(v, event_value, event) for v in value.values)
    raise UnsupportedSigmaFeature(f"Unsupported Sigma value type: {type(value).__name__}")


def _string_match(value: SigmaString, event_value: Any, case_sensitive: bool) -> bool:
    if event_value is None:
        return False
    flags = re.DOTALL if case_sensitive else re.DOTALL | re.IGNORECASE
    pattern = _compile(str(value.to_regex().regexp), flags)
    return pattern.fullmatch(_as_str(event_value)) is not None


def _number_match(number: int | float, event_value: Any) -> bool:
    if isinstance(event_value, bool):
        return False
    if isinstance(event_value, (int, float)):
        return event_value == number
    if isinstance(event_value, str):
        try:
            return float(event_value) == float(number)
        except ValueError:
            return event_value == str(number)
    return False


def _compare_match(value: SigmaCompareExpression, event_value: Any) -> bool:
    if isinstance(event_value, bool):
        return False
    try:
        event_number = float(event_value)
    except (TypeError, ValueError):
        return False
    rule_number = float(value.number.number)
    op = value.op
    if op == CompareOperators.LT:
        return event_number < rule_number
    if op == CompareOperators.LTE:
        return event_number <= rule_number
    if op == CompareOperators.GT:
        return event_number > rule_number
    if op == CompareOperators.GTE:
        return event_number >= rule_number
    if op == CompareOperators.NEQ:
        return event_number != rule_number
    raise UnsupportedSigmaFeature(f"Unsupported compare operator: {op}")


def _match_keyword(value: SigmaType, event: dict[str, Any]) -> bool:
    """Field-less (keyword) match: substring semantics over every string
    value in the event, mirroring the Lucene backend's *value* rendering."""
    if isinstance(value, SigmaExpansion):
        return any(_match_keyword(v, event) for v in value.values)
    if isinstance(value, SigmaCasedString):
        pattern = _compile(str(value.to_regex().regexp), re.DOTALL)
    elif isinstance(value, SigmaString):
        pattern = _compile(str(value.to_regex().regexp), re.DOTALL | re.IGNORECASE)
    elif isinstance(value, SigmaRegularExpression):
        pattern = _compile(str(value.regexp), _regex_flags(value))
    elif isinstance(value, (SigmaNumber, SigmaBool)):
        pattern = _compile(re.escape(str(value)), re.IGNORECASE)
    else:
        raise UnsupportedSigmaFeature(
            f"Unsupported keyword value type: {type(value).__name__}"
        )
    return any(pattern.search(text) is not None for text in _iter_strings(event))


def _iter_strings(obj: Any) -> Any:
    """Yield every scalar in the event as a string, recursing into
    nested objects and arrays."""
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_strings(v)
    elif obj is not None:
        yield _as_str(obj)


def _as_str(value: Any) -> str:
    if isinstance(value, bool):  # JSON booleans render lowercase
        return "true" if value else "false"
    return str(value)


def _regex_flags(value: SigmaRegularExpression) -> int:
    flags = 0
    for flag in value.flags:
        flags |= SigmaRegularExpression.sigma_to_python_flags[flag]
    return flags


@lru_cache(maxsize=4096)
def _compile(pattern: str, flags: int) -> re.Pattern[str]:
    return re.compile(pattern, flags)
