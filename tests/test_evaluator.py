"""Unit tests for the offline Sigma evaluator.

Every Sigma matching feature the evaluator claims to support gets a
minimal synthetic rule/event pair here. Everything else in the repo
trusts this module.
"""

import base64

import pytest
from sigma.rule import SigmaRule

from sigmaforge.evaluator import match_event


def make_rule(detection: dict) -> SigmaRule:
    return SigmaRule.from_dict(
        {
            "title": "evaluator test rule",
            "logsource": {"category": "test"},
            "detection": detection,
        }
    )


def matches(detection: dict, event: dict) -> bool:
    return match_event(make_rule(detection), event)


# --- field equality and case handling ---------------------------------------


def test_field_equals_exact():
    det = {"selection": {"Image": r"C:\Windows\System32\cmd.exe"}, "condition": "selection"}
    assert matches(det, {"Image": r"C:\Windows\System32\cmd.exe"})


def test_field_equals_case_insensitive_by_default():
    det = {"selection": {"Image": r"c:\windows\system32\CMD.EXE"}, "condition": "selection"}
    assert matches(det, {"Image": r"C:\Windows\System32\cmd.exe"})


def test_field_not_equal_no_match():
    det = {"selection": {"Image": "cmd.exe"}, "condition": "selection"}
    assert not matches(det, {"Image": "powershell.exe"})


def test_cased_modifier_is_case_sensitive():
    det = {"selection": {"Image|cased": "CMD.exe"}, "condition": "selection"}
    assert matches(det, {"Image": "CMD.exe"})
    assert not matches(det, {"Image": "cmd.exe"})


def test_number_equality():
    det = {"selection": {"EventID": 4688}, "condition": "selection"}
    assert matches(det, {"EventID": 4688})
    assert matches(det, {"EventID": "4688"})
    assert not matches(det, {"EventID": 4689})


def test_boolean_equality():
    det = {"selection": {"Elevated": True}, "condition": "selection"}
    assert matches(det, {"Elevated": True})
    assert matches(det, {"Elevated": "true"})
    assert not matches(det, {"Elevated": False})


# --- null and missing fields -------------------------------------------------


def test_missing_field_is_not_a_match():
    det = {"selection": {"ParentImage": "explorer.exe"}, "condition": "selection"}
    assert not matches(det, {"Image": "explorer.exe"})


def test_null_matches_missing_field():
    det = {"selection": {"ParentImage": None}, "condition": "selection"}
    assert matches(det, {"Image": "cmd.exe"})
    assert matches(det, {"Image": "cmd.exe", "ParentImage": None})
    assert not matches(det, {"ParentImage": "explorer.exe"})


def test_not_null_requires_field_present():
    det = {
        "selection": {"Image": "cmd.exe"},
        "filter": {"ParentImage": None},
        "condition": "selection and not filter",
    }
    assert matches(det, {"Image": "cmd.exe", "ParentImage": "explorer.exe"})
    assert not matches(det, {"Image": "cmd.exe"})


# --- string modifiers --------------------------------------------------------


def test_contains():
    det = {"selection": {"CommandLine|contains": "-enc"}, "condition": "selection"}
    assert matches(det, {"CommandLine": "powershell.exe -EnC SQBFAFgA"})
    assert not matches(det, {"CommandLine": "powershell.exe -File x.ps1"})


def test_startswith():
    det = {"selection": {"Image|startswith": r"C:\Users\\"}, "condition": "selection"}
    assert matches(det, {"Image": r"C:\Users\bob\evil.exe"})
    assert not matches(det, {"Image": r"C:\Windows\notepad.exe"})


def test_endswith():
    det = {"selection": {"Image|endswith": r"\cmd.exe"}, "condition": "selection"}
    assert matches(det, {"Image": r"C:\Windows\System32\cmd.exe"})
    assert not matches(det, {"Image": r"C:\Windows\System32\cmd.exe.bak"})


def test_re_fullmatch_semantics():
    # Anchored like Lucene field:/regex/ so Tier 1 and Tier 2 agree.
    det = {
        "selection": {"Image|re": r"C:\\Windows\\.*\.exe"},
        "condition": "selection",
    }
    assert matches(det, {"Image": r"C:\Windows\explorer.exe"})
    assert not matches(det, {"Image": r"C:\Windows\explorer.exe.bak"})


def test_re_is_case_sensitive():
    det = {"selection": {"Image|re": r".*cmd\.exe"}, "condition": "selection"}
    assert matches(det, {"Image": r"C:\Windows\System32\cmd.exe"})
    assert not matches(det, {"Image": r"C:\Windows\System32\CMD.EXE"})


def test_all_modifier_requires_every_value():
    det = {
        "selection": {"CommandLine|contains|all": ["vssadmin", "delete", "shadows"]},
        "condition": "selection",
    }
    assert matches(det, {"CommandLine": "vssadmin.exe delete shadows /all /quiet"})
    assert not matches(det, {"CommandLine": "vssadmin.exe list shadows"})


def test_base64_modifier():
    encoded = base64.b64encode(b"invoke-mimikatz").decode()
    det = {"selection": {"ScriptBlock|base64": "invoke-mimikatz"}, "condition": "selection"}
    assert matches(det, {"ScriptBlock": encoded})
    assert not matches(det, {"ScriptBlock": "invoke-mimikatz"})


def test_base64offset_modifier():
    det = {
        "selection": {"Data|base64offset|contains": "evil.com"},
        "condition": "selection",
    }
    for prefix in (b"", b"x", b"xx"):  # exercise all three byte offsets
        encoded = base64.b64encode(prefix + b"connect to evil.com now").decode()
        assert matches(det, {"Data": encoded}), f"offset prefix {prefix!r}"
    assert not matches(det, {"Data": base64.b64encode(b"connect to good.com").decode()})


def test_windash_modifier():
    det = {"selection": {"CommandLine|windash|contains": " -s "}, "condition": "selection"}
    assert matches(det, {"CommandLine": "certutil -s http://x"})
    assert matches(det, {"CommandLine": "certutil /s http://x"})
    assert not matches(det, {"CommandLine": "certutil -x http://x"})


def test_cidr_modifier():
    det = {"selection": {"SourceIp|cidr": "10.0.0.0/8"}, "condition": "selection"}
    assert matches(det, {"SourceIp": "10.1.2.3"})
    assert not matches(det, {"SourceIp": "192.168.1.1"})
    assert not matches(det, {"SourceIp": "not-an-ip"})


@pytest.mark.parametrize(
    ("modifier", "threshold", "value", "expected"),
    [
        ("gt", 10, 11, True),
        ("gt", 10, 10, False),
        ("gte", 10, 10, True),
        ("gte", 10, 9, False),
        ("lt", 10, 9, True),
        ("lt", 10, 10, False),
        ("lte", 10, 10, True),
        ("lte", 10, 11, False),
    ],
)
def test_numeric_comparison_modifiers(modifier, threshold, value, expected):
    det = {"selection": {f"Count|{modifier}": threshold}, "condition": "selection"}
    assert matches(det, {"Count": value}) is expected


# --- wildcards ---------------------------------------------------------------


def test_wildcard_star():
    det = {"selection": {"Image": r"*\cmd.exe"}, "condition": "selection"}
    assert matches(det, {"Image": r"C:\Windows\System32\cmd.exe"})
    assert not matches(det, {"Image": r"C:\Windows\System32\cmd.exe.tmp"})


def test_wildcard_question_mark():
    det = {"selection": {"Drive": "?:"}, "condition": "selection"}
    assert matches(det, {"Drive": "D:"})
    assert not matches(det, {"Drive": "DD:"})


def test_wildcard_star_matches_empty():
    det = {"selection": {"CommandLine": "cmd*"}, "condition": "selection"}
    assert matches(det, {"CommandLine": "cmd"})
    assert matches(det, {"CommandLine": "cmd.exe /c whoami"})


# --- selection structure -----------------------------------------------------


def test_value_list_is_or():
    det = {"selection": {"Image|endswith": [r"\wget.exe", r"\curl.exe"]}, "condition": "selection"}
    assert matches(det, {"Image": r"C:\tools\curl.exe"})
    assert matches(det, {"Image": r"C:\tools\wget.exe"})
    assert not matches(det, {"Image": r"C:\tools\git.exe"})


def test_multiple_fields_in_selection_are_and():
    det = {
        "selection": {"Image|endswith": r"\schtasks.exe", "CommandLine|contains": "/create"},
        "condition": "selection",
    }
    assert matches(det, {"Image": r"C:\Windows\schtasks.exe", "CommandLine": "schtasks /create"})
    assert not matches(det, {"Image": r"C:\Windows\schtasks.exe", "CommandLine": "schtasks /query"})


def test_event_list_field_matches_any_element():
    det = {"selection": {"Hashes|contains": "IMPHASH="}, "condition": "selection"}
    assert matches(det, {"Hashes": ["MD5=abc", "IMPHASH=def"]})
    assert not matches(det, {"Hashes": ["MD5=abc", "SHA1=def"]})


# --- condition expressions ---------------------------------------------------


def test_condition_and():
    det = {
        "sel_a": {"Image|endswith": r"\cmd.exe"},
        "sel_b": {"User": "SYSTEM"},
        "condition": "sel_a and sel_b",
    }
    assert matches(det, {"Image": r"C:\W\cmd.exe", "User": "SYSTEM"})
    assert not matches(det, {"Image": r"C:\W\cmd.exe", "User": "bob"})


def test_condition_or():
    det = {
        "sel_a": {"Image|endswith": r"\cmd.exe"},
        "sel_b": {"Image|endswith": r"\powershell.exe"},
        "condition": "sel_a or sel_b",
    }
    assert matches(det, {"Image": r"C:\W\powershell.exe"})
    assert not matches(det, {"Image": r"C:\W\notepad.exe"})


def test_condition_not_with_parentheses():
    det = {
        "selection": {"Image|endswith": r"\reg.exe"},
        "filter_user": {"User": "svc_deploy"},
        "filter_parent": {"ParentImage|endswith": r"\sccm.exe"},
        "condition": "selection and not (filter_user or filter_parent)",
    }
    assert matches(det, {"Image": r"C:\W\reg.exe", "User": "bob", "ParentImage": r"C:\W\x.exe"})
    assert not matches(
        det, {"Image": r"C:\W\reg.exe", "User": "svc_deploy", "ParentImage": r"C:\W\x.exe"}
    )
    assert not matches(
        det, {"Image": r"C:\W\reg.exe", "User": "bob", "ParentImage": r"C:\W\sccm.exe"}
    )


def test_one_of_selection_wildcard():
    det = {
        "selection_cmd": {"Image|endswith": r"\cmd.exe"},
        "selection_ps": {"Image|endswith": r"\powershell.exe"},
        "condition": "1 of selection_*",
    }
    assert matches(det, {"Image": r"C:\W\cmd.exe"})
    assert matches(det, {"Image": r"C:\W\powershell.exe"})
    assert not matches(det, {"Image": r"C:\W\notepad.exe"})


def test_all_of_selection_wildcard():
    det = {
        "selection_img": {"Image|endswith": r"\rundll32.exe"},
        "selection_cli": {"CommandLine|contains": "javascript:"},
        "condition": "all of selection_*",
    }
    assert matches(det, {"Image": r"C:\W\rundll32.exe", "CommandLine": "x javascript: y"})
    assert not matches(det, {"Image": r"C:\W\rundll32.exe", "CommandLine": "shell32.dll"})


def test_one_of_them():
    det = {
        "sel_a": {"Image|endswith": r"\certutil.exe"},
        "sel_b": {"Image|endswith": r"\bitsadmin.exe"},
        "condition": "1 of them",
    }
    assert matches(det, {"Image": r"C:\W\bitsadmin.exe"})
    assert not matches(det, {"Image": r"C:\W\notepad.exe"})


def test_all_of_them():
    det = {
        "sel_a": {"Image|endswith": r"\certutil.exe"},
        "sel_b": {"CommandLine|contains": "urlcache"},
        "condition": "all of them",
    }
    assert matches(det, {"Image": r"C:\W\certutil.exe", "CommandLine": "certutil -urlcache -f"})
    assert not matches(det, {"Image": r"C:\W\certutil.exe", "CommandLine": "certutil -hashfile"})


def test_multiple_conditions_are_or_linked():
    det = {
        "sel_a": {"Image|endswith": r"\cmd.exe"},
        "sel_b": {"Image|endswith": r"\powershell.exe"},
        "condition": ["sel_a", "sel_b"],
    }
    assert matches(det, {"Image": r"C:\W\powershell.exe"})
    assert not matches(det, {"Image": r"C:\W\notepad.exe"})


# --- keywords ----------------------------------------------------------------


def test_keywords_match_any_string_value():
    det = {"keywords": ["mimikatz"], "condition": "keywords"}
    assert matches(det, {"CommandLine": "Invoke-Mimikatz -DumpCreds", "Image": "ps.exe"})
    assert matches(det, {"Description": "MIMIKATZ credential dumper"})
    assert not matches(det, {"CommandLine": "whoami /all"})


def test_keywords_substring_semantics():
    # Lucene renders unbound values as *value*, so substrings must hit.
    det = {"keywords": ["sekurlsa::"], "condition": "keywords"}
    assert matches(det, {"CommandLine": "privilege::debug sekurlsa::logonpasswords exit"})


def test_keywords_recurse_into_nested_values():
    det = {"keywords": ["lsass"], "condition": "keywords"}
    assert matches(det, {"process": {"target": {"name": "lsass.exe"}}})
    assert matches(det, {"modules": ["a.dll", "lsass_dump.dll"]})
    assert not matches(det, {"process": {"target": {"name": "svchost.exe"}}})


# --- dotted field access -----------------------------------------------------


def test_dotted_field_resolves_flat_and_nested():
    det = {"selection": {"process.name": "cmd.exe"}, "condition": "selection"}
    assert matches(det, {"process.name": "cmd.exe"})
    assert matches(det, {"process": {"name": "cmd.exe"}})
    assert not matches(det, {"process": {"name": "ps.exe"}})
