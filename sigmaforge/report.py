"""Detection outcome dataset and Kibana wiring.

Builds one record per (rule, fixture): whether the rule fired, whether
that was the correct outcome, and the rule's ATT&CK mapping. The same
records feed both the HTML dashboard (sigmaforge.dashboard) and a live
Elasticsearch index that Kibana can explore.

The "fired" outcome is computed with the offline evaluator, which the
Tier 2 integration suite proves is identical to running the converted
query in Elasticsearch. So the dataset is real either way.

CLI:
  python -m sigmaforge.report              # print a summary table
  python -m sigmaforge.report --kibana     # index to ES + create data views
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import asdict, dataclass

import yaml

from sigmaforge.evaluator import match_event
from sigmaforge.loader import (
    discover_rule_paths,
    fixture_dir_for,
    load_fixture,
    load_rule,
)

DETECTIONS_INDEX = "sigmaforge-detections"
RULES_INDEX = "sigmaforge-rules"

TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")
NON_TACTIC_TAG_RE = re.compile(r"^attack\.[tgsm]\d{4}(\.\d{3})?$")


@dataclass
class DetectionRecord:
    rule: str
    title: str
    level: str
    tactics: list[str]
    techniques: list[str]
    fixture: str
    kind: str  # "true_positive" or "false_positive"
    expected_to_fire: bool
    fired: bool
    correct: bool
    comment: str


def _tags(raw: dict) -> tuple[list[str], list[str]]:
    tags = [str(t) for t in raw.get("tags") or []]
    techniques = [m.group(1).upper() for t in tags if (m := TECHNIQUE_TAG_RE.match(t))]
    tactics = [
        t.removeprefix("attack.")
        for t in tags
        if t.startswith("attack.") and not NON_TACTIC_TAG_RE.match(t)
    ]
    return tactics, techniques


def build_records() -> list[DetectionRecord]:
    records: list[DetectionRecord] = []
    for rule_path in discover_rule_paths():
        raw = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        rule = load_rule(rule_path)
        tactics, techniques = _tags(raw)
        fixture_dir = fixture_dir_for(rule_path)
        for fixture_path in sorted(fixture_dir.glob("*.json")):
            name = fixture_path.stem
            expected = name.startswith("tp_")
            raw_fixture = yaml.safe_load(fixture_path.read_text(encoding="utf-8"))
            comment = str(raw_fixture.get("_comment", "")) if isinstance(raw_fixture, dict) else ""
            event = load_fixture(fixture_path)
            fired = match_event(rule, event)
            records.append(
                DetectionRecord(
                    rule=rule_path.stem,
                    title=raw["title"],
                    level=raw.get("level", "unknown"),
                    tactics=tactics,
                    techniques=techniques,
                    fixture=name,
                    kind="true_positive" if expected else "false_positive",
                    expected_to_fire=expected,
                    fired=fired,
                    correct=fired == expected,
                    comment=comment,
                )
            )
    return records


def summary(records: list[DetectionRecord]) -> dict:
    rules = {r.rule for r in records}
    tp = [r for r in records if r.kind == "true_positive"]
    fp = [r for r in records if r.kind == "false_positive"]
    return {
        "rules": len(rules),
        "fixtures": len(records),
        "true_positives": len(tp),
        "false_positives": len(fp),
        "correct": sum(r.correct for r in records),
        "tp_caught": sum(r.fired for r in tp),
        "fp_suppressed": sum(not r.fired for r in fp),
        "tactics": sorted({t for r in records for t in r.tactics}),
    }


def push_to_kibana(url: str, api_key: str | None) -> None:
    """Index detection records + rules into Elasticsearch and create the
    Kibana data views so both are explorable in the UI."""
    import json
    import urllib.request

    from elasticsearch import Elasticsearch

    from sigmaforge.deploy import build_rule_docs

    es = Elasticsearch(url, api_key=api_key or None, request_timeout=30)
    if not es.ping():
        raise SystemExit(f"Cannot reach Elasticsearch at {url}. Run 'make up' first.")

    # Rules index.
    for doc in build_rule_docs():
        body = {k: v for k, v in doc.items() if k != "_id"}
        es.index(index=RULES_INDEX, id=doc["_id"], document=body)

    # Detections index, rebuilt fresh each run.
    if es.indices.exists(index=DETECTIONS_INDEX):
        es.indices.delete(index=DETECTIONS_INDEX)
    es.indices.create(
        index=DETECTIONS_INDEX,
        mappings={
            "properties": {
                "rule": {"type": "keyword"},
                "title": {"type": "keyword"},
                "level": {"type": "keyword"},
                "tactics": {"type": "keyword"},
                "techniques": {"type": "keyword"},
                "fixture": {"type": "keyword"},
                "kind": {"type": "keyword"},
                "expected_to_fire": {"type": "boolean"},
                "fired": {"type": "boolean"},
                "correct": {"type": "boolean"},
                "comment": {"type": "text"},
            }
        },
    )
    records = build_records()
    for rec in records:
        es.index(index=DETECTIONS_INDEX, document=asdict(rec))
    es.indices.refresh(index=DETECTIONS_INDEX)
    es.indices.refresh(index=RULES_INDEX)
    es.close()

    # Kibana data views (idempotent: ignore "already exists").
    kibana_url = url.replace(":9200", ":5601")
    data_views = (
        ("SigmaForge Rules", RULES_INDEX),
        ("SigmaForge Detections", DETECTIONS_INDEX),
    )
    for name, pattern in data_views:
        payload = json.dumps(
            {"data_view": {"title": pattern, "name": name}}
        ).encode()
        req = urllib.request.Request(
            f"{kibana_url}/api/data_views/data_view",
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json", "kbn-xsrf": "true"},
        )
        try:
            urllib.request.urlopen(req, timeout=30)
            print(f"created Kibana data view: {name} ({pattern})")
        except urllib.error.HTTPError as e:
            if e.code == 400:
                print(f"Kibana data view already exists: {name} ({pattern})")
            else:
                raise

    print(f"\nIndexed {len(records)} detection records to {DETECTIONS_INDEX}.")
    print(f"Open Kibana at {kibana_url} -> Discover -> SigmaForge Detections.")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    records = build_records()
    s = summary(records)
    print(
        f"Rules: {s['rules']}   Fixtures: {s['fixtures']}   "
        f"Correct outcomes: {s['correct']}/{s['fixtures']}"
    )
    print(
        f"True positives caught: {s['tp_caught']}/{s['true_positives']}   "
        f"False positives suppressed: {s['fp_suppressed']}/{s['false_positives']}"
    )
    print(f"Tactics covered: {', '.join(s['tactics'])}")
    if "--kibana" in args:
        url = os.environ.get("ELASTIC_URL", "http://localhost:9200")
        push_to_kibana(url, os.environ.get("ELASTIC_API_KEY"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
