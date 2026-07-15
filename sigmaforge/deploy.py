"""Deploy converted rules to an Elastic Stack.

Each rule is converted to its Lucene query and upserted into a rules
index (default: sigmaforge-rules) keyed by the rule's UUID, so repeated
deploys are idempotent and renames do not duplicate rules. Downstream
tooling (saved searches, alerting) consumes that index.

DRY RUN IS THE DEFAULT. Nothing is written unless --push is passed, so a
fork running CI cannot accidentally ship to a live SIEM. Connection
settings come from ELASTIC_URL and ELASTIC_API_KEY (optional when the
target has security disabled, e.g. the local docker compose stack).

CLI: python -m sigmaforge.deploy [--push] [--index NAME]
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import date, datetime
from typing import Any

import yaml
from elasticsearch import Elasticsearch

from sigmaforge.convert import convert_rule_to_lucene
from sigmaforge.loader import REPO_ROOT, discover_rule_paths, load_rule

DEFAULT_INDEX = "sigmaforge-rules"


def build_rule_docs() -> list[dict[str, Any]]:
    """Convert every rule and return the documents to upsert. Raises on
    the first rule that fails conversion: a broken rule must never
    half-deploy."""
    docs = []
    for rule_path in discover_rule_paths():
        raw = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        rule = load_rule(rule_path)
        rule_date = raw.get("date")
        if isinstance(rule_date, (date, datetime)):
            rule_date = rule_date.isoformat()
        docs.append(
            {
                "_id": str(raw["id"]),
                "rule_file": str(rule_path.relative_to(REPO_ROOT)).replace("\\", "/"),
                "title": raw["title"],
                "description": raw.get("description", "").strip(),
                "status": raw.get("status"),
                "level": raw.get("level"),
                "tags": [str(t) for t in raw.get("tags") or []],
                "date": rule_date,
                "query": convert_rule_to_lucene(rule),
                "language": "lucene",
            }
        )
    return docs


def deploy(url: str, api_key: str | None, index: str, push: bool) -> int:
    docs = build_rule_docs()
    if not push:
        print(f"DRY RUN: would upsert {len(docs)} rules to {url} index '{index}'.")
        for doc in docs:
            print(f"  {doc['_id']}  {doc['rule_file']}  [{doc['level']}] {doc['title']}")
        print("Pass --push to write. ELASTIC_URL and ELASTIC_API_KEY configure the target.")
        return 0

    client = Elasticsearch(url, api_key=api_key or None, request_timeout=30)
    if not client.ping():
        print(f"error: cannot reach Elasticsearch at {url}", file=sys.stderr)
        return 1
    try:
        for doc in docs:
            body = {k: v for k, v in doc.items() if k != "_id"}
            client.index(index=index, id=doc["_id"], document=body)
        client.indices.refresh(index=index)
        count = client.count(index=index)["count"]
        print(f"Deployed {len(docs)} rules to {url} index '{index}' (now {count} docs).")
        return 0
    finally:
        client.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m sigmaforge.deploy", description=__doc__
    )
    parser.add_argument(
        "--push",
        action="store_true",
        help="actually write to Elasticsearch (default is a dry run)",
    )
    parser.add_argument("--index", default=DEFAULT_INDEX, help="target index name")
    args = parser.parse_args(argv)

    url = os.environ.get("ELASTIC_URL", "http://localhost:9200")
    api_key = os.environ.get("ELASTIC_API_KEY")
    if args.push and not os.environ.get("ELASTIC_URL"):
        print(
            "error: --push requires ELASTIC_URL to be set explicitly. "
            "Refusing to push to an implicit default target.",
            file=sys.stderr,
        )
        return 2
    return deploy(url, api_key, args.index, args.push)


if __name__ == "__main__":
    sys.exit(main())
