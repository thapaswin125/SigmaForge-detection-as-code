"""Tier 2 integration tests against a live Elasticsearch.

For each rule: create a temp index with an ECS-ish keyword mapping, index
all of that rule's fixtures (ECS-mapped, as Winlogbeat would ship them)
with an added _fixture_name field, run the converted Lucene query, and
assert the returned fixture set is EXACTLY the set of tp_ fixtures.

If Tier 1 (offline evaluator) and Tier 2 (Elasticsearch) disagree for any
rule, the failure prints both results side by side. That divergence means
the conversion pipeline has a bug and is the most useful signal this repo
produces.
"""

import os
from collections import defaultdict

import pytest
from elasticsearch import Elasticsearch

from sigmaforge.convert import convert_rule_to_lucene, event_to_ecs
from sigmaforge.evaluator import match_event
from sigmaforge.loader import iter_rule_fixture_pairs, load_fixture

ELASTIC_URL = os.environ.get("ELASTIC_URL", "http://localhost:9200")

# Group fixture pairs per rule so each rule is one test case.
_BY_RULE = defaultdict(list)
for _pair in iter_rule_fixture_pairs():
    _BY_RULE[_pair.rule_path].append(_pair)
RULE_PARAMS = sorted(_BY_RULE.items())
RULE_IDS = [path.stem for path, _ in RULE_PARAMS]

INDEX_SETTINGS = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "dynamic_templates": [
            {
                "strings_as_keyword": {
                    "match_mapping_type": "string",
                    "mapping": {"type": "keyword", "ignore_above": 8192},
                }
            }
        ]
    },
}


@pytest.fixture(scope="module")
def es():
    client = Elasticsearch(ELASTIC_URL, request_timeout=30)
    if not client.ping():
        pytest.fail(
            f"Cannot reach Elasticsearch at {ELASTIC_URL}. "
            "Run 'make up' (docker compose up -d) first, or set ELASTIC_URL."
        )
    yield client
    client.close()


@pytest.mark.integration
@pytest.mark.parametrize(("rule_path", "pairs"), RULE_PARAMS, ids=RULE_IDS)
def test_rule_against_elasticsearch(es, rule_path, pairs):
    rule = pairs[0].rule
    category = rule.logsource.category
    index = f"sigmaforge-test-{rule_path.stem}".lower()

    query = convert_rule_to_lucene(rule)

    tier1 = {}
    events = {}
    for pair in pairs:
        event = load_fixture(pair.fixture_path)
        events[pair.fixture_name] = event
        tier1[pair.fixture_name] = match_event(rule, event)

    expected = {p.fixture_name for p in pairs if p.expect_match}

    if es.indices.exists(index=index):
        es.indices.delete(index=index)
    es.indices.create(index=index, body=INDEX_SETTINGS)
    try:
        for name, event in events.items():
            doc = event_to_ecs(event, category)
            doc["_fixture_name"] = name
            es.index(index=index, document=doc)
        es.indices.refresh(index=index)

        response = es.search(
            index=index,
            query={"query_string": {"query": query, "analyze_wildcard": True}},
            size=100,
        )
        tier2_hits = {hit["_source"]["_fixture_name"] for hit in response["hits"]["hits"]}
    finally:
        es.indices.delete(index=index)

    if tier2_hits != expected:
        lines = [
            f"Rule {rule_path.name}: Elasticsearch results do not match expected TP set.",
            f"Lucene query: {query}",
            "",
            f"{'fixture':<40} {'expected':>8} {'tier1':>6} {'tier2':>6}",
        ]
        for name in sorted(events):
            lines.append(
                f"{name:<40} {str(name in expected):>8} "
                f"{str(tier1[name]):>6} {str(name in tier2_hits):>6}"
            )
        divergent = {n for n in events if tier1[n] != (n in tier2_hits)}
        if divergent:
            lines.append("")
            lines.append(
                f"TIER 1 / TIER 2 DIVERGENCE on {sorted(divergent)}: "
                "the offline evaluator and the converted Elasticsearch query "
                "disagree. The conversion pipeline (or the evaluator) has a bug."
            )
        pytest.fail("\n".join(lines))

    # Tier 1 must agree with the fixture expectations too; test_rules.py
    # covers this, but assert here so a divergence is caught even when
    # Tier 2 happens to match the expected set.
    tier1_mismatch = {n: v for n, v in tier1.items() if v != (n in expected)}
    assert not tier1_mismatch, (
        f"Rule {rule_path.name}: Tier 1 disagrees with fixture expectations "
        f"while Tier 2 agrees: {tier1_mismatch}. Conversion is masking a logic bug."
    )
