# SigmaForge

Detection-as-code: a repository of Sigma detection rules with a CI
pipeline that lints them, validates their metadata, tests them against
sample event data, converts them to Elasticsearch queries, and deploys
them to an Elastic Stack. Rules that fail any gate do not merge.

A detection rule here is an artifact that must be reviewable, testable,
and explainable. Everything in this repo exists to enforce that.

## Two tier testing

**Tier 1, offline.** A pure Python evaluator (`sigmaforge/evaluator.py`)
parses each rule with pySigma and evaluates it directly against JSON
event fixtures. Every rule must fire on all of its `tp_` fixtures and
stay silent on all of its `fp_` fixtures. No Docker, runs in under a
second: `make test`.

**Tier 2, integration.** Each rule is converted to a Lucene query with
the real pySigma Elasticsearch backend (`ecs_windows` pipeline), the same
fixtures are indexed into a live Elasticsearch the way Winlogbeat would
ship them, the query runs, and the returned set must be exactly the
`tp_` fixtures. `make up && make test-all`.

Both tiers use the same fixture files. If they disagree, the test output
prints both results side by side: that divergence means the conversion
pipeline has a bug, and it is the most useful signal this repo produces.

## Quickstart

```
make install     # venv + pinned dependencies
make test        # Tier 1: evaluator, metadata gate, rule tests
make up          # Elasticsearch 8.19.3 + Kibana via docker compose
make test-all    # everything including Tier 2 integration tests
```

Current state: 8 rules, 32 fixtures, 175 offline tests plus 8
integration tests, all passing.

## Repository layout

```
rules/windows/           Sigma rules, one YAML per rule
tests/fixtures/<os>/<rule>/   tp_*.json / fp_*.json event fixtures
sigmaforge/              evaluator, loader, convert, deploy, coverage, scaffold
tests/                   Tier 1, metadata gate, Tier 2
docs/coverage.md         generated ATT&CK coverage (make coverage)
docs/navigator_layer.json  ATT&CK Navigator layer
```

## Rule and fixture conventions

A rule at `rules/windows/foo.yml` has fixtures at
`tests/fixtures/windows/foo/`. Files prefixed `tp_` must match, `fp_`
must not. Each fixture is one JSON event using Sysmon field names, with
an optional `_comment` explaining what it represents. A rule with no
fixture directory, or without at least one `tp_` and one `fp_` fixture,
fails the build. A rule without a false positive test is not a tested
rule.

Scaffold a new rule the right way with:

```
make new-rule NAME=my_rule_name
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the submission checklist.

## Make targets

| Target | What it does |
| --- | --- |
| `install` | venv, pinned deps, editable package install |
| `test` | Tier 1: evaluator, metadata, rule tests |
| `test-all` | full suite including `--integration` |
| `lint` | ruff |
| `coverage` | regenerate `docs/coverage.md` + Navigator layer |
| `up` / `down` | local Elasticsearch + Kibana |
| `convert RULE=rules/windows/foo.yml` | print a rule's Lucene query |
| `deploy` | dry run of the rule deploy (use `--push` to write) |
| `new-rule NAME=foo` | scaffold rule + fixture templates |

## ATT&CK coverage

Generated from rule tags by `make coverage`. Full table with technique
names and gaps in [docs/coverage.md](docs/coverage.md).

| Tactic | Techniques covered |
| --- | --- |
| command-and-control | T1105 |
| credential-access | T1003.001 |
| execution | T1059.001 |
| impact | T1490 |
| persistence | T1053.005, T1543.003, T1547.001 |
| privilege-escalation | T1053.005, T1055, T1543.003 |
| stealth | T1055, T1059.001 |

Tactics with zero coverage (honest gaps): collection, defense-impairment,
discovery, exfiltration, initial-access, lateral-movement,
reconnaissance, resource-development.

## Deployment

`python -m sigmaforge.deploy` converts every rule and upserts it (keyed
by rule UUID) into a `sigmaforge-rules` index. Dry run is the default;
`--push` writes and requires `ELASTIC_URL` to be set explicitly.
`ELASTIC_API_KEY` authenticates against a secured cluster. In CI the
deploy job only runs on push to main and is gated by the `production`
environment.

## Branch protection

GitHub cannot set these from repo code; configure once in
Settings -> Branches -> Add branch ruleset for `main`:

1. Require a pull request before merging, at least one approval.
2. Require status checks to pass: `test` and `integration` (the job
   names from `.github/workflows/ci.yml`).
3. Require branches to be up to date before merging.
4. Do not allow bypassing the above settings.

Also create the `production` environment under Settings -> Environments,
add `ELASTIC_URL` and `ELASTIC_API_KEY` as environment secrets, and
require reviewers on it so a deploy to the live SIEM always has a human
in the loop.

## Local stack notes

`docker-compose.yml` runs single-node Elasticsearch 8.19.3 and Kibana
with security disabled and memory capped (2g/1g). That configuration is
for local development only; never expose those ports.
