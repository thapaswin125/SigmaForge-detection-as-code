# SigmaForge

**Detection-as-code, taken literally.** A Sigma rule repository where every
detection rule is treated like production software: parsed, unit tested
against attack and benign event samples, converted to an Elasticsearch
query with the real backend, replay tested against a live cluster, and
deployed through a gated CI pipeline. A rule that cannot prove it fires
on the attack and stays silent on the lookalike does not merge.

```
$ make test
335 passed in 0.61s        # every rule vs every fixture, no Docker

$ make test-all
353 collected              # + one Tier 2 replay per rule against live Elasticsearch
```

18 rules, 72 fixtures, 13 of the 15 ATT&CK tactics.
**[Live coverage dashboard](https://thapaswin125.github.io/SigmaForge-detection-as-code/)**,
regenerated from test outcomes on every push to `main`.

## Why this exists

Most detection repos are YAML files and good intentions. The failure
modes are always the same: rules that never fired in testing, rules that
page the on-call for every backup job, and conversion pipelines that
silently mangle logic on the way to the SIEM. SigmaForge attacks all
three with the same idea: **a detection rule is an artifact that must be
reviewable, testable, and explainable**, and the repository's job is to
make the wrong way harder than the right way.

## The two tier testing model

```mermaid
flowchart LR
    R[rules/*.yml] --> G1[metadata gate]
    R --> T1[Tier 1: offline evaluator]
    F[fixtures tp_*.json / fp_*.json] --> T1
    R --> C[pySigma ecs_windows conversion]
    C --> T2[Tier 2: live Elasticsearch replay]
    F --> T2
    T1 <-. must agree .-> T2
    T2 --> D[deploy: gated, dry-run default]
```

**Tier 1** is a pure Python Sigma evaluator ([sigmaforge/evaluator.py](sigmaforge/evaluator.py))
that walks pySigma's parsed condition tree and evaluates rules directly
against JSON events. It implements Sigma's full matching semantics:
case-insensitive equality, `contains`/`startswith`/`endswith`, regex,
`base64`/`base64offset`, `cidr`, numeric comparisons, `windash` dash
variants, wildcards, null handling, keyword search, and every condition
form (`and`/`or`/`not`, parentheses, `1 of selection_*`, `all of them`).
It has its own 45-test suite because everything else trusts it. The
whole tier runs in well under a second, so it gates every commit.

**Tier 2** converts each rule to a Lucene query with the real
`pySigma-backend-elasticsearch` + `ecs_windows` pipeline, indexes the
same fixture events into a live Elasticsearch the way Winlogbeat would
ship them, runs the query, and asserts the hit set is **exactly** the
true positive fixtures. Not a superset. Exactly.

Both tiers share the same fixture files on purpose. If they ever
disagree, the test fails loudly and prints both results side by side:

```
fixture                                  expected  tier1  tier2
fp_backup_retention                         False  False   True
fp_vssadmin_list                            False  False   True
tp_vssadmin_quiet                            True   True   True
tp_wmic_shadowcopy                           True   True   True

TIER 1 / TIER 2 DIVERGENCE on ['fp_backup_retention', 'fp_vssadmin_list']:
the offline evaluator and the converted Elasticsearch query disagree.
The conversion pipeline (or the evaluator) has a bug.
```

That divergence signal is the single most useful thing this repo
produces: it means the logic you reviewed is not the logic your SIEM is
running.

## What a rule looks like here

Every rule ships with a false positive story, and the FP fixtures are
benign events that a naive version of the rule would catch:

```yaml
detection:
    selection_vssadmin:
        Image|endswith: '\vssadmin.exe'
        CommandLine|contains|all: ['delete', 'shadows']
    selection_wmic:
        Image|endswith: '\wmic.exe'
        CommandLine|contains|all: ['shadowcopy', 'delete']
    filter_backup_software:
        ParentImage|startswith:
            - 'C:\Program Files\Veeam\'
            - 'C:\Program Files\Microsoft Data Protection Manager\'
            - 'C:\Program Files\Veritas\'
    condition: 1 of selection_* and not filter_backup_software
```

Run against a live cluster, the ransomware precursor alerts and the
byte-for-byte identical command from a backup suite does not:

```
events indexed: 2 (one ransomware precursor, one Veeam backup cleanup)
query returned: 1 hit(s)
  ALERT -> tp_vssadmin_quiet
          command_line: vssadmin.exe delete shadows /all /quiet
          parent:       C:\Windows\System32\cmd.exe
```

Delete the `filter_backup_software` clause and CI tells you precisely
what you broke:

```
FAILED test_rule[shadow_copy_deletion-fp_backup_retention]
AssertionError: Rule shadow_copy_deletion.yml MATCHED false positive
fixture fp_backup_retention. The rule would fire on this benign activity.
```

## Live detection on real telemetry

The same rules that pass the test suite can run against **live Windows
process telemetry**, using the exact same offline evaluator
([sigmaforge/evaluator.py](sigmaforge/evaluator.py)) that Tier 1 proves. A
detection printed here is the identical rule logic CI validated, firing on
real activity on the host rather than on a JSON fixture.

```bash
make collect                       # watch until Ctrl+C
make collect ARGS="--duration 30"  # watch for 30 seconds
make collect ARGS="--jsonl"        # one JSON object per detection
```

```
SigmaForge live detection
  14 process_creation rules armed against the live WMI feed.
  4 rule(s) not exercised by this feed (need create_remote_thread, process_access, registry_set telemetry).

 MEDIUM  Archive Utility Staging Data With Password Or Into A World-Writable Path  [T1074.001, T1560.001]
    pid 13892  C:\Windows\system32\makecab.exe
    cmd  "C:\Windows\system32\makecab.exe" "...\collected.bin" "C:\Users\...\AppData\Local\Temp\staged.cab"
```

The event source is a zero-dependency WMI feed
([sigmaforge/feeds/wmi_process_feed.ps1](sigmaforge/feeds/wmi_process_feed.ps1)):
it snapshots the process table on an interval and emits each new process as
a Sysmon-shaped event, so it needs **no Sysmon install and no administrator
rights**. Only the 14 `process_creation` rules run against it; the four
registry/handle/thread rules need their own telemetry and are reported as
out of scope rather than silently skipped.

Honest limitation: a polling feed cannot see a process that starts *and*
exits within one interval (a ~50 ms `whoami` can slip between two polls).
Production deployments point SigmaForge at Sysmon's ETW stream, which is
push-based and has no such gap. **The evaluator and rules are identical
either way** — only the event source changes, which is the whole point of
keeping matching in one place.

## The gates

| Gate | What it rejects |
| --- | --- |
| Metadata (217 checks) | missing UUIDs, duplicate IDs, "Unknown" as the FP story, fake ATT&CK technique IDs, tactic tags that are not real tactics, missing references |
| Tier 1 rules | any rule that misses a `tp_` fixture or fires on an `fp_` fixture |
| Fixture convention | rules with no fixtures, no TP fixture, or no FP fixture. A rule without a false positive test is not a tested rule |
| Tier 2 integration | rules whose converted query returns anything other than exactly the TP set |
| Coverage freshness | PRs that change rules without regenerating `docs/coverage.md` |

Every failure message names the rule file and the specific problem.

## Current coverage

18 rules covering 26 techniques across 13 of the 15 tactics (MITRE
ATT&CK v19.1), generated by `make coverage` into
[docs/coverage.md](docs/coverage.md) and an
[ATT&CK Navigator layer](docs/navigator_layer.json):

| Tactic | Techniques |
| --- | --- |
| collection | T1074.001 Local Data Staging, T1539 Steal Web Session Cookie, T1555.003 Credentials from Web Browsers, T1560.001 Archive via Utility |
| command-and-control | T1105 Ingress Tool Transfer |
| credential-access | T1003.001 LSASS Memory, T1539, T1555.003 |
| defense-impairment | T1070 Indicator Removal, T1685 Disable or Modify Tools, T1685.005 Clear Windows Event Logs |
| discovery | T1018 Remote System Discovery, T1087.002 Domain Account, T1482 Domain Trust Discovery |
| execution | T1047 WMI, T1059.001 PowerShell, T1204.002 Malicious File, T1566.001 Spearphishing Attachment |
| exfiltration | T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol, T1567 Exfiltration Over Web Service |
| impact | T1490 Inhibit System Recovery |
| initial-access | T1204.002, T1566.001 |
| lateral-movement | T1021.002 SMB/Admin Shares, T1021.006 WinRM, T1047, T1570 Lateral Tool Transfer |
| persistence | T1053.005 Scheduled Task, T1543.003 Windows Service, T1547.001 Run Keys |
| privilege-escalation | T1053.005, T1055 Process Injection, T1543.003 |
| stealth | T1055, T1059.001 |

**Reconnaissance** and **resource-development** are deliberately empty.
Both describe adversary activity that happens on infrastructure you do
not own, before anything touches your estate, so endpoint telemetry
cannot see them. A rule claiming to cover them would be theatre. The
generated doc lists every zero-coverage tactic explicitly, because
honest gaps beat imaginary coverage.

Note the tactic names: ATT&CK v19 renamed `defense-evasion` to
`stealth` and added `defense-impairment`. The coverage generator reads
tactics out of pySigma's bundled ATT&CK dataset rather than a hardcoded
list, so this repo tracked the rename for free.

## Quickstart

```bash
make install     # venv + exact-pinned dependencies
make test        # Tier 1: evaluator, metadata gate, rule tests (< 1s)
make up          # Elasticsearch 8.19.3 + Kibana, single node, memory capped
make test-all    # everything, including Tier 2 replay
make new-rule NAME=my_rule    # scaffold a rule + fixture templates
make convert RULE=rules/windows/shadow_copy_deletion.yml
make deploy      # dry run; --push required to write, ELASTIC_URL required to push
```

Requires Python 3.11+, Docker, and make. Tested on Linux, macOS, and
Windows.

## Design decisions worth knowing about

**The evaluator walks pySigma's AST instead of reimplementing Sigma.**
pySigma already parses conditions into an
`AND`/`OR`/`NOT`/`FieldEqualsValue` tree with all modifiers folded into
typed leaf values. Tier 1 walks that tree, so rule parsing can never
disagree between tiers by construction. Matching semantics were chosen
to mirror the Lucene backend where Sigma leaves room: `re` is anchored
(Lucene `field:/regex/` is anchored), keywords are substrings (Lucene
renders unbound values as `*value*`).

**The event mapper is extracted from the pipeline, not copied.** Tier 2
must index fixtures with the same Sysmon-to-ECS field mapping the rule
conversion uses. Instead of maintaining a parallel mapping table,
[sigmaforge/convert.py](sigmaforge/convert.py) reads the mapping out of
the installed `ecs_windows` pipeline object at runtime. It cannot drift.

**The metadata gate validates against real ATT&CK data.** Technique and
tactic tags are checked against pySigma's bundled MITRE dataset, not a
regex. This caught a real issue during development: ATT&CK v19 replaced
the defense-evasion tactic, and the gate rejected the stale tag.

**Deploys are dry-run by default.** `python -m sigmaforge.deploy`
prints what would ship. Writing requires both `--push` and an explicit
`ELASTIC_URL`, and the CI deploy job only runs on main behind a
protected environment. Nobody ships to a live SIEM from a fork by
accident.

**Scaffolding makes the right way the lazy way.** `make new-rule`
generates the rule skeleton with a fresh UUID plus tp_/fp_ fixture
templates. The scaffold deliberately fails the gates until the
detection logic, FP story, and fixtures contain real content.

## Repository layout

```
rules/windows/                 one YAML per rule
tests/fixtures/<os>/<rule>/    tp_*.json / fp_*.json, one event each
sigmaforge/                    evaluator, loader, convert, deploy, coverage, scaffold, collect
sigmaforge/feeds/              live telemetry feeds (wmi_process_feed.ps1)
tests/                         evaluator suite, metadata gate, Tier 1, Tier 2
docs/                          generated coverage.md + navigator_layer.json
.github/workflows/             ci.yml (test -> integration -> deploy), pages.yml
```

## CI

Three jobs in [.github/workflows/ci.yml](.github/workflows/ci.yml):

1. **test**: ruff, evaluator suite, metadata gate, Tier 1 rule tests,
   coverage doc freshness.
2. **integration**: Elasticsearch service container, `pytest --integration`.
3. **deploy**: main only, gated by a `production` environment with
   `ELASTIC_URL`/`ELASTIC_API_KEY` secrets.

Recommended branch protection for `main` (Settings -> Branches): require
a PR with one approval, require the `test` and `integration` checks,
require branches up to date, no bypass. Add required reviewers on the
`production` environment so every deploy has a human in the loop.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the submission checklist. The
PR template asks three questions: what technique, what is the FP story,
and what did you test it against. If those are hard to answer, the rule
is not ready.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

SigmaForge imports pySigma and its Elasticsearch backend as unmodified
LGPL-2.1 libraries; the attribution and their terms are recorded in
NOTICE. MITRE ATT&CK is a registered trademark of The MITRE Corporation,
used here under MITRE's terms of use. MITRE has not reviewed or endorsed
this project.
