# Contributing a rule

Every rule in this repo is an artifact that must be reviewable, testable,
and explainable. The gates in CI enforce that; this checklist is the
human version.

## Workflow

1. `make new-rule NAME=my_rule_name` scaffolds the rule file and its
   fixture directory with tp_/fp_ templates.
2. Fill in the detection logic and every TODO in the metadata.
3. Replace the fixture templates with real events. Minimum 2 `tp_` and
   2 `fp_` fixtures. Use Sysmon field names.
4. `make test` until green, `make lint` for style.
5. `make up && make test-all` to prove the rule survives conversion to
   Elasticsearch.
6. `make coverage` and commit the regenerated docs.
7. Open a PR. The template asks for the technique, the FP story, and
   what you tested against.

## Rule submission checklist

- [ ] Title says what is detected and where, under 120 chars, no trailing period
- [ ] Fresh UUID, unique in the repo (the scaffold generates one)
- [ ] Description of at least 40 chars: behavior, why it matters, which
      log source and EventID sees it
- [ ] `logsource` has product/category (or service)
- [ ] At least one `attack.tNNNN` technique tag that exists in ATT&CK,
      plus real tactic tags
- [ ] `falsepositives` describes actual benign activity. "Unknown" fails CI
- [ ] At least one reference URL
- [ ] 2+ `tp_` fixtures covering distinct attack variants
- [ ] 2+ `fp_` fixtures of plausible benign activity that a naive version
      of the rule would catch. An empty event is not an FP fixture
- [ ] Each fixture has a `_comment` explaining what it represents
- [ ] `make test` and `make test-all` pass
- [ ] `docs/coverage.md` regenerated

## What reviewers push back on

- FP fixtures that could never fire the rule anyway. The FP fixture's job
  is to prove the filter earns its place.
- Filters broader than the FP story requires (an attacker should not be
  able to hide by naming a binary after your filter).
- Detection logic that relies on a field the stated logsource does not emit.
