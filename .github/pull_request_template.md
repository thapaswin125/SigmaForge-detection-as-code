# Rule PR

## What technique does this detect?

ATT&CK technique ID and a sentence on the attacker behavior.

## What is the false positive story?

What benign activity would a naive version of this rule catch, and how do
the filters and fp_ fixtures address it?

## What did you test it against?

Where did the fixture events come from (lab telemetry, sanitized
production events, public samples)? Anything you tried that the rule
missed?

## Checklist

- [ ] `make test` passes
- [ ] `make test-all` passes with the local stack up
- [ ] `docs/coverage.md` regenerated with `make coverage`
- [ ] FP fixtures represent plausible benign activity, not empty events
