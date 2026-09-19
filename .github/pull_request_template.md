## Summary

<!-- What does this change, and why? -->

## Checklist

- [ ] `npm run lint && npm run format && npm run typecheck && npm run typecheck:tests && npm run build && npm test` all pass locally
- [ ] If this adds/changes a check: it has a true-positive fixture (fires) and a true-negative fixture (stays silent) — see `test/checks/` and `test/fixtures/{vulnerable,clean}-agent/`
- [ ] `CHECKS.md` updated to match, if a check's id/title/severity/heuristic/remediation changed
- [ ] `CHANGELOG.md` entry added under `[Unreleased]`
- [ ] `DECISIONS.md` entry added, if this involved a non-obvious choice (library pick, heuristic trade-off, scope cut)

## Anything reviewers should look at closely?

<!-- Optional: call out a tricky part, an open question, or an assumption worth double-checking. -->
