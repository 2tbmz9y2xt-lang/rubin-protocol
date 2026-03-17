## Summary

<!-- What does this PR do? -->

## Scope

- [ ] Documentation-only
- [ ] Implementation-only change (no consensus change)
- [ ] Consensus-affecting change (requires explicit process)

**Consensus boundary (required):**

- Consensus rules unchanged: YES/NO
- `SECTION_HASHES.json` unchanged: YES/NO
- Wire format unchanged: YES/NO

## Evidence / Gates

<!-- Required for PV/CORE_EXT/consensus-sensitive areas -->

- CI links:
  - test:
  - coverage:
  - policy/validator:
- Conformance:
  - `run_cv_bundle.py`:
- Replay / determinism:
  - seq vs par equality (verdict/error/digests):

## Rollout / Flags (if applicable)

```text
pv-mode=off|shadow|on
pv-shadow-max=N
```

Refs: Q-XXX-YY-ZZ

