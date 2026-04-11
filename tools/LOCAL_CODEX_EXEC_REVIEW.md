# Local Codex Exec Pre-Push Review

This machine's sanctioned `rubin-protocol` push path is:

1. run local stack checks and `pre-pr` coverage preflight
2. call `cl push ...`
3. let `$(git rev-parse --git-path hooks-disabled/pre-push)` build the review bundle
4. let the hook run deterministic local gates plus isolated local `codex exec`
5. allow the network push only if there are no blocking findings

## Public repo boundary

- Entry command: `cl push ...`
- Hook: `$(git rev-parse --git-path hooks-disabled/pre-push)`
- Public repo contract stops here on purpose.
- This repository keeps only this README as the repo-facing pointer for this
  local push contract; unrelated repository tooling remains outside this
  contract boundary.
- The actual machine-local runtime assets live in the private orchestration
  repository under `inbox/operational/local_push_gate/protocol/`.
- That private path owns:
  - review contract JSON
  - prompt builder
  - skill-gate planner
  - summary validator
  - reusable preflight receipt helper
- `rubin-protocol` does not track those local push scripts/tests anymore.
- A clone without the private orchestration layer is intentionally unsupported
  for the sanctioned local push path and must fail closed before any network
  push.

## Blocking policy

- Blocking severities: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `PERF`
- Advisory only: `INFO`, `STYLE`

If the hook reports blocking findings, push stays blocked. If it reports only
advisory findings or no findings, the wrapper may continue to the real network
push.

## Evidence files

The local `pre-pr` receipt is written under the current git common-dir state
directory:

- `$(git rev-parse --git-common-dir)/local-security-review/pre-pr-receipt.json`

The live worktree-local review artifacts are written under the current git-dir
state directory:

- `last-run-id`
- `last-run-status`
- `last-run-meta.txt`
- `last-review-bundle.txt`
- `last-prompt.txt`
- `last-codex.log`
- `last-result-raw.json`
- `last-result.json`

The review still runs as part of the hook itself. The difference is location:
the runtime helpers now live in private orchestration state instead of this
public repository.
