# Local Codex Exec Pre-Push Review

This machine's sanctioned `rubin-protocol` push path is:

1. run local stack checks and `pre-pr` coverage preflight
2. call `cl push ...`
3. let `$(git rev-parse --git-path hooks-disabled/pre-push)` build the review bundle
4. let the hook run deterministic local gates plus isolated local `codex exec`
5. allow the network push only if there are no blocking findings

## Runtime contract

- Entry command: `cl push ...`
- Hook: `$(git rev-parse --git-path hooks-disabled/pre-push)`
- Review contract: `tools/prepush_review_contract.json`
- Prompt builder: `tools/prepush_prompt_pack.py`
- Skill-gate planner: `tools/check_local_prepush_skill_gates.py`

The hook launches `codex exec` in an isolated ephemeral `CODEX_HOME`, with a
read-only sandbox and JSON-schema output. The model/reasoning profile is picked
from `prepush_review_contract.json`; it is not a hardcoded one-size-fits-all
prompt.

## Runtime profiles

- `consensus_critical` -> `gpt-5.4` `xhigh`
- `formal_lean` -> `gpt-5.4` `xhigh`
- `code_noncritical` -> `gpt-5.4-mini` `xhigh`
- `diff_only` -> `gpt-5.4-mini` `xhigh`

The hook may clamp `diff_only` reasoning down when needed to avoid local stall
loops, but the sanctioned path remains the same: `cl push` -> `pre-push` ->
`codex exec` review.

If a local run hits a `no-json stall`, the hook may retry inside the same
sanctioned path with reduced reasoning for the affected review unit before it
gives up and blocks the push.

## Blocking policy

- Blocking severities: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `PERF`
- Advisory only: `INFO`, `STYLE`

If the hook reports blocking findings, push stays blocked. If it reports only
advisory findings or no findings, the wrapper may continue to the real network
push.

## Evidence files

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

There is no separate sanctioned helper script in the
current path. The review is part of the hook itself.
