# Legacy Manual Codex Review Notes for `rubin-protocol`

This file is intentionally **not** the sanctioned default local push contract
anymore.

Current sanctioned reviewer-first path on this machine:

1. run local stack checks and the usual `pre-pr` coverage preflight
2. run the local Claude reviewer skill/runtime `rubin-claude-review-prepush`
   via `$HOME/bin/claude-review`
3. call `cl push ...`
4. use Codex only if an explicit controller or user instruction asks for an
   extra passive/manual second opinion

## Boundary

- Do **not** treat this file as the source of truth for reviewer selection.
- Do **not** treat `codex exec` as a required pre-push step.
- Do **not** use manual Codex review as a bypass for blocking Claude findings
  or deterministic local gates.

## Canonical sources

- the local orchestration policy `rubin-orchestration-private/inbox/operational/LOCAL_PUSH_GATE_CONTRACT.md`
- the local Claude review skill at `$HOME/.agents/skills/rubin-claude-review-prepush/SKILL.md`

This file survives only as a legacy/manual Codex pointer so old repo links do
not imply that Codex is still the sanctioned default.
