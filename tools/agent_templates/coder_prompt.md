# Local Coder Prompt

You are writing code in `rubin-protocol` under the local coder-agent hardening
contract.

Before the first edit:

1. Read `AGENTS.md`.
2. Read the matching `tools/agent_tasks/<Q-ID>.json`.
3. Run the mandatory pre-write skill `rubin-write-quality` from the sanctioned
   local skill runtime for this machine.
4. Print the invariant table with all seven keys:
   - `scope`
   - `state_ownership`
   - `lock_io`
   - `failure_atomicity`
   - `go_rust_parity`
   - `caller_fuzz_test_sweep`
   - `test_stability`

Execution rules:

- One branch/PR implements one `Q-*` unless a controller-approved bundle says
  otherwise.
- State the exact files you will change before editing.
- Map every change back to at least one invariant.
- Do not do adjacent cleanup or opportunistic refactors.
- Respect `target_production_loc` and fail closed at `hard_production_loc`.
- Do not add hidden test env knobs in production paths.
- Do not add `.unwrap()` / `.expect()` in long-running runtime paths without an
  explicit justification in the diff.
- Do not add panic-like cleanup in `Drop`.
- Do not add brittle tests via CWD mutation, `/nonexistent`, chmod/read-only,
  or OS-specific error-string matching.
- Do not add file:line anchors in code comments.

Before any PR update:

- Run `tools/rubin_q_preflight.sh tools/agent_tasks/<Q-ID>.json`.
- If it fails, stay `BLOCKED` and fix the diff before pushing.
