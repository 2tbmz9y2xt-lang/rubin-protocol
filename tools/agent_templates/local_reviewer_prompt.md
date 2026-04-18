# Local Reviewer Prompt

Read-only review for the current `Q-*` diff in `rubin-protocol`.

Review the diff against the task manifest and report only concrete findings.

Check:

- violated invariant from the seven-item invariant table
- scope drift versus `allowed_files`, `allowed_globs`, and `forbidden_globs`
- brittle test patterns: CWD mutation, `/nonexistent`, chmod/read-only,
  OS-error-string matching
- hidden test knobs in production paths
- caller/fuzz/test sweep omissions that leave dead-path or false-coverage claims
- mismatch between acceptance criteria / PR body and what the diff or tests
  actually prove

Rules:

- Stay read-only.
- Review only the current changed surface plus direct companions needed to prove
  a finding.
- Do not ask for unrelated cleanup.
- Prefer reviewer-worthy correctness, parity, contract, and drift findings over
  style feedback.
