# OpenSSL CVE Response Runbook

Status: Operational policy (repository enforcement)  
Scope: `clients/go`, `clients/rust`, OpenSSL bundle pipeline, release packaging

## 1) Intake and Disclosure Channels

Primary intake channels:

1. GitHub Security Advisory (private report for this repository).
2. OpenSSL upstream security advisories and release notes.
3. NVD/CVE feed items referencing OpenSSL 3.x.

Internal disclosure path:

1. Open a private incident thread titled `OPENSSL-CVE-<id>`.
2. Assign one incident owner and one backup owner.
3. Record first-seen timestamp (UTC) and affected repository refs.

## 2) SLA Targets

The response SLA is measured from first-seen timestamp.

| Severity | Triage start | Impact decision | Patch PR opened | Release evidence complete |
|---|---:|---:|---:|---:|
| Critical (RCE/memory corruption in active path) | <= 2h | <= 6h | <= 24h | <= 48h |
| High | <= 4h | <= 12h | <= 48h | <= 72h |
| Medium | <= 1 business day | <= 2 business days | <= 5 business days | <= 7 business days |
| Low | <= 2 business days | <= 5 business days | Planned maintenance window | Planned maintenance window |

If SLA cannot be met, incident owner MUST publish a blocker note with ETA and mitigation status.

## 3) Patch Triage Procedure

1. Confirm whether affected OpenSSL versions intersect:
   - bundled version in CI/build scripts,
   - local runtime requirements in `scripts/dev-env.sh`,
   - production deployment constraints (if applicable).
2. Classify impact:
   - **Consensus-impacting**: can alter accept/reject decisions or signature verification outcomes.
   - **Operational-only**: availability/perf/compliance without consensus drift.
3. Prepare mitigation:
   - version bump and bundle rebuild,
   - temporary runtime guard (if needed),
   - tests for regression and deterministic behavior.
4. Open one PR for code/tooling updates and one PR for spec/ops updates when required.
5. Run mandatory validation gates before merge:
   - `policy`, `test`, `security_ai`, `formal`, `formal_refinement`, `validator`, `CodeQL`.

## 4) Release Evidence Requirements

A CVE response is not complete until evidence is attached in the release note or incident report.

Required evidence block:

1. CVE identifier(s) and severity.
2. Affected component list (Go/Rust/bundle/CI).
3. Fixed OpenSSL version and bundle hash/checksum.
4. PR links and merge commit SHAs.
5. CI run IDs for required checks.
6. `fips-preflight.sh` result for `RUBIN_OPENSSL_FIPS_MODE=only`.
7. Rollback instruction (previous known-good version + trigger condition).

## 5) Controller Escalation Rule

Mark as **НУЖНО ОДОБРЕНИЕ КОНТРОЛЕРА** when the mitigation requires:

- consensus-rule changes,
- error-code remapping in consensus paths,
- wire-format changes,
- governance-level freeze exceptions.

Operational-only OpenSSL version updates do not require controller approval if consensus behavior is unchanged.

## 6) Closure Criteria

Incident can be closed only when all are true:

1. Patch merged to default branch.
2. Required CI checks green on merge commit.
3. Evidence block complete.
4. Queue task updated to `DONE` with evidence reference.
