# RUBIN Crypto Backend Ops (NON-CONSENSUS)

Статус: **NON-CONSENSUS / operational**.

Назначение: операционные правила для crypto backend (OpenSSL) в клиентах/CI:

- KPI/перф-метрики;
- interop контроль (Go reference ↔ Rust parity);
- acceptance policy для изменений PQC stack и fallback процедур.

## 1) Source-of-truth документы

- `spec/RUBIN_CRYPTO_BACKEND_PROFILE.md` — **normative** профиль: OpenSSL-only, запреты зависимостей.
- `spec/RUBIN_SLH_FALLBACK_PLAYBOOK.md` — operational activation/rollback для SLH fallback (процедура).

## 2) KPI (baseline)

Рекомендуемый минимум KPI:

- verify throughput (ops/s) для ML-DSA и SLH-DSA;
- p99 latency batch verify (если используется);
- peak RSS при прогоне conformance bundle.

Политика: ухудшение >10% throughput или >20% p99 требует явного объяснения в PR.

## 3) Interop / acceptance

- `python3 conformance/runner/run_cv_bundle.py` MUST pass (Go↔Rust parity).
- Никаких “тихих” fallback путей без conformance coverage.

## 4) Рекомендованные команды

```bash
scripts/dev-env.sh -- python3 conformance/runner/run_cv_bundle.py
scripts/dev-env.sh -- bash -lc 'cd clients/go && go test ./...'
scripts/dev-env.sh -- bash -lc 'cd clients/rust && cargo test --workspace'
```

