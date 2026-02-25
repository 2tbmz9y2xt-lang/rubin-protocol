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
scripts/dev-env.sh -- bash -c 'cd clients/go && go test ./...'
scripts/dev-env.sh -- bash -c 'cd clients/rust && cargo test --workspace'
```

## 5) FIPS-ready (operational)

Репо поддерживает операционный FIPS-path через OpenSSL providers:

- `scripts/crypto/openssl/build-openssl-bundle.sh` теперь делает `enable-fips` + `install_fips` +
  `openssl fipsinstall`, создавая `fipsmodule.cnf` и `openssl-fips.cnf`.
- `scripts/crypto/openssl/fips-preflight.sh` проверяет загрузку `provider=fips` и видимость
  `ML-DSA`/`SLH-DSA` в режиме `RUBIN_OPENSSL_FIPS_MODE=only`.
- CI включает preflight в `mode=only` на собранном OpenSSL bundle.

Что это **не** означает:
- Это не автоматическая заявка “production FIPS compliance by default”.
- Для production/FIPS-claims нужны отдельные compliance-процедуры (CMVP scope, runtime policy,
  конкретная версия/сертификат, deployment controls).

Итого для Phase‑0/devnet:
- допустимы оба режима: `default` provider и `fips` provider;
- консенсус остаётся неизменным (provider selection non-consensus);
- формулировка уровня репо: `NIST/FIPS-aligned`, без overclaim про полный production compliance.

Что должно быть готово **заранее** (и уже поддерживается репо):

1) **OpenSSL-only** профиль (нормативно + CI enforcement):
   - `spec/RUBIN_CRYPTO_BACKEND_PROFILE.md`
   - CI: `python3 tools/check_crypto_backend_policy.py`

2) **Подмена OpenSSL без правок кода** (через env):
   - `RUBIN_OPENSSL_PREFIX=/path/to/openssl-prefix` (см. `scripts/dev-env.sh`)
   - опционально: `RUBIN_OPENSSL_MODULES=/path/to/ossl-modules`, `RUBIN_OPENSSL_CONF=/path/to/openssl.cnf`

3) **Preflight для FIPS provider**:

```bash
RUBIN_OPENSSL_FIPS_MODE=ready scripts/dev-env.sh -- scripts/crypto/openssl/fips-preflight.sh
RUBIN_OPENSSL_FIPS_MODE=only  scripts/dev-env.sh -- scripts/crypto/openssl/fips-preflight.sh
```

4) **Функциональная проверка “FIPS bundle build”** (не CMVP-сертификация):
   - `scripts/crypto/openssl/build-openssl-bundle.sh` собирает OpenSSL с `enable-fips`,
     устанавливает FIPS module и генерирует runtime `openssl-fips.cnf`.
