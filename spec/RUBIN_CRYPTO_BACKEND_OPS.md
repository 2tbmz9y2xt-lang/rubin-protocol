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

В репо поддержан рабочий **operational FIPS path**:

- bundle-сборка устанавливает `fips.*` модуль;
- генерируется `fipsmodule.cnf`;
- генерируется `openssl-fips.cnf` с `default_properties = fips=yes`.

Это не меняет консенсус и не является заявлением о CMVP-статусе продукта.
Консенсус остаётся в `RUBIN_L1_CANONICAL.md`; FIPS-only — операционный режим запуска.

Что поддерживается в репо:

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
   - `scripts/crypto/openssl/build-openssl-bundle.sh` выполняет `enable-fips`, `install_fips`, `fipsinstall`.
   - На выходе ожидаются:
     - `<prefix>/lib/ossl-modules/fips.*`
     - `<prefix>/ssl/fipsmodule.cnf`
     - `<prefix>/ssl/openssl-fips.cnf`
