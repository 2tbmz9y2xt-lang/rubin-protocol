# Аудит-репорт: Валидация второго аудита v1.1

**Date:** 2026-02-20
**Scope:** Валидация второго внешнего аудита против реального кода

---

## FALSE POSITIVES (7)

| Находка | Причина |
|---|---|
| P2P лимиты не реализованы | `inv.go` MaxInvEntries=50k, `headers.go` MaxHeadersPerMsg=2000, envelope MAX_RELAY_MSG_BYTES — всё есть |
| wolfCrypt hash integrity отсутствует | RUBIN_WOLFCRYPT_SHIM_SHA3_256 + STRICT реализованы в Go и Rust |
| BanScore не реализован | `banscore.go` — полная реализация с decay |
| unwrap/panic в consensus | 0 в продакшн пути |
| math/big overflow | big.Int безопасен от арифметического overflow |
| Differential testing отсутствует | run_cv_bundle.py делает cross-client сравнение |
| T-007 не доказана | lean4-proven в VersionBits.lean |

---

## РЕАЛЬНЫЕ НАХОДКИ → QUEUE.md

| Queue ID | Severity | Находка |
|---|---|---|
| Q-A10 | 🔴 P0 | **Go difficulty panic**: `maxTarget = targetOld*4` без cap на MAX_TARGET → `FillBytes([32]byte)` паникует при targetOld ≈ 0xFFFF... Rust безопасен (saturating). |
| Q-A11 | 🟠 P1 | TLS / P2P шифрование отсутствует — eclipse/MITM возможен |
| Q-A12 | 🟡 P1 | Threat Model документ отсутствует |
| Q-A05 | 🟠 P1 | SBOM отсутствует (уже в очереди) |

