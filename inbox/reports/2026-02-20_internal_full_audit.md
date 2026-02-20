# Аудит-репорт: Внутренний полный аудит consensus кода

**Date:** 2026-02-20  
**Scope:** Самостоятельный полный анализ Go+Rust consensus слоя  
**Methodology:** Code review + cross-client diff analysis + arithmetic proofs  

---

## Скоуп проверки

Файлы проанализированы полностью (byte-for-byte сравнение Go vs Rust):

- `clients/go/consensus/validate.go` (925 строк) vs `clients/rust/.../validate.rs` (724 строки)
- `clients/go/consensus/pow.go` vs `.../pow.rs`
- `clients/go/consensus/sighash.go` vs `.../sighash.rs`
- `clients/go/consensus/encode.go` vs `.../encode.rs`
- `clients/go/consensus/parse.go` vs `.../parse.rs`
- `clients/go/consensus/compactsize.go` vs `lib.rs compact_size_decode`
- `clients/go/consensus/chainstate_hash.go` vs `.../chainstate_hash.rs`
- `clients/go/consensus/util.go` vs `.../util.rs`
- `clients/go/consensus/wire.go` vs `.../wire.rs`
- `clients/go/node/p2p/` — envelope, banscore, inv, headers

---

## ПОДТВЕРЖДЁННЫЕ РЕАЛЬНЫЕ НАХОДКИ

### FIND-1: VAULT spend_delay overflow → timelock bypass
**Severity:** 🔴 HIGH  
**Files:** `validate.go:812`, `validate.rs:594`  
**Queue:** Q-A13

```go
// Go (validate.go:812) — UNCHECKED
if chainHeight < prevCreationHeight+spendDelay {
    return fmt.Errorf("TX_ERR_TIMELOCK_NOT_MET")
}
```
```rust
// Rust (validate.rs:594) — UNCHECKED (no overflow-checks in Cargo.toml)
&& chain_height < prev_creation_height + spend_delay
```

**Exploit:** Атакующий создаёт `CORE_VAULT_V1` output с `spend_delay = 2^64 - creationHeight`.
Сложение wraps в `1`. При `chainHeight > 1` условие `chainHeight < 1` → **false** → spend_delay
полностью обходится, vault немедленно тратим.

```
prevCreationHeight=500, spend_delay=18446744073709551117
(500 + 18446744073709551117) mod 2^64 = 1
chainHeight=100 < 1 → False → BYPASS
```

**Оба клиента затронуты одинаково** → нет форка, но vault timelock бесполезен при crafted spend_delay.

**Фикс:**
```go
// Go
unlockHeight, err := addUint64(prevCreationHeight, spendDelay)
if err != nil { return fmt.Errorf("TX_ERR_PARSE") }
if chainHeight < unlockHeight { return fmt.Errorf("TX_ERR_TIMELOCK_NOT_MET") }
```
```rust
// Rust
let unlock = prev_creation_height.checked_add(spend_delay)
    .ok_or("TX_ERR_PARSE")?;
if chain_height < unlock { return Err("TX_ERR_TIMELOCK_NOT_MET".into()); }
```

---

### FIND-2: parseInput — нет лимита на script_sig size
**Severity:** 🟠 MEDIUM (DoS в non-P2P контексте)  
**Files:** `parse.go:22-25`, `parse.rs:30-35`  
**Queue:** Q-A14

```go
// Go — allocates arbitrary bytes
scriptSigLen, err := toIntLen(scriptSigLenU64, "script_sig_len")
scriptSigBytes, err := cur.readExact(scriptSigLen)  // NO CAP
```

Spec §3.3: `script_sig_len` допустим только `0` или `32`, но парсер принимает любое значение.  
`MaxRelayMsgBytes=8MB` защищает P2P-канал, но:
- CLI/file import: `ParseBlockBytes(hugeFile)` → OOM
- Тестовые fixtures: могут содержать oversized transactions
- RPC-путь: зависит от реализации node

**Фикс:** В `parseInput` сразу после чтения `scriptSigLen`:
```go
if scriptSigLenU64 > 32 { return TxInput{}, fmt.Errorf("parse: script_sig too large") }
```

---

### FIND-3 (уже Q-A10): Go difficulty panic с MAX_TARGET
**Severity:** 🔴 HIGH  
**File:** `pow.go:96`

Подтверждено ранее. `maxTarget = targetOld * 4` через `big.Int` без cap на `maxTargetBig`.
При `targetOld = MAX_TARGET`, `maxTarget = MAX_TARGET*4` (258 бит) → `FillBytes([32]byte)` → panic.

---

### FIND-4: Go TxWeight — `base = base * 4` без overflow check
**Severity:** 🟢 LOW  
**File:** `validate.go:13`  
**Queue:** Q-A15

```go
// Go
base = base * 4  // bare int multiplication

// Rust
let base_weight = (base as u64).checked_mul(4)
    .ok_or_else(|| "TX_ERR_PARSE".to_string())?;
```

На 64-bit Go (`int`=64-bit) overflow невозможен при реалистичных транзакциях.
На 32-bit Go (`int`=32-bit) теоретически возможен, но P2P limits предотвращают.
Несогласованность с паттерном Rust — стоит исправить для единообразия.

---

## ЧТО ПОЛНОСТЬЮ ПРОВЕРЕНО И КОРРЕКТНО

| Компонент | Результат |
|---|---|
| CompactSize encode/decode (Go и Rust) | Идентичны, non-minimal rejection есть |
| Sighash preimage (Go vs Rust) | Байт-в-байт идентичны |
| UTXO set hash / sort (Go vs Rust) | Идентичны, domain prefix и lex sort |
| Merkle tree (odd node) | Нет CVE-2012-2459 (нет дублирования, promote) |
| Block header encoding (116 bytes) | LE, идентичны |
| addUint64/add_u64 overflow protection | Реализованы корректно |
| subUint64/sub_u64 underflow protection | Реализованы корректно |
| seenNonces map — nonce replay | Корректно, per-block |
| UTXO double-spend detection | seen() HashSet/map корректно |
| In-block spend ordering | Outputs добавляются в конце каждого tx → корректно |
| COINBASE_MATURITY overflow | Константа=100, не user-supplied → безопасно |
| HTLC_V2 matching anchor semantics | Per-tx (spec-compliant, intentional) |
| P2P BanScore | Реализован с decay |
| P2P inv/headers limits | MaxInvEntries=50k, MaxHeadersPerMsg=2000 |
| wolfCrypt shim hash check | RUBIN_WOLFCRYPT_SHIM_SHA3_256 + STRICT |
| MAX_RELAY_MSG_BYTES | 8MB, enforced до read payload |
| Rust unsafe | Только wolfCrypt FFI, изолировано |
| Go goroutine races | 0 (go test -race пройден) |
| TIMELOCK_V1 signature semantics | Go и Rust: SENTINEL → нет подписи (корректно по спеку) |

---

## ИТОГ

| Queue ID | Severity | Тип |
|---|---|---|
| Q-A13 | 🔴 HIGH | Vault spend_delay overflow — timelock bypass |
| Q-A10 | 🔴 HIGH | Go difficulty FillBytes panic |
| Q-A14 | 🟠 MEDIUM | parseInput script_sig OOM |
| Q-A15 | 🟢 LOW | Go TxWeight unchecked multiply |

**Никаких расхождений между Go и Rust** в алгоритмах сериализации, sighash, chainstate hash, difficulty retarget, или структуре валидации. Форк-риск минимален.

Критический приоритет: **Q-A13 + Q-A10** — оба фиксируются за 2-3 часа кода.
