# ТЗ: тесты для достижения coverage ≥70% (clients/go/consensus)

**Дата:** 2026-02-19  
**Файл:** `clients/go/consensus/`  
**Текущее покрытие:** consensus 24.8% / global 14.2%  
**Цель:** consensus ≥70% / global ≥50%  
**Файлы тестов:** добавлять в `clients/go/consensus/*_test.go`

---

## Приоритет 1 — критические пробелы (0% → нужно)

### 1.1 `parse.go` — ParseTxBytes / ParseBlockBytes (0%)

Все функции парсинга полностью без тестов. Самый большой вклад в coverage.

**Тест-файл:** `parse_test.go`

```
TestParseTxBytes_Valid
  - корректный tx: 1 input + 1 output + 1 witness (ML-DSA)
  - корректный tx: coinbase (нет inputs, нет witnesses)
  - trailing bytes → "parse: trailing bytes"

TestParseTxBytes_Truncated
  - обрезанный на version
  - обрезанный на input list
  - обрезанный на output list
  - обрезанный на witness
  - compactsize overflow в input_count

TestParseBlockBytes_Valid
  - блок с 1 coinbase транзакцией
  - блок с coinbase + 2 обычными tx
  - trailing bytes → BLOCK_ERR_PARSE

TestParseBlockHeader
  - корректный 116-байтовый header
  - короткий header → ошибка
  - truncated на midfield

TestParseOutput_CovenantTypes
  - CORE_P2PK output bytes
  - CORE_TIMELOCK_V1 output bytes
  - CORE_HTLC_V1 output bytes
  - CORE_VAULT_V1 output bytes (73 bytes и 81 bytes)

TestParseWitnessItem
  - SUITE_ID_SENTINEL (suiteID=0, нет pubkey/sig)
  - SUITE_ID_ML_DSA
  - SUITE_ID_SLH_DSA
  - неизвестный suiteID
```

---

### 1.2 `validate.go` — ApplyBlock (0%)

Самая важная функция — полностью непокрыта.

**Добавить в:** `apply_block_test.go`

```
TestApplyBlock_Valid
  - минимальный блок: coinbase tx только
    input ctx: height=1, ancestors=[genesis_header], utxo={}
    ожидание: OK, utxo содержит coinbase output

TestApplyBlock_MerkleInvalid
  - block.Header.MerkleRoot = неправильный хеш
  - ожидание: BLOCK_ERR_MERKLE_INVALID

TestApplyBlock_PoWInvalid
  - block.Header.Target = все нули (impossibly hard)
  - ожидание: BLOCK_ERR_POW_INVALID

TestApplyBlock_TimestampTooOld
  - block.Timestamp = medianPastTimestamp - 1
  - ожидание: BLOCK_ERR_TIMESTAMP_OLD

TestApplyBlock_TimestampTooFuture
  - blockCtx.LocalTimeSet=true, LocalTime = block.Timestamp - MAX_FUTURE_DRIFT - 1
  - ожидание: BLOCK_ERR_TIMESTAMP_FUTURE

TestApplyBlock_WeightExceeded
  - блок с tx превышающим MAX_BLOCK_WEIGHT
  - ожидание: BLOCK_ERR_WEIGHT_EXCEEDED

TestApplyBlock_SubsidyExceeded
  - coinbase output.Value > blockRewardForHeight(height)
  - ожидание: BLOCK_ERR_SUBSIDY_EXCEEDED

TestApplyBlock_CoinbaseMissing
  - блок без coinbase tx (первый tx не является coinbase)
  - ожидание: BLOCK_ERR_COINBASE_INVALID

TestApplyBlock_DoubleSpend
  - два tx тратят один и тот же outpoint
  - ожидание: TX_ERR_MISSING_UTXO (второй tx не найдёт utxo)

TestApplyBlock_UTXOUpdated
  - после применения блока: spent outpoints удалены, новые добавлены
  - проверка что utxo map изменилась корректно
```

---

### 1.3 `validate.go` — validateCoinbaseTxInputs (0%)

```
TestValidateCoinbaseTxInputs
  - валидный coinbase input: prevTxid=0x00..00, prevVout=0xFFFFFFFF, sequence=0xFFFFFFFF, scriptSig=[]
  - txNonce != 0 → BLOCK_ERR_COINBASE_INVALID
  - len(inputs) != 1 → BLOCK_ERR_COINBASE_INVALID
  - sequence != TX_COINBASE_PREVOUT_VOUT → BLOCK_ERR_COINBASE_INVALID
  - prevTxid != zero → BLOCK_ERR_COINBASE_INVALID
  - len(ScriptSig) != 0 → BLOCK_ERR_COINBASE_INVALID
  - len(witnesses) != 0 → BLOCK_ERR_COINBASE_INVALID
```

---

### 1.4 `pow.go` — blockRewardForHeight / medianPastTimestamp / blockExpectedTarget (0%)

**Тест-файл:** `pow_test.go`

```
TestBlockRewardForHeight
  - height=0 → base subsidy
  - height=rem-1 → base+1
  - height=rem → base
  - height=SUBSIDY_DURATION_BLOCKS → 0
  - height=SUBSIDY_DURATION_BLOCKS+1 → 0

TestMedianPastTimestamp
  - height=0 → BLOCK_ERR_TIMESTAMP_OLD
  - headers=[] → BLOCK_ERR_TIMESTAMP_OLD
  - height=1, headers=[{Timestamp:100}] → 100
  - height=5, headers=[t1..t5] → медиана из 5
  - height=20, headers=[t1..t20] → медиана из 11 последних

TestBlockExpectedTarget
  - height=0 → возвращает targetIn как есть
  - height=1, headers=[h1] → тот же target что у h1 (не окончание окна)
  - height=WINDOW_SIZE, len(headers)<WINDOW_SIZE → BLOCK_ERR_TARGET_INVALID
  - height=WINDOW_SIZE, корректные headers → пересчитанный target
  - retarget clamp: actualTime << targetBlockInterval → maxTarget (×4)
  - retarget clamp: actualTime >> targetBlockInterval → minTarget (÷4)
  - нулевой old target → minTarget=1
```

---

### 1.5 `chainstate_hash.go` — UtxoSetHash / outpointKeyBytes (0%)

**Добавить в:** `chainstate_hash_test.go`

```
TestUtxoSetHash_Empty
  - utxo={} → детерминированный хеш (не нулевой — DST + N_le=0)

TestUtxoSetHash_SingleEntry
  - 1 utxo запись → хеш, вручную сверить с SHA3-256(DST || n_le || pair)

TestUtxoSetHash_Deterministic
  - один и тот же utxo map, вызвать дважды → одинаковый хеш

TestUtxoSetHash_OrderIndependent
  - построить utxo map с 3 entries, передать в разном порядке вставки
  - хеш должен совпадать (сортировка работает корректно)

TestUtxoSetHash_DifferentEntries
  - два разных utxo set → разные хеши

TestOutpointKeyBytes
  - txid[0..31] + vout_le[4] → 36 байт, проверить little-endian порядок
```

---

## Приоритет 2 — частичное покрытие (расширить)

### 2.1 `validate.go` — validateOutputCovenantConstraints (40.9% → цель 80%)

Не покрыты: CORE_HTLC_V2 (claimKey==refundKey), CORE_VAULT_V1 (81 bytes), CORE_RESERVED_FUTURE, default.

```
TestValidateOutputCovenantConstraints_Missing
  - CORE_HTLC_V2: claimKeyID == refundKeyID → TX_ERR_PARSE
  - CORE_VAULT_V1: len=73 → OK
  - CORE_VAULT_V1: len=81 → OK
  - CORE_VAULT_V1: len=74 → TX_ERR_PARSE
  - CORE_RESERVED_FUTURE (0x7FFF) → TX_ERR_COVENANT_TYPE_INVALID
  - unknown type (0x9999) → TX_ERR_COVENANT_TYPE_INVALID
  - CORE_ANCHOR: value=1 → TX_ERR_COVENANT_TYPE_INVALID
  - CORE_ANCHOR: data=[] (empty) → TX_ERR_COVENANT_TYPE_INVALID
  - CORE_ANCHOR: data len > MAX_ANCHOR_PAYLOAD_SIZE → TX_ERR_COVENANT_TYPE_INVALID
```

### 2.2 `validate.go` — ValidateInputAuthorization (31.1% → цель 80%)

Не покрыты: CORE_P2PK полный путь, CORE_VAULT_V1 owner/recovery, CORE_TIMELOCK_V1 ветки, CORE_ANCHOR как input.

```
TestValidateInputAuthorization_P2PK
  - валидный P2PK (mock CryptoProvider с успешным verify)
  - неверная подпись → TX_ERR_SIG_INVALID
  - witness count != 1 → ошибка

TestValidateInputAuthorization_TIMELOCK
  - lockMode=HEIGHT, height не достигнут → TX_ERR_TIMELOCK_NOT_MET
  - lockMode=HEIGHT, height достигнут → OK (с валидной подписью)
  - lockMode=TIMESTAMP, timestamp не достигнут → TX_ERR_TIMELOCK_NOT_MET
  - data len != 9 → TX_ERR_PARSE

TestValidateInputAuthorization_VAULT_Owner
  - owner path: witness[0].Pubkey matches ownerKeyID → пройти
  - recovery path: witness[0].Pubkey matches recoveryKeyID, spend_delay выполнен
  - spend_delay не выполнен → TX_ERR_TIMELOCK_NOT_MET
  - ни owner ни recovery → TX_ERR_SIG_KEY_MISMATCH

TestValidateInputAuthorization_ANCHOR
  - CORE_ANCHOR как input → TX_ERR_COVENANT_TYPE_INVALID (anchor не спендится)
```

### 2.3 `validate.go` — ApplyTx (66% → цель 90%)

```
TestApplyTx_ValueConservation
  - outputSum > inputSum → TX_ERR_VALUE_CONSERVATION
  - overflow в output sum → TX_ERR_PARSE

TestApplyTx_MissingUTXO
  - input ссылается на несуществующий outpoint → TX_ERR_MISSING_UTXO

TestApplyTx_CoinbaseMaturity
  - попытка потратить coinbase output до достижения COINBASE_MATURITY → TX_ERR_COINBASE_IMMATURE

TestApplyTx_HTLC_NonCoinbase
  - CORE_ANCHOR output в не-coinbase tx → TX_ERR_COVENANT_TYPE_INVALID
```

---

## Приоритет 3 — util.go / encode.go (smoke)

```
TestUtil_SubUint64
  - a >= b → корректный результат
  - b > a → TX_ERR_VALUE_CONSERVATION

TestUtil_IsCoinbaseTx
  - nil tx → false
  - len(inputs) != 1 → false
  - locktime != blockHeight → false
  - все условия ок → true

TestEncode_BlockHeaderBytes
  - encode/decode roundtrip: ParseBlockHeader(BlockHeaderBytes(h)) == h

TestEncode_TxRoundtrip
  - ParseTxBytes(TxBytes(tx)) == tx (для простого tx)
```

---

## Вспомогательные структуры для тестов

Добавить в `testhelpers_test.go`:

```go
// mockCrypto — минимальный CryptoProvider для unit-тестов
type mockCrypto struct{ verifyResult error }
func (m *mockCrypto) SHA3_256(data []byte) ([32]byte, error) { ... реальный sha3 ... }
func (m *mockCrypto) VerifyMLDSA87(...) error { return m.verifyResult }
func (m *mockCrypto) VerifySLHDSA(...) error  { return m.verifyResult }

// buildMinimalCoinbaseTx(height, outputValue) *Tx
// buildMinimalBlock(header, txs) Block
// buildHeader(prevHash, target, timestamp) BlockHeader
// makeUTXO(txid, vout, value, covenantType, data) map[TxOutPoint]UtxoEntry
```

---

## Ожидаемые цифры после выполнения

| Файл | До | После |
|---|---|---|
| parse.go (все функции) | 0% | ~75% |
| validate.go (ApplyBlock) | 0% | ~70% |
| validate.go (validateCoinbaseTxInputs) | 0% | ~100% |
| pow.go (все) | 0% | ~85% |
| chainstate_hash.go | 0% | ~90% |
| validateOutputCovenantConstraints | 40.9% | ~85% |
| ValidateInputAuthorization | 31.1% | ~75% |
| **consensus пакет итого** | **24.8%** | **~72%** |
| **global (./...)** | **14.2%** | **~35%** |

Global ≥50% потребует дополнительно smoke-тестов для `crypto` и `node` пакетов (отдельное ТЗ).
