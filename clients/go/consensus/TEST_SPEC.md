# Test Plan: reach coverage >=70% (clients/go/consensus)

**Date:** 2026-02-19
**Path:** `clients/go/consensus/`
**Current coverage:** consensus 24.8% / global 14.2%
**Goal:** consensus >=70% / global >=50%
**Test files:** add to `clients/go/consensus/*_test.go`

---

## Priority 1 - critical gaps (0% -> must add)

### 1.1 `parse.go` - ParseTxBytes / ParseBlockBytes (0%)

All parsing functions have zero tests. Biggest coverage impact.

**Test file:** `parse_test.go`

```
TestParseTxBytes_Valid
  - valid tx: 1 input + 1 output + 1 witness (ML-DSA)
  - valid tx: coinbase (no inputs, no witnesses)
  - trailing bytes -> "parse: trailing bytes"

TestParseTxBytes_Truncated
  - truncated at version
  - truncated at input list
  - truncated at output list
  - truncated at witness
  - compactsize overflow in input_count

TestParseBlockBytes_Valid
  - block with 1 coinbase transaction
  - block with coinbase + 2 normal txs
  - trailing bytes -> BLOCK_ERR_PARSE

TestParseBlockHeader
  - correct 116-byte header
  - short header -> error
  - truncated mid-field

TestParseOutput_CovenantTypes
  - CORE_P2PK output bytes
  - CORE_TIMELOCK_V1 output bytes
  - CORE_HTLC_V1 output bytes
  - CORE_VAULT_V1 output bytes (73 bytes and 81 bytes)

TestParseWitnessItem
  - SUITE_ID_SENTINEL (suiteID=0, no pubkey/sig)
  - SUITE_ID_ML_DSA
  - SUITE_ID_SLH_DSA
  - unknown suiteID
```

---

### 1.2 `validate.go` - ApplyBlock (0%)

Most important function is completely untested.

**Add to:** `apply_block_test.go`

```
TestApplyBlock_Valid
  - minimal block: coinbase tx only
    input ctx: height=1, ancestors=[genesis_header], utxo={}
    expect: OK, utxo contains coinbase output

TestApplyBlock_MerkleInvalid
  - block.Header.MerkleRoot = wrong hash
  - expect: BLOCK_ERR_MERKLE_INVALID

TestApplyBlock_PoWInvalid
  - block.Header.Target = all zeros (impossibly hard)
  - expect: BLOCK_ERR_POW_INVALID

TestApplyBlock_TimestampTooOld
  - block.Timestamp = medianPastTimestamp - 1
  - expect: BLOCK_ERR_TIMESTAMP_OLD

TestApplyBlock_TimestampTooFuture
  - blockCtx.LocalTimeSet=true, LocalTime = block.Timestamp - MAX_FUTURE_DRIFT - 1
  - expect: BLOCK_ERR_TIMESTAMP_FUTURE

TestApplyBlock_WeightExceeded
  - block with tx exceeding MAX_BLOCK_WEIGHT
  - expect: BLOCK_ERR_WEIGHT_EXCEEDED

TestApplyBlock_SubsidyExceeded
  - coinbase output.Value > blockRewardForHeight(height)
  - expect: BLOCK_ERR_SUBSIDY_EXCEEDED

TestApplyBlock_CoinbaseMissing
  - block without coinbase tx (first tx is not coinbase)
  - expect: BLOCK_ERR_COINBASE_INVALID

TestApplyBlock_DoubleSpend
  - two tx spend the same outpoint
  - expect: TX_ERR_MISSING_UTXO (second tx cannot find the utxo)

TestApplyBlock_UTXOUpdated
  - after applying block: spent outpoints removed, new ones added
  - verify the utxo map changed correctly
```

---

### 1.3 `validate.go` - validateCoinbaseTxInputs (0%)

```
TestValidateCoinbaseTxInputs
  - valid coinbase input: prevTxid=0x00..00, prevVout=0xFFFFFFFF, sequence=0xFFFFFFFF, scriptSig=[]
  - txNonce != 0 -> BLOCK_ERR_COINBASE_INVALID
  - len(inputs) != 1 -> BLOCK_ERR_COINBASE_INVALID
  - sequence != TX_COINBASE_PREVOUT_VOUT -> BLOCK_ERR_COINBASE_INVALID
  - prevTxid != zero -> BLOCK_ERR_COINBASE_INVALID
  - len(ScriptSig) != 0 -> BLOCK_ERR_COINBASE_INVALID
  - len(witnesses) != 0 -> BLOCK_ERR_COINBASE_INVALID
```

---

### 1.4 `pow.go` - blockRewardForHeight / medianPastTimestamp / blockExpectedTarget (0%)

**Test file:** `pow_test.go`

```
TestBlockRewardForHeight
  - height=0 -> base subsidy
  - height=rem-1 -> base+1
  - height=rem -> base
  - height=SUBSIDY_DURATION_BLOCKS -> 0
  - height=SUBSIDY_DURATION_BLOCKS+1 -> 0

TestMedianPastTimestamp
  - height=0 -> BLOCK_ERR_TIMESTAMP_OLD
  - headers=[] -> BLOCK_ERR_TIMESTAMP_OLD
  - height=1, headers=[{Timestamp:100}] -> 100
  - height=5, headers=[t1..t5] -> median of 5
  - height=20, headers=[t1..t20] -> median of last 11

TestBlockExpectedTarget
  - height=0 -> returns targetIn as-is
  - height=1, headers=[h1] -> same target as h1 (not end-of-window)
  - height=WINDOW_SIZE, len(headers)<WINDOW_SIZE -> BLOCK_ERR_TARGET_INVALID
  - height=WINDOW_SIZE, valid headers -> retargeted target
  - retarget clamp: actualTime << targetBlockInterval -> maxTarget (x4)
  - retarget clamp: actualTime >> targetBlockInterval -> minTarget (/4)
  - zero old target -> minTarget=1
```

---

### 1.5 `chainstate_hash.go` - UtxoSetHash / outpointKeyBytes (0%)

**Add to:** `chainstate_hash_test.go`

```
TestUtxoSetHash_Empty
  - utxo={} -> deterministic hash (non-zero; DST + N_le=0)

TestUtxoSetHash_SingleEntry
  - 1 utxo entry -> hash; manually match SHA3-256(DST || n_le || pair)

TestUtxoSetHash_Deterministic
  - same utxo map, call twice -> same hash

TestUtxoSetHash_OrderIndependent
  - build utxo map with 3 entries, insert in different orders
  - hash must match (sorting is correct)

TestUtxoSetHash_DifferentEntries
  - two different utxo sets -> different hashes

TestOutpointKeyBytes
  - txid[0..31] + vout_le[4] -> 36 bytes; verify little-endian order
```

---

## Priority 2 - partial coverage (extend)

### 2.1 `validate.go` - validateOutputCovenantConstraints (40.9% -> goal 80%)

Missing: CORE_HTLC_V2 (claimKey==refundKey), CORE_VAULT_V1 (81 bytes), CORE_RESERVED_FUTURE, default.

```
TestValidateOutputCovenantConstraints_Missing
  - CORE_HTLC_V2: claimKeyID == refundKeyID -> TX_ERR_PARSE
  - CORE_VAULT_V1: len=73 -> OK
  - CORE_VAULT_V1: len=81 -> OK
  - CORE_VAULT_V1: len=74 -> TX_ERR_PARSE
  - CORE_RESERVED_FUTURE (0x7FFF) -> TX_ERR_COVENANT_TYPE_INVALID
  - unknown type (0x9999) -> TX_ERR_COVENANT_TYPE_INVALID
  - CORE_ANCHOR: value=1 -> TX_ERR_COVENANT_TYPE_INVALID
  - CORE_ANCHOR: data=[] (empty) -> TX_ERR_COVENANT_TYPE_INVALID
  - CORE_ANCHOR: data len > MAX_ANCHOR_PAYLOAD_SIZE -> TX_ERR_COVENANT_TYPE_INVALID
```

### 2.2 `validate.go` - ValidateInputAuthorization (31.1% -> goal 80%)

Missing: CORE_P2PK full path, CORE_VAULT_V1 owner/recovery, CORE_TIMELOCK_V1 branches, CORE_ANCHOR as input.

```
TestValidateInputAuthorization_P2PK
  - valid P2PK (mock CryptoProvider with successful verify)
  - invalid signature -> TX_ERR_SIG_INVALID
  - witness count != 1 -> error

TestValidateInputAuthorization_TIMELOCK
  - lockMode=HEIGHT, height not reached -> TX_ERR_TIMELOCK_NOT_MET
  - lockMode=HEIGHT, height reached -> OK (with valid signature)
  - lockMode=TIMESTAMP, timestamp not reached -> TX_ERR_TIMELOCK_NOT_MET
  - data len != 9 -> TX_ERR_PARSE

TestValidateInputAuthorization_VAULT_Owner
  - owner path: witness[0].Pubkey matches ownerKeyID -> pass
  - recovery path: witness[0].Pubkey matches recoveryKeyID, spend_delay satisfied
  - spend_delay not satisfied -> TX_ERR_TIMELOCK_NOT_MET
  - neither owner nor recovery -> TX_ERR_SIG_KEY_MISMATCH

TestValidateInputAuthorization_ANCHOR
  - CORE_ANCHOR as input -> TX_ERR_COVENANT_TYPE_INVALID (anchor is not spendable)
```

### 2.3 `validate.go` - ApplyTx (66% -> goal 90%)

```
TestApplyTx_ValueConservation
  - outputSum > inputSum -> TX_ERR_VALUE_CONSERVATION
  - overflow in output sum -> TX_ERR_PARSE

TestApplyTx_MissingUTXO
  - input references a non-existent outpoint -> TX_ERR_MISSING_UTXO

TestApplyTx_CoinbaseMaturity
  - attempt to spend coinbase output before COINBASE_MATURITY -> TX_ERR_COINBASE_IMMATURE

TestApplyTx_HTLC_NonCoinbase
  - CORE_ANCHOR output in non-coinbase tx -> TX_ERR_COVENANT_TYPE_INVALID
```

---

## Priority 3 - util.go / encode.go (smoke)

```
TestUtil_SubUint64
  - a >= b -> correct result
  - b > a -> TX_ERR_VALUE_CONSERVATION

TestUtil_IsCoinbaseTx
  - nil tx -> false
  - len(inputs) != 1 -> false
  - locktime != blockHeight -> false
  - all conditions OK -> true

TestEncode_BlockHeaderBytes
  - encode/decode roundtrip: ParseBlockHeader(BlockHeaderBytes(h)) == h

TestEncode_TxRoundtrip
  - ParseTxBytes(TxBytes(tx)) == tx (for a simple tx)
```

---

## Test helper structs

Add to `testhelpers_test.go`:

```go
// mockCrypto is a minimal CryptoProvider for unit tests.
type mockCrypto struct{ verifyResult error }
func (m *mockCrypto) SHA3_256(data []byte) ([32]byte, error) { /* real sha3 */ }
func (m *mockCrypto) VerifyMLDSA87(...) error { return m.verifyResult }
func (m *mockCrypto) VerifySLHDSA(...) error  { return m.verifyResult }

// buildMinimalCoinbaseTx(height, outputValue) *Tx
// buildMinimalBlock(header, txs) Block
// buildHeader(prevHash, target, timestamp) BlockHeader
// makeUTXO(txid, vout, value, covenantType, data) map[TxOutPoint]UtxoEntry
```

---

## Expected numbers after completion

| File | Before | After |
|---|---|---|
| parse.go (all functions) | 0% | ~75% |
| validate.go (ApplyBlock) | 0% | ~70% |
| validate.go (validateCoinbaseTxInputs) | 0% | ~100% |
| pow.go (all) | 0% | ~85% |
| chainstate_hash.go | 0% | ~90% |
| validateOutputCovenantConstraints | 40.9% | ~85% |
| ValidateInputAuthorization | 31.1% | ~75% |
| **consensus package total** | **24.8%** | **~72%** |
| **global (./...)** | **14.2%** | **~35%** |

Reaching global >=50% will additionally require smoke/integration tests for the
`crypto` and `node` packages (separate spec).
