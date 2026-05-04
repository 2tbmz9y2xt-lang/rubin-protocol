package node

import (
	"fmt"
	"math/bits"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// buildPolicyInputSnapshotIfNeeded returns the immutable pre-validation
// snapshot of only the transaction inputs that policy lanes inspect.
// The snapshot is needed only by policy lanes that read tx inputs from
// utxos (CORE_EXT pre-activation gate, or a DA-bearing tx under any
// non-zero DA-side fee term); non-DA tx with no CORE_EXT gate skip the
// map-copy entirely (returns nil, nil). Built before
// CheckTransaction*WithOwnedUtxoSet because that helper takes
// ownership of the supplied utxo map and removes spent inputs as part
// of validation. Extracted from checkTransactionWithSnapshot to keep
// cyclomatic complexity within the repository's lint budget.
func buildPolicyInputSnapshotIfNeeded(parsedTx *consensus.Tx, snapshot *chainStateAdmissionSnapshot, policy MempoolConfig) (map[consensus.Outpoint]consensus.UtxoEntry, error) {
	needs, err := policyNeedsInputSnapshotForTx(parsedTx, policy)
	if err != nil {
		return nil, txAdmitRejected(err.Error())
	}
	if !needs {
		return nil, nil
	}
	policyUtxos, err := policyInputSnapshot(parsedTx, snapshot.utxos)
	if err != nil {
		return nil, txAdmitRejected(err.Error())
	}
	return policyUtxos, nil
}

// checkTxParseAndContext resolves the chain-context inputs every
// admission needs (next block height + MTP) and parses the candidate
// transaction in canonical-bytes mode. Extracted from
// checkTransactionWithSnapshot to keep cyclomatic complexity within
// the repository's lint budget. Returns the parsed Tx, next-block
// height, next-block MTP, or a typed admission error if any step
// fails (Unavailable for chain-context failure, Rejected for parse
// failure / trailing bytes).
func (m *Mempool) checkTxParseAndContext(txBytes []byte, snapshot *chainStateAdmissionSnapshot) (*consensus.Tx, uint64, uint64, error) {
	if snapshot == nil {
		return nil, 0, 0, txAdmitUnavailable("nil chainstate")
	}
	nextHeight, _, err := nextBlockContextFromFields(snapshot.hasTip, snapshot.height, snapshot.tipHash)
	if err != nil {
		return nil, 0, 0, txAdmitUnavailable(err.Error())
	}
	blockMTP, err := m.nextBlockMTP(nextHeight)
	if err != nil {
		return nil, 0, 0, txAdmitUnavailable(err.Error())
	}
	parsedTx, _, _, consumed, err := consensus.ParseTx(txBytes)
	if err != nil {
		return nil, 0, 0, txAdmitRejected(err.Error())
	}
	if consumed != len(txBytes) {
		return nil, 0, 0, txAdmitRejected("trailing bytes after canonical tx")
	}
	return parsedTx, nextHeight, blockMTP, nil
}

// checkTransactionWithSnapshot validates a transaction against a consistent
// owned admission snapshot plus an immutable mempool policy snapshot.
//
// `snappedFloor` is the rolling-relay-floor value snapped ONCE in the
// caller (`addTxWithSource`) before either the precheck or the locked
// admission path runs. Wave-6 (PR #1422): both `cheapFeeFloorPrecheck`
// here AND the downstream `validateFeeFloorLocked` inside
// `addEntryLocked` use this exact value, so a concurrent
// `decayMinFeeRateAfterConnectedBlockLocked` cannot cause the precheck
// to reject on stale-higher floor while the locked path would have
// accepted on fresh-lower floor (per-admission consistency).
func (m *Mempool) checkTransactionWithSnapshot(txBytes []byte, snapshot *chainStateAdmissionSnapshot, policy MempoolConfig, snappedFloor uint64) (*consensus.CheckedTransaction, []consensus.Outpoint, error) {
	parsedTx, nextHeight, blockMTP, err := m.checkTxParseAndContext(txBytes, snapshot)
	if err != nil {
		return nil, nil, err
	}
	// Only plain P2PK candidates use the cheap floor reject. Transactions
	// that may hit DA, CORE_ANCHOR, CORE_EXT, or missing-UTXO policy lanes
	// keep the existing validation and policy-error precedence below.
	// Wave-4 (PR #1422): pass nextHeight + policy.RotationProvider so the
	// precheck can defer on consensus-invalid P2PK output shapes
	// (value==0, wrong covenant_data length, suite outside native create
	// set) that ValidateTxCovenantsGenesis would return Rejected
	// (terminal). Without these passes a below-floor + malformed tx
	// would be misclassified as transient Unavailable instead of
	// Rejected (terminal).
	if err := cheapFeeFloorPrecheck(parsedTx, snapshot, snappedFloor, nextHeight, policy.RotationProvider); err != nil {
		return nil, nil, err
	}
	policyUtxos, err := buildPolicyInputSnapshotIfNeeded(parsedTx, snapshot, policy)
	if err != nil {
		return nil, nil, err
	}
	checked, err := consensus.CheckTransactionWithOwnedUtxoSetAndCoreExtProfilesAndSuiteContext(
		txBytes,
		snapshot.utxos,
		nextHeight,
		blockMTP,
		m.chainID,
		policy.CoreExtProfiles,
		policy.RotationProvider,
		policy.SuiteRegistry,
	)
	if err != nil {
		return nil, nil, txAdmitRejected(err.Error())
	}
	if err := m.applyPolicyAgainstState(checked, nextHeight, policyUtxos, policy); err != nil {
		return nil, nil, txAdmitRejected(err.Error())
	}
	inputs := make([]consensus.Outpoint, 0, len(checked.Tx.Inputs))
	for _, in := range checked.Tx.Inputs {
		inputs = append(inputs, consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout})
	}
	return checked, inputs, nil
}

// cheapFeeFloorPrecheck fast-rejects below-floor plain P2PK transactions
// before the expensive ML-DSA signature verification, mirroring Rust
// `cheap_fee_floor_precheck` at
// `clients/rust/crates/rubin-node/src/txpool.rs`.
//
// Wave-4 class-closure conservatism: defer when the slow path
// (`ValidateTxCovenantsGenesis` and the per-tx nonce/UTXO checks
// inside `applyNonCoinbaseTxBasic*`) would return Rejected (terminal).
// Without these defers a below-floor tx that ALSO has a structural
// defect would be misclassified as transient Unavailable instead of
// Rejected (terminal), masking the structural error and allowing
// callers to retry forever.
//
// tx_nonce == 0 for non-coinbase: slow path returns
// `txerr(TX_ERR_TX_NONCE_INVALID, "tx_nonce must be >= 1 for
// non-coinbase")` at `clients/go/consensus/connect_block_parallel.go:290`
// and `clients/go/consensus/utxo_basic.go:161`.
func cheapFeeFloorPrecheck(tx *consensus.Tx, snapshot *chainStateAdmissionSnapshot, minFeeRate uint64, nextHeight uint64, rotation consensus.RotationProvider) error {
	if precheckEarlyDefer(tx) {
		return nil
	}
	inputValue, ok := feePrecheckP2PKInputValue(tx, snapshot.utxos, nextHeight)
	if !ok {
		return nil
	}
	outputValue, ok := feePrecheckP2PKOutputValue(tx.Outputs, nextHeight, rotation)
	if !ok || outputValue > inputValue {
		return nil
	}
	weight, _, _, err := consensus.TxWeightAndStats(tx)
	if err != nil || weight == 0 {
		return nil
	}
	fee := inputValue - outputValue
	if feeRateBelowFloor(fee, weight, minFeeRate) {
		return txAdmitUnavailable(fmt.Sprintf("mempool fee below rolling minimum: fee=%d weight=%d min_fee_rate=%d", fee, weight, minFeeRate))
	}
	return nil
}

// precheckEarlyDefer returns true when the tx shape disqualifies it
// from the cheap fast-reject path: non-plain tx_kind, DA-bearing
// payload, or tx_nonce == 0 (slow path returns Rejected
// TX_ERR_TX_NONCE_INVALID at clients/go/consensus/utxo_basic.go:160-162
// — wave-4 class-closure conservatism). Extracted from
// cheapFeeFloorPrecheck to keep cyclomatic complexity within the
// repository's lint budget.
func precheckEarlyDefer(tx *consensus.Tx) bool {
	if tx.TxKind != 0x00 {
		return true
	}
	if len(tx.DaPayload) != 0 {
		return true
	}
	return tx.TxNonce == 0
}

// feePrecheckP2PKInputValue returns the P2PK input value when tx has
// exactly one input AND that input is BOTH structurally valid
// (witness count == 1, no coinbase-prevout marker, empty ScriptSig,
// Sequence in standard range) AND resolves in utxos to a
// COV_TYPE_P2PK entry. Returns (0, false) for any other shape so the
// caller defers to the expensive admission path.
//
// Wave-4 class-closure conservatism: each input-side guard mirrors a
// terminal-reject branch in the slow path
// `applyNonCoinbaseTxBasic*` at
// `clients/go/consensus/utxo_basic.go:193-200`. Without these defers
// a below-floor tx with structurally-defective input would be
// misclassified as transient Unavailable instead of terminal
// Rejected, masking the structural error and allowing callers to
// retry forever. Mirrors Rust `fee_precheck_p2pk_input_value` in
// `clients/rust/crates/rubin-node/src/txpool.rs`.
//
// Scope-cap: P2PK signature-verification failure is NOT classified
// here. Verifying ML-DSA signatures is the expensive operation this
// fast-reject is designed to avoid. Below-floor txs with invalid
// signatures may surface as rolling-floor Unavailable until the fee
// floor no longer applies; this is intentional.
func feePrecheckP2PKInputValue(tx *consensus.Tx, utxos map[consensus.Outpoint]consensus.UtxoEntry, nextHeight uint64) (uint64, bool) {
	if utxos == nil || len(tx.Inputs) != 1 || len(tx.Witness) != 1 {
		return 0, false
	}
	in := tx.Inputs[0]
	if !precheckP2PKInputStructurallyValid(in) {
		return 0, false
	}
	entry, ok := utxos[consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}]
	if !ok || entry.CovenantType != consensus.COV_TYPE_P2PK {
		return 0, false
	}
	if precheckCoinbaseImmature(entry, nextHeight) {
		return 0, false
	}
	return entry.Value, true
}

// precheckP2PKInputStructurallyValid returns true iff the input is
// structurally valid for the cheap P2PK precheck. Wave-4 guards mirror
// terminal-reject parse-time checks at clients/go/consensus/utxo_basic.go
// for non-empty ScriptSig (193-194), out-of-range Sequence (196-197),
// and coinbase-prevout marker on non-coinbase (199-200). Returns false
// on any structural defect so the caller defers to the slow path.
func precheckP2PKInputStructurallyValid(in consensus.TxInput) bool {
	var zeroTxid [32]byte
	if in.PrevTxid == zeroTxid && in.PrevVout == 0xffffffff {
		return false
	}
	if len(in.ScriptSig) != 0 {
		return false
	}
	if in.Sequence > 0x7fffffff {
		return false
	}
	return true
}

// precheckCoinbaseImmature returns true iff the resolved P2PK input is
// an immature coinbase spend (wave-5 class-closure: slow path returns
// Rejected TX_ERR_COINBASE_IMMATURE at utxo_basic.go:217-219). Caller
// defers when this returns true so the slow path preserves the
// terminal-reject classification (different caller action than fee
// floor: wait for COINBASE_MATURITY blocks vs retry-with-higher-fee).
func precheckCoinbaseImmature(entry consensus.UtxoEntry, nextHeight uint64) bool {
	if !entry.CreatedByCoinbase {
		return false
	}
	if nextHeight < entry.CreationHeight {
		return true
	}
	return nextHeight-entry.CreationHeight < consensus.COINBASE_MATURITY
}

// feePrecheckP2PKOutputValue returns the sum of P2PK output values when
// every output is a CONSENSUS-VALID `COV_TYPE_P2PK` (non-zero value,
// exactly `MAX_P2PK_COVENANT_DATA == 33` byte covenant_data, and a
// suite_id in the active `NativeCreateSuites(nextHeight)` set) and the
// running sum does not overflow `uint64`. Returns `(0, false)` for any
// other shape so the caller defers to the expensive admission path.
//
// Wave-4 class-closure conservatism: each guard mirrors a permanent-
// reject branch in `ValidateTxCovenantsGenesis` at
// `clients/go/consensus/covenant_genesis.go:19-26`. Without them a
// below-floor tx with consensus-invalid P2PK outputs would be
// misclassified as transient Unavailable instead of permanent Rejected.
// Mirrors Rust `fee_precheck_p2pk_output_value` at
// `clients/rust/crates/rubin-node/src/txpool.rs`.
func feePrecheckP2PKOutputValue(outputs []consensus.TxOutput, nextHeight uint64, rotation consensus.RotationProvider) (uint64, bool) {
	if rotation == nil {
		rotation = consensus.DefaultRotationProvider{}
	}
	nativeSuites := rotation.NativeCreateSuites(nextHeight)
	var total uint64
	for _, out := range outputs {
		if out.CovenantType != consensus.COV_TYPE_P2PK {
			return 0, false
		}
		// Wave-4 class-closure conservatism: each guard mirrors a
		// permanent-reject branch in ValidateTxCovenantsGenesis
		// (covenant_genesis.go:19-26).
		if out.Value == 0 {
			return 0, false
		}
		if uint64(len(out.CovenantData)) != consensus.MAX_P2PK_COVENANT_DATA {
			return 0, false
		}
		suiteID := out.CovenantData[0]
		if !nativeSuites.Contains(suiteID) {
			return 0, false
		}
		next, carry := bits.Add64(total, out.Value, 0)
		if carry != 0 {
			return 0, false
		}
		total = next
	}
	return total, true
}
