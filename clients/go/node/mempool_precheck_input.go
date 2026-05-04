package node

import (
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

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
func feePrecheckP2PKInputValue(tx *consensus.Tx, utxos map[consensus.Outpoint]consensus.UtxoEntry, nextHeight uint64, rotation consensus.RotationProvider, registry *consensus.SuiteRegistry) (uint64, bool) {
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
	if !precheckP2PKWitnessItemValid(&tx.Witness[0], entry, nextHeight, rotation, registry) {
		return 0, false
	}
	return entry.Value, true
}

// precheckP2PKWitnessItemValid returns true iff the single P2PK witness
// item is structurally valid for the cheap precheck. Wave-14 mirrors
// terminal-reject branches in slow-path validate_p2pk_spend_q at
// clients/go/consensus/spend_verify.go (suite in NativeSpendSuites,
// registry lookup, canonical pubkey/signature lengths, suite consistency
// with input UTXO covenant_data[0]). ML-DSA signature verification and
// pubkey key-binding sha3 stay out of the precheck by design (those are
// the expensive operations this fast-reject is built to skip).
func precheckP2PKWitnessItemValid(w *consensus.WitnessItem, entry consensus.UtxoEntry, nextHeight uint64, rotation consensus.RotationProvider, registry *consensus.SuiteRegistry) bool {
	if rotation == nil {
		rotation = consensus.DefaultRotationProvider{}
	}
	if !rotation.NativeSpendSuites(nextHeight).Contains(w.SuiteID) {
		return false
	}
	if registry == nil {
		registry = consensus.DefaultSuiteRegistry()
	}
	params, ok := registry.Lookup(w.SuiteID)
	if !ok {
		return false
	}
	if len(w.Pubkey) != params.PubkeyLen ||
		len(w.Signature) != params.SigLen+1 {
		return false
	}
	return entry.CovenantData[0] == w.SuiteID
}

// precheckP2PKInputStructurallyValid returns true iff the input is
// structurally valid for the cheap P2PK precheck. Wave-4 guards mirror
// terminal-reject parse-time checks at clients/go/consensus/utxo_basic.go
// for non-empty ScriptSig (193-194), out-of-range Sequence (196-197),
// and coinbase-prevout marker on non-coinbase (199-200). Returns false
// on any structural defect so the caller defers to the slow path.
func precheckP2PKInputStructurallyValid(in consensus.TxInput) bool {
	var zeroTxid [32]byte
	isCoinbasePrevout := in.PrevTxid == zeroTxid && in.PrevVout == 0xffffffff
	return !isCoinbasePrevout && len(in.ScriptSig) == 0 && in.Sequence <= 0x7fffffff
}

// precheckCoinbaseImmature returns true iff the resolved P2PK input is
// an immature coinbase spend (wave-5 class-closure: slow path returns
// Rejected TX_ERR_COINBASE_IMMATURE at utxo_basic.go:217-219). Caller
// defers when this returns true so the slow path preserves the
// terminal-reject classification (different caller action than fee
// floor: wait for COINBASE_MATURITY blocks vs retry-with-higher-fee).
func precheckCoinbaseImmature(entry consensus.UtxoEntry, nextHeight uint64) bool {
	return entry.CreatedByCoinbase &&
		(nextHeight < entry.CreationHeight ||
			nextHeight-entry.CreationHeight < consensus.COINBASE_MATURITY)
}
