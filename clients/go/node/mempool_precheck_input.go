package node

import (
	"bytes"
	"crypto/sha3"

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
// item is structurally valid for the cheap precheck. Mirrors terminal-
// reject branches in slow-path validate_p2pk_spend_q at
// clients/go/consensus/spend_verify.go: suite in NativeSpendSuites
// (wave-14), registry lookup (wave-14), canonical pubkey/signature
// lengths (wave-14), covenant_data length + suite consistency with
// input UTXO covenant_data[0] (wave-15 panic-safety + wave-14),
// sighash trailer SIGHASH_ALL (wave-15), and key-binding
// SHA3(pubkey)==CovenantData[1:33] (wave-15). ML-DSA signature
// verification stays out of the precheck by design (the only
// documented scope-cap; SHA3 and byte compare are CHEAP and in scope).
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
	// Wave-15 panic-safety + suite consistency. The covenant_data length
	// check MUST precede the [0] / [1:33] indexing because
	// chainStateFromDisk accepts arbitrary persisted covenant_data
	// bytes without per-covenant structure validation, so a corrupted
	// on-disk UTXO entry could otherwise panic the admission loop on
	// the next spend. Mirror of slow-path spend_verify.go counterpart.
	if len(entry.CovenantData) != int(consensus.MAX_P2PK_COVENANT_DATA) {
		return false
	}
	if entry.CovenantData[0] != w.SuiteID {
		return false
	}
	// Wave-16 sighash trailer: defer only on INVALID sighash type. The
	// slow path's IsValidSighashType (sighash.go:12+) accepts six
	// canonical trailers (SIGHASH_ALL/NONE/SINGLE × ANYONECANPAY); only
	// bytes outside that set are terminal-rejected. Wave-15's literal
	// `!= SIGHASH_ALL` check over-deferred 5/6 valid types and let
	// attackers flip the trailer byte to bypass the cheap reject —
	// hostile-reviewer P1. Free check (single byte compare).
	if !consensus.IsValidSighashType(w.Signature[len(w.Signature)-1]) {
		return false
	}
	// Wave-15 key-binding: SHA3(pubkey) must match CovenantData[1:33].
	// Cost: one SHA3 hash on a ~2.6KB pubkey, ≪ ML-DSA verify (the
	// documented scope-cap). Slow-path counterpart returns SigInvalid
	// "CORE_P2PK key binding mismatch".
	pubkeyHash := sha3.Sum256(w.Pubkey)
	return bytes.Equal(pubkeyHash[:], entry.CovenantData[1:33])
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
