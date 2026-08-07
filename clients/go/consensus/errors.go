package consensus

import "fmt"

type ErrorCode string

const (
	TX_ERR_PARSE                ErrorCode = "TX_ERR_PARSE"
	TX_ERR_WITNESS_OVERFLOW     ErrorCode = "TX_ERR_WITNESS_OVERFLOW"
	TX_ERR_SIG_NONCANONICAL     ErrorCode = "TX_ERR_SIG_NONCANONICAL"
	TX_ERR_SIG_ALG_INVALID      ErrorCode = "TX_ERR_SIG_ALG_INVALID"
	TX_ERR_SIG_INVALID          ErrorCode = "TX_ERR_SIG_INVALID"
	TX_ERR_SIGHASH_TYPE_INVALID ErrorCode = "TX_ERR_SIGHASH_TYPE_INVALID"
	TX_ERR_TIMELOCK_NOT_MET     ErrorCode = "TX_ERR_TIMELOCK_NOT_MET"

	TX_ERR_VALUE_CONSERVATION ErrorCode = "TX_ERR_VALUE_CONSERVATION"
	TX_ERR_TX_NONCE_INVALID   ErrorCode = "TX_ERR_TX_NONCE_INVALID"
	TX_ERR_SEQUENCE_INVALID   ErrorCode = "TX_ERR_SEQUENCE_INVALID"
	TX_ERR_NONCE_REPLAY       ErrorCode = "TX_ERR_NONCE_REPLAY"

	TX_ERR_COVENANT_TYPE_INVALID             ErrorCode = "TX_ERR_COVENANT_TYPE_INVALID"
	TX_ERR_SIMPLICITY_DECODE                 ErrorCode = "TX_ERR_SIMPLICITY_DECODE"
	TX_ERR_SIMPLICITY_PROGRAM_TOO_LARGE      ErrorCode = "TX_ERR_SIMPLICITY_PROGRAM_TOO_LARGE"
	TX_ERR_SIMPLICITY_ENVELOPE_TOO_LARGE     ErrorCode = "TX_ERR_SIMPLICITY_ENVELOPE_TOO_LARGE"
	TX_ERR_SIMPLICITY_CMR_MISMATCH           ErrorCode = "TX_ERR_SIMPLICITY_CMR_MISMATCH"
	TX_ERR_SIMPLICITY_JET_DISALLOWED         ErrorCode = "TX_ERR_SIMPLICITY_JET_DISALLOWED"
	TX_ERR_SIMPLICITY_BUDGET_EXCEEDED        ErrorCode = "TX_ERR_SIMPLICITY_BUDGET_EXCEEDED"
	TX_ERR_SIMPLICITY_REJECTED               ErrorCode = "TX_ERR_SIMPLICITY_REJECTED"
	TX_ERR_VAULT_MALFORMED                   ErrorCode = "TX_ERR_VAULT_MALFORMED"
	TX_ERR_VAULT_PARAMS_INVALID              ErrorCode = "TX_ERR_VAULT_PARAMS_INVALID"
	TX_ERR_VAULT_KEYS_NOT_CANONICAL          ErrorCode = "TX_ERR_VAULT_KEYS_NOT_CANONICAL"
	TX_ERR_VAULT_WHITELIST_NOT_CANONICAL     ErrorCode = "TX_ERR_VAULT_WHITELIST_NOT_CANONICAL"
	TX_ERR_VAULT_OWNER_DESTINATION_FORBIDDEN ErrorCode = "TX_ERR_VAULT_OWNER_DESTINATION_FORBIDDEN"
	TX_ERR_VAULT_OWNER_AUTH_REQUIRED         ErrorCode = "TX_ERR_VAULT_OWNER_AUTH_REQUIRED"
	TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN       ErrorCode = "TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN"
	TX_ERR_VAULT_MULTI_INPUT_FORBIDDEN       ErrorCode = "TX_ERR_VAULT_MULTI_INPUT_FORBIDDEN"
	TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED      ErrorCode = "TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED"
	TX_ERR_MISSING_UTXO                      ErrorCode = "TX_ERR_MISSING_UTXO"
	TX_ERR_COINBASE_IMMATURE                 ErrorCode = "TX_ERR_COINBASE_IMMATURE"

	BLOCK_ERR_PARSE                     ErrorCode = "BLOCK_ERR_PARSE"
	BLOCK_ERR_WEIGHT_EXCEEDED           ErrorCode = "BLOCK_ERR_WEIGHT_EXCEEDED"
	BLOCK_ERR_ANCHOR_BYTES_EXCEEDED     ErrorCode = "BLOCK_ERR_ANCHOR_BYTES_EXCEEDED"
	BLOCK_ERR_POW_INVALID               ErrorCode = "BLOCK_ERR_POW_INVALID"
	BLOCK_ERR_TARGET_INVALID            ErrorCode = "BLOCK_ERR_TARGET_INVALID"
	BLOCK_ERR_LINKAGE_INVALID           ErrorCode = "BLOCK_ERR_LINKAGE_INVALID"
	BLOCK_ERR_MERKLE_INVALID            ErrorCode = "BLOCK_ERR_MERKLE_INVALID"
	BLOCK_ERR_WITNESS_COMMITMENT        ErrorCode = "BLOCK_ERR_WITNESS_COMMITMENT"
	BLOCK_ERR_COINBASE_INVALID          ErrorCode = "BLOCK_ERR_COINBASE_INVALID"
	BLOCK_ERR_SUBSIDY_EXCEEDED          ErrorCode = "BLOCK_ERR_SUBSIDY_EXCEEDED"
	BLOCK_ERR_TIMESTAMP_OLD             ErrorCode = "BLOCK_ERR_TIMESTAMP_OLD"
	BLOCK_ERR_TIMESTAMP_FUTURE          ErrorCode = "BLOCK_ERR_TIMESTAMP_FUTURE"
	BLOCK_ERR_DA_INCOMPLETE             ErrorCode = "BLOCK_ERR_DA_INCOMPLETE"
	BLOCK_ERR_DA_CHUNK_HASH_INVALID     ErrorCode = "BLOCK_ERR_DA_CHUNK_HASH_INVALID"
	BLOCK_ERR_DA_SET_INVALID            ErrorCode = "BLOCK_ERR_DA_SET_INVALID"
	BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID ErrorCode = "BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID"
	BLOCK_ERR_DA_BATCH_EXCEEDED         ErrorCode = "BLOCK_ERR_DA_BATCH_EXCEEDED"
)

// TxErrorCause is the closed, source-owned classification of WHY a consensus
// error was produced, for the consumers that must tell a fault of THIS PROCESS
// apart from invalidity of the candidate bytes. The public ErrorCode alone
// cannot express that difference: TX_ERR_PARSE, TX_ERR_SIG_INVALID and
// TX_ERR_SIG_ALG_INVALID each carry both meanings today.
//
// It is additive in BEHAVIOR, not in struct shape. Preserved exactly: every
// public ErrorCode, every message, Error() rendering, every accept/reject
// decision, every counter, and validation order — none of them read the cause,
// and an error whose producer selected no cause keeps its exact baseline
// classification everywhere. NOT preserved: the shape of the exported TxError,
// which grows an unexported field, so an UNKEYED composite literal such as
// consensus.TxError{code, msg} no longer compiles.
//
// That source break is deliberate and accepted. Keeping the cause unexported
// is what makes it unforgeable outside this package and invisible to every
// public view, and an unkeyed literal fails LOUDLY at compile time rather than
// silently mis-assigning. `go vet` runs the composites check by default, so the
// fragile form is reported before it can become a hard break, and every TxError
// literal in this repository is already keyed. To migrate one: name the fields,
// or construct through txerr / txerrWithCause inside this package.
//
// The FIRST producing branch owns the cause. An outer wrapper may carry an
// already-selected cause forward but must never overwrite or erase it, and no
// consumer may infer one from message text.
//
// Adding a member is a constant plus one consumer arm. It never changes this
// type, the accessor, or an existing mapping.
type TxErrorCause uint8

const (
	// TxErrorCauseUnspecified means no producing branch selected a cause. It is
	// the zero value and carries no new meaning.
	TxErrorCauseUnspecified TxErrorCause = iota
	// TxErrorCauseLocalCryptoBackendFault means this node's own OpenSSL
	// consensus backend could not initialize, could not resolve its live
	// verifier binding from local runtime/configuration state, or failed
	// INSIDE verification for a reason that is not a property of the candidate.
	// It is evidence about this process, never about the transaction, so a
	// consumer must not publish the outcome as a stable terminal rejection of
	// these bytes and must not let it authorize a negative cache.
	//
	// It is deliberately NOT selected when the candidate itself selected an
	// unsupported or unauthorized suite: that verdict is a property of the
	// bytes and keeps its baseline classification.
	TxErrorCauseLocalCryptoBackendFault
)

type TxError struct {
	Code ErrorCode
	Msg  string
	// cause is the producing branch's own typed classification. It is
	// unexported and outside every public view — Error(), Code, Msg, the JSON
	// and HTTP mappings neither read it nor change with it — so a consumer that
	// wants it MUST call Cause(). Its zero value is TxErrorCauseUnspecified.
	cause TxErrorCause
}

func (e *TxError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Msg == "" {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Msg)
}

// Cause reports the typed cause the producing branch selected, or
// TxErrorCauseUnspecified when none did. It is a pure read: it allocates
// nothing, mutates nothing, and is nil-safe like Error().
func (e *TxError) Cause() TxErrorCause {
	if e == nil {
		return TxErrorCauseUnspecified
	}
	return e.cause
}

// txerr is the compatibility constructor: it selects no cause, so every
// existing call site keeps its exact baseline behavior.
func txerr(code ErrorCode, msg string) error {
	return &TxError{Code: code, Msg: msg}
}

// txerrWithCause is the ONE cause-aware constructor. It is used only AT a
// producing branch that owns the classification, or by a wrapper carrying an
// already-selected cause forward unchanged.
//
// First-wins is a CALLER obligation, not a constructor guard: this function
// accepts any cause and always builds a fresh error, so a wrapper MUST pass the
// inner error's own Cause() and never a cause literal of its own.
func txerrWithCause(code ErrorCode, msg string, cause TxErrorCause) error {
	return &TxError{Code: code, Msg: msg, cause: cause}
}
