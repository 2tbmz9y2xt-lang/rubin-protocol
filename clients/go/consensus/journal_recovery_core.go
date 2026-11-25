package consensus

import (
	"bytes"
	"errors"
)

// RecoveryCoreHeaderModeV1 selects the header checks for a recovery-core fact.
type RecoveryCoreHeaderModeV1 uint8

const (
	RecoveryCoreFullV1 RecoveryCoreHeaderModeV1 = iota + 1
	RecoveryCoreQualifiedImageV1
)

// RecoveryCoreFullHeaderV1 supplies the original limit and expected target.
// Parent is present at positive heights and absent at height zero.
type RecoveryCoreFullHeaderV1 struct {
	PowLimit       [32]byte
	ExpectedTarget [32]byte
	Parent         *[32]byte
}

// RecoveryCoreHeaderInputV1 supplies the payload selected by Mode.
// Image is the exact raw header from a positively qualified IMAGE position.
type RecoveryCoreHeaderInputV1 struct {
	Mode  RecoveryCoreHeaderModeV1
	Full  *RecoveryCoreFullHeaderV1
	Image *[Initial148HeaderBytes]byte
}

// RecoveryCoreGateV1 identifies the first failed check or is empty on a fact.
type RecoveryCoreGateV1 string

const (
	RecoveryCoreInvalidInputV1   RecoveryCoreGateV1 = "INVALID_INPUT"
	RecoveryCoreParseV1          RecoveryCoreGateV1 = "PARSE"
	RecoveryCoreEmptyTxCountV1   RecoveryCoreGateV1 = "EMPTY_TX_COUNT"
	RecoveryCoreExpectedHashV1   RecoveryCoreGateV1 = "EXPECTED_HASH"
	RecoveryCoreTargetRangeV1    RecoveryCoreGateV1 = "TARGET_RANGE"
	RecoveryCorePowHashV1        RecoveryCoreGateV1 = "POW_HASH"
	RecoveryCoreExpectedTargetV1 RecoveryCoreGateV1 = "EXPECTED_TARGET"
	RecoveryCoreExpectedParentV1 RecoveryCoreGateV1 = "EXPECTED_PARENT"
	RecoveryCoreImageHeaderV1    RecoveryCoreGateV1 = "IMAGE_HEADER"
	RecoveryCoreTxidMerkleV1     RecoveryCoreGateV1 = "TXID_MERKLE"
	RecoveryCorePredicateFalseV1 RecoveryCoreGateV1 = "PREDICATE_FALSE"
)

// RecoveryCoreReasonV1 identifies the structural defect in the committed core.
type RecoveryCoreReasonV1 string

const (
	RecoveryCoreAnchorCountV1       RecoveryCoreReasonV1 = "ANCHOR_COUNT"
	RecoveryCorePositionZeroChunkV1 RecoveryCoreReasonV1 = "POSITION_ZERO_CHUNK"
)

// RecoveryCoreFactV1 is the tx0 kind, exact anchor count and structural reason.
type RecoveryCoreFactV1 struct {
	Kind        uint8
	AnchorCount int
	Reason      RecoveryCoreReasonV1
}

// RecoveryCoreResultV1 reports a gate or a fact. On refusal Fact is zero.
// ParserCause is populated only on a parser refusal.
type RecoveryCoreResultV1 struct {
	Gate        RecoveryCoreGateV1
	ParserCause error
	Fact        RecoveryCoreFactV1
}

// DeriveRecoveryCoreFactV1 returns the first failed gate or the structural fact
// over the header-committed transaction core. The caller supplies immutable
// inputs and binds the header context (RUBIN_MEMPOOL_POLICY.md Section 6.4.1.8).
func DeriveRecoveryCoreFactV1(raw []byte, expectedHash [32]byte, height uint64, input RecoveryCoreHeaderInputV1) RecoveryCoreResultV1 {
	if !recoveryCoreHeaderInputValidV1(height, input) {
		return RecoveryCoreResultV1{Gate: RecoveryCoreInvalidInputV1}
	}
	block, err := ParseInitial148BlockBytes(raw)
	if err != nil {
		return recoveryCoreParseRefusalV1(err)
	}
	// A successful parse supplies exactly 148 header bytes and nonempty txids.
	digest, _ := Initial148BlockHash(block.HeaderBytes)
	if digest != expectedHash {
		return RecoveryCoreResultV1{Gate: RecoveryCoreExpectedHashV1}
	}
	if gate := recoveryCoreHeaderGateV1(block, digest, input); gate != "" {
		return RecoveryCoreResultV1{Gate: gate}
	}
	root, _ := MerkleRootTxids(block.Txids)
	if root != block.Header.MerkleRoot {
		return RecoveryCoreResultV1{Gate: RecoveryCoreTxidMerkleV1}
	}
	return recoveryCorePredicateV1(block.Txs[0])
}

// recoveryCoreHeaderInputValidV1 accepts only the selected payload and parent presence.
func recoveryCoreHeaderInputValidV1(height uint64, input RecoveryCoreHeaderInputV1) bool {
	switch input.Mode {
	case RecoveryCoreFullV1:
		return input.Full != nil && input.Image == nil && (height == 0) == (input.Full.Parent == nil)
	case RecoveryCoreQualifiedImageV1:
		return input.Image != nil && input.Full == nil
	default:
		return false
	}
}

// recoveryCoreParseRefusalV1 preserves the parser error and labels canonical zero.
func recoveryCoreParseRefusalV1(err error) RecoveryCoreResultV1 {
	gate := RecoveryCoreParseV1
	if txErr, ok := errors.AsType[*TxError](err); ok && txErr.Code == BLOCK_ERR_COINBASE_INVALID {
		gate = RecoveryCoreEmptyTxCountV1
	}
	return RecoveryCoreResultV1{Gate: gate, ParserCause: err}
}

// recoveryCoreHeaderGateV1 compares the supplied IMAGE header or checks the FULL
// range, work, expected target and applicable parent in order.
func recoveryCoreHeaderGateV1(block *Initial148ParsedBlock, digest [32]byte, input RecoveryCoreHeaderInputV1) RecoveryCoreGateV1 {
	if input.Mode == RecoveryCoreQualifiedImageV1 {
		if !bytes.Equal(block.HeaderBytes, input.Image[:]) {
			return RecoveryCoreImageHeaderV1
		}
		return ""
	}
	if gate := recoveryCorePowGateV1(digest, block.Header.Target, input.Full.PowLimit); gate != "" {
		return gate
	}
	if block.Header.Target != input.Full.ExpectedTarget {
		return RecoveryCoreExpectedTargetV1
	}
	if parent := input.Full.Parent; parent != nil && block.Header.PrevBlockHash != *parent {
		return RecoveryCoreExpectedParentV1
	}
	return ""
}

// recoveryCorePowGateV1 requires 1 <= target <= limit and digest < target
// in unsigned big-endian order (RUBIN_L1_CANONICAL.md Section 10.3).
func recoveryCorePowGateV1(digest, target, limit [32]byte) RecoveryCoreGateV1 {
	if target == ([32]byte{}) || bytes.Compare(target[:], limit[:]) > 0 {
		return RecoveryCoreTargetRangeV1
	}
	if bytes.Compare(digest[:], target[:]) >= 0 {
		return RecoveryCorePowHashV1
	}
	return ""
}

// recoveryCorePredicateV1 counts qualifying tx0 outputs before checking its kind.
func recoveryCorePredicateV1(tx *Tx) RecoveryCoreResultV1 {
	count := 0
	for _, output := range tx.Outputs {
		if output.CovenantType == COV_TYPE_ANCHOR && len(output.CovenantData) == 32 {
			count++
		}
	}
	if count != 1 {
		return RecoveryCoreResultV1{Fact: RecoveryCoreFactV1{Kind: tx.TxKind, AnchorCount: count, Reason: RecoveryCoreAnchorCountV1}}
	}
	if tx.TxKind == 0x02 {
		return RecoveryCoreResultV1{Fact: RecoveryCoreFactV1{Kind: tx.TxKind, AnchorCount: 1, Reason: RecoveryCorePositionZeroChunkV1}}
	}
	return RecoveryCoreResultV1{Gate: RecoveryCorePredicateFalseV1}
}
