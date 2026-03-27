package consensus

import (
	"encoding/binary"
	"fmt"
	"math/bits"
)

const governanceReplayTokenBytes = 26

type governanceReplayTokenValidation uint8

const (
	governanceReplayTokenValid governanceReplayTokenValidation = iota
	governanceReplayTokenExtIDMismatch
	governanceReplayTokenNonceMismatch
	governanceReplayTokenNotYetValid
	governanceReplayTokenExpired
)

// GovernanceReplayToken binds a governance authorization to a specific height
// window and nonce so stale governance actions cannot be replayed across
// activation cycles.
type GovernanceReplayToken struct {
	ExtID          uint16
	Nonce          uint64
	IssuedAtHeight uint64
	ValidityWindow uint64
}

func IssueGovernanceReplayToken(extID uint16, nonce uint64, currentHeight uint64, validityWindow uint64) GovernanceReplayToken {
	// Keep zero-window behavior aligned with Rust: the token is created
	// successfully but is immediately expired at issued_at_height.
	return GovernanceReplayToken{
		ExtID:          extID,
		Nonce:          nonce,
		IssuedAtHeight: currentHeight,
		ValidityWindow: validityWindow,
	}
}

func (t GovernanceReplayToken) Validate(expectedExtID uint16, currentHeight uint64, expectedNonce uint64) error {
	switch t.validationOutcome(expectedExtID, currentHeight, expectedNonce) {
	case governanceReplayTokenValid:
		return nil
	case governanceReplayTokenExtIDMismatch:
		return fmt.Errorf(
			"governance replay token ext_id mismatch: token=%d expected=%d",
			t.ExtID,
			expectedExtID,
		)
	case governanceReplayTokenNonceMismatch:
		return fmt.Errorf(
			"governance replay token nonce mismatch: token=%d expected=%d",
			t.Nonce,
			expectedNonce,
		)
	case governanceReplayTokenNotYetValid:
		return fmt.Errorf(
			"governance replay token not yet valid: issued_at=%d current=%d",
			t.IssuedAtHeight,
			currentHeight,
		)
	case governanceReplayTokenExpired:
		return fmt.Errorf(
			"governance replay token expired: expiry=%d current=%d",
			t.expiryHeight(),
			currentHeight,
		)
	default:
		return fmt.Errorf("governance replay token validation failed")
	}
}

func (t GovernanceReplayToken) validationOutcome(expectedExtID uint16, currentHeight uint64, expectedNonce uint64) governanceReplayTokenValidation {
	// Keep this ordering in lockstep with Rust for parity:
	// ext_id -> nonce -> issued_at -> expiry.
	if t.ExtID != expectedExtID {
		return governanceReplayTokenExtIDMismatch
	}
	if t.Nonce != expectedNonce {
		return governanceReplayTokenNonceMismatch
	}
	if currentHeight < t.IssuedAtHeight {
		return governanceReplayTokenNotYetValid
	}
	if currentHeight >= t.expiryHeight() {
		return governanceReplayTokenExpired
	}
	return governanceReplayTokenValid
}

func (t GovernanceReplayToken) expiryHeight() uint64 {
	expiry, carry := bits.Add64(t.IssuedAtHeight, t.ValidityWindow, 0)
	if carry != 0 {
		return ^uint64(0)
	}
	return expiry
}

func (t GovernanceReplayToken) ToBytes() []byte {
	out := make([]byte, governanceReplayTokenBytes)
	binary.LittleEndian.PutUint16(out[0:2], t.ExtID)
	binary.LittleEndian.PutUint64(out[2:10], t.Nonce)
	binary.LittleEndian.PutUint64(out[10:18], t.IssuedAtHeight)
	binary.LittleEndian.PutUint64(out[18:26], t.ValidityWindow)
	return out
}

func GovernanceReplayTokenFromBytes(data []byte) (GovernanceReplayToken, error) {
	if len(data) != governanceReplayTokenBytes {
		return GovernanceReplayToken{}, fmt.Errorf(
			"governance replay token: expected 26 bytes, got %d",
			len(data),
		)
	}
	return GovernanceReplayToken{
		ExtID:          binary.LittleEndian.Uint16(data[0:2]),
		Nonce:          binary.LittleEndian.Uint64(data[2:10]),
		IssuedAtHeight: binary.LittleEndian.Uint64(data[10:18]),
		ValidityWindow: binary.LittleEndian.Uint64(data[18:26]),
	}, nil
}
