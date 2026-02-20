package p2p

import (
	"errors"
	"testing"

	"rubin.dev/node/consensus"
	"rubin.dev/node/crypto"
)

func TestValidateHeadersProfilePassAndLinkageFail(t *testing.T) {
	var cp crypto.DevStdCryptoProvider

	parent := consensus.BlockHeader{
		Version:   1,
		Timestamp: 1000,
		Target:    consensus.MAX_TARGET,
		Nonce:     1,
	}
	parentHash, err := consensus.BlockHeaderHash(cp, parent)
	if err != nil {
		t.Fatal(err)
	}

	h1 := consensus.BlockHeader{
		Version:       1,
		PrevBlockHash: parentHash,
		Timestamp:     2000,
		Target:        consensus.MAX_TARGET,
		Nonce:         2,
	}
	ctx := consensus.BlockValidationContext{
		Height:          1,
		AncestorHeaders: []consensus.BlockHeader{parent},
		LocalTime:       10_000,
		LocalTimeSet:    true,
	}
	if err := ValidateHeadersProfile(cp, []consensus.BlockHeader{h1}, ctx); err != nil {
		t.Fatalf("expected pass, got %v", err)
	}

	// Linkage mismatch should fail.
	hBad := h1
	hBad.PrevBlockHash[0] ^= 0xff
	if err := ValidateHeadersProfile(cp, []consensus.BlockHeader{hBad}, ctx); err == nil || !errors.Is(err, ErrHeaderLinkageInvalid) {
		t.Fatalf("expected %v, got %v", ErrHeaderLinkageInvalid, err)
	}
}
