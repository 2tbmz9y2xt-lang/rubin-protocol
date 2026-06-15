package simplicity

import "crypto/sha3"

const (
	sha3256JetBaseCost   uint64 = 64
	mldsa87VerifyJetCost uint64 = 50_000
	mldsa87PubkeyBytes          = 2_592
	mldsa87SigBytes             = 4_627
)

// These helpers are staged Go-native primitives. They do not wire Program.Evaluate
// or consensus validation; Rust/shared parity slices must land before dispatch.
type SHA3256JetResult struct {
	Digest [32]byte
	Cost   uint64
}

func EvaluateSHA3256Jet(message []byte) SHA3256JetResult {
	return SHA3256JetResult{
		Digest: sha3.Sum256(message),
		Cost:   sha3256JetBaseCost + uint64(len(message)),
	}
}

// A false verification result is program-visible and is not an error here.
type MLDSA87VerifyJetResult struct {
	Verified bool
	Cost     uint64
}

type MLDSA87Digest32Verifier func(pubkey []byte, signature []byte, digest32 [32]byte) (bool, error)

// EvaluateMLDSA87VerifyJet accepts raw ML-DSA-87 signatures only; no trailing
// sighash byte is stripped or interpreted.
func EvaluateMLDSA87VerifyJet(pubkey []byte, signature []byte, digest32 [32]byte, verifier MLDSA87Digest32Verifier) (MLDSA87VerifyJetResult, error) {
	result := MLDSA87VerifyJetResult{Cost: mldsa87VerifyJetCost}
	if len(pubkey) != mldsa87PubkeyBytes || len(signature) != mldsa87SigBytes {
		return result, nil
	}
	if verifier == nil {
		return result, &Error{Code: ErrJetDisallowed}
	}
	ok, err := verifier(pubkey, signature, digest32)
	if err != nil {
		return result, err
	}
	result.Verified = ok
	return result, nil
}
