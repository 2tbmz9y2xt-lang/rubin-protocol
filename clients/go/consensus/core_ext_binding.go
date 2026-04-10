package consensus

import (
	"bytes"
	"fmt"
	"math"
	"strings"
)

const CoreExtBindingNameVerifySigExtOpenSSLDigest32V1 = "verify_sig_ext_openssl_digest32_v1"

var coreExtOpenSSLDigest32BindingDescriptorPrefix = []byte("RUBIN-CORE-EXT-VERIFY-SIG-OPENSSL-DIGEST32-v1")

type CoreExtOpenSSLDigest32BindingDescriptor struct {
	OpenSSLAlg string
	PubkeyLen  int
	SigLen     int
}

// NormalizeCoreExtBindingName canonicalizes the repository-wide binding name
// vocabulary shared by helper, archival, and conformance surfaces.
func NormalizeCoreExtBindingName(binding string) (string, error) {
	binding = strings.TrimSpace(binding)
	switch binding {
	case "", "native_verify_sig", CoreExtBindingNameVerifySigExtOpenSSLDigest32V1:
		return binding, nil
	default:
		return "", fmt.Errorf("unsupported core_ext binding: %q", binding)
	}
}

// NormalizeLiveCoreExtBindingName enforces the current chain-instance live
// manifest contract. In the current repository baseline, live CORE_EXT
// verification is pinned to the OpenSSL digest32 binding; native/empty
// bindings remain non-live helper surfaces and must not reach runtime loaders.
func NormalizeLiveCoreExtBindingName(binding string) (string, error) {
	binding, err := NormalizeCoreExtBindingName(binding)
	if err != nil {
		return "", err
	}
	switch binding {
	case CoreExtBindingNameVerifySigExtOpenSSLDigest32V1:
		return binding, nil
	default:
		return "", fmt.Errorf("unsupported core_ext binding: %q", binding)
	}
}

func parseNormalizedCoreExtVerifySigExtBinding(binding string, bindingDescriptor []byte, extPayloadSchema []byte) (CoreExtVerifySigExtFunc, error) {
	switch binding {
	case "", "native_verify_sig":
		return nil, nil
	case CoreExtBindingNameVerifySigExtOpenSSLDigest32V1:
		if len(extPayloadSchema) == 0 {
			return nil, fmt.Errorf("core_ext binding %s requires ext_payload_schema_hex", CoreExtBindingNameVerifySigExtOpenSSLDigest32V1)
		}
		desc, err := ParseCoreExtOpenSSLDigest32BindingDescriptor(bindingDescriptor)
		if err != nil {
			return nil, err
		}
		return func(_ uint16, _ uint8, pubkey []byte, signature []byte, digest32 [32]byte, _ []byte) (bool, error) {
			return verifyCoreExtOpenSSLDigest32(desc, pubkey, signature, digest32)
		}, nil
	default:
		return nil, fmt.Errorf("unsupported core_ext binding: %q", binding)
	}
}

// ParseNormalizedCoreExtVerifySigExtBinding assumes binding already came from
// NormalizeCoreExtBindingName or NormalizeLiveCoreExtBindingName.
//
// Even helper/conformance/archive surfaces must provide ext_payload_schema_hex
// for the OpenSSL verify_sig_ext binding so Go/Rust do not expose a looser
// helper-only parser surface than the live runtime.
func ParseNormalizedCoreExtVerifySigExtBinding(binding string, bindingDescriptor []byte, extPayloadSchema []byte) (CoreExtVerifySigExtFunc, error) {
	return parseNormalizedCoreExtVerifySigExtBinding(binding, bindingDescriptor, extPayloadSchema)
}

// ParseNormalizedLiveCoreExtVerifySigExtBinding assumes binding already passed
// NormalizeLiveCoreExtBindingName and enforces the live manifest requirement
// that verify_sig_ext OpenSSL bindings carry a non-empty ext_payload_schema.
func ParseNormalizedLiveCoreExtVerifySigExtBinding(binding string, bindingDescriptor []byte, extPayloadSchema []byte) (CoreExtVerifySigExtFunc, error) {
	return parseNormalizedCoreExtVerifySigExtBinding(binding, bindingDescriptor, extPayloadSchema)
}

func ParseCoreExtVerifySigExtBinding(binding string, bindingDescriptor []byte, extPayloadSchema []byte) (CoreExtVerifySigExtFunc, error) {
	var err error
	binding, err = NormalizeCoreExtBindingName(binding)
	if err != nil {
		return nil, err
	}
	return ParseNormalizedCoreExtVerifySigExtBinding(binding, bindingDescriptor, extPayloadSchema)
}

// ParseLiveCoreExtVerifySigExtBinding is the live runtime loader path for
// manifest-derived CORE_EXT verification. Historical/helper paths may still
// use ParseCoreExtVerifySigExtBinding directly, but live consumers must call
// this stricter entrypoint so manifest drift cannot silently switch bindings.
func ParseLiveCoreExtVerifySigExtBinding(binding string, bindingDescriptor []byte, extPayloadSchema []byte) (CoreExtVerifySigExtFunc, error) {
	binding, err := NormalizeLiveCoreExtBindingName(binding)
	if err != nil {
		return nil, err
	}
	return ParseNormalizedLiveCoreExtVerifySigExtBinding(binding, bindingDescriptor, extPayloadSchema)
}

func CoreExtOpenSSLDigest32BindingDescriptorBytes(opensslAlg string, pubkeyLen int, sigLen int) ([]byte, error) {
	if err := validateCoreExtOpenSSLBindingDescriptor(opensslAlg, pubkeyLen, sigLen); err != nil {
		return nil, err
	}
	out := append([]byte(nil), coreExtOpenSSLDigest32BindingDescriptorPrefix...)
	out = AppendCompactSize(out, uint64(len(opensslAlg)))
	out = append(out, opensslAlg...)
	out = AppendCompactSize(out, uint64(pubkeyLen)) // #nosec G115 -- validateCoreExtOpenSSLBindingDescriptor enforces exact ML-DSA-87 sizes.
	out = AppendCompactSize(out, uint64(sigLen))    // #nosec G115 -- validateCoreExtOpenSSLBindingDescriptor enforces exact ML-DSA-87 sizes.
	return out, nil
}

func ParseCoreExtOpenSSLDigest32BindingDescriptor(raw []byte) (CoreExtOpenSSLDigest32BindingDescriptor, error) {
	if !bytes.HasPrefix(raw, coreExtOpenSSLDigest32BindingDescriptorPrefix) {
		return CoreExtOpenSSLDigest32BindingDescriptor{}, fmt.Errorf("bad core_ext binding_descriptor")
	}
	off := len(coreExtOpenSSLDigest32BindingDescriptorPrefix)
	algLenU64, _, err := readCompactSize(raw, &off)
	if err != nil {
		return CoreExtOpenSSLDigest32BindingDescriptor{}, fmt.Errorf("bad core_ext binding_descriptor")
	}
	if algLenU64 > uint64(math.MaxInt) {
		return CoreExtOpenSSLDigest32BindingDescriptor{}, fmt.Errorf("bad core_ext binding_descriptor")
	}
	algBytes, err := readBytes(raw, &off, int(algLenU64))
	if err != nil {
		return CoreExtOpenSSLDigest32BindingDescriptor{}, fmt.Errorf("bad core_ext binding_descriptor")
	}
	pubkeyLenU64, _, err := readCompactSize(raw, &off)
	if err != nil {
		return CoreExtOpenSSLDigest32BindingDescriptor{}, fmt.Errorf("bad core_ext binding_descriptor")
	}
	sigLenU64, _, err := readCompactSize(raw, &off)
	if err != nil {
		return CoreExtOpenSSLDigest32BindingDescriptor{}, fmt.Errorf("bad core_ext binding_descriptor")
	}
	if off != len(raw) || pubkeyLenU64 > uint64(math.MaxInt) || sigLenU64 > uint64(math.MaxInt) {
		return CoreExtOpenSSLDigest32BindingDescriptor{}, fmt.Errorf("bad core_ext binding_descriptor")
	}

	desc := CoreExtOpenSSLDigest32BindingDescriptor{
		OpenSSLAlg: string(algBytes),
		PubkeyLen:  int(pubkeyLenU64),
		SigLen:     int(sigLenU64),
	}
	if err := validateCoreExtOpenSSLBindingDescriptor(desc.OpenSSLAlg, desc.PubkeyLen, desc.SigLen); err != nil {
		return CoreExtOpenSSLDigest32BindingDescriptor{}, err
	}
	return desc, nil
}

func validateCoreExtOpenSSLBindingDescriptor(opensslAlg string, pubkeyLen int, sigLen int) error {
	requiredPubkeyLen, ok := keygenAllowlist[opensslAlg]
	if !ok {
		return fmt.Errorf("unsupported core_ext OpenSSL alg: %s", opensslAlg)
	}
	if opensslAlg != "ML-DSA-87" {
		return fmt.Errorf("unsupported core_ext OpenSSL alg: %s", opensslAlg)
	}
	if pubkeyLen != requiredPubkeyLen {
		return fmt.Errorf("core_ext OpenSSL binding pubkey length mismatch for %s: got %d want %d", opensslAlg, pubkeyLen, requiredPubkeyLen)
	}
	if sigLen != ML_DSA_87_SIG_BYTES {
		return fmt.Errorf("core_ext OpenSSL binding sig length mismatch for %s: got %d want %d", opensslAlg, sigLen, ML_DSA_87_SIG_BYTES)
	}
	return nil
}

func verifyCoreExtOpenSSLDigest32(desc CoreExtOpenSSLDigest32BindingDescriptor, pubkey []byte, signature []byte, digest32 [32]byte) (bool, error) {
	if len(pubkey) != desc.PubkeyLen || len(signature) != desc.SigLen {
		return false, nil
	}
	if err := ensureOpenSSLConsensusInit(); err != nil {
		return false, err
	}
	ok, err := opensslVerifySigOneShotFn(desc.OpenSSLAlg, pubkey, signature, digest32[:])
	if err != nil {
		return false, txerr(TX_ERR_SIG_INVALID, "verify_sig_ext: EVP_DigestVerify internal error")
	}
	return ok, nil
}
