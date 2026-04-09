package consensus

import (
	"fmt"
	"strings"
)

const (
	RotationV1ProductionAtMostOneDescriptorErrStem = "rotation: v1 production profile allows at most one descriptor"
	RotationV1ProductionFiniteH4RequiredErrStem    = "rotation: v1 production profile requires finite sunset_height (H4)"
)

// IsV1ProductionRotationNetwork reports whether the node or harness network name
// uses the v1 production rotation profile (finite H4 required). This matches
// RUBIN_NATIVE_CRYPTO_ROTATION_SPEC_v1.md: mainnet and public testnet.
func IsV1ProductionRotationNetwork(network string) bool {
	n := strings.ToLower(strings.TrimSpace(network))
	return n == "mainnet" || n == "testnet"
}

// ValidateRotationDescriptorForNetwork runs generic descriptor validation, then applies
// v1 production profile rules (finite H4) when network is mainnet or testnet.
func ValidateRotationDescriptorForNetwork(network string, d CryptoRotationDescriptor, registry *SuiteRegistry) error {
	if IsV1ProductionRotationNetwork(network) {
		return ValidateV1ProductionRotationDescriptor(d, registry)
	}
	return d.Validate(registry)
}

// ValidateRotationSetForNetwork runs ValidateRotationSet on devnet and private nets,
// and adds the strict v1 production rules (single descriptor + finite H4) on
// mainnet/testnet.
func ValidateRotationSetForNetwork(network string, descriptors []CryptoRotationDescriptor, registry *SuiteRegistry) error {
	if IsV1ProductionRotationNetwork(network) {
		return ValidateV1ProductionRotationSet(descriptors, registry)
	}
	return ValidateRotationSet(descriptors, registry)
}

// ValidateV1ProductionRotationDescriptor enforces the v1 production profile on a
// single descriptor (finite H4) after generic Validate() invariants.
func ValidateV1ProductionRotationDescriptor(d CryptoRotationDescriptor, registry *SuiteRegistry) error {
	if err := d.Validate(registry); err != nil {
		return err
	}
	if d.SunsetHeight == 0 {
		return fmt.Errorf(RotationV1ProductionFiniteH4RequiredErrStem)
	}
	return nil
}

// RequireFiniteV1ProductionRotationSunsetHeight applies the production-only H4
// rule to an already-validated descriptor.
func RequireFiniteV1ProductionRotationSunsetHeight(d CryptoRotationDescriptor) error {
	if d.SunsetHeight == 0 {
		return fmt.Errorf(RotationV1ProductionFiniteH4RequiredErrStem)
	}
	return nil
}

// ValidateV1ProductionRotationSet checks a descriptor batch for production:
// at most one descriptor, and for the only allowed descriptor it enforces the
// full production descriptor helper directly (generic descriptor validation +
// finite H4) without running set-only overlap logic.
func ValidateV1ProductionRotationSet(descriptors []CryptoRotationDescriptor, registry *SuiteRegistry) error {
	switch len(descriptors) {
	case 0:
		return nil
	case 1:
		return ValidateV1ProductionRotationDescriptor(descriptors[0], registry)
	default:
		return fmt.Errorf(
			"%s, got %d",
			RotationV1ProductionAtMostOneDescriptorErrStem,
			len(descriptors),
		)
	}
}
