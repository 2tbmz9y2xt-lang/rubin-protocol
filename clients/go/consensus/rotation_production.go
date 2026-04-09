package consensus

import (
	"fmt"
	"strings"
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
	if err := d.Validate(registry); err != nil {
		return err
	}
	if IsV1ProductionRotationNetwork(network) && d.SunsetHeight == 0 {
		return fmt.Errorf("rotation: v1 production profile requires finite sunset_height (H4)")
	}
	return nil
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
		return fmt.Errorf("rotation: v1 production profile requires finite sunset_height (H4)")
	}
	return nil
}

// ValidateV1ProductionRotationSet checks a descriptor batch for production:
// at most one descriptor, and for the only allowed descriptor it enforces the
// full production helper (generic descriptor validation + finite H4).
func ValidateV1ProductionRotationSet(descriptors []CryptoRotationDescriptor, registry *SuiteRegistry) error {
	switch len(descriptors) {
	case 0:
		return nil
	case 1:
		// Keep the generic set validator on the single-descriptor path so
		// production and non-production share the same descriptor/set baseline
		// before the stricter finite-H4 production rule applies.
		if err := ValidateRotationSet(descriptors, registry); err != nil {
			return err
		}
		return ValidateV1ProductionRotationDescriptor(descriptors[0], registry)
	default:
		return fmt.Errorf(
			"rotation: v1 production profile allows at most one descriptor, got %d",
			len(descriptors),
		)
	}
}
