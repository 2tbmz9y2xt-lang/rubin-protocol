package consensus

import (
	"fmt"
	"sort"
	"strings"
)

// IsV1ProductionRotationNetwork reports whether the node or harness network name
// uses the v1 production rotation profile (finite H4 required). This matches
// RUBIN_NATIVE_CRYPTO_ROTATION_SPEC_v1.md: mainnet and public testnet.
func IsV1ProductionRotationNetwork(network string) bool {
	n := strings.ToLower(strings.TrimSpace(network))
	return n == "mainnet" || n == "testnet"
}

// ValidateV1ProductionRotationDescriptor enforces the v1 production profile on a
// single descriptor after generic Validate() invariants.
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
// generic overlap rules, finite H4 on every descriptor, and chained H1 ≥ prior H4.
func ValidateV1ProductionRotationSet(descriptors []CryptoRotationDescriptor, registry *SuiteRegistry) error {
	if err := ValidateRotationSet(descriptors, registry); err != nil {
		return err
	}
	for i, d := range descriptors {
		if d.SunsetHeight == 0 {
			return fmt.Errorf("rotation[%d] %q: v1 production profile requires finite sunset_height (H4)", i, d.Name)
		}
	}
	if len(descriptors) <= 1 {
		return nil
	}
	order := make([]int, len(descriptors))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(i, j int) bool {
		a, b := descriptors[order[i]], descriptors[order[j]]
		if a.CreateHeight == b.CreateHeight {
			return a.Name < b.Name
		}
		return a.CreateHeight < b.CreateHeight
	})
	for w := 1; w < len(order); w++ {
		prev := descriptors[order[w-1]]
		cur := descriptors[order[w]]
		if cur.CreateHeight < prev.SunsetHeight {
			return fmt.Errorf(
				"rotation: successor %q H1 (%d) must be >= prior %q H4 (%d)",
				cur.Name, cur.CreateHeight, prev.Name, prev.SunsetHeight,
			)
		}
	}
	return nil
}
