package consensus

import "fmt"

// CryptoRotationDescriptor defines a scheduled transition from one native
// signature suite to another. It specifies the heights at which the new
// suite becomes valid for creation and spending.
//
// Implements CANONICAL §23 rotation lifecycle:
//   - H1 (CreateHeight): new suite becomes valid for covenant creation
//   - H2 (SpendHeight):  new suite becomes valid for covenant spending
//   - H4 (SunsetHeight): optional — old suite ceases to be valid for creation
//
// Invariants enforced by Validate():
//   - OldSuiteID != NewSuiteID
//   - Both suites are registered native suites
//   - H1 < H2
//   - H4 > H2 if defined (H4 != 0)
//   - No CORE_EXT-only suite IDs (i.e., both must be in the native registry)
type CryptoRotationDescriptor struct {
	Name         string
	OldSuiteID   uint8
	NewSuiteID   uint8
	CreateHeight uint64 // H1: new suite valid for creation
	SpendHeight  uint64 // H2: new suite valid for spending
	SunsetHeight uint64 // H4: old suite ceases creation (0 = not defined)
}

// Validate checks the descriptor's invariants against the given registry.
// Returns nil if the descriptor is valid.
func (d CryptoRotationDescriptor) Validate(registry *SuiteRegistry) error {
	if d.Name == "" {
		return fmt.Errorf("rotation: name required")
	}
	if d.OldSuiteID == d.NewSuiteID {
		return fmt.Errorf("rotation: old suite (0x%02x) must differ from new suite", d.OldSuiteID)
	}
	if registry == nil {
		registry = DefaultSuiteRegistry()
	}
	if !registry.IsRegistered(d.OldSuiteID) {
		return fmt.Errorf("rotation: old suite 0x%02x not registered", d.OldSuiteID)
	}
	if !registry.IsRegistered(d.NewSuiteID) {
		return fmt.Errorf("rotation: new suite 0x%02x not registered", d.NewSuiteID)
	}
	if d.CreateHeight >= d.SpendHeight {
		return fmt.Errorf("rotation: create_height (%d) must be < spend_height (%d)", d.CreateHeight, d.SpendHeight)
	}
	if d.SunsetHeight != 0 && d.SunsetHeight <= d.SpendHeight {
		return fmt.Errorf("rotation: sunset_height (%d) must be > spend_height (%d)", d.SunsetHeight, d.SpendHeight)
	}
	return nil
}

// ValidateRotationSet checks a set of descriptors for internal consistency:
//   - Each descriptor must be individually valid
//   - At most one rotation may be active at any given height
//     (i.e., no overlapping [CreateHeight, SpendHeight) intervals)
func ValidateRotationSet(descriptors []CryptoRotationDescriptor, registry *SuiteRegistry) error {
	if registry == nil {
		registry = DefaultSuiteRegistry()
	}
	for i, d := range descriptors {
		if err := d.Validate(registry); err != nil {
			return fmt.Errorf("rotation[%d] %q: %w", i, d.Name, err)
		}
	}
	// Check pairwise overlap: two rotations overlap if their
	// [CreateHeight, SpendHeight) intervals intersect.
	for i := 0; i < len(descriptors); i++ {
		for j := i + 1; j < len(descriptors); j++ {
			a, b := descriptors[i], descriptors[j]
			// Intervals [a.Create, a.Spend) and [b.Create, b.Spend) overlap
			// if a.Create < b.Spend && b.Create < a.Spend.
			if a.CreateHeight < b.SpendHeight && b.CreateHeight < a.SpendHeight {
				return fmt.Errorf(
					"rotation: overlapping rotations %q [%d,%d) and %q [%d,%d)",
					a.Name, a.CreateHeight, a.SpendHeight,
					b.Name, b.CreateHeight, b.SpendHeight,
				)
			}
		}
	}
	return nil
}

// DescriptorRotationProvider implements RotationProvider using a validated
// CryptoRotationDescriptor. It assumes Validate() has already been called.
//
// Logic:
//   - Before H1: only OldSuiteID
//   - [H1, H4) or [H1, ∞) if H4=0: OldSuiteID + NewSuiteID for creation
//   - [H4, ∞): only NewSuiteID for creation
//   - Before H2: only OldSuiteID for spending
//   - [H2, ∞): OldSuiteID + NewSuiteID for spending
type DescriptorRotationProvider struct {
	Descriptor CryptoRotationDescriptor
}

// NativeCreateSuites implements RotationProvider.
func (p DescriptorRotationProvider) NativeCreateSuites(height uint64) *NativeSuiteSet {
	d := p.Descriptor
	if height < d.CreateHeight {
		return NewNativeSuiteSet(d.OldSuiteID)
	}
	if d.SunsetHeight != 0 && height >= d.SunsetHeight {
		return NewNativeSuiteSet(d.NewSuiteID)
	}
	return NewNativeSuiteSet(d.OldSuiteID, d.NewSuiteID)
}

// NativeSpendSuites implements RotationProvider.
func (p DescriptorRotationProvider) NativeSpendSuites(height uint64) *NativeSuiteSet {
	d := p.Descriptor
	if height < d.SpendHeight {
		return NewNativeSuiteSet(d.OldSuiteID)
	}
	return NewNativeSuiteSet(d.OldSuiteID, d.NewSuiteID)
}
