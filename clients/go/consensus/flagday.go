package consensus

import (
	"fmt"
	"sort"
)

// FlagDayDeployment implements CANONICAL §23.2 height-activation semantics.
//
// Consensus validity MUST depend only on (height >= activation_height). Any version-bit signaling
// is telemetry-only and MUST NOT gate validity.
type FlagDayDeployment struct {
	Name             string
	ActivationHeight uint64
	// Bit is optional and telemetry-only (0..31).
	Bit *uint8
}

func (d FlagDayDeployment) Validate() error {
	if d.Name == "" {
		return fmt.Errorf("flagday: name required")
	}
	if d.Bit != nil && *d.Bit > 31 {
		return fmt.Errorf("flagday: bit out of range: %d", *d.Bit)
	}
	return nil
}

// ValidateDeploymentBitUniqueness checks a set of FlagDayDeployments for
// telemetry-bit reuse conflicts per CANONICAL §23.2.3. Returns a list of
// human-readable warnings. An empty slice means no conflicts detected.
//
// This is non-consensus: bit collisions do not invalidate blocks. Implementations
// SHOULD log returned warnings at startup.
func ValidateDeploymentBitUniqueness(deployments []FlagDayDeployment) []string {
	// Collect deployments that have a telemetry bit assigned.
	type entry struct {
		name       string
		bit        uint8
		reserveEnd uint64 // activation_height + FALLOW_PERIOD
	}
	var withBit []entry
	for _, d := range deployments {
		if d.Bit == nil {
			continue
		}
		end := d.ActivationHeight + FALLOW_PERIOD
		// Handle uint64 overflow (unlikely but defensive).
		if end < d.ActivationHeight {
			end = ^uint64(0)
		}
		withBit = append(withBit, entry{
			name:       d.Name,
			bit:        *d.Bit,
			reserveEnd: end,
		})
	}

	// Sort by bit, then by reserveEnd for deterministic output.
	sort.Slice(withBit, func(i, j int) bool {
		if withBit[i].bit != withBit[j].bit {
			return withBit[i].bit < withBit[j].bit
		}
		return withBit[i].reserveEnd < withBit[j].reserveEnd
	})

	var warnings []string
	for i := 0; i < len(withBit); i++ {
		for j := i + 1; j < len(withBit); j++ {
			if withBit[i].bit != withBit[j].bit {
				break // sorted by bit — no more matches
			}
			// Same bit: check if reservation windows overlap.
			// Deployment j's bit is assigned from height 0 (or whenever it was declared)
			// through deployment j's reserveEnd. Since we only track reserveEnd (upper bound),
			// any two deployments on the same bit whose reserveEnd windows coexist = overlap.
			warnings = append(warnings, fmt.Sprintf(
				"flagday: bit %d reuse overlap between %q (reserved until height %d) and %q (reserved until height %d) — §23.2.3 FALLOW_PERIOD violation",
				withBit[i].bit,
				withBit[i].name, withBit[i].reserveEnd,
				withBit[j].name, withBit[j].reserveEnd,
			))
		}
	}
	return warnings
}

func FlagDayActiveAtHeight(d FlagDayDeployment, height uint64) (bool, error) {
	if err := d.Validate(); err != nil {
		return false, err
	}
	return height >= d.ActivationHeight, nil
}
