package consensus

import "fmt"

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

func FlagDayActiveAtHeight(d FlagDayDeployment, height uint64) (bool, error) {
	if err := d.Validate(); err != nil {
		return false, err
	}
	return height >= d.ActivationHeight, nil
}
