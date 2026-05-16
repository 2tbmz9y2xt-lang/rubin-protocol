package node

import (
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// initializeRotationSchedule creates the base schedule structure
func initializeRotationSchedule(wire productionRotationScheduleWire) *productionRotationSchedule {
	return &productionRotationSchedule{
		Version:  wire.Version,
		Networks: make(map[string]*consensus.CryptoRotationDescriptor, len(wire.Networks)),
	}
}

// ensureRegistry returns a non-nil SuiteRegistry, defaulting to DefaultSuiteRegistry when nil is passed.
func ensureRegistry(registry *consensus.SuiteRegistry) *consensus.SuiteRegistry {
	if registry == nil {
		return consensus.DefaultSuiteRegistry()
	}
	return registry
}

// buildProductionRotationScheduleNetworks builds descriptors for all networks
func buildProductionRotationScheduleNetworks(
	parsedDescriptors map[string]*RotationConfigJSON,
	schedule *productionRotationSchedule,
	registry *consensus.SuiteRegistry,
) error {
	for _, network := range []string{"mainnet", "testnet"} {
		desc, err := buildProductionRotationScheduleDescriptor(parsedDescriptors[network], network, registry)
		if err != nil {
			return err
		}
		schedule.Networks[network] = desc
	}
	return nil
}
