package node

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const productionRotationScheduleVersion = 1
const productionRotationScheduleErrStem = "production_rotation_schedule"

// Derived runtime copy of conformance/fixtures/protocol/production_rotation_schedule_v1.json.
// Go embed cannot read a parent-path artifact directly, so tests keep this byte-equivalent
// to the canonical protocol fixture.
//
//go:embed production_rotation_schedule_v1_embedded.json
var embeddedProductionRotationScheduleV1 []byte

type productionRotationSchedule struct {
	Version  uint64
	Networks map[string]*consensus.CryptoRotationDescriptor
}

type productionRotationScheduleWire struct {
	Version  uint64                     `json:"version"`
	Networks map[string]json.RawMessage `json:"networks"`
}

func productionRotationScheduleError(format string, args ...any) error {
	return fmt.Errorf(productionRotationScheduleErrStem+": "+format, args...)
}

func decodeSingleJSONValue(data []byte, dest any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dest); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON tokens")
		}
		return err
	}
	return nil
}

func loadCompiledProductionRotationSchedule() (*productionRotationSchedule, *consensus.SuiteRegistry, error) {
	return loadCompiledProductionRotationScheduleFromJSONWithRegistry(
		embeddedProductionRotationScheduleV1,
		consensus.DefaultSuiteRegistry(),
	)
}

func loadCompiledProductionRotationScheduleFromJSONWithRegistry(
	raw []byte,
	registry *consensus.SuiteRegistry,
) (*productionRotationSchedule, *consensus.SuiteRegistry, error) {
	if registry == nil {
		registry = consensus.DefaultSuiteRegistry()
	}
	var wire productionRotationScheduleWire
	if err := decodeSingleJSONValue(raw, &wire); err != nil {
		return nil, nil, productionRotationScheduleError("parse embedded artifact: %v", err)
	}
	if wire.Version != productionRotationScheduleVersion {
		return nil, nil, productionRotationScheduleError(
			"unsupported version %d (want %d)",
			wire.Version,
			productionRotationScheduleVersion,
		)
	}
	for key := range wire.Networks {
		if key != "mainnet" && key != "testnet" {
			return nil, nil, productionRotationScheduleError(
				"unknown networks.%s entry",
				key,
			)
		}
	}
	schedule := &productionRotationSchedule{
		Version:  wire.Version,
		Networks: make(map[string]*consensus.CryptoRotationDescriptor, len(wire.Networks)),
	}
	for _, network := range []string{"mainnet", "testnet"} {
		raw, ok := wire.Networks[network]
		if !ok {
			return nil, nil, productionRotationScheduleError(
				"networks.%s missing",
				network,
			)
		}
		desc, err := parseProductionRotationScheduleDescriptor(raw, network, registry)
		if err != nil {
			return nil, nil, err
		}
		schedule.Networks[network] = desc
	}
	return schedule, registry, nil
}

func parseProductionRotationScheduleDescriptor(
	raw json.RawMessage,
	network string,
	registry *consensus.SuiteRegistry,
) (*consensus.CryptoRotationDescriptor, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var descriptorJSON RotationConfigJSON
	if err := decodeSingleJSONValue(raw, &descriptorJSON); err != nil {
		return nil, productionRotationScheduleError("networks.%s: %v", network, err)
	}
	descriptor := consensus.CryptoRotationDescriptor{
		Name:         descriptorJSON.Name,
		OldSuiteID:   descriptorJSON.OldSuiteID,
		NewSuiteID:   descriptorJSON.NewSuiteID,
		CreateHeight: descriptorJSON.CreateHeight,
		SpendHeight:  descriptorJSON.SpendHeight,
		SunsetHeight: descriptorJSON.SunsetHeight,
	}
	if err := consensus.ValidateRotationDescriptorForNetwork(network, descriptor, registry); err != nil {
		return nil, productionRotationScheduleError(
			"networks.%s: rotation_descriptor: %v",
			network,
			err,
		)
	}
	return &descriptor, nil
}

func productionRotationDescriptorForNetwork(
	network string,
) (*consensus.CryptoRotationDescriptor, *consensus.SuiteRegistry, error) {
	schedule, registry, err := loadCompiledProductionRotationSchedule()
	if err != nil {
		return nil, nil, err
	}
	if network != "mainnet" && network != "testnet" {
		return nil, nil, productionRotationScheduleError(
			"network %q is not a production schedule caller",
			network,
		)
	}
	descriptor := schedule.Networks[network]
	if descriptor == nil {
		return nil, nil, nil
	}
	return descriptor, registry, nil
}
