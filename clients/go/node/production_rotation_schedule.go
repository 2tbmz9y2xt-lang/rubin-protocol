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
// Go embed cannot read a parent-path artifact directly, so tests keep this JSON-equivalent
// to the canonical protocol fixture (ignoring insignificant whitespace differences).
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

type productionRotationDescriptorWire struct {
	Name         *string `json:"name"`
	OldSuiteID   *uint8  `json:"old_suite_id"`
	NewSuiteID   *uint8  `json:"new_suite_id"`
	CreateHeight *uint64 `json:"create_height"`
	SpendHeight  *uint64 `json:"spend_height"`
	SunsetHeight *uint64 `json:"sunset_height,omitempty"`
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
	var wire productionRotationScheduleWire
	if err := decodeSingleJSONValue(raw, &wire); err != nil {
		return nil, nil, productionRotationScheduleError("parse embedded artifact: %w", err)
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
	parsedDescriptors := make(map[string]*RotationConfigJSON, len(wire.Networks))
	for _, network := range []string{"mainnet", "testnet"} {
		entryRaw, ok := wire.Networks[network]
		if !ok {
			return nil, nil, productionRotationScheduleError(
				"networks.%s missing",
				network,
			)
		}
		descriptorJSON, err := parseProductionRotationScheduleDescriptorJSON(entryRaw, network)
		if err != nil {
			return nil, nil, err
		}
		parsedDescriptors[network] = descriptorJSON
	}
	// The compiled production schedule is activation-only authority. When the
	// caller does not supply an explicit canonical registry contract, fail
	// closed to the default live manifest instead of synthesizing suite params
	// from schedule IDs.
	if registry == nil {
		registry = consensus.DefaultSuiteRegistry()
	}
	for _, network := range []string{"mainnet", "testnet"} {
		desc, err := buildProductionRotationScheduleDescriptor(
			parsedDescriptors[network],
			network,
			registry,
		)
		if err != nil {
			return nil, nil, err
		}
		schedule.Networks[network] = desc
	}
	return schedule, registry, nil
}

func parseProductionRotationScheduleDescriptorJSON(
	raw json.RawMessage,
	network string,
) (*RotationConfigJSON, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var wire productionRotationDescriptorWire
	if err := decodeSingleJSONValue(raw, &wire); err != nil {
		return nil, productionRotationScheduleError("networks.%s: %w", network, err)
	}
	descriptorJSON, err := wire.toRotationConfigJSON()
	if err != nil {
		return nil, productionRotationScheduleError("networks.%s: %w", network, err)
	}
	return &descriptorJSON, nil
}

func buildProductionRotationScheduleDescriptor(
	descriptorJSON *RotationConfigJSON,
	network string,
	registry *consensus.SuiteRegistry,
) (*consensus.CryptoRotationDescriptor, error) {
	if descriptorJSON == nil {
		return nil, nil
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

func (wire productionRotationDescriptorWire) toRotationConfigJSON() (RotationConfigJSON, error) {
	name, err := requireProductionRotationScheduleField("name", wire.Name)
	if err != nil {
		return RotationConfigJSON{}, err
	}
	oldSuiteID, err := requireProductionRotationScheduleField("old_suite_id", wire.OldSuiteID)
	if err != nil {
		return RotationConfigJSON{}, err
	}
	newSuiteID, err := requireProductionRotationScheduleField("new_suite_id", wire.NewSuiteID)
	if err != nil {
		return RotationConfigJSON{}, err
	}
	if err := rejectReservedProductionRotationScheduleSuiteID("old_suite_id", oldSuiteID); err != nil {
		return RotationConfigJSON{}, err
	}
	if err := rejectReservedProductionRotationScheduleSuiteID("new_suite_id", newSuiteID); err != nil {
		return RotationConfigJSON{}, err
	}
	createHeight, err := requireProductionRotationScheduleField("create_height", wire.CreateHeight)
	if err != nil {
		return RotationConfigJSON{}, err
	}
	spendHeight, err := requireProductionRotationScheduleField("spend_height", wire.SpendHeight)
	if err != nil {
		return RotationConfigJSON{}, err
	}
	var sunsetHeight uint64
	if wire.SunsetHeight != nil {
		sunsetHeight = *wire.SunsetHeight
	}
	return RotationConfigJSON{
		Name:         name,
		OldSuiteID:   oldSuiteID,
		NewSuiteID:   newSuiteID,
		CreateHeight: createHeight,
		SpendHeight:  spendHeight,
		SunsetHeight: sunsetHeight,
	}, nil
}

func rejectReservedProductionRotationScheduleSuiteID(field string, suiteID uint8) error {
	if suiteID == consensus.SUITE_ID_SENTINEL {
		return fmt.Errorf("%s 0x%02x reserved", field, suiteID)
	}
	return nil
}

func requireProductionRotationScheduleField[T any](name string, value *T) (T, error) {
	if value == nil {
		var zero T
		return zero, fmt.Errorf("missing required field %q", name)
	}
	return *value, nil
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
		// A null slot means this network has no authoritative production activation state.
		// Pre-rotation production callers still need the canonical default registry,
		// but must not inherit foreign-network suites from the compiled schedule.
		return nil, consensus.DefaultSuiteRegistry(), nil
	}
	return descriptor, registry, nil
}
