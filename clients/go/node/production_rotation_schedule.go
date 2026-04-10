package node

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"sort"

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
		nil,
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
		raw, ok := wire.Networks[network]
		if !ok {
			return nil, nil, productionRotationScheduleError(
				"networks.%s missing",
				network,
			)
		}
		descriptorJSON, err := parseProductionRotationScheduleDescriptorJSON(raw, network)
		if err != nil {
			return nil, nil, err
		}
		parsedDescriptors[network] = descriptorJSON
	}
	if registry == nil {
		registry = canonicalProductionScheduleRegistryFromDescriptors(parsedDescriptors)
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

func canonicalProductionScheduleRegistryFromDescriptors(
	descriptors map[string]*RotationConfigJSON,
) *consensus.SuiteRegistry {
	paramsByID := map[uint8]consensus.SuiteParams{
		consensus.SUITE_ID_ML_DSA_87: defaultSuiteRegistryParams(),
	}
	for _, descriptor := range descriptors {
		if descriptor == nil {
			continue
		}
		paramsByID[descriptor.OldSuiteID] = canonicalProductionScheduleSuiteParams(descriptor.OldSuiteID)
		paramsByID[descriptor.NewSuiteID] = canonicalProductionScheduleSuiteParams(descriptor.NewSuiteID)
	}
	params := make([]consensus.SuiteParams, 0, len(paramsByID))
	for _, suiteID := range sortedSuiteIDs(paramsByID) {
		params = append(params, paramsByID[suiteID])
	}
	return consensus.NewSuiteRegistryFromParams(params)
}

func canonicalProductionScheduleSuiteParams(suiteID uint8) consensus.SuiteParams {
	params := defaultSuiteRegistryParams()
	params.SuiteID = suiteID
	return params
}

func sortedSuiteIDs(paramsByID map[uint8]consensus.SuiteParams) []uint8 {
	ids := make([]uint8, 0, len(paramsByID))
	for suiteID := range paramsByID {
		ids = append(ids, suiteID)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
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
		// The compiled registry is derived across schedule entries, so returning it here
		// would leak foreign-network suites into an empty-slot caller.
		return nil, nil, nil
	}
	return descriptor, registry, nil
}
