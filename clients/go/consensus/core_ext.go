package consensus

import (
	"encoding/binary"
	"fmt"
	"math"
)

type CoreExtVerifySigExtFunc func(extID uint16, suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte, extPayload []byte) (bool, error)

type CoreExtProfile struct {
	Active         bool
	AllowedSuites  map[uint8]struct{}
	VerifySigExtFn CoreExtVerifySigExtFunc
}

type CoreExtProfileProvider interface {
	LookupCoreExtProfile(extID uint16, height uint64) (CoreExtProfile, bool, error)
}

type CoreExtDeploymentProfile struct {
	ExtID            uint16
	ActivationHeight uint64
	AllowedSuites    map[uint8]struct{}
	VerifySigExtFn   CoreExtVerifySigExtFunc
}

type StaticCoreExtProfileProvider struct {
	deployments map[uint16]CoreExtDeploymentProfile
}

func NewStaticCoreExtProfileProvider(deployments []CoreExtDeploymentProfile) (*StaticCoreExtProfileProvider, error) {
	if len(deployments) == 0 {
		return nil, nil
	}
	provider := &StaticCoreExtProfileProvider{
		deployments: make(map[uint16]CoreExtDeploymentProfile, len(deployments)),
	}
	for _, item := range deployments {
		if _, exists := provider.deployments[item.ExtID]; exists {
			return nil, fmt.Errorf("duplicate core_ext deployment for ext_id=%d", item.ExtID)
		}
		provider.deployments[item.ExtID] = CoreExtDeploymentProfile{
			ExtID:            item.ExtID,
			ActivationHeight: item.ActivationHeight,
			AllowedSuites:    cloneAllowedSuites(item.AllowedSuites),
			VerifySigExtFn:   item.VerifySigExtFn,
		}
	}
	return provider, nil
}

func (p *StaticCoreExtProfileProvider) LookupCoreExtProfile(extID uint16, height uint64) (CoreExtProfile, bool, error) {
	if p == nil {
		return CoreExtProfile{}, false, nil
	}
	deployment, ok := p.deployments[extID]
	if !ok || height < deployment.ActivationHeight {
		return CoreExtProfile{}, false, nil
	}
	return CoreExtProfile{
		Active:         true,
		AllowedSuites:  cloneAllowedSuites(deployment.AllowedSuites),
		VerifySigExtFn: deployment.VerifySigExtFn,
	}, true, nil
}

type CoreExtCovenantData struct {
	ExtID      uint16
	ExtPayload []byte
}

func ParseCoreExtCovenantData(covenantData []byte) (*CoreExtCovenantData, error) {
	if len(covenantData) < 2 {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT covenant_data too short")
	}
	if len(covenantData) > MAX_COVENANT_DATA_PER_OUTPUT {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT covenant_data too large")
	}

	off := 0
	extIDBytes, err := readBytes(covenantData, &off, 2)
	if err != nil {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT covenant_data ext_id parse failure")
	}
	extID := binary.LittleEndian.Uint16(extIDBytes)

	payloadLenU64, payloadLenVarintBytes, err := readCompactSize(covenantData, &off)
	if err != nil {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT covenant_data ext_payload_len parse failure")
	}
	if payloadLenU64 > uint64(math.MaxInt) {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT ext_payload_len overflows int")
	}
	payloadLen := int(payloadLenU64)

	payload, err := readBytes(covenantData, &off, payloadLen)
	if err != nil {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT covenant_data ext_payload parse failure")
	}

	expectedLen := 2 + payloadLenVarintBytes + payloadLen
	if len(covenantData) != expectedLen {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT covenant_data length mismatch")
	}

	return &CoreExtCovenantData{
		ExtID:      extID,
		ExtPayload: payload,
	}, nil
}

func hasSuite(allowed map[uint8]struct{}, suiteID uint8) bool {
	if len(allowed) == 0 {
		return false
	}
	_, ok := allowed[suiteID]
	return ok
}

// HasSuiteExported is the exported wrapper for hasSuite, used by CLI runtime.
func HasSuiteExported(allowed map[uint8]struct{}, suiteID uint8) bool {
	return hasSuite(allowed, suiteID)
}

func cloneAllowedSuites(allowed map[uint8]struct{}) map[uint8]struct{} {
	if len(allowed) == 0 {
		return nil
	}
	out := make(map[uint8]struct{}, len(allowed))
	for suiteID := range allowed {
		out[suiteID] = struct{}{}
	}
	return out
}
