package consensus

import (
	"encoding/binary"
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
