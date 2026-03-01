package consensus

import "math"

type CoreExtCovenant struct {
	ExtPayload []byte
	ExtID      uint16
}

type CoreExtProfile struct {
	AllowedSuiteIDs  []uint8
	ActivationHeight uint64
	ExtID            uint16
}

var coreExtDeploymentProfiles = []CoreExtProfile{}

func ParseCoreExtCovenantData(covData []byte) (*CoreExtCovenant, error) {
	if covData == nil || len(covData) < 3 {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT covenant_data too short")
	}

	off := 0
	extID, err := readU16le(covData, &off)
	if err != nil {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT missing ext_id")
	}

	extPayloadLenU64, _, err := readCompactSize(covData, &off)
	if err != nil {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT malformed ext_payload_len")
	}
	if extPayloadLenU64 > uint64(math.MaxInt) {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT ext_payload_len overflows int")
	}
	extPayloadLen := int(extPayloadLenU64)
	if off+extPayloadLen != len(covData) {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT covenant_data length mismatch")
	}
	extPayload, err := readBytes(covData, &off, extPayloadLen)
	if err != nil {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT truncated ext_payload")
	}

	return &CoreExtCovenant{
		ExtID:      extID,
		ExtPayload: append([]byte(nil), extPayload...),
	}, nil
}

func ActiveCoreExtProfile(extID uint16, blockHeight uint64) (*CoreExtProfile, error) {
	return ActiveCoreExtProfileWithProfiles(extID, blockHeight, nil)
}

func ActiveCoreExtProfileWithProfiles(extID uint16, blockHeight uint64, profiles []CoreExtProfile) (*CoreExtProfile, error) {
	if len(profiles) == 0 {
		profiles = coreExtDeploymentProfiles
	}
	var active *CoreExtProfile
	for i := range profiles {
		profile := &profiles[i]
		if profile.ExtID != extID || blockHeight < profile.ActivationHeight {
			continue
		}
		if active != nil {
			return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "multiple active CORE_EXT profiles for ext_id")
		}
		active = profile
	}
	return active, nil
}

func CoreExtSuiteAllowed(profile *CoreExtProfile, suiteID uint8) bool {
	if profile == nil {
		return false
	}
	for _, allowed := range profile.AllowedSuiteIDs {
		if allowed == suiteID {
			return true
		}
	}
	return false
}

func verifySigExt(profile *CoreExtProfile, ext *CoreExtCovenant, w WitnessItem, digest [32]byte) (bool, error) {
	if profile == nil {
		return false, txerr(TX_ERR_SIG_ALG_INVALID, "CORE_EXT verifier binding missing")
	}
	if ext == nil {
		return false, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT covenant missing")
	}
	switch w.SuiteID {
	case SUITE_ID_ML_DSA_87, SUITE_ID_SLH_DSA_SHAKE_256F:
		return verifySig(w.SuiteID, w.Pubkey, w.Signature, digest)
	default:
		return false, txerr(TX_ERR_SIG_ALG_INVALID, "CORE_EXT verifier binding unsupported for non-native suite")
	}
}
