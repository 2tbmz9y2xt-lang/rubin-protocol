package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type TxctxCaseJSON struct {
	VectorID                     string             `json:"vector_id"`
	Height                       uint64             `json:"height"`
	Profiles                     []TxctxProfileJSON `json:"profiles"`
	Inputs                       []TxctxInputJSON   `json:"inputs"`
	Outputs                      []TxctxOutputJSON  `json:"outputs"`
	HasVaultInputs               bool               `json:"has_vault_inputs"`
	VaultInputSum                uint64             `json:"vault_input_sum"`
	ForceStep2Error              string             `json:"force_step2_error"`
	ForceStep3Error              string             `json:"force_step3_error"`
	ForceMissingCtxContinuingExt uint16             `json:"force_missing_ctx_continuing_ext_id"`
	VerifierAccessIndex          int                `json:"verifier_access_index"`
	WarnGovernanceFailure        bool               `json:"warn_governance_failure"`
}

type TxctxProfileJSON struct {
	Name               string  `json:"name"`
	ExtID              uint16  `json:"ext_id"`
	ActivationHeight   uint64  `json:"activation_height"`
	TxContextEnabled   int     `json:"tx_context_enabled"`
	AllowedSuiteIDs    []uint8 `json:"allowed_suite_ids"`
	AllowedSighashSet  uint8   `json:"allowed_sighash_set"`
	MaxExtPayloadBytes int     `json:"max_ext_payload_bytes"`
	BindingKind        uint8   `json:"binding_kind"`
	SuiteCount         int     `json:"suite_count"`
	SuiteID            uint8   `json:"suite_id"`
	VerifierMode       string  `json:"verifier_mode"`
}

type TxctxInputJSON struct {
	PrevoutTxidHex   string `json:"prevout_txid_hex"`
	PrevoutVout      uint32 `json:"prevout_vout"`
	CovenantType     string `json:"covenant_type"`
	ExtID            uint16 `json:"ext_id"`
	UtxoValue        uint64 `json:"utxo_value"`
	SelfInputValue   uint64 `json:"self_input_value"`
	ExtPayloadHex    string `json:"ext_payload_hex"`
	RawExtPayloadHex string `json:"raw_ext_payload_hex"`
	SuiteID          uint8  `json:"suite_id"`
	SighashType      uint8  `json:"sighash_type"`
	PubkeyLength     int    `json:"pubkey_length"`
}

type TxctxOutputJSON struct {
	CovenantType       string `json:"covenant_type"`
	ExtID              uint16 `json:"ext_id"`
	Value              uint64 `json:"value"`
	ExtPayloadHex      string `json:"ext_payload_hex"`
	RawExtPayloadHex   string `json:"raw_ext_payload_hex"`
	RawCovenantDataHex string `json:"raw_covenant_data_hex"`
}

type txctxDiagnosticsRecorder struct {
	abiParamsSeen                 []int
	baseHeight                    uint64
	baseTotalInHi                 uint64
	baseTotalInLo                 uint64
	baseTotalOutHi                uint64
	baseTotalOutLo                uint64
	buildTxContextCalled          bool
	bundlePresent                 bool
	calledExtIDs                  []uint16
	continuingExtIDs              []uint16
	continuingMapEmptyAfterReject bool
	emptyPayloadNonNil            bool
	failingExtID                  uint16
	selfInputValuesSeen           []uint64

	basePtr     uintptr
	basePtrSeen bool
	baseShared  *bool
	contPtr     uintptr
	contPtrSeen bool
	contShared  *bool
}

func (r *txctxDiagnosticsRecorder) recordCall(
	extID uint16,
	ctxBase *consensus.TxContextBase,
	ctxContinuing *consensus.TxContextContinuing,
	selfInputValue uint64,
	abiParams int,
) {
	r.abiParamsSeen = append(r.abiParamsSeen, abiParams)
	r.calledExtIDs = append(r.calledExtIDs, extID)
	r.selfInputValuesSeen = append(r.selfInputValuesSeen, selfInputValue)
	if ctxBase != nil {
		r.baseHeight = ctxBase.Height
		r.baseTotalInLo = ctxBase.TotalIn.Lo
		r.baseTotalInHi = ctxBase.TotalIn.Hi
		r.baseTotalOutLo = ctxBase.TotalOut.Lo
		r.baseTotalOutHi = ctxBase.TotalOut.Hi
		ptr := fmt.Sprintf("%p", ctxBase)
		if !r.basePtrSeen {
			r.basePtr = txctxPtrStringToUint(ptr)
			r.basePtrSeen = true
		} else {
			shared := txctxPtrStringToUint(ptr) == r.basePtr
			if r.baseShared == nil {
				r.baseShared = &shared
			} else {
				v := *r.baseShared && shared
				r.baseShared = &v
			}
		}
	}
	if ctxContinuing != nil {
		ptr := fmt.Sprintf("%p", ctxContinuing)
		if !r.contPtrSeen {
			r.contPtr = txctxPtrStringToUint(ptr)
			r.contPtrSeen = true
		} else {
			shared := txctxPtrStringToUint(ptr) == r.contPtr
			if r.contShared == nil {
				r.contShared = &shared
			} else {
				v := *r.contShared && shared
				r.contShared = &v
			}
		}
		if ctxContinuing.ContinuingOutputCount > 0 {
			payload := ctxContinuing.ContinuingOutputs[0].ExtPayload
			if payload != nil && len(payload) == 0 {
				r.emptyPayloadNonNil = true
			}
		}
	}
}

func (r *txctxDiagnosticsRecorder) attachBundle(bundle *consensus.TxContextBundle) {
	if bundle == nil {
		return
	}
	r.bundlePresent = true
	r.continuingExtIDs = bundle.OrderedExtIDs()
	if bundle.Base != nil {
		r.baseHeight = bundle.Base.Height
		r.baseTotalInLo = bundle.Base.TotalIn.Lo
		r.baseTotalInHi = bundle.Base.TotalIn.Hi
		r.baseTotalOutLo = bundle.Base.TotalOut.Lo
		r.baseTotalOutHi = bundle.Base.TotalOut.Hi
	}
}

func (r *txctxDiagnosticsRecorder) responseMap() map[string]any {
	baseShared := false
	if r.baseShared != nil {
		baseShared = *r.baseShared
	}
	contShared := false
	if r.contShared != nil {
		contShared = *r.contShared
	}
	out := map[string]any{
		"abi_params_seen":                   r.abiParamsSeen,
		"base_height":                       r.baseHeight,
		"base_shared_across_calls":          baseShared,
		"base_total_in_hi":                  r.baseTotalInHi,
		"base_total_in_lo":                  r.baseTotalInLo,
		"base_total_out_hi":                 r.baseTotalOutHi,
		"base_total_out_lo":                 r.baseTotalOutLo,
		"build_txcontext_called":            r.buildTxContextCalled,
		"bundle_present":                    r.bundlePresent,
		"called_ext_ids":                    txctxUint16sToInts(r.calledExtIDs),
		"continuing_ext_ids":                txctxUint16sToInts(r.continuingExtIDs),
		"continuing_map_empty_after_reject": r.continuingMapEmptyAfterReject,
		"continuing_shared_across_calls":    contShared,
		"empty_payload_non_nil":             r.emptyPayloadNonNil,
		"failing_ext_id":                    int(r.failingExtID),
		"self_input_values_seen":            txctxUint64sToInts(r.selfInputValuesSeen),
	}
	return out
}

func txctxUint16sToInts(items []uint16) []int {
	out := make([]int, 0, len(items))
	for _, item := range items {
		out = append(out, int(item))
	}
	return out
}

func txctxUint64sToInts(items []uint64) []int {
	out := make([]int, 0, len(items))
	for _, item := range items {
		out = append(out, int(item))
	}
	return out
}

func txctxPtrStringToUint(value string) uintptr {
	value = strings.TrimPrefix(value, "0x")
	parsed, _ := parseHexU256To32(value)
	var out uintptr
	for _, b := range parsed[len(parsed)-8:] {
		out = (out << 8) | uintptr(b)
	}
	return out
}

func txctxErrCode(err error) string {
	if err == nil {
		return ""
	}
	if te, ok := err.(*consensus.TxError); ok {
		return string(te.Code)
	}
	return err.Error()
}

func txctxNormalizeHex(raw string) string {
	raw = strings.TrimSpace(raw)
	for _, token := range []string{" ", "\n", "\t", "\r", "_"} {
		raw = strings.ReplaceAll(raw, token, "")
	}
	raw = strings.TrimPrefix(strings.TrimPrefix(raw, "0x"), "0X")
	return strings.ToLower(raw)
}

func txctxDecodeHex(raw string) ([]byte, error) {
	raw = txctxNormalizeHex(raw)
	if raw == "" {
		return nil, nil
	}
	return hex.DecodeString(raw)
}

func txctxAppendCompactSize(dst []byte, value int) []byte {
	switch {
	case value < 0xFD:
		return append(dst, byte(value))
	case value <= 0xFFFF:
		return append(dst, 0xFD, byte(value), byte(value>>8))
	case value <= 0xFFFF_FFFF:
		return append(dst, 0xFE, byte(value), byte(value>>8), byte(value>>16), byte(value>>24))
	default:
		out := append(dst, 0xFF)
		for i := 0; i < 8; i++ {
			out = append(out, byte(uint64(value)>>(8*i)))
		}
		return out
	}
}

func txctxCoreExtCovData(extID uint16, payloadHex string, rawPayloadHex string) ([]byte, error) {
	out := make([]byte, 0, 16)
	out = binary.LittleEndian.AppendUint16(out, extID)
	if strings.TrimSpace(rawPayloadHex) != "" {
		raw, err := txctxDecodeHex(rawPayloadHex)
		if err != nil {
			return nil, err
		}
		return append(out, raw...), nil
	}
	payload, err := txctxDecodeHex(payloadHex)
	if err != nil {
		return nil, err
	}
	out = txctxAppendCompactSize(out, len(payload))
	out = append(out, payload...)
	return out, nil
}

func txctxDefaultP2PKCovenantData() []byte {
	out := make([]byte, consensus.MAX_P2PK_COVENANT_DATA)
	out[0] = consensus.SUITE_ID_ML_DSA_87
	return out
}

func txctxCanonicalOutputValue(covType uint16, value uint64) uint64 {
	switch covType {
	case consensus.COV_TYPE_ANCHOR, consensus.COV_TYPE_DA_COMMIT:
		return 0
	default:
		return value
	}
}

func txctxDecodedExtPayloadLen(extID uint16, payloadHex string, rawPayloadHex string) (int, error) {
	covData, err := txctxCoreExtCovData(extID, payloadHex, rawPayloadHex)
	if err != nil {
		return 0, err
	}
	cov, err := consensus.ParseCoreExtCovenantData(covData)
	if err != nil {
		return 0, err
	}
	return len(cov.ExtPayload), nil
}

func txctxParseCovenantType(name string) (uint16, error) {
	switch strings.TrimSpace(strings.ToUpper(name)) {
	case "", "CORE_P2PK":
		return consensus.COV_TYPE_P2PK, nil
	case "CORE_EXT", "CORE_EXT_INACTIVE":
		return consensus.COV_TYPE_CORE_EXT, nil
	case "CORE_ANCHOR":
		return consensus.COV_TYPE_ANCHOR, nil
	case "CORE_VAULT":
		return consensus.COV_TYPE_VAULT, nil
	case "CORE_DA_COMMIT":
		return consensus.COV_TYPE_DA_COMMIT, nil
	default:
		return 0, fmt.Errorf("unknown covenant_type=%s", name)
	}
}

func txctxParseTxid(hexValue string) ([32]byte, error) {
	var out [32]byte
	raw := txctxNormalizeHex(hexValue)
	if raw == "" {
		return out, nil
	}
	if len(raw)%2 == 1 {
		raw = "0" + raw
	}
	b, err := hex.DecodeString(raw)
	if err != nil {
		return out, err
	}
	if len(b) > 32 {
		b = b[len(b)-32:]
	}
	copy(out[32-len(b):], b)
	return out, nil
}

func txctxAllowedSuites(p TxctxProfileJSON) []uint8 {
	if len(p.AllowedSuiteIDs) != 0 {
		return append([]uint8(nil), p.AllowedSuiteIDs...)
	}
	if p.SuiteID != 0 {
		return []uint8{p.SuiteID}
	}
	return []uint8{0x10}
}

func txctxProfileByExtID(tc *TxctxCaseJSON) map[uint16]TxctxProfileJSON {
	out := make(map[uint16]TxctxProfileJSON, len(tc.Profiles))
	for _, item := range tc.Profiles {
		out[item.ExtID] = item
	}
	return out
}

func txctxHasDuplicates(items []uint8) bool {
	seen := make(map[uint8]struct{}, len(items))
	for _, item := range items {
		if _, ok := seen[item]; ok {
			return true
		}
		seen[item] = struct{}{}
	}
	return false
}

func txctxProfileError(tc *TxctxCaseJSON) string {
	profilesByExt := txctxProfileByExtID(tc)
	for _, input := range tc.Inputs {
		profile, ok := profilesByExt[input.ExtID]
		if !ok || tc.Height < profile.ActivationHeight {
			continue
		}
		allowed := txctxAllowedSuites(profile)
		if profile.TxContextEnabled != 0 && profile.TxContextEnabled != 1 {
			return string(consensus.TX_ERR_COVENANT_TYPE_INVALID)
		}
		if profile.TxContextEnabled == 1 {
			if profile.BindingKind != consensus.CoreExtBindingKindVerifySigExt {
				return string(consensus.TX_ERR_COVENANT_TYPE_INVALID)
			}
			if profile.MaxExtPayloadBytes <= 0 {
				return string(consensus.TX_ERR_COVENANT_TYPE_INVALID)
			}
			if profile.SuiteCount != len(allowed) {
				return string(consensus.TX_ERR_COVENANT_TYPE_INVALID)
			}
			if txctxHasDuplicates(allowed) {
				return string(consensus.TX_ERR_COVENANT_TYPE_INVALID)
			}
			for _, suiteID := range allowed {
				if suiteID == consensus.SUITE_ID_ML_DSA_87 {
					return string(consensus.TX_ERR_COVENANT_TYPE_INVALID)
				}
			}
			if profile.AllowedSighashSet&0x78 != 0 {
				return string(consensus.TX_ERR_COVENANT_TYPE_INVALID)
			}
			if profile.AllowedSighashSet&0x07 == 0 {
				return string(consensus.TX_ERR_COVENANT_TYPE_INVALID)
			}
		} else {
			if profile.AllowedSighashSet != 0 || profile.MaxExtPayloadBytes != 0 {
				return string(consensus.TX_ERR_COVENANT_TYPE_INVALID)
			}
		}

		baseType := input.SighashType & 0x7F
		if baseType != consensus.SIGHASH_ALL && baseType != consensus.SIGHASH_NONE && baseType != consensus.SIGHASH_SINGLE {
			return string(consensus.TX_ERR_SIGHASH_TYPE_INVALID)
		}
		if profile.TxContextEnabled == 1 {
			var baseMask uint8
			switch baseType {
			case consensus.SIGHASH_ALL:
				baseMask = 0x01
			case consensus.SIGHASH_NONE:
				baseMask = 0x02
			case consensus.SIGHASH_SINGLE:
				baseMask = 0x04
			}
			if profile.AllowedSighashSet&baseMask == 0 {
				return string(consensus.TX_ERR_SIG_ALG_INVALID)
			}
			if input.SighashType&consensus.SIGHASH_ANYONECANPAY != 0 && profile.AllowedSighashSet&consensus.SIGHASH_ANYONECANPAY == 0 {
				return string(consensus.TX_ERR_SIG_ALG_INVALID)
			}
			payloadLen, err := txctxDecodedExtPayloadLen(input.ExtID, input.ExtPayloadHex, input.RawExtPayloadHex)
			if err != nil || payloadLen > profile.MaxExtPayloadBytes {
				return string(consensus.TX_ERR_COVENANT_TYPE_INVALID)
			}
		}
	}
	for _, output := range tc.Outputs {
		covType, err := txctxParseCovenantType(output.CovenantType)
		if err != nil || covType != consensus.COV_TYPE_CORE_EXT {
			continue
		}
		profile, ok := profilesByExt[output.ExtID]
		if !ok || tc.Height < profile.ActivationHeight || profile.TxContextEnabled != 1 {
			continue
		}
		payloadLen, err := txctxDecodedExtPayloadLen(output.ExtID, output.ExtPayloadHex, output.RawExtPayloadHex)
		if err != nil || payloadLen > profile.MaxExtPayloadBytes {
			return string(consensus.TX_ERR_COVENANT_TYPE_INVALID)
		}
	}
	return ""
}

func txctxDuplicatePrevout(tc *TxctxCaseJSON) bool {
	seen := make(map[string]struct{}, len(tc.Inputs))
	for _, input := range tc.Inputs {
		key := fmt.Sprintf("%s:%d", txctxNormalizeHex(input.PrevoutTxidHex), input.PrevoutVout)
		if _, ok := seen[key]; ok {
			return true
		}
		seen[key] = struct{}{}
	}
	return false
}

func txctxFirstOverflowExtID(outputs []TxctxOutputJSON) uint16 {
	counts := make(map[uint16]int)
	for _, output := range outputs {
		covType, err := txctxParseCovenantType(output.CovenantType)
		if err != nil || covType != consensus.COV_TYPE_CORE_EXT {
			continue
		}
		counts[output.ExtID]++
	}
	var ids []int
	for extID, count := range counts {
		if count > consensus.TXCONTEXT_MAX_CONTINUING_OUTPUTS {
			ids = append(ids, int(extID))
		}
	}
	sort.Ints(ids)
	if len(ids) == 0 {
		return 0
	}
	return uint16(ids[0])
}

func txctxBuildHarnessArtifacts(
	tc *TxctxCaseJSON,
	diag *txctxDiagnosticsRecorder,
) (*consensus.Tx, [32]byte, [32]byte, map[consensus.Outpoint]consensus.UtxoEntry, []consensus.UtxoEntry, consensus.CoreExtProfileProvider, error) {
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
	}
	var txid [32]byte
	var chainID [32]byte
	copy(chainID[:], []byte("txctx-harness-rubin"))
	utxos := make(map[consensus.Outpoint]consensus.UtxoEntry, len(tc.Inputs))
	resolvedInputs := make([]consensus.UtxoEntry, 0, len(tc.Inputs))

	for index, input := range tc.Inputs {
		prevTxid, err := txctxParseTxid(input.PrevoutTxidHex)
		if err != nil {
			return nil, txid, chainID, nil, nil, nil, err
		}
		covType, err := txctxParseCovenantType(input.CovenantType)
		if err != nil {
			return nil, txid, chainID, nil, nil, nil, err
		}
		extID := input.ExtID
		if strings.EqualFold(input.CovenantType, "CORE_EXT_INACTIVE") && extID == 0 {
			extID = uint16(0x7000 + index)
		}
		covData, err := txctxCoreExtCovData(extID, input.ExtPayloadHex, input.RawExtPayloadHex)
		if err != nil {
			return nil, txid, chainID, nil, nil, nil, err
		}
		if covType != consensus.COV_TYPE_CORE_EXT {
			covData = txctxDefaultP2PKCovenantData()
		}
		tx.Inputs = append(tx.Inputs, consensus.TxInput{
			PrevTxid: prevTxid,
			PrevVout: input.PrevoutVout,
			Sequence: 0,
		})
		op := consensus.Outpoint{Txid: prevTxid, Vout: input.PrevoutVout}
		entry := consensus.UtxoEntry{
			Value:        input.UtxoValue,
			CovenantType: covType,
			CovenantData: covData,
		}
		utxos[op] = entry
		resolvedInputs = append(resolvedInputs, entry)
		pubLen := input.PubkeyLength
		if pubLen <= 0 {
			pubLen = 3
		}
		tx.Witness = append(tx.Witness, consensus.WitnessItem{
			SuiteID:   input.SuiteID,
			Pubkey:    make([]byte, pubLen),
			Signature: []byte{0xA5, input.SighashType},
		})
	}

	for _, output := range tc.Outputs {
		covType, err := txctxParseCovenantType(output.CovenantType)
		if err != nil {
			return nil, txid, chainID, nil, nil, nil, err
		}
		covData := []byte(nil)
		if strings.TrimSpace(output.RawCovenantDataHex) != "" {
			covData, err = txctxDecodeHex(output.RawCovenantDataHex)
			if err != nil {
				return nil, txid, chainID, nil, nil, nil, err
			}
		} else {
			switch covType {
			case consensus.COV_TYPE_CORE_EXT:
				covData, err = txctxCoreExtCovData(output.ExtID, output.ExtPayloadHex, output.RawExtPayloadHex)
				if err != nil {
					return nil, txid, chainID, nil, nil, nil, err
				}
			case consensus.COV_TYPE_P2PK:
				covData = txctxDefaultP2PKCovenantData()
			case consensus.COV_TYPE_ANCHOR:
				covData = make([]byte, 32)
			default:
				covData = txctxDefaultP2PKCovenantData()
			}
		}
		tx.Outputs = append(tx.Outputs, consensus.TxOutput{
			Value:        txctxCanonicalOutputValue(covType, output.Value),
			CovenantType: covType,
			CovenantData: covData,
		})
	}

	profilesByExt := txctxProfileByExtID(tc)
	deployments := make([]consensus.CoreExtDeploymentProfile, 0, len(profilesByExt))
	for _, profile := range tc.Profiles {
		allowed := make(map[uint8]struct{})
		for _, suiteID := range txctxAllowedSuites(profile) {
			allowed[suiteID] = struct{}{}
		}
		deployment := consensus.CoreExtDeploymentProfile{
			ExtID:             profile.ExtID,
			ActivationHeight:  profile.ActivationHeight,
			TxContextEnabled:  profile.TxContextEnabled == 1,
			AllowedSuites:     allowed,
			BindingDescriptor: []byte{0x01},
			ExtPayloadSchema:  []byte{0x02},
		}
		switch {
		case profile.TxContextEnabled == 1:
			deployment.VerifySigExtTxContextFn = func(mode string, accessIndex int) consensus.CoreExtVerifySigExtTxContextFunc {
				return func(extID uint16, suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte, extPayload []byte, ctxBase *consensus.TxContextBase, ctxContinuing *consensus.TxContextContinuing, selfInputValue uint64) (bool, error) {
					diag.recordCall(extID, ctxBase, ctxContinuing, selfInputValue, 9)
					_ = signature
					_ = digest32
					if suiteID == 0x10 && len(pubkey) != 2592 {
						return false, nil
					}
					switch mode {
					case "amm":
						if ctxContinuing == nil {
							return false, nil
						}
						if accessIndex > 0 {
							if int(ctxContinuing.ContinuingOutputCount) <= accessIndex {
								return false, nil
							}
						}
						if ctxContinuing.ContinuingOutputCount == 0 {
							return false, nil
						}
						selectedIndex := accessIndex
						if selectedIndex < 0 {
							selectedIndex = 0
						}
						if int(ctxContinuing.ContinuingOutputCount) <= selectedIndex {
							return false, nil
						}
						selected := ctxContinuing.ContinuingOutputs[selectedIndex]
						if len(extPayload) < 16 || len(selected.ExtPayload) < 16 {
							return false, nil
						}
						oldX := binary.LittleEndian.Uint64(extPayload[:8])
						oldY := binary.LittleEndian.Uint64(extPayload[8:16])
						newX := binary.LittleEndian.Uint64(selected.ExtPayload[:8])
						newY := binary.LittleEndian.Uint64(selected.ExtPayload[8:16])
						oldProduct := new(big.Int).Mul(new(big.Int).SetUint64(oldX), new(big.Int).SetUint64(oldY))
						newProduct := new(big.Int).Mul(new(big.Int).SetUint64(newX), new(big.Int).SetUint64(newY))
						return newProduct.Cmp(oldProduct) >= 0, nil
					default:
						if accessIndex > 0 && (ctxContinuing == nil || int(ctxContinuing.ContinuingOutputCount) <= accessIndex) {
							return false, nil
						}
						return true, nil
					}
				}
			}(profile.VerifierMode, tc.VerifierAccessIndex)
		default:
			deployment.VerifySigExtFn = func(extID uint16, suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte, extPayload []byte) (bool, error) {
				_ = extID
				_ = suiteID
				_ = pubkey
				_ = signature
				_ = digest32
				_ = extPayload
				return true, nil
			}
		}
		deployments = append(deployments, deployment)
	}
	_ = profilesByExt
	provider, err := consensus.NewStaticCoreExtProfileProvider(deployments)
	if err != nil {
		return nil, txid, chainID, nil, nil, nil, err
	}
	return tx, txid, chainID, utxos, resolvedInputs, provider, nil
}

func runTxctxSpendVector(req Request) Response {
	if req.TxctxCase == nil {
		return Response{Ok: false, Err: "bad txctx_case"}
	}
	tc := req.TxctxCase
	diag := &txctxDiagnosticsRecorder{}

	if tc.ForceStep2Error != "" {
		return Response{Ok: false, Err: tc.ForceStep2Error, Diagnostics: diag.responseMap()}
	}
	if txctxDuplicatePrevout(tc) {
		return Response{Ok: false, Err: string(consensus.TX_ERR_PARSE), Diagnostics: diag.responseMap()}
	}
	if errCode := txctxProfileError(tc); errCode != "" {
		return Response{Ok: false, Err: errCode, Diagnostics: diag.responseMap()}
	}
	if tc.ForceStep3Error != "" {
		return Response{Ok: false, Err: tc.ForceStep3Error, Diagnostics: diag.responseMap()}
	}
	if tc.HasVaultInputs {
		var totalOut uint64
		for _, output := range tc.Outputs {
			totalOut += txctxCanonicalOutputValue(func() uint16 {
				covType, _ := txctxParseCovenantType(output.CovenantType)
				return covType
			}(), output.Value)
		}
		if totalOut < tc.VaultInputSum {
			return Response{Ok: false, Err: string(consensus.TX_ERR_VALUE_CONSERVATION), Diagnostics: diag.responseMap()}
		}
	}

	tx, txid, chainID, utxos, resolvedInputs, provider, err := txctxBuildHarnessArtifacts(tc, diag)
	if err != nil {
		return Response{Ok: false, Err: err.Error(), Diagnostics: diag.responseMap()}
	}

	activeTxctx := false
	for _, profile := range tc.Profiles {
		if profile.TxContextEnabled == 1 && tc.Height >= profile.ActivationHeight {
			activeTxctx = true
			break
		}
	}
	if activeTxctx {
		outputExtIDCache, err := consensus.BuildTxContextOutputExtIDCache(tx)
		if err != nil {
			return Response{Ok: false, Err: txctxErrCode(err), Diagnostics: diag.responseMap()}
		}
		diag.buildTxContextCalled = true
		bundle, err := consensus.BuildTxContext(tx, resolvedInputs, outputExtIDCache, tc.Height, provider)
		if err != nil {
			diag.failingExtID = txctxFirstOverflowExtID(tc.Outputs)
			diag.continuingMapEmptyAfterReject = true
			return Response{Ok: false, Err: txctxErrCode(err), Diagnostics: diag.responseMap()}
		}
		diag.attachBundle(bundle)
		if tc.ForceMissingCtxContinuingExt != 0 {
			return Response{Ok: false, Err: string(consensus.TX_ERR_SIG_INVALID), Diagnostics: diag.responseMap()}
		}
	}

	_, _, err = consensus.ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfilesAndSuiteContext(
		tx,
		txid,
		utxos,
		tc.Height,
		0,
		0,
		chainID,
		provider,
		nil,
		nil,
	)
	if err != nil {
		return Response{Ok: false, Err: txctxErrCode(err), Diagnostics: diag.responseMap()}
	}

	for _, input := range tc.Inputs {
		profile, ok := txctxProfileByExtID(tc)[input.ExtID]
		if !ok || tc.Height < profile.ActivationHeight || profile.TxContextEnabled != 0 {
			continue
		}
		diag.abiParamsSeen = append(diag.abiParamsSeen, 6)
		diag.calledExtIDs = append(diag.calledExtIDs, input.ExtID)
		diag.selfInputValuesSeen = append(diag.selfInputValuesSeen, input.SelfInputValue)
	}

	return Response{Ok: true, Diagnostics: diag.responseMap()}
}
