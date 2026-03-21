package consensus

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"sort"
)

type CoreExtVerifySigExtFunc func(extID uint16, suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte, extPayload []byte) (bool, error)
type CoreExtVerifySigExtTxContextFunc func(
	extID uint16,
	suiteID uint8,
	pubkey []byte,
	signature []byte,
	digest32 [32]byte,
	extPayload []byte,
	ctxBase *TxContextBase,
	ctxContinuing *TxContextContinuing,
	selfInputValue uint64,
) (bool, error)

const (
	CoreExtBindingKindNativeOnly   byte = 0x01
	CoreExtBindingKindVerifySigExt byte = 0x02
)

type CoreExtProfile struct {
	Active                  bool
	TxContextEnabled        bool
	AllowedSuites           map[uint8]struct{}
	VerifySigExtFn          CoreExtVerifySigExtFunc
	VerifySigExtTxContextFn CoreExtVerifySigExtTxContextFunc
	BindingDescriptor       []byte
	ExtPayloadSchema        []byte
}

type CoreExtProfileProvider interface {
	LookupCoreExtProfile(extID uint16, height uint64) (CoreExtProfile, bool, error)
}

type emptyCoreExtProfileProvider struct{}

type CoreExtDeploymentProfile struct {
	ExtID                   uint16
	ActivationHeight        uint64
	TxContextEnabled        bool
	AllowedSuites           map[uint8]struct{}
	VerifySigExtFn          CoreExtVerifySigExtFunc
	VerifySigExtTxContextFn CoreExtVerifySigExtTxContextFunc
	BindingDescriptor       []byte
	ExtPayloadSchema        []byte
}

type StaticCoreExtProfileProvider struct {
	deployments map[uint16]CoreExtDeploymentProfile
}

func EmptyCoreExtProfileProvider() CoreExtProfileProvider {
	return emptyCoreExtProfileProvider{}
}

func NewStaticCoreExtProfileProvider(deployments []CoreExtDeploymentProfile) (*StaticCoreExtProfileProvider, error) {
	if len(deployments) == 0 {
		return &StaticCoreExtProfileProvider{
			deployments: make(map[uint16]CoreExtDeploymentProfile),
		}, nil
	}
	provider := &StaticCoreExtProfileProvider{
		deployments: make(map[uint16]CoreExtDeploymentProfile, len(deployments)),
	}
	for _, item := range deployments {
		if _, exists := provider.deployments[item.ExtID]; exists {
			return nil, fmt.Errorf("duplicate core_ext deployment for ext_id=%d", item.ExtID)
		}
		if len(item.AllowedSuites) == 0 {
			return nil, fmt.Errorf("core_ext deployment for ext_id=%d must have non-empty allowed suites", item.ExtID)
		}
		provider.deployments[item.ExtID] = CoreExtDeploymentProfile{
			ExtID:                   item.ExtID,
			ActivationHeight:        item.ActivationHeight,
			TxContextEnabled:        item.TxContextEnabled,
			AllowedSuites:           cloneAllowedSuites(item.AllowedSuites),
			VerifySigExtFn:          item.VerifySigExtFn,
			VerifySigExtTxContextFn: item.VerifySigExtTxContextFn,
			BindingDescriptor:       cloneBytes(item.BindingDescriptor),
			ExtPayloadSchema:        cloneBytes(item.ExtPayloadSchema),
		}
	}
	return provider, nil
}

func (emptyCoreExtProfileProvider) LookupCoreExtProfile(uint16, uint64) (CoreExtProfile, bool, error) {
	return CoreExtProfile{}, false, nil
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
		Active:                  true,
		TxContextEnabled:        deployment.TxContextEnabled,
		AllowedSuites:           cloneAllowedSuites(deployment.AllowedSuites),
		VerifySigExtFn:          deployment.VerifySigExtFn,
		VerifySigExtTxContextFn: deployment.VerifySigExtTxContextFn,
		BindingDescriptor:       cloneBytes(deployment.BindingDescriptor),
		ExtPayloadSchema:        cloneBytes(deployment.ExtPayloadSchema),
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

func cloneBytes(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	out := make([]byte, len(src))
	copy(out, src)
	return out
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

func wrapCoreExtVerifySigExtWithTxContext(fn CoreExtVerifySigExtFunc) CoreExtVerifySigExtTxContextFunc {
	if fn == nil {
		return nil
	}
	return func(
		extID uint16,
		suiteID uint8,
		pubkey []byte,
		signature []byte,
		digest32 [32]byte,
		extPayload []byte,
		_ *TxContextBase,
		_ *TxContextContinuing,
		_ uint64,
	) (bool, error) {
		return fn(extID, suiteID, pubkey, signature, digest32, extPayload)
	}
}

func hasCoreExtVerifySigExtBinding(profile CoreExtDeploymentProfile) bool {
	return profile.VerifySigExtFn != nil || profile.VerifySigExtTxContextFn != nil
}

func coreExtVerifySigExtTxContextFn(profile CoreExtProfile) CoreExtVerifySigExtTxContextFunc {
	if profile.VerifySigExtTxContextFn != nil {
		return profile.VerifySigExtTxContextFn
	}
	return wrapCoreExtVerifySigExtWithTxContext(profile.VerifySigExtFn)
}

func sortedAllowedSuites(allowed map[uint8]struct{}) []uint8 {
	if len(allowed) == 0 {
		return nil
	}
	out := make([]uint8, 0, len(allowed))
	for suiteID := range allowed {
		out = append(out, suiteID)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func coreExtBindingKind(profile CoreExtDeploymentProfile) (byte, error) {
	if !hasCoreExtVerifySigExtBinding(profile) {
		if len(profile.BindingDescriptor) != 0 {
			return 0, fmt.Errorf("core_ext profile ext_id=%d native-only profile must not carry binding_descriptor", profile.ExtID)
		}
		return CoreExtBindingKindNativeOnly, nil
	}
	if len(profile.BindingDescriptor) == 0 {
		return 0, fmt.Errorf("core_ext profile ext_id=%d verify_sig_ext profile must carry binding_descriptor", profile.ExtID)
	}
	return CoreExtBindingKindVerifySigExt, nil
}

func CoreExtProfileBytesV1(profile CoreExtDeploymentProfile) ([]byte, error) {
	if profile.TxContextEnabled {
		return nil, fmt.Errorf("core_ext profile ext_id=%d txcontext-enabled profile requires v2 anchor pipeline", profile.ExtID)
	}
	allowed := sortedAllowedSuites(profile.AllowedSuites)
	if len(allowed) == 0 {
		return nil, fmt.Errorf("core_ext profile ext_id=%d must have non-empty allowed suites", profile.ExtID)
	}
	if len(profile.ExtPayloadSchema) == 0 {
		return nil, fmt.Errorf("core_ext profile ext_id=%d must carry ext_payload_schema", profile.ExtID)
	}
	bindingKind, err := coreExtBindingKind(profile)
	if err != nil {
		return nil, err
	}

	out := append([]byte(nil), []byte("RUBIN-CORE-EXT-PROFILE-v1")...)
	out = AppendU16le(out, profile.ExtID)
	out = AppendU64le(out, profile.ActivationHeight)
	out = AppendCompactSize(out, uint64(len(allowed)))
	out = append(out, allowed...)
	out = append(out, bindingKind)
	out = AppendCompactSize(out, uint64(len(profile.BindingDescriptor)))
	out = append(out, profile.BindingDescriptor...)
	out = AppendCompactSize(out, uint64(len(profile.ExtPayloadSchema)))
	out = append(out, profile.ExtPayloadSchema...)
	return out, nil
}

func CoreExtProfileAnchorV1(profile CoreExtDeploymentProfile) ([32]byte, error) {
	profileBytes, err := CoreExtProfileBytesV1(profile)
	if err != nil {
		return [32]byte{}, err
	}
	preimage := append([]byte("RUBIN-CORE-EXT-PROFILE-ANCHOR-v1"), profileBytes...)
	return sha3_256(preimage), nil
}

func CoreExtProfileSetAnchorV1(chainID [32]byte, deployments []CoreExtDeploymentProfile) ([32]byte, error) {
	anchors := make([][32]byte, 0, len(deployments))
	for _, deployment := range deployments {
		anchor, err := CoreExtProfileAnchorV1(deployment)
		if err != nil {
			return [32]byte{}, err
		}
		anchors = append(anchors, anchor)
	}
	sort.Slice(anchors, func(i, j int) bool {
		return bytes.Compare(anchors[i][:], anchors[j][:]) < 0
	})

	preimage := append([]byte(nil), []byte("RUBIN-CORE-EXT-PROFILE-SET-v1")...)
	preimage = append(preimage, chainID[:]...)
	preimage = AppendCompactSize(preimage, uint64(len(anchors)))
	for _, anchor := range anchors {
		preimage = append(preimage, anchor[:]...)
	}
	return sha3_256(preimage), nil
}

func normalizeCoreExtSuiteContext(rotation RotationProvider, registry *SuiteRegistry) (RotationProvider, *SuiteRegistry) {
	if rotation == nil {
		rotation = DefaultRotationProvider{}
	}
	if registry == nil {
		registry = DefaultSuiteRegistry()
	}
	return rotation, registry
}

func validateCoreExtNativeWitness(w WitnessItem, params SuiteParams) error {
	if len(w.Pubkey) != params.PubkeyLen || len(w.Signature) != params.SigLen+1 {
		return txerr(TX_ERR_SIG_NONCANONICAL, "non-canonical CORE_EXT native witness item lengths")
	}
	return nil
}

func validateCoreExtWitnessAtHeight(
	cd *CoreExtCovenantData,
	profile CoreExtProfile,
	w WitnessItem,
	tx *Tx,
	inputIndex uint32,
	inputValue uint64,
	chainID [32]byte,
	blockHeight uint64,
	sighashCache *SighashV1PrehashCache,
	rotation RotationProvider,
	registry *SuiteRegistry,
	txContext *TxContextBundle,
	sigQueue *SigCheckQueue,
) error {
	rotation, registry = normalizeCoreExtSuiteContext(rotation, registry)
	if !hasSuite(profile.AllowedSuites, w.SuiteID) {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_EXT suite disallowed under ACTIVE profile")
	}
	if w.SuiteID == SUITE_ID_SENTINEL {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_EXT sentinel forbidden under ACTIVE profile")
	}

	extractSigDigest := func() ([]byte, [32]byte, error) {
		return extractSigAndDigestWithCache(w, tx, inputIndex, inputValue, chainID, sighashCache)
	}

	nativeSpendSuites := rotation.NativeSpendSuites(blockHeight)
	params, nativeRegistered := registry.Lookup(w.SuiteID)

	// Per CANONICAL §12.5 / §23.2.2, registry-known native suites stay on the
	// native path only while currently spend-permitted at this height; suites
	// outside the current native spend set reject here and never fall through to
	// verify_sig_ext.
	if nativeRegistered {
		if !nativeSpendSuites.Contains(w.SuiteID) {
			return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_EXT registered native suite not spend-permitted at this height")
		}
		if err := validateCoreExtNativeWitness(w, params); err != nil {
			return err
		}
		cryptoSig, digest, err := extractSigDigest()
		if err != nil {
			return err
		}
		if sigQueue != nil {
			sigQueue.Push(w.SuiteID, w.Pubkey, cryptoSig, digest, txerr(TX_ERR_SIG_INVALID, "CORE_EXT signature invalid"))
			return nil
		}
		ok, err := verifySigWithRegistry(w.SuiteID, w.Pubkey, cryptoSig, digest, registry)
		if err != nil {
			return err
		}
		if !ok {
			return txerr(TX_ERR_SIG_INVALID, "CORE_EXT signature invalid")
		}
		return nil
	}
	if nativeSpendSuites.Contains(w.SuiteID) {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_EXT registered native suite missing from registry")
	}

	cryptoSig, digest, err := extractSigDigest()
	if err != nil {
		return err
	}
	if profile.TxContextEnabled {
		verifyTxContextFn := coreExtVerifySigExtTxContextFn(profile)
		if verifyTxContextFn == nil {
			return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_EXT verify_sig_ext unsupported")
		}
		if txContext == nil || txContext.Base == nil {
			return txerr(TX_ERR_SIG_INVALID, "CORE_EXT txcontext bundle missing")
		}
		ctxContinuing, ok := txContext.Continuing(cd.ExtID)
		if !ok || ctxContinuing == nil {
			return txerr(TX_ERR_SIG_INVALID, "CORE_EXT txcontext continuing bundle missing")
		}
		ok, err := verifyTxContextFn(
			cd.ExtID,
			w.SuiteID,
			w.Pubkey,
			cryptoSig,
			digest,
			cd.ExtPayload,
			txContext.Base,
			ctxContinuing,
			inputValue,
		)
		if err != nil {
			return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_EXT verify_sig_ext error")
		}
		if !ok {
			return txerr(TX_ERR_SIG_INVALID, "CORE_EXT signature invalid")
		}
		return nil
	}
	if profile.VerifySigExtFn == nil {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_EXT verify_sig_ext unsupported")
	}
	ok, err := profile.VerifySigExtFn(cd.ExtID, w.SuiteID, w.Pubkey, cryptoSig, digest, cd.ExtPayload)
	if err != nil {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_EXT verify_sig_ext error")
	}
	if !ok {
		return txerr(TX_ERR_SIG_INVALID, "CORE_EXT signature invalid")
	}
	return nil
}

func validateCoreExtSpendWithCache(
	entry UtxoEntry,
	w WitnessItem,
	tx *Tx,
	inputIndex uint32,
	inputValue uint64,
	chainID [32]byte,
	blockHeight uint64,
	sighashCache *SighashV1PrehashCache,
	coreExtProfiles CoreExtProfileProvider,
	rotation RotationProvider,
	registry *SuiteRegistry,
	txContext *TxContextBundle,
) error {
	cd, err := ParseCoreExtCovenantData(entry.CovenantData)
	if err != nil {
		return err
	}

	if coreExtProfiles == nil {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT profile provider missing")
	}

	profile := CoreExtProfile{}
	active := false
	resolved, ok, err := coreExtProfiles.LookupCoreExtProfile(cd.ExtID, blockHeight)
	if err != nil {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT profile lookup failure")
	}
	if ok && resolved.Active {
		active = true
		profile = resolved
	}
	if !active {
		return nil
	}

	return validateCoreExtWitnessAtHeight(
		cd,
		profile,
		w,
		tx,
		inputIndex,
		inputValue,
		chainID,
		blockHeight,
		sighashCache,
		rotation,
		registry,
		txContext,
		nil,
	)
}
