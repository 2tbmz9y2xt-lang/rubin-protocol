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
	payloadLenPrefix := 2 + payloadLenVarintBytes
	if payloadLenU64 > uint64(math.MaxInt-payloadLenPrefix) {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT covenant_data ext_payload parse failure")
	}
	payloadLen := int(payloadLenU64)

	payload, err := readBytes(covenantData, &off, payloadLen)
	if err != nil {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT covenant_data ext_payload parse failure")
	}

	expectedLen := payloadLenPrefix + payloadLen
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

type coreExtVerifySigExtTxContextCall struct {
	extID          uint16
	suiteID        uint8
	pubkey         []byte
	signature      []byte
	digest32       [32]byte
	extPayload     []byte
	ctxBase        *TxContextBase
	ctxContinuing  *TxContextContinuing
	selfInputValue uint64
}

func hasCoreExtVerifySigExtBinding(profile CoreExtDeploymentProfile) bool {
	return profile.VerifySigExtFn != nil || profile.VerifySigExtTxContextFn != nil
}

func verifyCoreExtProfileTxContext(profile CoreExtProfile, call coreExtVerifySigExtTxContextCall) (bool, error) {
	if profile.VerifySigExtTxContextFn != nil {
		return profile.VerifySigExtTxContextFn(
			call.extID,
			call.suiteID,
			call.pubkey,
			call.signature,
			call.digest32,
			call.extPayload,
			call.ctxBase,
			call.ctxContinuing,
			call.selfInputValue,
		)
	}
	if profile.VerifySigExtFn != nil {
		return profile.VerifySigExtFn(call.extID, call.suiteID, call.pubkey, call.signature, call.digest32, call.extPayload)
	}
	return false, nil
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

type coreExtWitnessValidation struct {
	cd           *CoreExtCovenantData
	profile      CoreExtProfile
	w            WitnessItem
	tx           *Tx
	inputIndex   uint32
	inputValue   uint64
	chainID      [32]byte
	blockHeight  uint64
	sighashCache *SighashV1PrehashCache
	rotation     RotationProvider
	registry     *SuiteRegistry
	txContext    *TxContextBundle
	sigQueue     *SigCheckQueue
}

func validateCoreExtWitnessAtHeight(check coreExtWitnessValidation) error {
	check.rotation, check.registry = normalizeCoreExtSuiteContext(check.rotation, check.registry)
	if !hasSuite(check.profile.AllowedSuites, check.w.SuiteID) {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_EXT suite disallowed under ACTIVE profile")
	}
	if check.w.SuiteID == SUITE_ID_SENTINEL {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_EXT sentinel forbidden under ACTIVE profile")
	}

	nativeSpendSuites := check.rotation.NativeSpendSuites(check.blockHeight)
	params, nativeRegistered := check.registry.Lookup(check.w.SuiteID)

	// Per CANONICAL §12.5 / §23.2.2, registry-known native suites stay on the
	// native path only while currently spend-permitted at this height; suites
	// outside the current native spend set reject here and never fall through to
	// verify_sig_ext.
	if nativeRegistered {
		if !nativeSpendSuites.Contains(check.w.SuiteID) {
			return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_EXT registered native suite not spend-permitted at this height")
		}
		return check.validateCoreExtNativeWitnessPath(params)
	}
	if nativeSpendSuites.Contains(check.w.SuiteID) {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_EXT registered native suite missing from registry")
	}

	return check.validateCoreExtProfilePath()
}

func (check coreExtWitnessValidation) extractSigDigest() ([]byte, [32]byte, error) {
	return extractSigAndDigestWithCache(
		check.w,
		check.tx,
		check.inputIndex,
		check.inputValue,
		check.chainID,
		check.sighashCache,
	)
}

func (check coreExtWitnessValidation) validateCoreExtNativeWitnessPath(params SuiteParams) error {
	if err := validateCoreExtNativeWitness(check.w, params); err != nil {
		return err
	}
	cryptoSig, digest, err := check.extractSigDigest()
	if err != nil {
		return err
	}
	if check.sigQueue != nil {
		check.sigQueue.Push(check.w.SuiteID, check.w.Pubkey, cryptoSig, digest, txerr(TX_ERR_SIG_INVALID, "CORE_EXT signature invalid"))
		return nil
	}
	ok, err := verifySigWithRegistry(check.w.SuiteID, check.w.Pubkey, cryptoSig, digest, check.registry)
	if err != nil {
		return err
	}
	if !ok {
		return txerr(TX_ERR_SIG_INVALID, "CORE_EXT signature invalid")
	}
	return nil
}

func (check coreExtWitnessValidation) validateCoreExtProfilePath() error {
	cryptoSig, digest, err := check.extractSigDigest()
	if err != nil {
		return err
	}
	if check.profile.TxContextEnabled {
		return check.validateCoreExtTxContextVerifier(cryptoSig, digest)
	}
	return check.validateCoreExtLegacyVerifier(cryptoSig, digest)
}

func (check coreExtWitnessValidation) validateCoreExtTxContextVerifier(cryptoSig []byte, digest [32]byte) error {
	if coreExtTxContextVerifierUnsupported(check.profile) {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_EXT verify_sig_ext unsupported")
	}
	ctxBase, ctxContinuing, err := check.txContextVerifierBundles()
	if err != nil {
		return err
	}
	ok, err := verifyCoreExtProfileTxContext(check.profile, coreExtVerifySigExtTxContextCall{
		extID:          check.cd.ExtID,
		suiteID:        check.w.SuiteID,
		pubkey:         check.w.Pubkey,
		signature:      cryptoSig,
		digest32:       digest,
		extPayload:     check.cd.ExtPayload,
		ctxBase:        ctxBase,
		ctxContinuing:  ctxContinuing,
		selfInputValue: check.inputValue,
	})
	if err != nil {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_EXT verify_sig_ext error")
	}
	if !ok {
		return txerr(TX_ERR_SIG_INVALID, "CORE_EXT signature invalid")
	}
	return nil
}

func coreExtTxContextVerifierUnsupported(profile CoreExtProfile) bool {
	return profile.VerifySigExtFn == nil && profile.VerifySigExtTxContextFn == nil
}

func (check coreExtWitnessValidation) txContextVerifierBundles() (*TxContextBase, *TxContextContinuing, error) {
	if check.txContext == nil {
		return nil, nil, txerr(TX_ERR_SIG_INVALID, "CORE_EXT txcontext bundle missing")
	}
	if check.txContext.Base == nil {
		return nil, nil, txerr(TX_ERR_SIG_INVALID, "CORE_EXT txcontext bundle missing")
	}
	ctxContinuing, ok := check.txContext.Continuing(check.cd.ExtID)
	if !ok {
		return nil, nil, txerr(TX_ERR_SIG_INVALID, "CORE_EXT txcontext continuing bundle missing")
	}
	if ctxContinuing == nil {
		return nil, nil, txerr(TX_ERR_SIG_INVALID, "CORE_EXT txcontext continuing bundle missing")
	}
	return check.txContext.Base, ctxContinuing, nil
}

func (check coreExtWitnessValidation) validateCoreExtLegacyVerifier(cryptoSig []byte, digest [32]byte) error {
	if check.profile.VerifySigExtFn == nil {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_EXT verify_sig_ext unsupported")
	}
	ok, err := check.profile.VerifySigExtFn(check.cd.ExtID, check.w.SuiteID, check.w.Pubkey, cryptoSig, digest, check.cd.ExtPayload)
	if err != nil {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_EXT verify_sig_ext error")
	}
	if !ok {
		return txerr(TX_ERR_SIG_INVALID, "CORE_EXT signature invalid")
	}
	return nil
}

type coreExtSpendValidation struct {
	entry           UtxoEntry
	w               WitnessItem
	tx              *Tx
	inputIndex      uint32
	inputValue      uint64
	chainID         [32]byte
	blockHeight     uint64
	sighashCache    *SighashV1PrehashCache
	coreExtProfiles CoreExtProfileProvider
	rotation        RotationProvider
	registry        *SuiteRegistry
	txContext       *TxContextBundle
}

func validateCoreExtSpendWithCache(check coreExtSpendValidation) error {
	cd, err := ParseCoreExtCovenantData(check.entry.CovenantData)
	if err != nil {
		return err
	}

	if check.coreExtProfiles == nil {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT profile provider missing")
	}

	profile := CoreExtProfile{}
	active := false
	resolved, ok, err := check.coreExtProfiles.LookupCoreExtProfile(cd.ExtID, check.blockHeight)
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

	return validateCoreExtWitnessAtHeight(coreExtWitnessValidation{
		cd:           cd,
		profile:      profile,
		w:            check.w,
		tx:           check.tx,
		inputIndex:   check.inputIndex,
		inputValue:   check.inputValue,
		chainID:      check.chainID,
		blockHeight:  check.blockHeight,
		sighashCache: check.sighashCache,
		rotation:     check.rotation,
		registry:     check.registry,
		txContext:    check.txContext,
	})
}
