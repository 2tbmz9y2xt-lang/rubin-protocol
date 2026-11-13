package mdbx

import (
	"crypto/sha3"
	"encoding/binary"
)

type TreeEndpointKindV1 uint8

const (
	TreeEndpointPreGenesisV1 TreeEndpointKindV1 = 0
	TreeEndpointAppliedV1    TreeEndpointKindV1 = 1
)

type TreeEndpointV1 struct {
	Kind                TreeEndpointKindV1
	Height              uint64
	BlockHash           [32]byte
	CumulativeChainwork [40]byte
}

type TreeTopKindV1 uint8

const (
	TreeTopEmptyV1  TreeTopKindV1 = 0
	TreeTopLeafV1   TreeTopKindV1 = 1
	TreeTopBranchV1 TreeTopKindV1 = 2
)

type TreeTopV1 struct {
	Kind TreeTopKindV1
	Node *TreeNodeIDV1
}

type TreeAssuranceKindV1 uint8

const (
	TreeAssuranceFullHistoryV1  TreeAssuranceKindV1 = 1
	TreeAssuranceImportedBaseV1 TreeAssuranceKindV1 = 2
)

type TreeOriginalRoleV1 uint8

const (
	TreeOriginalCurrentV1 TreeOriginalRoleV1 = 1
	TreeOriginalLagV1     TreeOriginalRoleV1 = 2
)

type TreeImportReferenceV1 struct {
	OriginalDatabaseID               [32]byte
	OriginalCurrentID, OriginalLagID uint64
	OriginalRole                     TreeOriginalRoleV1
	EvidenceID                       [32]byte
}

type TreeAssuranceV1 struct {
	Kind   TreeAssuranceKindV1
	Import *TreeImportReferenceV1
}

type RootBindingV1 struct {
	DatabaseID           [32]byte
	CommitmentVersion    uint8
	ChainID, GenesisHash [32]byte
	Endpoint             TreeEndpointV1
	RootDigest           [32]byte
	Top                  TreeTopV1
	Assurance            TreeAssuranceV1
}

type TreeEvidenceV1 struct {
	OriginalDatabaseID               [32]byte
	OriginalCurrentID, OriginalLagID uint64
	Payload                          []byte
}

type TreeSourceKindV1 uint8

const (
	TreeSourceNoneV1          TreeSourceKindV1 = 0
	TreeSourceGenesisReplayV1 TreeSourceKindV1 = 1
	TreeSourceImageV1         TreeSourceKindV1 = 2
)

type TreeProgressKindV1 uint8

const (
	TreeProgressNoneV1     TreeProgressKindV1 = 0
	TreeProgressPartialV1  TreeProgressKindV1 = 1
	TreeProgressCompleteV1 TreeProgressKindV1 = 2
)

type TreeProgressV1 struct {
	Kind    TreeProgressKindV1
	Payload []byte
}

type TreeSourceIntentKindV1 uint8

const (
	TreeSourceIntentNoneV1  TreeSourceIntentKindV1 = 0
	TreeSourceIntentImageV1 TreeSourceIntentKindV1 = 1
)

// TreeSourceIntentV1 is a retained first-install IMAGE source intent. Payload is
// opaque here; its grammar belongs to the intent producer.
type TreeSourceIntentV1 struct {
	Kind    TreeSourceIntentKindV1
	Payload []byte
}

type TreeAuthorityV1 struct {
	Authority                              StorageAuthorityV1
	LagGenerationID, TargetLagGenerationID uint64
	SourceKind                             TreeSourceKindV1
	Progress                               TreeProgressV1
	// SourceIntent is the client-local encoding of the retained first-install
	// IMAGE source intent outside ReplayV1 (RUBIN_MEMPOOL_POLICY.md 6.4.1.8:
	// clearing ReplayV1 does not clear it). nil is intent none; a non-nil value
	// must hold Kind IMAGE and a nonempty Payload. It is legal only in REPLAY with
	// SourceKind IMAGE, PRUNE_GC/RECOVERY_REQUIRED and NONE/RECOVERY_REQUIRED, and
	// the codec never requires it. A commit leaving RECOVERY_REQUIRED for STABLE
	// must clear it. Every envelope writer other than the intent producer and its
	// consumer must copy it unchanged and never mutate the pointee in place.
	// Absence never establishes ordinary dispatch; a decode failure is integrity;
	// borrowed inspection decode validates but does not materialize it.
	SourceIntent *TreeSourceIntentV1
}

func validTreeOrigin(database [32]byte, current, lag uint64) bool {
	return database != ([32]byte{}) && current != 0 && lag != 0 && current != lag
}

func validTreeReference(ref TreeImportReferenceV1) bool {
	return validTreeOrigin(ref.OriginalDatabaseID, ref.OriginalCurrentID, ref.OriginalLagID) && (ref.OriginalRole == TreeOriginalCurrentV1 || ref.OriginalRole == TreeOriginalLagV1)
}

func validTreeEndpoint(endpoint TreeEndpointV1) bool {
	switch endpoint.Kind {
	case TreeEndpointPreGenesisV1:
		return endpoint.Height == 0 && endpoint.BlockHash == ([32]byte{}) && endpoint.CumulativeChainwork == ([40]byte{})
	case TreeEndpointAppliedV1:
		return endpoint.Height <= maxAuthorityHeight && validWork(endpoint.CumulativeChainwork)
	default:
		return false
	}
}

func validTreeTop(top TreeTopV1) bool {
	switch top.Kind {
	case TreeTopEmptyV1:
		return top.Node == nil
	case TreeTopLeafV1, TreeTopBranchV1:
		return top.Node != nil && TreeNodeKindV1(top.Kind) == top.Node.Kind && validTreeNodeID(*top.Node)
	default:
		return false
	}
}

func validTreeAssurance(assurance TreeAssuranceV1) bool {
	switch assurance.Kind {
	case TreeAssuranceFullHistoryV1:
		return assurance.Import == nil
	case TreeAssuranceImportedBaseV1:
		return assurance.Import != nil && validTreeReference(*assurance.Import)
	default:
		return false
	}
}

func validRootBinding(root RootBindingV1) bool {
	if !all(root.DatabaseID != ([32]byte{}), root.CommitmentVersion == 1,
		validTreeEndpoint(root.Endpoint), validTreeTop(root.Top), validTreeAssurance(root.Assurance)) {
		return false
	}
	if root.Endpoint.Kind == TreeEndpointPreGenesisV1 {
		return root.Top.Kind == TreeTopEmptyV1 && root.RootDigest == sha3.Sum256([]byte("RUBIN_UTXO_TREE_V1\x00"))
	}
	return true
}

func (root RootBindingV1) Encode() ([]byte, error) {
	if !validRootBinding(root) {
		return nil, errSchema
	}
	out := append([]byte{1}, root.DatabaseID[:]...)
	out = append(out, root.CommitmentVersion)
	out = append(out, root.ChainID[:]...)
	out = append(out, root.GenesisHash[:]...)
	out = append(out, byte(root.Endpoint.Kind))
	if root.Endpoint.Kind == TreeEndpointAppliedV1 {
		var height [8]byte
		binary.BigEndian.PutUint64(height[:], root.Endpoint.Height)
		out = append(out, height[4:]...)
		out = append(out, root.Endpoint.BlockHash[:]...)
		out = append(out, root.Endpoint.CumulativeChainwork[:]...)
	}
	out = append(out, root.RootDigest[:]...)
	out = append(out, byte(root.Top.Kind))
	if root.Top.Node != nil {
		key, _ := TreeNodeKey(1, *root.Top.Node)
		out = append(out, key[8:]...)
	}
	out = append(out, byte(root.Assurance.Kind))
	if root.Assurance.Import != nil {
		encodeTreeReference(&out, *root.Assurance.Import)
	}
	return out, nil
}

func encodeTreeReference(out *[]byte, ref TreeImportReferenceV1) {
	*out = append(*out, ref.OriginalDatabaseID[:]...)
	appendU64(out, ref.OriginalCurrentID)
	appendU64(out, ref.OriginalLagID)
	*out = append(*out, byte(ref.OriginalRole))
	*out = append(*out, ref.EvidenceID[:]...)
}

type rootDecodeControl struct {
	top      TreeNodeIDV1
	imported TreeImportReferenceV1
}

func decodeTreeReference(r *authorityReader, c *rootDecodeControl) *TreeImportReferenceV1 {
	c.imported = TreeImportReferenceV1{OriginalDatabaseID: r.hash32(), OriginalCurrentID: r.u64(), OriginalLagID: r.u64(), OriginalRole: TreeOriginalRoleV1(r.tag(2)), EvidenceID: r.hash32()}
	return &c.imported
}

func DecodeRootBindingV1(b []byte) (RootBindingV1, error) {
	var control rootDecodeControl
	return decodeRootBindingV1(b, &control)
}

func inspectRootBindingV1(b []byte) error {
	var control rootDecodeControl
	_, err := decodeRootBindingV1(b, &control)
	return err
}

func decodeRootBindingV1(b []byte, control *rootDecodeControl) (RootBindingV1, error) {
	if len(b) < 133 || len(b) > 328 {
		return RootBindingV1{}, errSchema
	}
	r := authorityReader{b: b, ok: true}
	if r.tag(1) != 1 {
		return RootBindingV1{}, errSchema
	}
	root := RootBindingV1{DatabaseID: r.hash32(), CommitmentVersion: r.u8(), ChainID: r.hash32(), GenesisHash: r.hash32()}
	root.Endpoint = decodeTreeEndpoint(&r)
	root.RootDigest, root.Top = r.hash32(), decodeTreeTop(&r, control)
	root.Assurance.Kind = TreeAssuranceKindV1(r.tag(2))
	if root.Assurance.Kind == TreeAssuranceImportedBaseV1 {
		root.Assurance.Import = decodeTreeReference(&r, control)
	}
	if !all(r.ok, r.remaining() == 0, validRootBinding(root)) {
		return RootBindingV1{}, errSchema
	}
	return root, nil
}

func decodeTreeEndpoint(r *authorityReader) TreeEndpointV1 {
	endpoint := TreeEndpointV1{Kind: TreeEndpointKindV1(r.u8())}
	switch endpoint.Kind {
	case TreeEndpointPreGenesisV1:
	case TreeEndpointAppliedV1:
		endpoint.Height, endpoint.BlockHash, endpoint.CumulativeChainwork = uint64(r.u32()), r.hash32(), r.work40()
	default:
		r.ok = false
	}
	return endpoint
}

func decodeTreeTop(r *authorityReader, control *rootDecodeControl) TreeTopV1 {
	top := TreeTopV1{Kind: TreeTopKindV1(r.u8())}
	switch top.Kind {
	case TreeTopEmptyV1:
	case TreeTopLeafV1, TreeTopBranchV1:
		id, err := decodeTreeSuffix(r.take(38))
		if err != nil {
			r.ok = false
			return top
		}
		control.top = id
		top.Node = &control.top
	default:
		r.ok = false
	}
	return top
}

func (evidence TreeEvidenceV1) Encode() ([]byte, error) {
	if !validTreeOrigin(evidence.OriginalDatabaseID, evidence.OriginalCurrentID, evidence.OriginalLagID) || len(evidence.Payload) == 0 || len(evidence.Payload) > MaxMetadataBytes-53 {
		return nil, errSchema
	}
	out := append([]byte{1}, evidence.OriginalDatabaseID[:]...)
	appendU64(&out, evidence.OriginalCurrentID)
	appendU64(&out, evidence.OriginalLagID)
	appendBlob(&out, evidence.Payload)
	return out, nil
}

func DecodeTreeEvidenceV1(b []byte) (TreeEvidenceV1, error) {
	if len(b) < 54 || len(b) > MaxMetadataBytes || b[0] != 1 {
		return TreeEvidenceV1{}, errSchema
	}
	r := authorityReader{b: b[1:], ok: true}
	evidence := TreeEvidenceV1{OriginalDatabaseID: r.hash32(), OriginalCurrentID: r.u64(), OriginalLagID: r.u64()}
	n := int64(r.u32())
	if n == 0 || n != int64(r.remaining()) || !validTreeOrigin(evidence.OriginalDatabaseID, evidence.OriginalCurrentID, evidence.OriginalLagID) {
		return TreeEvidenceV1{}, errSchema
	}
	evidence.Payload = append([]byte(nil), r.take(r.remaining())...)
	return evidence, nil
}

func validTreeSource(tree TreeAuthorityV1) bool {
	a, progress := tree.Authority, tree.Progress
	if a.Phase != StoragePhaseReplayV1 {
		return all(tree.SourceKind == TreeSourceNoneV1, tree.TargetLagGenerationID == 0, progress.Kind == TreeProgressNoneV1, len(progress.Payload) == 0)
	}
	if a.Replay == nil || tree.TargetLagGenerationID == 0 {
		return false
	}
	switch tree.SourceKind {
	case TreeSourceGenesisReplayV1:
		return all(a.Replay.Cursor.Kind != 0, progress.Kind == TreeProgressNoneV1, len(progress.Payload) == 0)
	case TreeSourceImageV1:
		return all(a.Replay.Cursor == (ReplayCursorV1{}), anyTrue(progress.Kind == TreeProgressPartialV1, progress.Kind == TreeProgressCompleteV1), len(progress.Payload) > 0)
	default:
		return false
	}
}

func validTreeRoles(tree TreeAuthorityV1, projection authorityValidation) bool {
	a := tree.Authority
	roles := [4]uint64{a.ActiveGenerationID, tree.LagGenerationID}
	n := 2
	if a.Replay != nil {
		roles[2], roles[3], n = a.Replay.TargetGenerationID, tree.TargetLagGenerationID, 4
	}
	for i, role := range roles[:n] {
		if role == 0 || role >= a.NextGenerationID {
			return false
		}
		for _, earlier := range roles[:i] {
			if earlier == role {
				return false
			}
		}
	}
	return treeExcludedOwners(projection, roles[:n])
}

func treeExcludedOwners(a authorityValidation, roles []uint64) bool {
	cleanup, selected := a.phase, a.SelectedSide
	if a.Ordinary != nil {
		cleanup, selected = a.carried, a.Ordinary.CapturedSelectedSide
	}
	for _, role := range roles {
		if selected != nil && selected.GenerationID == role {
			return false
		}
		if !treeCleanupExcludes(cleanup, role) {
			return false
		}
	}
	return true
}

func treeCleanupExcludes(cleanup authoritySpans, role uint64) bool {
	for i := 0; i < cleanup.len(); i++ {
		span := cleanup.at(i)
		if (span.Kind == CleanupSpanGenerationV1 || span.Kind == CleanupSpanSideV1) && span.GenerationID == role {
			return false
		}
	}
	return true
}

func validTreeAuthority(tree TreeAuthorityV1) bool {
	return validTreeAuthorityFor(tree, projectAuthority(tree.Authority, nil))
}

// treeIntentPhaseLegal is the legal-phase domain of a retained source intent.
func treeIntentPhaseLegal(present bool, phase StoragePhaseV1, lifecycle StorageLifecycleV1, source TreeSourceKindV1) bool {
	switch {
	case !present:
		return true
	case phase == StoragePhaseReplayV1:
		return source == TreeSourceImageV1
	case phase == StoragePhaseNoneV1, phase == StoragePhasePruneGCV1:
		return lifecycle == StorageLifecycleRecoveryRequiredV1
	}
	return false
}

func validTreeIntent(intent *TreeSourceIntentV1, phase StoragePhaseV1, lifecycle StorageLifecycleV1, source TreeSourceKindV1) bool {
	if intent == nil {
		return true
	}
	return all(intent.Kind == TreeSourceIntentImageV1, len(intent.Payload) > 0) && treeIntentPhaseLegal(true, phase, lifecycle, source)
}

func validTreeAuthorityFor(tree TreeAuthorityV1, a authorityValidation) bool {
	return validTreeSource(tree) && validTreeIntent(tree.SourceIntent, tree.Authority.Phase, tree.Authority.Lifecycle, tree.SourceKind) && validTop(a.StorageAuthorityV1) && validPhasePayloadFor(a, true) && validDescriptorsFor(a, true) && validOwners(a) && validTreeRoles(tree, a)
}

// Encode returns the envelope bytes: tag 1 when SourceIntent is nil (the bytes
// are those of an envelope without the field), tag 2 with carrier kind IMAGE and
// the intent payload otherwise. It refuses with errSchema a tree that fails
// validation, including a non-nil SourceIntent whose Kind is not IMAGE or whose
// Payload is empty, an intent outside its legal phases, and an envelope larger
// than MaxMetadataBytes, so Encode and DecodeTreeAuthorityV1 stay one-to-one.
func (tree TreeAuthorityV1) Encode() ([]byte, error) {
	if !validTreeAuthority(tree) {
		return nil, errSchema
	}
	n, ok := treeEnvelopeAuthoritySize(&tree)
	if !ok {
		return nil, errSchema
	}
	out := []byte{1, byte(tree.SourceKind)}
	appendU64(&out, tree.LagGenerationID)
	appendU64(&out, tree.TargetLagGenerationID)
	appendU32(&out, uint32(n))
	encodeAuthority(&out, tree.Authority)
	out = append(out, byte(tree.Progress.Kind))
	appendBlob(&out, tree.Progress.Payload)
	if tree.SourceIntent != nil {
		out[0] = 2
		out = append(out, byte(tree.SourceIntent.Kind))
		appendBlob(&out, tree.SourceIntent.Payload)
	}
	return out, nil
}

// treeEnvelopeAuthoritySize returns the inner authority length when the whole
// envelope (outer 27 bytes, plus 5 carrier bytes and the intent payload when
// present) fits MaxMetadataBytes. Each bound is checked before it is subtracted.
func treeEnvelopeAuthoritySize(tree *TreeAuthorityV1) (int, bool) {
	n, ok := authoritySize(tree.Authority)
	if !ok || n < 40 || n > MaxMetadataBytes-27 || len(tree.Progress.Payload) > MaxMetadataBytes-27-n {
		return 0, false
	}
	room := MaxMetadataBytes - 27 - n - len(tree.Progress.Payload)
	return n, tree.SourceIntent == nil || len(tree.SourceIntent.Payload) <= room-5
}

// DecodeTreeAuthorityV1 parses and validates one envelope and returns errSchema
// on any failure. Tag 1 yields SourceIntent nil; a legal tag 2 yields a fresh
// pointee of Kind IMAGE whose Payload is a fresh copy sharing no byte with b or
// with Progress.Payload. Progress.Payload is also a fresh copy of the input.
func DecodeTreeAuthorityV1(b []byte) (TreeAuthorityV1, error) {
	var control authorityDecodeControl
	control.ordinary.Cursor = &control.cursor
	control.ordinary.CapturedSelectedSide = &control.selected
	control.ordinary.CarriedCleanup = &control.cleanup
	control.ordinary.RecordedFailure = &control.failure
	control.failure.FailedBlockHash = &control.hash
	return decodeTreeAuthorityV1(b, &control, nil)
}

func inspectTreeAuthorityV1(b []byte) error {
	var control authorityDecodeControl
	control.ordinary.Cursor = &control.cursor
	control.ordinary.CapturedSelectedSide = &control.selected
	control.ordinary.CarriedCleanup = &control.cleanup
	control.ordinary.RecordedFailure = &control.failure
	control.failure.FailedBlockHash = &control.hash
	var inspection authorityInspection
	_, err := decodeTreeAuthorityV1(b, &control, &inspection)
	return err
}

// decodeTreeAuthorityV1 applies the carrier grammar and the intent phase check in
// both modes. With inspection non-nil (borrowed) it allocates nothing and leaves
// SourceIntent nil; otherwise SourceIntent is a fresh copy sharing no byte with b.
func decodeTreeAuthorityV1(b []byte, control *authorityDecodeControl, inspection *authorityInspection) (TreeAuthorityV1, error) {
	if !all(len(b) >= 67, len(b) <= MaxMetadataBytes) {
		return TreeAuthorityV1{}, errSchema
	}
	r := authorityReader{b: b, ok: true, tree: true}
	tree, authorityBytes, carrier := decodeTreeEnvelope(&r)
	if !r.ok {
		return TreeAuthorityV1{}, errSchema
	}
	inner := authorityReader{b: authorityBytes, ok: true, tree: true, borrowed: inspection != nil}
	tree.Authority = decodeAuthority(&inner, control, inspection)
	if !inner.ok || inner.remaining() != 0 {
		return TreeAuthorityV1{}, errSchema
	}
	if !treeIntentPhaseLegal(carrier != nil, tree.Authority.Phase, tree.Authority.Lifecycle, tree.SourceKind) {
		return TreeAuthorityV1{}, errSchema
	}
	if !validTreeAuthorityFor(tree, projectAuthority(tree.Authority, inspection)) {
		return TreeAuthorityV1{}, errSchema
	}
	if inspection == nil {
		tree.Progress.Payload = append([]byte(nil), tree.Progress.Payload...)
		tree.SourceIntent = materializeTreeIntent(carrier)
	}
	return tree, nil
}

func materializeTreeIntent(carrier []byte) *TreeSourceIntentV1 {
	if carrier == nil {
		return nil
	}
	return &TreeSourceIntentV1{Kind: TreeSourceIntentImageV1, Payload: append([]byte(nil), carrier...)}
}

// decodeTreeEnvelope reads envelope tag 1 (no intent) or tag 2 (tag-1 fields,
// then carrier kind 1 and a nonempty u32-length intent payload ending the input).
// It returns the borrowed authority bytes and carrier payload, nil for tag 1.
func decodeTreeEnvelope(r *authorityReader) (TreeAuthorityV1, []byte, []byte) {
	tag := r.tag(2)
	if !r.ok {
		return TreeAuthorityV1{}, nil, nil
	}
	tree := TreeAuthorityV1{SourceKind: TreeSourceKindV1(r.u8()), LagGenerationID: r.u64(), TargetLagGenerationID: r.u64()}
	if tree.SourceKind > 2 {
		r.ok = false
		return TreeAuthorityV1{}, nil, nil
	}
	n := int64(r.u32())
	if !all(n >= 40, n <= int64(r.remaining())) {
		r.ok = false
		return TreeAuthorityV1{}, nil, nil
	}
	authorityBytes := r.take(int(n))
	tree.Progress.Kind = TreeProgressKindV1(r.u8())
	if tree.Progress.Kind > 2 {
		r.ok = false
		return TreeAuthorityV1{}, nil, nil
	}
	var carrier []byte
	tree.Progress.Payload, carrier = decodeTreeTail(r, tag)
	if !r.ok {
		return TreeAuthorityV1{}, nil, nil
	}
	return tree, authorityBytes, carrier
}

// decodeTreeTail returns the progress payload and, for tag 2, the carrier
// payload. For tag 2 the progress length delimits only the progress bytes.
func decodeTreeTail(r *authorityReader, tag uint8) ([]byte, []byte) {
	n := int64(r.u32())
	if !r.ok || n > int64(r.remaining()) || tag == 1 && n != int64(r.remaining()) {
		r.ok = false
		return nil, nil
	}
	progress := r.take(int(n))
	if tag == 1 {
		return progress, nil
	}
	return progress, decodeTreeCarrier(r)
}

func decodeTreeCarrier(r *authorityReader) []byte {
	kind := r.u8()
	n := int64(r.u32())
	if !all(r.ok, kind == byte(TreeSourceIntentImageV1), n > 0, n == int64(r.remaining())) {
		r.ok = false
		return nil
	}
	return r.take(int(n))
}
