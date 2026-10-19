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

type TreeAuthorityV1 struct {
	Authority                              StorageAuthorityV1
	LagGenerationID, TargetLagGenerationID uint64
	SourceKind                             TreeSourceKindV1
	Progress                               TreeProgressV1
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

func decodeTreeReference(r *authorityReader) *TreeImportReferenceV1 {
	return &TreeImportReferenceV1{OriginalDatabaseID: r.hash32(), OriginalCurrentID: r.u64(), OriginalLagID: r.u64(), OriginalRole: TreeOriginalRoleV1(r.tag(2)), EvidenceID: r.hash32()}
}

func DecodeRootBindingV1(b []byte) (RootBindingV1, error) {
	if len(b) < 133 || len(b) > 328 {
		return RootBindingV1{}, errSchema
	}
	r := authorityReader{b: b, ok: true}
	if r.tag(1) != 1 {
		return RootBindingV1{}, errSchema
	}
	root := RootBindingV1{DatabaseID: r.hash32(), CommitmentVersion: r.u8(), ChainID: r.hash32(), GenesisHash: r.hash32()}
	root.Endpoint = decodeTreeEndpoint(&r)
	root.RootDigest, root.Top = r.hash32(), decodeTreeTop(&r)
	root.Assurance.Kind = TreeAssuranceKindV1(r.tag(2))
	if root.Assurance.Kind == TreeAssuranceImportedBaseV1 {
		root.Assurance.Import = decodeTreeReference(&r)
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

func decodeTreeTop(r *authorityReader) TreeTopV1 {
	top := TreeTopV1{Kind: TreeTopKindV1(r.u8())}
	switch top.Kind {
	case TreeTopEmptyV1:
	case TreeTopLeafV1, TreeTopBranchV1:
		id, err := decodeTreeSuffix(r.take(38))
		if err != nil {
			r.ok = false
			return top
		}
		top.Node = &id
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

func validTreeRoles(tree TreeAuthorityV1) bool {
	a := tree.Authority
	roles := []uint64{a.ActiveGenerationID, tree.LagGenerationID}
	if a.Replay != nil {
		roles = append(roles, a.Replay.TargetGenerationID, tree.TargetLagGenerationID)
	}
	for i, role := range roles {
		if role == 0 || role >= a.NextGenerationID {
			return false
		}
		for _, earlier := range roles[:i] {
			if earlier == role {
				return false
			}
		}
	}
	return treeExcludedOwners(a, roles)
}

func treeExcludedOwners(a StorageAuthorityV1, roles []uint64) bool {
	cleanup, selected := a.Cleanup, a.SelectedSide
	if a.Ordinary != nil {
		cleanup, selected = a.Ordinary.CarriedCleanup, a.Ordinary.CapturedSelectedSide
	}
	for _, role := range roles {
		if selected != nil && selected.GenerationID == role {
			return false
		}
		if cleanup != nil && !treeCleanupExcludes(cleanup, role, a.NextGenerationID) {
			return false
		}
	}
	return true
}

func treeCleanupExcludes(cleanup *CleanupV1, role, next uint64) bool {
	for _, span := range cleanup.Spans {
		if span.Kind == CleanupSpanGenerationV1 && span.GenerationID >= next {
			return false
		}
		if (span.Kind == CleanupSpanGenerationV1 || span.Kind == CleanupSpanSideV1) && span.GenerationID == role {
			return false
		}
	}
	return true
}

func validTreeAuthority(tree TreeAuthorityV1) bool {
	a := tree.Authority
	return validTreeSource(tree) && validTop(a) && validPhasePayloadFor(a, true) && validDescriptorsFor(a, true) && validOwners(a) && validTreeRoles(tree)
}

func (tree TreeAuthorityV1) Encode() ([]byte, error) {
	if !validTreeAuthority(tree) {
		return nil, errSchema
	}
	n, ok := authoritySize(tree.Authority)
	if !ok || n < 40 || n > MaxMetadataBytes-27 || len(tree.Progress.Payload) > MaxMetadataBytes-27-n {
		return nil, errSchema
	}
	out := []byte{1, byte(tree.SourceKind)}
	appendU64(&out, tree.LagGenerationID)
	appendU64(&out, tree.TargetLagGenerationID)
	appendU32(&out, uint32(n))
	encodeAuthority(&out, tree.Authority)
	out = append(out, byte(tree.Progress.Kind))
	appendBlob(&out, tree.Progress.Payload)
	return out, nil
}

func DecodeTreeAuthorityV1(b []byte) (TreeAuthorityV1, error) {
	if !all(len(b) >= 67, len(b) <= MaxMetadataBytes) {
		return TreeAuthorityV1{}, errSchema
	}
	r := authorityReader{b: b, ok: true, tree: true}
	if r.tag(1) != 1 {
		return TreeAuthorityV1{}, errSchema
	}
	tree := TreeAuthorityV1{SourceKind: TreeSourceKindV1(r.u8()), LagGenerationID: r.u64(), TargetLagGenerationID: r.u64()}
	if tree.SourceKind > 2 {
		return TreeAuthorityV1{}, errSchema
	}
	n := int64(r.u32())
	if !all(n >= 40, n <= int64(r.remaining())) {
		return TreeAuthorityV1{}, errSchema
	}
	authorityBytes := r.take(int(n))
	tree.Progress.Kind = TreeProgressKindV1(r.u8())
	if tree.Progress.Kind > 2 {
		return TreeAuthorityV1{}, errSchema
	}
	payloadLength := int64(r.u32())
	if !all(r.ok, payloadLength == int64(r.remaining())) {
		return TreeAuthorityV1{}, errSchema
	}
	inner := authorityReader{b: authorityBytes, ok: true, tree: true}
	tree.Authority = decodeAuthority(&inner)
	tree.Progress.Payload = r.take(r.remaining())
	if !all(inner.ok, inner.remaining() == 0, validTreeAuthority(tree)) {
		return TreeAuthorityV1{}, errSchema
	}
	tree.Progress.Payload = append([]byte(nil), tree.Progress.Payload...)
	return tree, nil
}
