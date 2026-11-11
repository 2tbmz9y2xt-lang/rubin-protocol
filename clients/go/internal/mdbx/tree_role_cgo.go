//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"encoding/binary"
	"slices"
)

// TreeRoleSelectorV1 names one required generation role. Only (Current, Lag)
// or (TargetCurrent, TargetLag) form a pair. Zero and values above 4 are
// invalid input. They map to Authority.ActiveGenerationID, LagGenerationID,
// ReplayV1.TargetGenerationID and TargetLagGenerationID.
type TreeRoleSelectorV1 uint8

const (
	TreeRoleCurrentV1, TreeRoleLagV1             TreeRoleSelectorV1 = 1, 2
	TreeRoleTargetCurrentV1, TreeRoleTargetLagV1 TreeRoleSelectorV1 = 3, 4
)

// TreeRoleCountersV1 is one generation's logical counter row: S then N.
type TreeRoleCountersV1 struct {
	LogicalStateBytes, UTXOCount uint64
}

// TreeRoleBindingRequestV1 is the early binding-stage input. The caller has
// decoded and validated Authority on the same Reader at the reached worklist
// position; its role mapping and source discriminator are caller
// preconditions and decoded IMAGE progress bytes are not authentication. The
// producer retains no Authority pointer, Progress.Payload slice or other
// caller-owned mutable value, only an immutable scalar pair projection.
type TreeRoleBindingRequestV1 struct {
	Authority            TreeAuthorityV1
	Role                 TreeRoleSelectorV1
	ChainID, GenesisHash [32]byte
}

// TreeRoleRequestV1 is the later finite-stage input. Bound is the authentic
// same-Reader binding-stage output. Endpoint is exactly the endpoint the
// caller's worklist established. HeaderRoot is non-nil exactly for APPLIED
// and is the raw root of that endpoint's already healthy header. Non-nil
// Counters means an earlier owner read these counters on this Reader; they
// are reused as an explicit caller precondition, not a proof. Endpoint,
// HeaderRoot and Counters are copied synchronously and never retained.
type TreeRoleRequestV1 struct {
	Bound      TreeRoleObservationV1
	Endpoint   TreeEndpointV1
	HeaderRoot *[32]byte
	Counters   *TreeRoleCountersV1
}

// TreeRoleStatusV1 is the result domain of one role observation. Qualified
// requires the complete later finite visit; Positive is a positive required
// finding at Position; PartialDomain is an IMAGE PARTIAL target role outside
// the complete-role API; Bound proves only the early binding checks and is
// incomplete.
type TreeRoleStatusV1 uint8

const (
	TreeRoleQualifiedV1, TreeRolePositiveV1  TreeRoleStatusV1 = 1, 2
	TreeRolePartialDomainV1, TreeRoleBoundV1 TreeRoleStatusV1 = 3, 4
)

// TreeRolePositionV1 is the observation being checked when the first
// non-valid result occurs. At N=1 the single point stage (read, decode, key,
// hash) reports TreeRoleAtZeroPointV1 and top read, decode and
// digest-against-binding failures report TreeRoleAtTopV1;
// TreeRoleAtZeroChildV1, TreeRoleAtOneChildV1 and TreeRoleAtOnePointV1 never
// occur at N=1. Endpoint and header-root mismatches report
// TreeRoleAtBindingV1. Every relation checked before the top read (N and S
// against the top kind, and the N=0 empty digest) and every final
// cardinality or S relation reports TreeRoleAtCardinalityV1.
type TreeRolePositionV1 uint8

const (
	TreeRoleAtBindingV1, TreeRoleAtCounterV1, TreeRoleAtTopV1            TreeRolePositionV1 = 1, 2, 3
	TreeRoleAtZeroChildV1, TreeRoleAtOneChildV1                          TreeRolePositionV1 = 4, 5
	TreeRoleAtZeroPointV1, TreeRoleAtOnePointV1, TreeRoleAtCardinalityV1 TreeRolePositionV1 = 6, 7, 8
)

// TreeRoleFindingV1 classifies a positive finding: definitive row absence is
// Absent; a width, decode, commitment-version or top-payload failure is
// Malformed; a database, chain_id, genesis_hash, generation, endpoint or
// APPLIED header-root mismatch is WrongIdentity; every failed listed relation
// (every digest inequality, top-kind, cardinality and S relation) is
// RelationFailed.
type TreeRoleFindingV1 uint8

const (
	TreeRoleAbsentV1, TreeRoleMalformedV1             TreeRoleFindingV1 = 1, 2
	TreeRoleWrongIdentityV1, TreeRoleRelationFailedV1 TreeRoleFindingV1 = 3, 4
)

// TreeRoleObservationV1 is one role result. Bound sets Status, Role,
// Generation and Binding; Qualified adds Counters and keeps the exact private
// Bound identity; Positive sets only Status, Role, Generation, Position and
// Finding; PartialDomain sets only Status, Role and Generation. Every other
// field is zero. Binding.Top.Node and Binding.Assurance.Import are copies
// owned by this value and never the private canonical backing. Copying an
// unchanged value keeps its private identity; editing any exported field or
// a nested pointer target invalidates it, and no public construction can
// acquire private identity. Bound is incomplete: it is not a complete role,
// source-qualified progress, IMAGE authentication or service permission.
type TreeRoleObservationV1 struct {
	Status     TreeRoleStatusV1
	Role       TreeRoleSelectorV1
	Generation uint64
	Binding    RootBindingV1
	Counters   TreeRoleCountersV1
	Position   TreeRolePositionV1
	Finding    TreeRoleFindingV1

	bound  *treeRoleBoundV1
	finite *treeRoleFiniteV1
}

// TreePairStatusV1 is the result domain of a pair stage. Qualified is the
// final join of two full Qualified roles; Defective is an assurance finding on
// Affected; AssuranceOnly is the early assurance result, incomplete and never
// healthy.
type TreePairStatusV1 uint8

const TreePairQualifiedV1, TreePairDefectiveV1, TreePairAssuranceOnlyV1 TreePairStatusV1 = 1, 2, 3

// TreePairAffectedV1 names the roles a pair defect affects.
type TreePairAffectedV1 uint8

const (
	TreePairAffectedNoneV1, TreePairAffectedCurrentV1 TreePairAffectedV1 = 0, 1
	TreePairAffectedLagV1, TreePairAffectedBothV1     TreePairAffectedV1 = 2, 3
)

// TreePairDefectV1 is the assurance defect kind. Unresolved covers an
// undecodable evidence value, a SHA3-256 differing from EvidenceID and
// original origin IDs differing from the reference.
type TreePairDefectV1 uint8

const (
	TreePairEvidenceAbsentV1, TreePairEvidenceUnresolvedV1 TreePairDefectV1 = 1, 2
	TreePairWrongRoleV1, TreePairProvenanceConflictV1      TreePairDefectV1 = 3, 4
)

// TreePairQualificationV1 is one pair result. AssuranceOnly holds copies of
// its two Bound roles, Affected none and Defect zero; Defective holds its two
// Bound roles with the exact Affected and Defect; Qualified holds its two
// full Qualified roles, Affected none and Defect zero. Public values never
// share mutable backing with private canonical values or with a separately
// returned result. No result grants service, selection, FULL_HISTORY or
// source authentication.
type TreePairQualificationV1 struct {
	Status   TreePairStatusV1
	Affected TreePairAffectedV1
	Defect   TreePairDefectV1
	Current  TreeRoleObservationV1
	Lag      TreeRoleObservationV1

	stage *treePairStageV1
}

// treeRolePairIDV1 is the immutable scalar authority projection of one pair.
type treeRolePairIDV1 struct {
	database, chainID, genesis [32]byte
	generations                [4]uint64
	target                     bool
	source                     TreeSourceKindV1
	progress                   TreeProgressKindV1
	cursor                     ReplayCursorV1
}

// treeRoleBoundV1 is the immutable private binding record of one Bound role.
type treeRoleBoundV1 struct {
	reader     *Reader
	pair       treeRolePairIDV1
	role       TreeRoleSelectorV1
	generation uint64
	binding    RootBindingV1
	top        TreeNodeIDV1
	imported   TreeImportReferenceV1
}

// treeRoleFiniteV1 is the immutable private record of one Qualified role.
type treeRoleFiniteV1 struct {
	bound    *treeRoleBoundV1
	counters TreeRoleCountersV1
}

// treePairStageV1 is the immutable private canonical snapshot of a pair.
type treePairStageV1 struct {
	reader         *Reader
	status         TreePairStatusV1
	affected       TreePairAffectedV1
	defect         TreePairDefectV1
	current, lag   *treeRoleBoundV1
	currentQ, lagQ *treeRoleFiniteV1
}

const (
	treeRoleBindingChargeV1  uint64 = 3380
	treeRoleFiniteChargeV1   uint64 = 135028
	treeRoleEvidenceChargeV1 uint64 = 2099268
)

func treeRoleInvalidV1() error {
	return adapterError(operationGet, EngineInvalidInput, codeEINVAL, "invalid tree role input", nil)
}

func (r *Reader) treeRoleAdmitV1(account *OperationAccount) error {
	if r == nil {
		return treeRoleInvalidV1()
	}
	if err := r.treeContext(); err != nil {
		return err
	}
	if !account.openV1() {
		return treeRoleInvalidV1()
	}
	return nil
}

// treeRolePointV1 is the one read path, treeReadPointV1's two steps with a native failure recorded once as in treeRootOldV1.getV1.
// A value above bound is never borrowed: it reads as empty, which each caller's decoder refuses as it refuses that value.
func (r *Reader) treeRolePointV1(rank uint8, key []byte, bound uint64) (treeImageV1, error) {
	r.getMu.Lock()
	defer r.getMu.Unlock()
	if err := r.treeContext(); err != nil {
		return treeImageV1{}, err
	}
	image, err := updateNativeImage(r.txn, r.dbis[rank], key)
	if err != nil {
		return treeImageV1{}, r.treeRecord(err)
	}
	if n := uint64(image.length); n > bound && n <= uint64(^uint(0)>>1) {
		return treeImageV1{present: true}, nil
	}
	view, err := treeBorrowV1(image)
	return view, r.treeRecord(err)
}

func treeRoleMetaKeyV1(kind byte, generation uint64) [9]byte {
	var key [9]byte
	key[0] = kind
	binary.BigEndian.PutUint64(key[1:], generation)
	return key
}

// ObserveTreeRoleBindingV1 is the early binding stage of one role. Admission
// order: nil receiver; the existing treeContext error unchanged (an inactive
// Reader is never revived); nil, zero or closed account; then the request
// domain (role 1 to 4, nonzero ChainID and GenesisHash, the closed source
// domain of the Authority, a nonzero mapped generation, target roles only in
// REPLAY). Each refusal is EngineInvalidInput/codeEINVAL/get, not recorded,
// with no read and no charge. An IMAGE PARTIAL target returns PartialDomain
// with zero reads and zero reservation. Otherwise it reserves 3380 temporary
// bytes on account (a refusal is returned unchanged, zero reads) and reads
// only that generation's root binding (key 0x11 then the generation), then
// checks decode, database identity, chain_id and genesis_hash in that order.
// It reads no endpoint, header, counter or node. The first non-valid result
// ends the call: absence is Positive/Absent at Binding, a decode failure
// (framing, width, commitment version, top or assurance payload) is
// Positive/Malformed at Binding, an identity mismatch is
// Positive/WrongIdentity at Binding; a Positive result records nothing and
// leaves the Reader usable. A native read failure is returned unchanged,
// recorded once on the Reader, with a zero observation. The 3380 bytes are released
// before return. Success returns Bound; Bound and AssuranceOnly are incomplete (no complete
// role, source-qualified progress, IMAGE authentication or service permission) and usable
// only on this Reader while it stays usable. The by-value request and the result are caller
// copies charged on the caller-held per-pair retention frame; this method makes no
// reservation for them and retains no borrowed reference.
func (r *Reader) ObserveTreeRoleBindingV1(account *OperationAccount, request TreeRoleBindingRequestV1) (TreeRoleObservationV1, error) {
	if err := r.treeRoleAdmitV1(account); err != nil {
		return TreeRoleObservationV1{}, err
	}
	generation, ok := treeRoleBindingInputV1(&request)
	if !ok {
		return TreeRoleObservationV1{}, treeRoleInvalidV1()
	}
	if treeRolePartialV1(&request) {
		return TreeRoleObservationV1{Status: TreeRolePartialDomainV1, Role: request.Role, Generation: generation}, nil
	}
	var out TreeRoleObservationV1
	err := account.WithReservation(treeRoleBindingChargeV1, func() error {
		return r.treeRoleBindV1(&request, generation, &out)
	})
	if err != nil {
		return TreeRoleObservationV1{}, err
	}
	return out, nil
}

func treeRoleGenerationV1(t *TreeAuthorityV1, role TreeRoleSelectorV1) uint64 {
	switch role {
	case TreeRoleCurrentV1:
		return t.Authority.ActiveGenerationID
	case TreeRoleLagV1:
		return t.LagGenerationID
	case TreeRoleTargetCurrentV1, TreeRoleTargetLagV1:
		return treeRoleTargetGenerationV1(t, role)
	}
	return 0
}

func treeRoleTargetGenerationV1(t *TreeAuthorityV1, role TreeRoleSelectorV1) uint64 {
	if t.Authority.Phase != StoragePhaseReplayV1 || t.Authority.Replay == nil {
		return 0
	}
	if role == TreeRoleTargetCurrentV1 {
		return t.Authority.Replay.TargetGenerationID
	}
	return t.TargetLagGenerationID
}

// treeRoleSourceOKV1 mirrors validTreeSource through a pointer.
func treeRoleSourceOKV1(t *TreeAuthorityV1) bool {
	a, progress := &t.Authority, &t.Progress
	if a.Phase != StoragePhaseReplayV1 {
		return all(t.SourceKind == TreeSourceNoneV1, t.TargetLagGenerationID == 0, progress.Kind == TreeProgressNoneV1, len(progress.Payload) == 0)
	}
	if a.Replay == nil || t.TargetLagGenerationID == 0 {
		return false
	}
	switch t.SourceKind {
	case TreeSourceGenesisReplayV1:
		return all(a.Replay.Cursor.Kind != 0, progress.Kind == TreeProgressNoneV1, len(progress.Payload) == 0)
	case TreeSourceImageV1:
		return treeRoleImageSourceOKV1(t)
	case TreeSourceNoneV1:
	}
	return false
}

func treeRoleImageSourceOKV1(t *TreeAuthorityV1) bool {
	cursor := &t.Authority.Replay.Cursor
	return all(cursor.Kind == 0, cursor.Height == 0, cursor.BlockHash == [32]byte{},
		anyTrue(t.Progress.Kind == TreeProgressPartialV1, t.Progress.Kind == TreeProgressCompleteV1), len(t.Progress.Payload) > 0)
}

func treeRoleBindingInputV1(request *TreeRoleBindingRequestV1) (uint64, bool) {
	if request.Role < TreeRoleCurrentV1 || request.Role > TreeRoleTargetLagV1 {
		return 0, false
	}
	if request.ChainID == [32]byte{} || request.GenesisHash == [32]byte{} || !treeRoleSourceOKV1(&request.Authority) {
		return 0, false
	}
	generation := treeRoleGenerationV1(&request.Authority, request.Role)
	return generation, generation != 0
}

func treeRoleIsTargetV1(role TreeRoleSelectorV1) bool {
	return role == TreeRoleTargetCurrentV1 || role == TreeRoleTargetLagV1
}

func treeRolePartialV1(request *TreeRoleBindingRequestV1) bool {
	t := &request.Authority
	return treeRoleIsTargetV1(request.Role) && t.SourceKind == TreeSourceImageV1 && t.Progress.Kind == TreeProgressPartialV1
}

func (r *Reader) treeRoleBindV1(request *TreeRoleBindingRequestV1, generation uint64, out *TreeRoleObservationV1) error {
	key := treeRoleMetaKeyV1(0x11, generation)
	image, err := r.treeRolePointV1(0, key[:], 328)
	if err != nil {
		return err
	}
	finding := TreeRoleAbsentV1
	if image.present {
		finding = r.treeRoleDecodeBindingV1(request, generation, image.value, out)
	}
	if finding != 0 {
		treeRolePositiveV1(out, request.Role, generation, TreeRoleAtBindingV1, finding)
	}
	return nil
}

// treeRoleDecodeBindingV1 decodes and identity-checks the binding; on success
// it fills out with a Bound observation and returns 0.
func (r *Reader) treeRoleDecodeBindingV1(request *TreeRoleBindingRequestV1, generation uint64, value []byte, out *TreeRoleObservationV1) TreeRoleFindingV1 {
	bound := &treeRoleBoundV1{reader: r, role: request.Role, generation: generation}
	binding, err := DecodeRootBindingV1(value)
	if err != nil {
		return TreeRoleMalformedV1
	}
	if !all(binding.DatabaseID == r.databaseID, binding.ChainID == request.ChainID, binding.GenesisHash == request.GenesisHash) {
		return TreeRoleWrongIdentityV1
	}
	bound.binding = binding
	treeRoleOwnBindingV1(&bound.binding, &bound.top, &bound.imported)
	treeRolePairProjectV1(&bound.pair, request, r)
	treeRoleBoundPublicV1(out, bound)
	return 0
}

func treeRoleOwnBindingV1(binding *RootBindingV1, top *TreeNodeIDV1, imported *TreeImportReferenceV1) {
	if binding.Top.Node != nil {
		*top = *binding.Top.Node
		binding.Top.Node = top
	}
	if binding.Assurance.Import != nil {
		*imported = *binding.Assurance.Import
		binding.Assurance.Import = imported
	}
}

func treeRolePairProjectV1(pair *treeRolePairIDV1, request *TreeRoleBindingRequestV1, r *Reader) {
	t := &request.Authority
	pair.database, pair.chainID, pair.genesis = r.databaseID, request.ChainID, request.GenesisHash
	pair.generations[0], pair.generations[1] = t.Authority.ActiveGenerationID, t.LagGenerationID
	pair.target, pair.source, pair.progress = treeRoleIsTargetV1(request.Role), t.SourceKind, t.Progress.Kind
	if t.Authority.Replay != nil {
		pair.generations[2], pair.generations[3] = t.Authority.Replay.TargetGenerationID, t.TargetLagGenerationID
		pair.cursor = t.Authority.Replay.Cursor
	}
}

func treeRolePositiveV1(out *TreeRoleObservationV1, role TreeRoleSelectorV1, generation uint64, position TreeRolePositionV1, finding TreeRoleFindingV1) {
	*out = TreeRoleObservationV1{Status: TreeRolePositiveV1, Role: role, Generation: generation, Position: position, Finding: finding}
}

func treeRoleBoundPublicV1(out *TreeRoleObservationV1, bound *treeRoleBoundV1) {
	*out = TreeRoleObservationV1{Status: TreeRoleBoundV1, Role: bound.role, Generation: bound.generation, bound: bound}
	treeRolePublicBindingV1(&out.Binding, &bound.binding)
}

func treeRolePublicBindingV1(dst, src *RootBindingV1) {
	*dst = *src
	if src.Top.Node != nil {
		node := *src.Top.Node
		dst.Top.Node = &node
	}
	if src.Assurance.Import != nil {
		imported := *src.Assurance.Import
		dst.Assurance.Import = &imported
	}
}

func treeRolePtrEqualV1[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func treeRoleBindingEqualV1(a, b *RootBindingV1) bool {
	return all(a.DatabaseID == b.DatabaseID, a.CommitmentVersion == b.CommitmentVersion, a.ChainID == b.ChainID,
		a.GenesisHash == b.GenesisHash, a.Endpoint == b.Endpoint, a.RootDigest == b.RootDigest, a.Top.Kind == b.Top.Kind,
		a.Assurance.Kind == b.Assurance.Kind, treeRolePtrEqualV1(a.Top.Node, b.Top.Node),
		treeRolePtrEqualV1(a.Assurance.Import, b.Assurance.Import))
}

func (r *Reader) treeRoleOwnsV1(o *TreeRoleObservationV1, status TreeRoleStatusV1) bool {
	return o.bound != nil && o.bound.reader == r && o.Status == status && all(o.Role == o.bound.role, o.Generation == o.bound.generation, o.Position == 0, o.Finding == 0, treeRoleBindingEqualV1(&o.Binding, &o.bound.binding))
}

func (r *Reader) treeRoleAuthenticV1(o *TreeRoleObservationV1, status TreeRoleStatusV1) bool {
	if !r.treeRoleOwnsV1(o, status) {
		return false
	}
	b := o.bound
	if status == TreeRoleBoundV1 {
		return o.finite == nil && o.Counters == TreeRoleCountersV1{}
	}
	return o.finite != nil && o.finite.bound == b && o.Counters == o.finite.counters
}

// ObserveTreeRoleV1 is the later finite stage of one role. It accepts only an
// authentic same-Reader Bound observation, which is incomplete (Bound proves
// only the early binding checks); a PartialDomain, Positive,
// Qualified, zero, forged, altered or expired value is invalid input.
// Admission order: nil receiver; the existing treeContext error unchanged;
// nil, zero or closed account; then the request domain (authentic Bound, a
// valid Endpoint, HeaderRoot non-nil exactly for APPLIED, and for target
// CURRENT under GENESIS_REPLAY an endpoint whose kind corresponds by name to
// the cursor kind with equal Height and BlockHash). Each refusal is
// EngineInvalidInput/codeEINVAL/get, not recorded, with no read and no
// charge. It then reserves 135028 temporary bytes on account (a refusal is
// returned unchanged, zero reads). It reuses the Bound binding without I/O
// and checks, in order: endpoint equality and the APPLIED header root
// (WrongIdentity at Binding); the counter row (key 0x10 then the
// generation) unless Counters is supplied (Absent or Malformed at Counter);
// N and S against the top kind and, at N=0, the empty digest (RelationFailed
// at Cardinality, no node read). N=0 reads nothing more. N=1 reads the top
// leaf node, then its single UTXO point (AtTop, then AtZeroPoint), and checks
// S against that point's full entry length. N>=2 reads the top branch, the
// zero and one child nodes and the leaf-child UTXO points in zero/one order,
// then checks the final cardinality and S relations. Each node or point is
// read, decoded and its digest or leaf hash compared. It reads at most three
// nodes and two points, never a grandchild or subtree. The first non-valid result ends the call with a Positive
// observation, nothing recorded and the Reader usable. A native read
// failure is returned unchanged, recorded once, with a zero observation.
// The 135028 bytes are released before return. Qualified proves only this finite observation (not
// unread subtree contents, whole-history or whole-image health, source-progress qualification or
// service permission); Bound and AssuranceOnly are incomplete. Results are usable only on this
// Reader while it stays usable. The by-value request and the result are caller copies charged on
// the caller-held per-pair retention frame; this method makes no reservation for them and retains no borrowed reference.
func (r *Reader) ObserveTreeRoleV1(account *OperationAccount, request TreeRoleRequestV1) (TreeRoleObservationV1, error) {
	if err := r.treeRoleAdmitV1(account); err != nil {
		return TreeRoleObservationV1{}, err
	}
	if !r.treeRoleFiniteInputV1(&request) {
		return TreeRoleObservationV1{}, treeRoleInvalidV1()
	}
	var out TreeRoleObservationV1
	err := account.WithReservation(treeRoleFiniteChargeV1, func() error {
		return r.treeRoleFiniteVisitV1(&request, &out)
	})
	if err != nil {
		return TreeRoleObservationV1{}, err
	}
	return out, nil
}

// treeRoleWorkOKV1 mirrors validWork through a pointer.
func treeRoleWorkOKV1(w *[40]byte) bool {
	if !all(w[0] == 0, w[1] == 0, w[2] == 0, w[3] <= 1) {
		return false
	}
	nonzero := slices.ContainsFunc(w[4:], func(n byte) bool { return n != 0 })
	return nonzero == (w[3] == 0)
}

// treeRoleEndpointOKV1 mirrors validTreeEndpoint through a pointer and checks HeaderRoot nilness.
func treeRoleEndpointOKV1(e *TreeEndpointV1, headerRoot *[32]byte) bool {
	switch e.Kind {
	case TreeEndpointPreGenesisV1:
		return all(headerRoot == nil, e.Height == 0, e.BlockHash == [32]byte{}, e.CumulativeChainwork == [40]byte{})
	case TreeEndpointAppliedV1:
		return all(headerRoot != nil, e.Height <= maxAuthorityHeight, treeRoleWorkOKV1(&e.CumulativeChainwork))
	}
	return false
}

// treeRoleCursorOKV1 checks the target CURRENT endpoint under GENESIS_REPLAY against its cursor.
func treeRoleCursorOKV1(b *treeRoleBoundV1, e *TreeEndpointV1) bool {
	if b.role != TreeRoleTargetCurrentV1 || b.pair.source != TreeSourceGenesisReplayV1 {
		return true
	}
	c := &b.pair.cursor
	kind := anyTrue(all(e.Kind == TreeEndpointPreGenesisV1, c.Kind == ReplayCursorPreGenesisV1), all(e.Kind == TreeEndpointAppliedV1, c.Kind == ReplayCursorAppliedV1))
	return all(kind, e.Height == c.Height, e.BlockHash == c.BlockHash)
}

func (r *Reader) treeRoleFiniteInputV1(request *TreeRoleRequestV1) bool {
	if !r.treeRoleAuthenticV1(&request.Bound, TreeRoleBoundV1) {
		return false
	}
	return treeRoleEndpointOKV1(&request.Endpoint, request.HeaderRoot) && treeRoleCursorOKV1(request.Bound.bound, &request.Endpoint)
}

// treeRoleVisitV1 holds the finite visit's working state.
type treeRoleVisitV1 struct {
	reader   *Reader
	bound    *treeRoleBoundV1
	counters TreeRoleCountersV1
	top      TreeNodeV1
	children [2]TreeNodeV1
	entries  [2]uint64
	position TreeRolePositionV1
	finding  TreeRoleFindingV1
}

func (v *treeRoleVisitV1) failV1(position TreeRolePositionV1, finding TreeRoleFindingV1) {
	v.position, v.finding = position, finding
}

func (r *Reader) treeRoleFiniteVisitV1(request *TreeRoleRequestV1, out *TreeRoleObservationV1) error {
	v := &treeRoleVisitV1{reader: r, bound: request.Bound.bound}
	if !treeRoleIdentityV1(v, request) {
		treeRolePositiveV1(out, v.bound.role, v.bound.generation, v.position, v.finding)
		return nil
	}
	err := v.countersV1(request.Counters)
	if err == nil && v.finding == 0 {
		err = v.treeV1()
	}
	if err == nil {
		treeRoleVisitResultV1(v, out)
	}
	return err
}

func treeRoleVisitResultV1(v *treeRoleVisitV1, out *TreeRoleObservationV1) {
	if v.finding != 0 {
		treeRolePositiveV1(out, v.bound.role, v.bound.generation, v.position, v.finding)
		return
	}
	treeRoleStagePublicV1(out, v.bound, &treeRoleFiniteV1{bound: v.bound, counters: v.counters})
}

func treeRoleIdentityV1(v *treeRoleVisitV1, request *TreeRoleRequestV1) bool {
	b := &v.bound.binding
	if request.Endpoint != b.Endpoint {
		v.failV1(TreeRoleAtBindingV1, TreeRoleWrongIdentityV1)
		return false
	}
	if request.HeaderRoot != nil && *request.HeaderRoot != b.RootDigest {
		v.failV1(TreeRoleAtBindingV1, TreeRoleWrongIdentityV1)
		return false
	}
	return true
}

func (v *treeRoleVisitV1) countersV1(supplied *TreeRoleCountersV1) error {
	if supplied != nil {
		v.counters = *supplied
	} else if err := v.readCountersV1(); err != nil || v.finding != 0 {
		return err
	}
	if !treeRoleShapeOKV1(&v.bound.binding, &v.counters) {
		v.failV1(TreeRoleAtCardinalityV1, TreeRoleRelationFailedV1)
	}
	return nil
}

// malformedV1 records a decode or key failure as a Positive Malformed finding, never an error.
func (v *treeRoleVisitV1) malformedV1(err error, position TreeRolePositionV1) bool {
	if err == nil {
		return false
	}
	v.failV1(position, TreeRoleMalformedV1)
	return true
}

func (v *treeRoleVisitV1) readCountersV1() error {
	key := treeRoleMetaKeyV1(0x10, v.bound.generation)
	image, err := v.reader.treeRolePointV1(0, key[:], 16)
	if err != nil {
		return err
	}
	if !image.present {
		v.failV1(TreeRoleAtCounterV1, TreeRoleAbsentV1)
		return nil
	}
	s, n, err := DecodeLogicalCounterValue(image.value)
	if v.malformedV1(err, TreeRoleAtCounterV1) {
		return nil
	}
	v.counters = TreeRoleCountersV1{LogicalStateBytes: s, UTXOCount: n}
	return nil
}

// treeRoleShapeOKV1 is the pre-read stage: N and S against the top kind and,
// at N=0, the binding root against the defined empty digest.
func treeRoleShapeOKV1(b *RootBindingV1, c *TreeRoleCountersV1) bool {
	switch c.UTXOCount {
	case 0:
		return all(b.Top.Kind == TreeTopEmptyV1, c.LogicalStateBytes == 0, b.RootDigest == treeEmptyDigestV1())
	case 1:
		return b.Top.Kind == TreeTopLeafV1
	}
	return b.Top.Kind == TreeTopBranchV1
}

func (v *treeRoleVisitV1) treeV1() error {
	if v.counters.UTXOCount == 0 {
		return nil
	}
	top := v.bound.binding.Top.Node
	if err := v.nodeV1(top, &v.top, &v.bound.binding.RootDigest, TreeRoleAtTopV1); err != nil || v.finding != 0 {
		return err
	}
	if v.counters.UTXOCount == 1 {
		return v.singletonV1(top)
	}
	return v.branchV1()
}

func (v *treeRoleVisitV1) singletonV1(top *TreeNodeIDV1) error {
	if err := v.pointV1(top, &v.top.LeafDigest, 0, TreeRoleAtZeroPointV1); err != nil || v.finding != 0 {
		return err
	}
	if v.counters.LogicalStateBytes != v.entries[0] {
		v.failV1(TreeRoleAtCardinalityV1, TreeRoleRelationFailedV1)
	}
	return nil
}

func (v *treeRoleVisitV1) childrenV1() error {
	if err := v.nodeV1(&v.top.Zero.ID, &v.children[0], &v.top.Zero.Digest, TreeRoleAtZeroChildV1); err != nil || v.finding != 0 {
		return err
	}
	return v.nodeV1(&v.top.One.ID, &v.children[1], &v.top.One.Digest, TreeRoleAtOneChildV1)
}

func (v *treeRoleVisitV1) branchV1() error {
	if err := v.childrenV1(); err != nil || v.finding != 0 {
		return err
	}
	if err := v.childPointV1(0, TreeRoleAtZeroPointV1); err != nil || v.finding != 0 {
		return err
	}
	if err := v.childPointV1(1, TreeRoleAtOnePointV1); err != nil || v.finding != 0 {
		return err
	}
	if !treeRoleBranchCardinalityV1(v) {
		v.failV1(TreeRoleAtCardinalityV1, TreeRoleRelationFailedV1)
	}
	return nil
}

func (v *treeRoleVisitV1) childPointV1(side int, position TreeRolePositionV1) error {
	child := v.top.Zero
	if side == 1 {
		child = v.top.One
	}
	if child.ID.Kind != TreeNodeLeafV1 {
		return nil
	}
	return v.pointV1(&child.ID, &v.children[side].LeafDigest, side, position)
}

func treeRoleBranchCardinalityV1(v *treeRoleVisitV1) bool {
	n, leaves := v.counters.UTXOCount, 0
	for _, child := range [2]*TreeChildV1{v.top.Zero, v.top.One} {
		if child.ID.Kind == TreeNodeLeafV1 {
			leaves++
		}
	}
	switch leaves {
	case 2:
		return n == 2 && v.counters.LogicalStateBytes == v.entries[0]+v.entries[1]
	case 1:
		return n >= 3
	}
	return n >= 4
}

func (v *treeRoleVisitV1) nodeV1(id *TreeNodeIDV1, node *TreeNodeV1, want *[32]byte, position TreeRolePositionV1) error {
	key, err := TreeNodeKey(v.bound.generation, *id)
	if v.malformedV1(err, position) {
		return nil
	}
	image, err := v.reader.treeRolePointV1(8, key, 140)
	if err != nil {
		return err
	}
	if !image.present {
		v.failV1(position, TreeRoleAbsentV1)
		return nil
	}
	if *node, err = DecodeTreeNodeValue(*id, image.value); v.malformedV1(err, position) {
		return nil
	}
	if treeRoleNodeDigestV1(id, node) != *want {
		v.failV1(position, TreeRoleRelationFailedV1)
	}
	return nil
}

func treeRoleNodeDigestV1(id *TreeNodeIDV1, node *TreeNodeV1) [32]byte {
	if id.Kind == TreeNodeLeafV1 {
		return node.LeafDigest
	}
	return treeBranchDigestV1(*id, node.Zero.Digest, node.One.Digest)
}

func (v *treeRoleVisitV1) pointV1(leaf *TreeNodeIDV1, want *[32]byte, side int, position TreeRolePositionV1) error {
	var txid [32]byte
	copy(txid[:], leaf.RoutingKey[:32])
	key, err := UTXOKey(v.bound.generation, txid, binary.BigEndian.Uint32(leaf.RoutingKey[32:]))
	if v.malformedV1(err, position) {
		return nil
	}
	image, err := v.reader.treeRolePointV1(1, key, 65560)
	if err != nil {
		return err
	}
	if !image.present {
		v.failV1(position, TreeRoleAbsentV1)
		return nil
	}
	if _, err = decodeUTXOValue(image.value); v.malformedV1(err, position) {
		return nil
	}
	if treeLeafDigestV1(leaf.RoutingKey, image.value) != *want {
		v.failV1(position, TreeRoleRelationFailedV1)
		return nil
	}
	v.entries[side] = 36 + uint64(len(image.value))
	return nil
}

// QualifyTreePairAssuranceV1 is the early assurance stage of exactly one
// pair, before full role qualification. It accepts two authentic same-Reader
// Bound roles: current is Current or TargetCurrent and lag the matching Lag
// or TargetLag of the same pair projection; anything else (crossed pair,
// reversed roles, other Reader, zero, forged, altered, expired, PartialDomain
// or Qualified members) is EngineInvalidInput/codeEINVAL/get after the nil receiver (the same
// error), the treeContext error (unchanged) and a nil, zero or closed account (the same error), not recorded, with no read and
// no charge. Pair rule (F = FULL_HISTORY, C = CONDITIONAL_IMPORTED_BASE;
// Current roles require TreeOriginalCurrentV1, Lag roles TreeOriginalLagV1):
// F,F reads nothing; C,F and F,C check the conditional member's original role
// first (wrong: Defective with that member affected and TreePairWrongRoleV1,
// no read) and then read its evidence once; C,C checks each member's
// original role (wrong: Defective Both WrongRole) before comparing original
// database, current, lag and EvidenceID (different: Defective Both
// ProvenanceConflict), each with no read, and otherwise reads the shared
// evidence once. An evidence read reserves 2099268 temporary bytes (a
// refusal is returned unchanged, zero reads), reads key 0x12 then
// EvidenceID, and maps absence to TreePairEvidenceAbsentV1 and a decode,
// SHA3-256 or original-origin failure to TreePairEvidenceUnresolvedV1, with
// the affected role(s) of its row; the evidence Payload is dropped and never
// returned. A Defective result records nothing and leaves the Reader usable;
// a native read failure is returned unchanged, recorded once, with a zero
// result; the 2099268 bytes are released before return. A resolved row returns
// AssuranceOnly; Bound and AssuranceOnly are incomplete and never HealthyOn, and the
// result is usable only on this Reader while it stays usable. Outer evidence decode, hash
// or origin does not authenticate IMAGE progress. It reads no index, header, counter or
// node. The first Defective check or evidence finding ends the call. The by-value arguments and the result are caller copies
// charged on the caller-held per-pair retention frame; this method makes no reservation for them and retains no borrowed reference.
func (r *Reader) QualifyTreePairAssuranceV1(account *OperationAccount, current, lag TreeRoleObservationV1) (TreePairQualificationV1, error) {
	if err := r.treeRoleAdmitV1(account); err != nil {
		return TreePairQualificationV1{}, err
	}
	if !r.treePairMembersV1(&current, &lag, TreeRoleBoundV1) {
		return TreePairQualificationV1{}, treeRoleInvalidV1()
	}
	stage := &treePairStageV1{reader: r, current: current.bound, lag: lag.bound}
	reference, affected := treePairRuleV1(stage)
	if stage.status == 0 && reference != nil {
		err := account.WithReservation(treeRoleEvidenceChargeV1, func() error {
			return r.treePairEvidenceV1(stage, reference, affected)
		})
		if err != nil {
			return TreePairQualificationV1{}, err
		}
	}
	if stage.status == 0 {
		stage.status = TreePairAssuranceOnlyV1
	}
	var out TreePairQualificationV1
	treePairPublicV1(&out, stage)
	return out, nil
}

func (r *Reader) treePairMembersV1(current, lag *TreeRoleObservationV1, status TreeRoleStatusV1) bool {
	if !r.treeRoleAuthenticV1(current, status) || !r.treeRoleAuthenticV1(lag, status) {
		return false
	}
	c, l := current.bound, lag.bound
	ordered := anyTrue(all(c.role == TreeRoleCurrentV1, l.role == TreeRoleLagV1), all(c.role == TreeRoleTargetCurrentV1, l.role == TreeRoleTargetLagV1))
	return ordered && c.pair == l.pair
}

func treePairExpectedRoleV1(role TreeRoleSelectorV1) TreeOriginalRoleV1 {
	if role == TreeRoleCurrentV1 || role == TreeRoleTargetCurrentV1 {
		return TreeOriginalCurrentV1
	}
	return TreeOriginalLagV1
}

// treePairConditionalV1 returns the import reference of a conditional member and
// whether its original role is right, or nil for FULL_HISTORY.
func treePairConditionalV1(b *treeRoleBoundV1) (*TreeImportReferenceV1, bool) {
	if b.binding.Assurance.Kind != TreeAssuranceImportedBaseV1 {
		return nil, true
	}
	return b.binding.Assurance.Import, b.binding.Assurance.Import.OriginalRole == treePairExpectedRoleV1(b.role)
}

func treePairDefectiveV1(stage *treePairStageV1, affected TreePairAffectedV1, defect TreePairDefectV1) {
	stage.status, stage.affected, stage.defect = TreePairDefectiveV1, affected, defect
}

func treePairRuleV1(stage *treePairStageV1) (*TreeImportReferenceV1, TreePairAffectedV1) {
	c, cOK := treePairConditionalV1(stage.current)
	l, lOK := treePairConditionalV1(stage.lag)
	switch {
	case c != nil && l != nil:
		return treePairBothV1(stage, c, l, cOK && lOK)
	case c != nil:
		return treePairSingleV1(stage, c, cOK, TreePairAffectedCurrentV1)
	case l != nil:
		return treePairSingleV1(stage, l, lOK, TreePairAffectedLagV1)
	}
	return nil, TreePairAffectedNoneV1
}

func treePairSingleV1(stage *treePairStageV1, ref *TreeImportReferenceV1, roleOK bool, affected TreePairAffectedV1) (*TreeImportReferenceV1, TreePairAffectedV1) {
	if !roleOK {
		treePairDefectiveV1(stage, affected, TreePairWrongRoleV1)
		return nil, affected
	}
	return ref, affected
}

func treePairBothV1(stage *treePairStageV1, c, l *TreeImportReferenceV1, rolesOK bool) (*TreeImportReferenceV1, TreePairAffectedV1) {
	if !rolesOK {
		treePairDefectiveV1(stage, TreePairAffectedBothV1, TreePairWrongRoleV1)
		return nil, TreePairAffectedBothV1
	}
	same := all(c.OriginalDatabaseID == l.OriginalDatabaseID, c.OriginalCurrentID == l.OriginalCurrentID,
		c.OriginalLagID == l.OriginalLagID, c.EvidenceID == l.EvidenceID)
	if !same {
		treePairDefectiveV1(stage, TreePairAffectedBothV1, TreePairProvenanceConflictV1)
		return nil, TreePairAffectedBothV1
	}
	return c, TreePairAffectedBothV1
}

func (r *Reader) treePairEvidenceV1(stage *treePairStageV1, reference *TreeImportReferenceV1, affected TreePairAffectedV1) error {
	var key [33]byte
	key[0] = 0x12
	copy(key[1:], reference.EvidenceID[:])
	image, err := r.treeRolePointV1(0, key[:], 1048576)
	if err != nil {
		return err
	}
	if !image.present {
		treePairDefectiveV1(stage, affected, TreePairEvidenceAbsentV1)
		return nil
	}
	if _, err = treeResolvedEvidence(image.value, *reference); err != nil {
		treePairDefectiveV1(stage, affected, TreePairEvidenceUnresolvedV1)
	}
	return nil
}

func treePairPublicV1(out *TreePairQualificationV1, stage *treePairStageV1) {
	*out = TreePairQualificationV1{Status: stage.status, Affected: stage.affected, Defect: stage.defect, stage: stage}
	treeRoleStagePublicV1(&out.Current, stage.current, stage.currentQ)
	treeRoleStagePublicV1(&out.Lag, stage.lag, stage.lagQ)
}

func treeRoleStagePublicV1(out *TreeRoleObservationV1, bound *treeRoleBoundV1, finite *treeRoleFiniteV1) {
	treeRoleBoundPublicV1(out, bound)
	if finite != nil {
		out.Status, out.Counters, out.finite = TreeRoleQualifiedV1, finite.counters, finite
	}
}

func (r *Reader) treePairAuthenticV1(q *TreePairQualificationV1, status TreePairStatusV1) bool {
	s := q.stage
	if s == nil || s.reader != r || s.status != status {
		return false
	}
	if !all(q.Status == s.status, q.Affected == s.affected, q.Defect == s.defect) {
		return false
	}
	if !treeRoleStageMatchV1(r, &q.Current, s.current, s.currentQ) {
		return false
	}
	return treeRoleStageMatchV1(r, &q.Lag, s.lag, s.lagQ)
}

func treeRoleStageMatchV1(r *Reader, o *TreeRoleObservationV1, bound *treeRoleBoundV1, finite *treeRoleFiniteV1) bool {
	if finite == nil {
		return o.bound == bound && r.treeRoleAuthenticV1(o, TreeRoleBoundV1)
	}
	return o.bound == bound && o.finite == finite && r.treeRoleAuthenticV1(o, TreeRoleQualifiedV1)
}

// CompleteTreePairQualificationV1 is the final zero-I/O join. Admission
// order: nil receiver (EngineInvalidInput/codeEINVAL/get); the existing treeContext error unchanged; then the
// inputs (no account step). Bound roles and the AssuranceOnly pair are
// incomplete. Only an authentic unaltered AssuranceOnly result of this Reader plus two authentic same-Reader Qualified roles whose private
// Bound identities are exactly its ordered current and lag yield Qualified;
// a zero, forged, mutated, expired, cross-Reader, crossed-pair,
// reversed-role, incomplete, Defective or mismatched-stage input is
// EngineInvalidInput/codeEINVAL/get, not recorded, before any effect. It
// performs no read and no reservation and does not authenticate source
// progress or publish permission; the caller's applicable worklist checks
// remain its own. The result is usable only on this Reader while it stays
// usable. The by-value arguments and the result are caller copies charged on the caller-held
// per-pair retention frame; this method makes no reservation for them and retains no borrowed reference.
func (r *Reader) CompleteTreePairQualificationV1(assurance TreePairQualificationV1, current, lag TreeRoleObservationV1) (TreePairQualificationV1, error) {
	if r == nil {
		return TreePairQualificationV1{}, treeRoleInvalidV1()
	}
	if err := r.treeContext(); err != nil {
		return TreePairQualificationV1{}, err
	}
	if !r.treePairCompletableV1(&assurance, &current, &lag) {
		return TreePairQualificationV1{}, treeRoleInvalidV1()
	}
	s := assurance.stage
	stage := &treePairStageV1{reader: r, status: TreePairQualifiedV1, current: s.current, lag: s.lag, currentQ: current.finite, lagQ: lag.finite}
	var out TreePairQualificationV1
	treePairPublicV1(&out, stage)
	return out, nil
}

func (r *Reader) treePairCompletableV1(assurance *TreePairQualificationV1, current, lag *TreeRoleObservationV1) bool {
	if !r.treePairAuthenticV1(assurance, TreePairAssuranceOnlyV1) || !r.treePairMembersV1(current, lag, TreeRoleQualifiedV1) {
		return false
	}
	return current.bound == assurance.stage.current && lag.bound == assurance.stage.lag
}

// HealthyOn performs no I/O and reports true exactly for an authentic final
// Qualified pair whose exported fields still match its private canonical
// snapshot, whose two full observations and early pair identity agree, and
// whose owner is r, non-nil and still usable. It is false for AssuranceOnly,
// Defective, Bound-derived or incomplete (Bound and AssuranceOnly are
// incomplete), zero, forged, altered, expired and other-Reader values; a public-field edit cannot create or repair a proof.
// The value receiver is a caller copy charged on the caller-held per-pair
// retention frame; this method makes no reservation for it and retains no borrowed reference.
func (q TreePairQualificationV1) HealthyOn(r *Reader) bool {
	if r == nil || r.treeContext() != nil {
		return false
	}
	return r.treePairAuthenticV1(&q, TreePairQualifiedV1) && q.stage.current.pair == q.stage.lag.pair
}
