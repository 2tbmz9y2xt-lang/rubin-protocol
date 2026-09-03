package node

// Seam: the dormant paired canonical D1/O1 candidate builder — its intrinsic
// snapshot validation, its phase-ordered terminals, its exact removals and
// survivors, its claim bijection, and its dormancy.

import (
	"crypto/sha3"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// canonicalDAOwnerFixture retains two owner-ready records through the REAL DA
// admission path — a State A record of two chunks and a State B record of a
// commit and one chunk — and captures the caller-owned pair of snapshots the
// builder consumes. Every provenance kind the owner-ready domain admits is
// represented, so the per-peer accounting key and the two keyless kinds are all
// exercised by the positive baseline.
type canonicalDAOwnerFixture struct {
	t        *testing.T
	f        *daNonReplayFixture
	owner    *PendingOutpointOwner
	retained *DARelayState
	pending  pendingOutpointSnapshot
	chain    canonicalFinalChainContext
	included []canonicalDASetIdentity
	stateA   [32]byte
	stateB   [32]byte
	txs      map[string]daNonReplayTx
	roster   []string
	keys     map[string]string
	standard PendingOutpointToken
}

// canonicalDAOwnerInputs is the complete deep image of both builder inputs, so
// "the inputs never move" is compared over every observable rather than sampled.
type canonicalDAOwnerInputs struct {
	relay   daRelayStateView
	pending pendingOutpointSnapshot
	owner   *PendingOutpointOwner
}

func newCanonicalDAOwnerFixture(t *testing.T) *canonicalDAOwnerFixture {
	t.Helper()
	x := canonicalDAOwnerFixtureOver(t, newDANonReplayFixture(t, 10))
	x.admit("a0", daNonReplayTxSpec{kind: 0x02, daID: x.stateA, chunkIndex: 0, payload: []byte("state-a chunk zero")}, daNonReplayPeer("peer-a"))
	x.admit("a1", daNonReplayTxSpec{kind: 0x02, daID: x.stateA, chunkIndex: 1, payload: []byte("state-a chunk one")}, LocalDAProvenance())
	x.admit("commit", daNonReplayTxSpec{kind: 0x01, daID: x.stateB, chunkCount: 2, commitment: sha3.Sum256([]byte("state-b payload")), commitmentOutputs: 1}, daNonReplayPeer("peer-b"))
	x.admit("b0", daNonReplayTxSpec{kind: 0x02, daID: x.stateB, chunkIndex: 0, payload: []byte("state-b chunk zero"), inputCount: 2}, DetachedReorgDAProvenance())
	// One unadmitted chunk, so a REAL complete-set identity for the State B
	// record can be rendered from a block without changing what is retained.
	x.txs["b1"] = x.f.signed(daNonReplayTxSpec{kind: 0x02, daID: x.stateB, chunkIndex: 1, payload: []byte("state-b chunk one")})
	x.standard = x.reserveStandardClaim()
	x.capture()
	x.requireFixturePremises()
	return x
}

func canonicalDAOwnerFixtureOver(t *testing.T, f *daNonReplayFixture) *canonicalDAOwnerFixture {
	return &canonicalDAOwnerFixture{
		t: t, f: f, owner: f.mp.pendingOutpoints,
		stateA: daRelayTestID(0x11), stateB: daRelayTestID(0x22),
		txs: map[string]daNonReplayTx{}, keys: map[string]string{},
	}
}

// newCanonicalDAOwnerPeerCapFixture retains two State B records — a commit and
// one chunk each — under ONE peer quota key after lowering the relay's per-peer
// cap below any member's charge. The REAL admission accepts them because it
// enforces that cap for State A only, so the captured snapshot is consistent
// with its peer counter above the cap.
func newCanonicalDAOwnerPeerCapFixture(t *testing.T) *canonicalDAOwnerFixture {
	t.Helper()
	f := newDANonReplayFixture(t, 10)
	f.relay.caps.orphanPoolPerPeerBytes = 1
	x := canonicalDAOwnerFixtureOver(t, f)
	for _, record := range []struct {
		daID          [32]byte
		commit, chunk string
	}{{x.stateA, "commitA", "a0"}, {x.stateB, "commit", "b0"}} {
		x.admit(record.commit, daNonReplayTxSpec{kind: 0x01, daID: record.daID, chunkCount: 2, commitment: sha3.Sum256([]byte(record.commit)), commitmentOutputs: 1}, daNonReplayPeer("peer-x"))
		x.admit(record.chunk, daNonReplayTxSpec{kind: 0x02, daID: record.daID, chunkIndex: 0, payload: []byte(record.chunk)}, daNonReplayPeer("peer-x"))
	}
	x.capture()
	if peer, capBytes := x.retained.orphanBytesByPeerQuotaKey["peer-x"], x.retained.caps.orphanPoolPerPeerBytes; peer <= capBytes {
		t.Fatalf("per-peer bytes %d do not exceed the cap %d", peer, capBytes)
	}
	return x
}

// admit retains one member through the real admission and records its name,
// quota key and roster position for the exact-image oracle.
func (x *canonicalDAOwnerFixture) admit(name string, spec daNonReplayTxSpec, provenance daProvenance) {
	x.t.Helper()
	tx := x.f.signed(spec)
	x.f.admit(tx, provenance)
	x.txs[name], x.keys[name] = tx, provenance.quotaKey()
	x.roster = append(x.roster, name)
}

// reserveStandardClaim installs one finalized STANDARD claim the builder must
// never bind, reorder or drop.
func (x *canonicalDAOwnerFixture) reserveStandardClaim() PendingOutpointToken {
	x.t.Helper()
	txid := daRelayTestID(0x99)
	token := mustReserve(x.t, x.owner, txid, consensus.Outpoint{Txid: txid, Vout: 7})
	if err := x.owner.Finalize(token); err != nil {
		x.t.Fatalf("Finalize(standard): %v", err)
	}
	return token
}

// capture takes the caller-owned snapshot pair exactly as RUB-678 will: the
// retained image under the relay lock, then every record deep-copied so the
// snapshot shares no mutable state with the live relay at all, and the owner
// image under the owner lock.
func (x *canonicalDAOwnerFixture) capture() {
	x.f.relay.mu.Lock()
	snapshot := x.f.relay.cloneForAtomicBatchLocked()
	x.f.relay.mu.Unlock()
	for daID, record := range snapshot.sets {
		snapshot.sets[daID] = record.cloneOwnerReady()
	}
	// Reservations no phase reads, so a released set and a preserved one are
	// both observable in D1.
	snapshot.prefetch = daRelayPrefetchState{
		indexes: map[[32]byte]map[uint16]string{x.stateA: {5: "peer-a"}, x.stateB: {7: "peer-b"}},
		expires: map[[32]byte]time.Time{x.stateA: time.Unix(1, 0), x.stateB: time.Unix(2, 0)},
	}
	x.retained, x.pending, x.chain = snapshot, x.owner.snapshot(), canonicalDATestChainFromState(x.t, x.f.state)
}

// emptyRetained leaves the retained snapshot with no record at all — fresh
// empty containers, zero recomputable counters, no reservation — and both
// high-waters untouched.
func (x *canonicalDAOwnerFixture) emptyRetained() {
	x.retained.sets, x.retained.locators = map[[32]byte]daRelaySetRecord{}, map[[32]byte]daRelayLocator{}
	x.retained.orphanBytesByDAID, x.retained.orphanBytesByPeerQuotaKey = map[[32]byte]uint64{}, map[string]uint64{}
	x.retained.orphanBytes, x.retained.orphanCommitOverheadBytes, x.retained.prefetch = 0, 0, daRelayPrefetchState{}
}

// requireFixturePremises fails the FIXTURE rather than a row when the real
// admission path stops producing the image these rows corrupt one field of: a
// zero aggregate or a missing claim would let a corruption row pass on a builder
// that never reads that field.
func (x *canonicalDAOwnerFixture) requireFixturePremises() {
	x.t.Helper()
	if len(x.retained.sets) != 2 || x.retained.sets[x.stateA].state != daRelayStateOrphanChunks || x.retained.sets[x.stateB].state != daRelayStateStagedCommit {
		x.t.Fatalf("fixture states=%v", x.retained.sets)
	}
	for _, record := range x.retained.sets {
		if record.revision == 0 || record.receivedTime == 0 || record.ttlBlocksRemaining == 0 {
			x.t.Fatalf("admitted record %x carries revision=%d receivedTime=%d ttl=%d", record.daID, record.revision, record.receivedTime, record.ttlBlocksRemaining)
		}
	}
	if x.retained.orphanBytes == 0 || x.retained.orphanCommitOverheadBytes == 0 || x.retained.pinnedPayloadBytes != 0 {
		x.t.Fatalf("fixture aggregates orphan=%d commit=%d pinned=%d", x.retained.orphanBytes, x.retained.orphanCommitOverheadBytes, x.retained.pinnedPayloadBytes)
	}
	if len(x.retained.orphanBytesByPeerQuotaKey) != 2 || len(x.retained.orphanBytesByDAID) != 2 || len(x.retained.locators) != 4 {
		x.t.Fatalf("fixture peers=%v da_ids=%v locators=%d", x.retained.orphanBytesByPeerQuotaKey, x.retained.orphanBytesByDAID, len(x.retained.locators))
	}
	standard := slices.IndexFunc(x.pending.claims, func(c pendingOutpointClaim) bool {
		return c.token == x.standard && c.domain == PendingOutpointStandardMempool
	})
	if da := canonicalDAOwnerDomainClaims(x.pending); da != 4 || standard < 0 || len(x.pending.claims) != da+1 {
		x.t.Fatalf("fixture claims=%d: %d DA, standard at %d; want 4 DA and 1 standard", len(x.pending.claims), da, standard)
	}
	for _, claim := range x.pending.claims {
		if claim.domain == PendingOutpointDA && !claim.finalized {
			x.t.Fatalf("admitted DA claim for %x is not finalized", claim.txid)
		}
	}
}

func (x *canonicalDAOwnerFixture) build() (preparedCanonicalDAOwnerCandidates, error) {
	return prepareCanonicalDAOwnerCandidates(x.retained, x.owner, x.pending, x.included, x.chain)
}

// inputs deep-copies both builder inputs. The two nil arms serve the rows that
// pass a missing input on purpose; every other row compares a complete image.
func (x *canonicalDAOwnerFixture) inputs() canonicalDAOwnerInputs {
	image := canonicalDAOwnerInputs{pending: clonePendingOutpointSnapshot(x.pending)}
	if x.retained != nil {
		image.relay = daRelayStateSnapshot(x.retained)
	}
	if x.owner != nil {
		image.owner = cloneDAAdmissionOwner(x.owner)
	}
	return image
}

func clonePendingOutpointSnapshot(pending pendingOutpointSnapshot) pendingOutpointSnapshot {
	out := pending
	out.claims = make([]pendingOutpointClaim, len(pending.claims))
	for i := range pending.claims {
		out.claims[i] = pending.claims[i]
		out.claims[i].inputs = slices.Clone(pending.claims[i].inputs)
	}
	return out
}

func (x *canonicalDAOwnerFixture) requireInputsUnchanged(before canonicalDAOwnerInputs) {
	x.t.Helper()
	if got := x.inputs(); !reflect.DeepEqual(got, before) { //nolint:govet // deepequalerrors: complete private-image equality is the assertion, error identities included
		x.t.Fatalf("a builder call moved its inputs:\ngot  %+v\nwant %+v", got, before)
	}
}

// requirePair runs the builder, requires both halves and proves neither input
// moved.
func (x *canonicalDAOwnerFixture) requirePair() preparedCanonicalDAOwnerCandidates {
	x.t.Helper()
	before := x.inputs()
	candidates, err := x.build()
	if err != nil {
		x.t.Fatalf("prepareCanonicalDAOwnerCandidates: %v", err)
	}
	if candidates.retained == nil || candidates.ownerIndex.byToken == nil || candidates.ownerIndex.byOutpoint == nil {
		x.t.Fatalf("candidates=%+v, want both halves", candidates)
	}
	x.requireInputsUnchanged(before)
	return candidates
}

// requirePlanAbort requires the shared plan-abort class unchanged, NEITHER half,
// and both inputs byte-identical.
func (x *canonicalDAOwnerFixture) requirePlanAbort() {
	x.t.Helper()
	before := x.inputs()
	candidates, err := x.build()
	var plan *canonicalMOPlanError
	if !errors.As(err, &plan) || isCanonicalTransitionTerminalError(err) {
		x.t.Fatalf("err=%v, want the shared plan-abort class", err)
	}
	if !reflect.DeepEqual(candidates, preparedCanonicalDAOwnerCandidates{}) { //nolint:govet // deepequalerrors: the zero value of the pair is the assertion
		x.t.Fatalf("candidates=%+v, want neither half", candidates)
	}
	x.requireInputsUnchanged(before)
}

// requireTerminal requires the retained-DA terminal class naming want, NEITHER
// half, and both inputs byte-identical.
func (x *canonicalDAOwnerFixture) requireTerminal(want string) error {
	x.t.Helper()
	before := x.inputs()
	candidates, err := x.build()
	var terminal *canonicalDATerminalError
	if !errors.As(err, &terminal) || !isCanonicalTransitionTerminalError(err) {
		x.t.Fatalf("err=%v, want the retained-DA terminal class", err)
	}
	if !strings.Contains(err.Error(), want) {
		x.t.Fatalf("terminal=%q, want it to name %q", err.Error(), want)
	}
	if !reflect.DeepEqual(candidates, preparedCanonicalDAOwnerCandidates{}) { //nolint:govet // deepequalerrors: the zero value of the pair is the assertion
		x.t.Fatalf("candidates=%+v, want neither half", candidates)
	}
	x.requireInputsUnchanged(before)
	return err
}

// requireStableTerminal repeats one build so a walk that depended on map
// iteration order would report another record's or another member's defect on
// some round instead of the same evidence on every round.
// Go's iteration over a two-key map is measurably biased (~86/14, not uniform), so a low round count only weakens this pin probabilistically; callers pass a round count high enough that the biased walk cannot pass by chance.
func (x *canonicalDAOwnerFixture) requireStableTerminal(want string, rounds int) error {
	x.t.Helper()
	first := x.requireTerminal(want)
	for round := 1; round < rounds; round++ {
		if again := x.requireTerminal(want); again.Error() != first.Error() {
			x.t.Fatalf("round %d reported %q, want %q on every round", round, again, first)
		}
	}
	return first
}

// corrupt replaces one snapshot record with a deep copy the row mutated, so a
// row changes exactly the field it names.
func (x *canonicalDAOwnerFixture) corrupt(daID [32]byte, mutate func(*daRelaySetRecord)) {
	record := x.retained.sets[daID].cloneOwnerReady()
	mutate(&record)
	x.retained.sets[daID] = record
}

// corruptChunk replaces one chunk of one snapshot record with a copy the row mutated.
func (x *canonicalDAOwnerFixture) corruptChunk(daID [32]byte, index uint16, mutate func(*daRelayChunk)) {
	x.corrupt(daID, func(record *daRelaySetRecord) { corruptDAChunk(record, index, mutate) })
}

func corruptDAChunk(record *daRelaySetRecord, index uint16, mutate func(*daRelayChunk)) {
	chunk := record.chunks[index]
	mutate(&chunk)
	record.chunks[index] = chunk
}

// corruptClaim replaces one owner-snapshot claim by token with a copy the row
// mutated; the snapshot slice itself is caller-owned.
func (x *canonicalDAOwnerFixture) corruptClaim(token PendingOutpointToken, mutate func(*pendingOutpointClaim)) {
	x.pending = clonePendingOutpointSnapshot(x.pending)
	for i := range x.pending.claims {
		if x.pending.claims[i].token == token {
			mutate(&x.pending.claims[i])
			return
		}
	}
	x.t.Fatalf("no claim for token seq %d", token.seq)
}

func (x *canonicalDAOwnerFixture) tokenOf(name string) PendingOutpointToken {
	x.t.Helper()
	for _, claim := range x.pending.claims {
		if claim.txid == x.txs[name].txid {
			return claim.token
		}
	}
	x.t.Fatalf("no claim for %s", name)
	return PendingOutpointToken{}
}

// identityOf renders one exact set identity from the fixture's OWN parsed
// transaction identities, never from the builder's derivation.
func (x *canonicalDAOwnerFixture) identityOf(daID [32]byte, commit string, chunks ...string) canonicalDASetIdentity {
	identity := canonicalDASetIdentity{daID: daID}
	if commit != "" {
		identity.commit = canonicalDATxIdentity{txid: x.txs[commit].txid, wtxid: x.txs[commit].wtxid}
	}
	for i, name := range chunks {
		identity.chunks = append(identity.chunks, canonicalDAChunkIdentity{
			canonicalDATxIdentity: canonicalDATxIdentity{txid: x.txs[name].txid, wtxid: x.txs[name].wtxid},
			index:                 uint16(i),
		})
	}
	return identity
}

// spendInput drops one member's input from the private final-chain view, which
// is how a member becomes final-chain INVALID without any error.
func (x *canonicalDAOwnerFixture) spendInput(name string) {
	x.chain.final.mu.Lock()
	defer x.chain.final.mu.Unlock()
	for _, input := range x.txs[name].inputs {
		delete(x.chain.final.Utxos, input)
	}
}

// memberCharge is the owner-ready charge one member contributes, derived from
// the fixture's own bytes rather than from the accounting under test.
func (x *canonicalDAOwnerFixture) memberCharge(name string) uint64 {
	tx := x.txs[name]
	return uint64(len(tx.raw) + len(tx.spec.payload))
}

// admitLocktimeChunk retains one more record whose only member is locked beyond
// the final chain's next height. That member is refused by the chain-POLICY half
// of final_chain_valid rather than by its consensus half, and admission itself
// does not gate locktime, so this is the one input that reaches the second half.
func (x *canonicalDAOwnerFixture) admitLocktimeChunk(daID [32]byte, locktime uint32) {
	x.t.Helper()
	outpoint := x.f.outpoints[x.f.next]
	x.f.next++
	payload := []byte("locktime chunk")
	tx := &consensus.Tx{
		Version: 1, TxKind: 0x02, TxNonce: 7373, Locktime: locktime,
		Inputs:      []consensus.TxInput{{PrevTxid: outpoint.Txid, PrevVout: outpoint.Vout, Sequence: 77}},
		Outputs:     []consensus.TxOutput{{Value: 1_400_000, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: slices.Clone(x.f.address)}},
		DaPayload:   payload,
		DaChunkCore: &consensus.DaChunkCore{DaID: daID, ChunkIndex: 0, ChunkHash: sha3.Sum256(payload)},
	}
	if err := consensus.SignTransaction(tx, x.f.state.Utxos, devnetGenesisChainID, x.f.signer); err != nil {
		x.t.Fatalf("SignTransaction(locktime chunk): %v", err)
	}
	raw := mustMarshalTxForNodeTest(x.t, tx)
	admission := mustDAAdmission(x.t, x.f.mp, raw)
	defer admission.Close()
	if _, err := x.f.relay.admitDANonReplay(admission, LocalDAProvenance()); err != nil {
		x.t.Fatalf("admitDANonReplay(locktime chunk): %v", err)
	}
	_, txid, wtxid, _, err := consensus.ParseTx(raw)
	if err != nil {
		x.t.Fatalf("ParseTx(locktime chunk): %v", err)
	}
	x.txs["locked"] = daNonReplayTx{spec: daNonReplayTxSpec{kind: 0x02, daID: daID, payload: payload}, raw: raw, txid: txid, wtxid: wtxid, inputs: []consensus.Outpoint{outpoint}}
	x.roster = append(x.roster, "locked")
}

// membersOf names one record's retained members from the fixture's roster.
func (x *canonicalDAOwnerFixture) membersOf(daID [32]byte) []string {
	var names []string
	for _, name := range x.roster {
		if x.txs[name].spec.daID == daID {
			names = append(names, name)
		}
	}
	return names
}

// requireExactImage proves the pair holds EXACTLY the survivors: D1 is the
// input image minus the removed records' OWN contributions — record, locator
// rows, per-da_id, per-peer, global and commit-overhead bytes and prefetch
// reservations — and nothing else moved, while O1 is the input claim list minus
// exactly those records' member claims with the index rebuilt from it. Every
// subtracted charge comes from the fixture's own bytes, never from the
// accounting under test.
func (x *canonicalDAOwnerFixture) requireExactImage(candidates preparedCanonicalDAOwnerCandidates, removed ...[32]byte) {
	x.t.Helper()
	want := daRelayStateSnapshot(x.retained)
	dropped := map[PendingOutpointToken]bool{}
	for _, daID := range removed {
		delete(want.sets, daID)
		delete(want.daIDBytes, daID)
		delete(want.prefetchIndexes, daID)
		delete(want.prefetchExpires, daID)
		for _, name := range x.membersOf(daID) {
			charge := x.memberCharge(name)
			want.orphanBytes -= charge
			delete(want.locators, x.txs[name].txid)
			dropped[x.tokenOf(name)] = true
			if x.txs[name].spec.kind == 0x01 {
				want.commitBytes -= charge
			}
			if key := x.keys[name]; key != "" {
				if want.peerBytes[key] -= charge; want.peerBytes[key] == 0 {
					delete(want.peerBytes, key)
				}
			}
		}
	}
	if got := daRelayStateSnapshot(candidates.retained); !reflect.DeepEqual(got, want) { //nolint:govet // deepequalerrors: complete image equality is the assertion
		x.t.Fatalf("D1=%+v,\nwant %+v", got, want)
	}
	x.requireExactOwnerHalf(candidates, dropped)
}

// requireExactOwnerHalf proves O1 keeps every surviving claim byte-identical and
// in its original order, standard claims included, and that the rebuilt index
// resolves exactly those claims and their outpoint rows.
func (x *canonicalDAOwnerFixture) requireExactOwnerHalf(candidates preparedCanonicalDAOwnerCandidates, dropped map[PendingOutpointToken]bool) {
	x.t.Helper()
	want := clonePendingOutpointSnapshot(x.pending)
	want.claims = slices.DeleteFunc(want.claims, func(claim pendingOutpointClaim) bool { return dropped[claim.token] })
	if !reflect.DeepEqual(candidates.pending, want) { //nolint:govet // deepequalerrors: claim-list equality and order are the assertion
		x.t.Fatalf("O1=%+v,\nwant %+v", candidates.pending, want)
	}
	rows := 0
	for _, claim := range want.claims {
		indexed := candidates.ownerIndex.byToken[claim.token]
		if indexed == nil || !reflect.DeepEqual(*indexed, claim) { //nolint:govet // deepequalerrors: the rebuilt index must describe the same claim
			x.t.Fatalf("the O1 index token %d=%+v, want %+v", claim.token.seq, indexed, claim)
		}
		for _, input := range claim.inputs {
			if candidates.ownerIndex.byOutpoint[input] != (pendingOutpointRow{token: claim.token, txid: claim.txid}) {
				x.t.Fatalf("the O1 outpoint row for %+v=%+v", input, candidates.ownerIndex.byOutpoint[input])
			}
			rows++
		}
	}
	type index struct {
		tokens, outpoints int
		highWater         uint64
		owner             *PendingOutpointOwner
	}
	got := index{len(candidates.ownerIndex.byToken), len(candidates.ownerIndex.byOutpoint), candidates.ownerIndex.tokenHighWater, candidates.ownerIndex.owner}
	if wantIndex := (index{len(want.claims), rows, want.tokenHighWater, x.owner}); got != wantIndex {
		x.t.Fatalf("O1 index=%+v, want %+v", got, wantIndex)
	}
}

// reinsert rebuilds the snapshot's keyed containers in the opposite insertion
// order, so a walk that depended on map order would change its result.
func (x *canonicalDAOwnerFixture) reinsert() {
	sets := make(map[[32]byte]daRelaySetRecord, len(x.retained.sets))
	daIDBytes := make(map[[32]byte]uint64, len(x.retained.orphanBytesByDAID))
	for _, daID := range [][32]byte{x.stateB, x.stateA} {
		sets[daID] = x.retained.sets[daID]
		daIDBytes[daID] = x.retained.orphanBytesByDAID[daID]
	}
	locators := make(map[[32]byte]daRelayLocator, len(x.retained.locators))
	for _, name := range []string{"b0", "commit", "a1", "a0"} {
		locators[x.txs[name].txid] = x.retained.locators[x.txs[name].txid]
	}
	x.retained.sets, x.retained.orphanBytesByDAID, x.retained.locators = sets, daIDBytes, locators
}

// TestCanonicalDAOwnerCandidatesValidateAndRemoveExactly is the accepted half:
// one pair is built from real owner-ready records of both states and every
// admitted provenance kind, and a record leaves D1 exactly when a member is not
// final_chain_valid or its EXACT set identity was canonically included — once,
// for either cause or both, and never for a near miss.
func TestCanonicalDAOwnerCandidatesValidateAndRemoveExactly(t *testing.T) {
	t.Run("M1-M4 both owner-ready states and every provenance kind pair unchanged", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		x.requireExactImage(x.requirePair())
	})

	for _, tc := range []struct {
		name     string
		included func(*canonicalDAOwnerFixture) []canonicalDASetIdentity
		removed  bool
	}{
		{"I1 a hand-built partial identity equal to the resident's removes it once", func(x *canonicalDAOwnerFixture) []canonicalDASetIdentity {
			return []canonicalDASetIdentity{x.identityOf(x.stateB, "commit", "b0")}
		}, true},
		{"I5 the same hand-built partial identity twice still removes once", func(x *canonicalDAOwnerFixture) []canonicalDASetIdentity {
			identity := x.identityOf(x.stateB, "commit", "b0")
			return []canonicalDASetIdentity{identity, identity}
		}, true},
		{"I2 a real complete-set identity does not match its incomplete resident", func(x *canonicalDAOwnerFixture) []canonicalDASetIdentity {
			return identitiesOf(x.t, x.txs["commit"].raw, x.txs["b0"].raw, x.txs["b1"].raw)
		}, false},
		{"I3 another chunk identity under the same da_id is a no-op", func(x *canonicalDAOwnerFixture) []canonicalDASetIdentity {
			return []canonicalDASetIdentity{x.identityOf(x.stateB, "commit", "b1")}
		}, false},
		{"I4 another wtxid under the same commit txid is a no-op", func(x *canonicalDAOwnerFixture) []canonicalDASetIdentity {
			identity := x.identityOf(x.stateB, "commit", "b0")
			identity.commit.wtxid[0] ^= 1
			return []canonicalDASetIdentity{identity}
		}, false},
		{"I6 no inclusion list removes nothing", func(*canonicalDAOwnerFixture) []canonicalDASetIdentity { return nil }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newCanonicalDAOwnerFixture(t)
			x.included = tc.included(x)
			var removed [][32]byte
			if tc.removed {
				removed = [][32]byte{x.stateB}
			}
			x.requireExactImage(x.requirePair(), removed...)
		})
	}

	t.Run("F2 one final-chain-invalid member removes its whole record and no other", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		x.spendInput("a0")
		x.requireExactImage(x.requirePair(), x.stateA)
	})

	t.Run("F1 a member locked beyond the final chain's next height is excluded", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		locked := daRelayTestID(0x33)
		x.admitLocktimeChunk(locked, 4242)
		x.capture()
		if _, retained := x.retained.sets[locked]; !retained {
			t.Fatal("the locktime record was not retained")
		}
		x.requireExactImage(x.requirePair(), locked)
	})

	t.Run("H3 final invalidity and a hand-built partial identity together still remove once", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		x.spendInput("commit")
		x.included = []canonicalDASetIdentity{x.identityOf(x.stateB, "commit", "b0")}
		x.requireExactImage(x.requirePair(), x.stateB)
	})

	t.Run("A1 an empty retained and DA-claim image pairs unchanged and independently owned", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		x.emptyRetained()
		x.pending = clonePendingOutpointSnapshot(x.pending)
		x.pending.claims = slices.DeleteFunc(x.pending.claims, func(c pendingOutpointClaim) bool { return c.domain == PendingOutpointDA })
		candidates := x.requirePair()
		x.requireExactImage(candidates)
		candidates.retained.sets[x.stateA], candidates.retained.locators[x.txs["a0"].txid] = daRelaySetRecord{}, daRelayLocator{}
		if len(x.retained.sets) != 0 || len(x.retained.locators) != 0 {
			t.Fatal("the D1 half shares a container with the emptied input")
		}
	})

	t.Run("Q0 map insertion order changes neither half", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		x.included = []canonicalDASetIdentity{x.identityOf(x.stateB, "commit", "b0")}
		first := x.requirePair()
		for round := 0; round < 3; round++ {
			x.reinsert()
			again := x.requirePair()
			if !reflect.DeepEqual(daRelayStateSnapshot(again.retained), daRelayStateSnapshot(first.retained)) { //nolint:govet // deepequalerrors: image identity across runs is the assertion
				t.Fatalf("round %d produced another D1 image", round)
			}
			if !reflect.DeepEqual(again.pending, first.pending) || !reflect.DeepEqual(again.ownerIndex.byOutpoint, first.ownerIndex.byOutpoint) { //nolint:govet // deepequalerrors: owner-half identity across runs is the assertion
				t.Fatalf("round %d produced another O1 image", round)
			}
		}
	})
}

// TestCanonicalDAOwnerCandidatesAreTerminalByPhase is the ordered-terminal half.
// Every row corrupts ONE field of the caller-owned snapshot, or of the supplied
// context, and requires the retained-DA terminal class naming that defect, no
// pair, and both inputs byte-identical. The precedence rows place the
// HIGHER-precedence defect in the LATER record, so a record-major walk would
// report the other one.
func TestCanonicalDAOwnerCandidatesAreTerminalByPhase(t *testing.T) {
	t.Run("S0a no retained snapshot", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		x.retained = nil
		x.requireTerminal("no retained DA snapshot")
	})
	t.Run("S0c a nil owner is refused before any record is read", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		x.owner = nil
		x.requireTerminal("no pending-outpoint owner")
	})
	t.Run("S0d an empty snapshot with a nil owner is terminal", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		x.emptyRetained()
		x.pending.claims, x.owner = nil, nil
		x.requireTerminal("no pending-outpoint owner")
	})
	t.Run("S0b a nil final chain is refused at entry, before any record is read", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		x.chain.final = nil
		if err := x.requireTerminal("no final-chain context"); strings.Contains(err.Error(), "retained DA") {
			t.Fatalf("terminal=%q names a record, want the entry refusal", err.Error())
		}
	})
	t.Run("S0e an empty snapshot with a nil final chain is terminal", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		x.emptyRetained()
		x.pending.claims, x.chain.final = nil, nil
		x.requireTerminal("no final-chain context")
	})
	t.Run("S14 the member walk itself refuses a memberless chunk slot instead of dereferencing it", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		record := x.retained.sets[x.stateA].cloneOwnerReady()
		corruptDAChunk(&record, 1, func(c *daRelayChunk) { c.member = nil })
		_, err := canonicalDARetainedMemberIdentities(record)
		var terminal *canonicalDATerminalError
		if !errors.As(err, &terminal) || !strings.Contains(err.Error(), fmt.Sprintf("retained DA chunk 1 for %x has no stored member", x.stateA)) {
			t.Fatalf("err=%v, want the terminal memberless-slot refusal", err)
		}
	})
	t.Run("S8b the D1 closure itself refuses a record stored under another da_id", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		record := x.retained.sets[x.stateA]
		delete(x.retained.sets, x.stateA)
		x.retained.sets[daRelayTestID(0x05)] = record
		err := canonicalDARetainedImageClosed(x.retained, x.retained.sortedRetainedDAIDsLocked())
		var terminal *canonicalDATerminalError
		if !errors.As(err, &terminal) || !strings.Contains(err.Error(), "carries da_id") {
			t.Fatalf("err=%v, want the terminal da_id disagreement", err)
		}
	})

	for _, tc := range []struct {
		name    string
		want    string
		corrupt func(*canonicalDAOwnerFixture)
	}{
		{"S1 a COMPLETE_SET record is outside the owner-ready domain", "is not owner-ready", func(x *canonicalDAOwnerFixture) {
			x.corrupt(x.stateA, func(r *daRelaySetRecord) { r.state = daRelayStateCompleteSet })
		}},
		{"S2 an undefined record state", "is not owner-ready", func(x *canonicalDAOwnerFixture) {
			x.corrupt(x.stateA, func(r *daRelaySetRecord) { r.state = daRelaySetState(7) })
		}},
		{"S3 a zero ttl", "is not owner-ready", func(x *canonicalDAOwnerFixture) {
			x.corrupt(x.stateA, func(r *daRelaySetRecord) { r.ttlBlocksRemaining = 0 })
		}},
		{"S4 a zero revision", "is not owner-ready", func(x *canonicalDAOwnerFixture) { x.corrupt(x.stateA, func(r *daRelaySetRecord) { r.revision = 0 }) }},
		{"S5 a zero received time", "is not owner-ready", func(x *canonicalDAOwnerFixture) {
			x.corrupt(x.stateA, func(r *daRelaySetRecord) { r.receivedTime = 0 })
		}},
		{"S6 legacy record wire bytes", "is not owner-ready", func(x *canonicalDAOwnerFixture) { x.corrupt(x.stateA, func(r *daRelaySetRecord) { r.wireBytes = 1 }) }},
		{"S7 a latched chunk hash", "is not owner-ready", func(x *canonicalDAOwnerFixture) {
			x.corruptChunk(x.stateA, 0, func(c *daRelayChunk) { c.hashChecked = true })
		}},
		{"S8 a record stored under another da_id", "is not owner-ready", func(x *canonicalDAOwnerFixture) {
			record := x.retained.sets[x.stateA]
			delete(x.retained.sets, x.stateA)
			x.retained.sets[daRelayTestID(0x05)] = record
		}},
		{"S13 a record retaining no member at all", "retains no member", func(x *canonicalDAOwnerFixture) {
			x.corrupt(x.stateA, func(r *daRelaySetRecord) { r.chunks = map[uint16]daRelayChunk{} })
		}},
		{"S9 a State B record with no commit member", "is not owner-ready", func(x *canonicalDAOwnerFixture) {
			x.corrupt(x.stateB, func(r *daRelaySetRecord) { r.commit.member = nil })
		}},
		{"S10a a zero declared chunk count", "is not owner-ready", func(x *canonicalDAOwnerFixture) {
			x.corrupt(x.stateB, func(r *daRelaySetRecord) { r.commit.chunkCount = 0 })
		}},
		{"S10b a declared chunk count above the maximum", "is not owner-ready", func(x *canonicalDAOwnerFixture) {
			x.corrupt(x.stateB, func(r *daRelaySetRecord) { r.commit.chunkCount = uint16(consensus.MAX_DA_CHUNK_COUNT) + 1 })
		}},
		{"S11 a chunk at the declared count", "is not owner-ready", func(x *canonicalDAOwnerFixture) {
			x.corrupt(x.stateB, func(r *daRelaySetRecord) {
				chunk := r.chunks[0]
				delete(r.chunks, 0)
				chunk.chunkIndex = 2
				r.chunks[2] = chunk
			})
		}},
		{"S12a a zero token sequence", "is not owner-ready", func(x *canonicalDAOwnerFixture) {
			x.corruptChunk(x.stateA, 0, func(c *daRelayChunk) { c.member.token.seq = 0 })
		}},
		{"S12b a foreign owner token", "is not owner-ready", func(x *canonicalDAOwnerFixture) {
			foreign := newPendingOutpointOwner(PendingOutpointTip{})
			x.corruptChunk(x.stateA, 0, func(c *daRelayChunk) { c.member.token.owner = foreign })
		}},
		{"P1 no retained bytes is refused before the parse", "is not owner-ready", func(x *canonicalDAOwnerFixture) {
			x.corrupt(x.stateB, func(r *daRelaySetRecord) { r.commit.txBytes = nil })
		}},
		{"P8a an empty stored input set is refused before the parse", "is not owner-ready", func(x *canonicalDAOwnerFixture) {
			x.corruptChunk(x.stateA, 0, func(c *daRelayChunk) { c.member.inputs = nil })
		}},
		{"P9 zero provenance is refused before the parse", "is not owner-ready", func(x *canonicalDAOwnerFixture) {
			x.corruptChunk(x.stateA, 0, func(c *daRelayChunk) { c.member.provenance = DAProvenance{} })
		}},
		{"P2a trailing bytes after the canonical transaction", "has trailing bytes", func(x *canonicalDAOwnerFixture) {
			x.corrupt(x.stateB, func(r *daRelaySetRecord) { r.commit.txBytes = append(r.commit.txBytes, 0x00) })
		}},
		{"P2b retained bytes that do not parse", "does not canonically parse", func(x *canonicalDAOwnerFixture) {
			x.corrupt(x.stateB, func(r *daRelaySetRecord) { r.commit.txBytes = []byte{0xff, 0xfe} })
		}},
		{"P3 a chunk transaction in the commit slot", "is tx_kind 0x02", func(x *canonicalDAOwnerFixture) {
			x.corrupt(x.stateB, func(r *daRelaySetRecord) { r.commit.txBytes = slices.Clone(x.txs["b0"].raw) })
		}},
		{"P4 a chunk carrying another da_id", "carries da_id", func(x *canonicalDAOwnerFixture) {
			x.corruptChunk(x.stateB, 0, func(c *daRelayChunk) { c.txBytes = slices.Clone(x.txs["a0"].raw) })
		}},
		{"P5 a chunk stored at another index", "is stored at index 0 and declares 1", func(x *canonicalDAOwnerFixture) {
			x.corruptChunk(x.stateA, 0, func(c *daRelayChunk) { c.txBytes = slices.Clone(x.txs["a1"].raw) })
		}},
		{"P6 a stored txid the retained bytes do not derive", "contradicts its parsed identity", func(x *canonicalDAOwnerFixture) {
			x.corruptChunk(x.stateA, 0, func(c *daRelayChunk) { c.member.txid[0] ^= 1 })
		}},
		{"P7 a stored wtxid the retained bytes do not derive", "contradicts its parsed identity", func(x *canonicalDAOwnerFixture) {
			x.corruptChunk(x.stateA, 0, func(c *daRelayChunk) { c.member.wtxid[0] ^= 1 })
		}},
		{"P8b a stored input the retained bytes do not spend", "contradicts its parsed identity", func(x *canonicalDAOwnerFixture) {
			x.corruptChunk(x.stateA, 0, func(c *daRelayChunk) { c.member.inputs[0].Vout ^= 1 })
		}},
		{"P8c stored inputs in another order", "contradicts its parsed identity", func(x *canonicalDAOwnerFixture) {
			x.corrupt(x.stateB, func(r *daRelaySetRecord) {
				corruptDAChunk(r, 0, func(c *daRelayChunk) {
					c.member.inputs[0], c.member.inputs[1] = c.member.inputs[1], c.member.inputs[0]
				})
			})
		}},
		{"P10 a stored payload commitment the commit does not carry", "contradicts its payload commitment", func(x *canonicalDAOwnerFixture) {
			x.corrupt(x.stateB, func(r *daRelaySetRecord) { r.commit.payloadCommitment[0] ^= 1 })
		}},
		{"P10b a commit whose retained bytes carry no payload-commitment output", "carries no usable payload-commitment output", func(x *canonicalDAOwnerFixture) {
			bare := x.f.signed(daNonReplayTxSpec{kind: 0x01, daID: x.stateB, chunkCount: 2, commitmentOutputs: 0})
			x.corrupt(x.stateB, func(r *daRelaySetRecord) {
				r.commit.txBytes = slices.Clone(bare.raw)
				r.commit.member.txid, r.commit.member.wtxid, r.commit.member.inputs = bare.txid, bare.wtxid, slices.Clone(bare.inputs)
			})
		}},
		{"P11 a retained payload the stored hash does not cover", "contradicts its payload hash", func(x *canonicalDAOwnerFixture) {
			x.corruptChunk(x.stateA, 0, func(c *daRelayChunk) { c.payload = append(slices.Clone(c.payload), 0x01) })
		}},
		{"P12 a stored hash the retained bytes do not declare", "contradicts its payload hash", func(x *canonicalDAOwnerFixture) {
			x.corruptChunk(x.stateA, 0, func(c *daRelayChunk) { c.chunkHash[0] ^= 1 })
		}},
		{"P12b a stored hash of an altered same-length payload the retained bytes do not declare", "contradicts its payload hash", func(x *canonicalDAOwnerFixture) {
			x.corruptChunk(x.stateA, 0, func(c *daRelayChunk) {
				c.payload = slices.Clone(c.payload)
				c.payload[0] ^= 1
				c.chunkHash = sha3.Sum256(c.payload)
			})
		}},
		{"P13 a chunk retaining a payload its own bytes do not carry", "retains a payload its bytes do not carry", func(x *canonicalDAOwnerFixture) {
			other := x.f.signed(daNonReplayTxSpec{kind: 0x02, daID: x.stateA, chunkIndex: 0, payload: []byte("another payload!!!"), literalChunkHash: true, chunkHash: x.retained.sets[x.stateA].chunks[0].chunkHash})
			x.corruptChunk(x.stateA, 0, func(c *daRelayChunk) {
				c.txBytes, c.member.txid, c.member.wtxid, c.member.inputs = slices.Clone(other.raw), other.txid, other.wtxid, slices.Clone(other.inputs)
			})
			x.retained.locators[other.txid] = x.retained.locators[x.txs["a0"].txid]
			delete(x.retained.locators, x.txs["a0"].txid)
			x.corruptClaim(x.tokenOf("a0"), func(c *pendingOutpointClaim) { c.txid, c.inputs = other.txid, slices.Clone(other.inputs) })
		}},
		{"L1 a retained member with no locator row", "is not the sole locator of txid", func(x *canonicalDAOwnerFixture) { delete(x.retained.locators, x.txs["a0"].txid) }},
		{"L2 a locator row naming another slot", "is not the sole locator of txid", func(x *canonicalDAOwnerFixture) {
			x.retained.locators[x.txs["a0"].txid] = daRelayLocator{daID: x.stateA, kind: daRelayLocatorChunk, chunkIndex: 9}
		}},
		{"L3 a locator row no retained member implies", "locator index holds 5 rows against 4 retained members", func(x *canonicalDAOwnerFixture) {
			x.retained.locators[daRelayTestID(0xfe)] = daRelayLocator{daID: daRelayTestID(0xfd), kind: daRelayLocatorCommit}
		}},
		{"L4 no locator index at all", "carries no locator index", func(x *canonicalDAOwnerFixture) { x.retained.locators = nil }},
		{"L5 no record map at all, on the empty snapshot that would otherwise pair", "carries no record map", func(x *canonicalDAOwnerFixture) {
			x.emptyRetained()
			x.pending.claims, x.retained.sets = nil, nil
		}},
		{"L6 a nil record map is refused before the walk, not as a locator-count mismatch", "carries no record map", func(x *canonicalDAOwnerFixture) { x.retained.sets = nil }},
		{"AC1 global orphan bytes", "orphan pool bytes", func(x *canonicalDAOwnerFixture) { x.retained.orphanBytes++ }},
		{"AC2 commit overhead bytes", "orphan commit overhead bytes", func(x *canonicalDAOwnerFixture) { x.retained.orphanCommitOverheadBytes++ }},
		{"AC3 a per-da_id counter", "per-da_id orphan bytes for", func(x *canonicalDAOwnerFixture) { x.retained.orphanBytesByDAID[x.stateA]-- }},
		{"AC4 a per-peer counter billed to another key", "per-peer orphan bytes for", func(x *canonicalDAOwnerFixture) {
			x.retained.orphanBytesByPeerQuotaKey[""] = x.retained.orphanBytesByPeerQuotaKey["peer-a"]
			delete(x.retained.orphanBytesByPeerQuotaKey, "peer-a")
		}},
		{"AC5 a per-da_id entry no record implies", "per-da_id orphan bytes: records imply 2 entries, state holds 3", func(x *canonicalDAOwnerFixture) { x.retained.orphanBytesByDAID[daRelayTestID(0xfe)] = 1 }},
		{"AC6 pinned payload bytes in the owner-ready domain", "pinned payload bytes", func(x *canonicalDAOwnerFixture) { x.retained.pinnedPayloadBytes = 1 }},
		{"AC7 a per-peer entry no record implies", "per-peer orphan bytes: records imply 2 entries, state holds 3", func(x *canonicalDAOwnerFixture) { x.retained.orphanBytesByPeerQuotaKey["peer-that-owns-nothing"] = 1 }},
		{"AC8 no per-da_id counter map at all, on the empty snapshot that would otherwise pair", "carries no per-da_id orphan byte index", func(x *canonicalDAOwnerFixture) {
			x.emptyRetained()
			x.pending.claims, x.retained.orphanBytesByDAID = nil, nil
		}},
		{"AC9 no per-peer counter map at all, on the empty snapshot that would otherwise pair", "carries no per-peer orphan byte index", func(x *canonicalDAOwnerFixture) {
			x.emptyRetained()
			x.pending.claims, x.retained.orphanBytesByPeerQuotaKey = nil, nil
		}},
		{"A9 a record revision above the stored high-water", "carries revision", func(x *canonicalDAOwnerFixture) {
			x.corrupt(x.stateA, func(r *daRelaySetRecord) { r.revision = x.retained.records + 1 })
		}},
		{"A10 a record received time above the stored high-water", "carries received time", func(x *canonicalDAOwnerFixture) {
			x.corrupt(x.stateA, func(r *daRelaySetRecord) { r.receivedTime = x.retained.nextReceivedTime + 1 })
		}},
		{"F3 a stored fee one above the final-chain fee", "stores fee", func(x *canonicalDAOwnerFixture) {
			x.corruptChunk(x.stateA, 0, func(c *daRelayChunk) { c.member.fee.Lo++ })
		}},
		{"F4 a stored fee one high word above the final-chain fee", "stores fee", func(x *canonicalDAOwnerFixture) {
			x.corruptChunk(x.stateA, 0, func(c *daRelayChunk) { c.member.fee.Hi++ })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newCanonicalDAOwnerFixture(t)
			tc.corrupt(x)
			x.requireTerminal(tc.want)
		})
	}

	t.Run("F8 an ordinary invalid earlier member cannot hide a later member's terminal", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		x.spendInput("a0")
		x.corrupt(x.stateB, func(r *daRelaySetRecord) { r.commit.member.fee.Lo++ })
		x.requireTerminal(fmt.Sprintf("retained DA commit of %x stores fee", x.stateB))
	})

	t.Run("F9 a policy-excluded member with a wrong stored fee is still terminal", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		locked := daRelayTestID(0x33)
		x.admitLocktimeChunk(locked, 4242)
		x.capture()
		x.corruptChunk(locked, 0, func(c *daRelayChunk) { c.member.fee.Lo++ })
		x.requireTerminal(fmt.Sprintf("retained DA chunk 0 of %x stores fee", locked))
	})

	t.Run("F5 a canonical plan abort is returned unchanged, never promoted", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		x.chain.policy.SuiteRegistry = unboundAlgSuiteRegistry()
		x.requirePlanAbort()
	})

	t.Run("F10 a plan abort outranks a fee mismatch on the same member", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		x.corruptChunk(x.stateA, 0, func(c *daRelayChunk) { c.member.fee.Lo++ })
		x.chain.policy.SuiteRegistry = unboundAlgSuiteRegistry()
		x.requirePlanAbort()
	})

	t.Run("Q5 an ordinary exclusion does not hide a plan abort", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		x.spendInput("a0")
		x.spendInput("a1")
		x.chain.policy.SuiteRegistry = unboundAlgSuiteRegistry()
		x.requirePlanAbort()
	})

	for _, tc := range []struct {
		name    string
		want    string
		absent  string
		corrupt func(*canonicalDAOwnerFixture)
	}{
		{"Q1 a later structural defect outranks an earlier parse defect", "is not owner-ready", "has trailing bytes", func(x *canonicalDAOwnerFixture) {
			x.corruptChunk(x.stateA, 0, func(c *daRelayChunk) { c.txBytes = append(slices.Clone(c.txBytes), 0x00) })
			x.corrupt(x.stateB, func(r *daRelaySetRecord) { r.state = daRelayStateCompleteSet })
		}},
		{"Q2 a later parse defect outranks an earlier locator defect", "has trailing bytes", "sole locator", func(x *canonicalDAOwnerFixture) {
			delete(x.retained.locators, x.txs["a0"].txid)
			x.corrupt(x.stateB, func(r *daRelaySetRecord) { r.commit.txBytes = append(r.commit.txBytes, 0x00) })
		}},
		{"Q3 an accounting defect outranks an earlier fee defect", "orphan pool bytes", "stores fee", func(x *canonicalDAOwnerFixture) {
			x.corruptChunk(x.stateA, 0, func(c *daRelayChunk) { c.member.fee.Lo++ })
			x.retained.orphanBytes++
		}},
		{"Q4 a later fee defect outranks an earlier extra owner claim", "stores fee", "binds no retained member", func(x *canonicalDAOwnerFixture) {
			x.corruptClaim(x.standard, func(c *pendingOutpointClaim) { c.domain = PendingOutpointDA })
			x.corrupt(x.stateB, func(r *daRelaySetRecord) { r.commit.member.fee.Lo++ })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newCanonicalDAOwnerFixture(t)
			tc.corrupt(x)
			err := x.requireStableTerminal(tc.want, 16)
			if strings.Contains(err.Error(), tc.absent) {
				t.Fatalf("terminal=%q names the lower-precedence defect %q", err.Error(), tc.absent)
			}
		})
	}

	t.Run("Q7 inside one record the commit outranks its chunks", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		x.corrupt(x.stateB, func(r *daRelaySetRecord) {
			r.commit.payloadCommitment[0] ^= 1
			corruptDAChunk(r, 0, func(c *daRelayChunk) { c.chunkHash[0] ^= 1 })
		})
		if err := x.requireStableTerminal("commit", 64); strings.Contains(err.Error(), "chunk 0") {
			t.Fatalf("terminal=%q names the later member", err.Error())
		}
	})

	t.Run("Q7b inside one record a chunk's parse defect outranks the commit's binding defect", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		x.corrupt(x.stateB, func(r *daRelaySetRecord) {
			r.commit.payloadCommitment[0] ^= 1
			corruptDAChunk(r, 0, func(c *daRelayChunk) { c.txBytes = append(slices.Clone(c.txBytes), 0x00) })
		})
		if err := x.requireStableTerminal(fmt.Sprintf("retained DA record %x: retained DA chunk 0 has trailing bytes", x.stateB), 64); strings.Contains(err.Error(), "commit") {
			t.Fatalf("terminal=%q names the commit's binding defect", err.Error())
		}
	})

	t.Run("Q8 inside one phase the lowest raw da_id wins", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		for _, daID := range [][32]byte{x.stateA, x.stateB} {
			x.corrupt(daID, func(r *daRelaySetRecord) {
				corruptDAChunk(r, 0, func(c *daRelayChunk) { c.member.txid[0] ^= 1 })
			})
		}
		err := x.requireStableTerminal("contradicts its parsed identity", 64)
		if !strings.Contains(err.Error(), fmt.Sprintf("%x", x.stateA)) || strings.Contains(err.Error(), fmt.Sprintf("%x", x.stateB)) {
			t.Fatalf("terminal=%q, want the lowest raw da_id record", err.Error())
		}
	})
}

// TestCanonicalDAOwnerCandidatesPreserveSurvivorsAndInputs pins the isolation
// half: after a removal every survivor is exact, and neither returned half
// shares a mutable container with an input or with its sibling — in either
// direction.
func TestCanonicalDAOwnerCandidatesPreserveSurvivorsAndInputs(t *testing.T) {
	t.Run("X1-X9 a removal leaves exactly the survivors in both halves", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		x.spendInput("b0")
		candidates := x.requirePair()
		x.requireExactImage(candidates, x.stateB)
		for _, name := range []string{"commit", "b0"} {
			if _, live := candidates.ownerIndex.byToken[x.tokenOf(name)]; live {
				t.Fatalf("the O1 half kept the claim of removed member %s", name)
			}
		}
	})

	t.Run("X13 removing one of two State B records of a peer above the per-peer cap yields the pair", func(t *testing.T) {
		x := newCanonicalDAOwnerPeerCapFixture(t)
		x.spendInput("commit")
		x.requireExactImage(x.requirePair(), x.stateB)
	})

	t.Run("N3 a later mutation of either input cannot reach the pair", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		candidates := x.requirePair()
		relayBefore, pendingBefore := daRelayStateSnapshot(candidates.retained), clonePendingOutpointSnapshot(candidates.pending)
		indexBefore := clonePendingOutpointClaims(candidates.ownerIndex.byToken)
		// In place, through the input's own live containers: a D1 that shared the
		// record's chunk map or payload backing would move with it.
		x.retained.sets[x.stateA].chunks[0].payload[0] ^= 1
		delete(x.retained.sets[x.stateA].chunks, 1)
		delete(x.retained.locators, x.txs["a0"].txid)
		x.retained.orphanBytes++
		x.pending.claims[0].inputs[0].Vout ^= 1
		if !reflect.DeepEqual(daRelayStateSnapshot(candidates.retained), relayBefore) { //nolint:govet // deepequalerrors: image identity is the assertion
			t.Fatal("mutating the retained input moved D1")
		}
		if !reflect.DeepEqual(candidates.pending, pendingBefore) || !reflect.DeepEqual(clonePendingOutpointClaims(candidates.ownerIndex.byToken), indexBefore) { //nolint:govet // deepequalerrors: owner-half identity is the assertion
			t.Fatal("mutating the owner input moved O1")
		}
	})

	t.Run("N1-N5 mutating either half reaches neither the inputs nor its sibling", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		x.included = []canonicalDASetIdentity{x.identityOf(x.stateB, "commit", "b0")}
		candidates := x.requirePair()
		before := x.inputs()
		pendingBefore := clonePendingOutpointSnapshot(candidates.pending)
		indexBefore := clonePendingOutpointClaims(candidates.ownerIndex.byToken)
		// N1 record and payload, N2 locators, N4 claims and their inputs, N5 index rows.
		candidates.retained.sets[x.stateA].chunks[0].payload[0] ^= 1
		delete(candidates.retained.sets[x.stateA].chunks, 1)
		delete(candidates.retained.locators, x.txs["a0"].txid)
		candidates.retained.orphanBytesByPeerQuotaKey["peer-a"] = 0
		candidates.pending.claims[0].inputs[0].Vout ^= 1
		candidates.pending.claims[0].finalized = !candidates.pending.claims[0].finalized
		candidates.ownerIndex.byOutpoint[consensus.Outpoint{Vout: 41}] = pendingOutpointRow{}
		x.requireInputsUnchanged(before)
		if !reflect.DeepEqual(clonePendingOutpointClaims(candidates.ownerIndex.byToken), indexBefore) { //nolint:govet // deepequalerrors: sibling isolation is the assertion
			t.Fatal("mutating O1's claims moved the index rebuilt beside them")
		}
		if len(candidates.pending.claims) != len(pendingBefore.claims) {
			t.Fatal("mutating the index moved O1's claims")
		}
	})
}

func clonePendingOutpointClaims(byToken map[PendingOutpointToken]*pendingOutpointClaim) map[PendingOutpointToken]pendingOutpointClaim {
	out := make(map[PendingOutpointToken]pendingOutpointClaim, len(byToken))
	for token, claim := range byToken {
		copied := *claim
		copied.inputs = slices.Clone(claim.inputs)
		out[token] = copied
	}
	return out
}

// TestCanonicalDAOwnerCandidatesCloseTheClaimBijection pins the owner half: every
// retained member holds its own exclusive finalized DA claim of this owner, no
// DA claim is left over, and standard claims are never inspected.
func TestCanonicalDAOwnerCandidatesCloseTheClaimBijection(t *testing.T) {
	for _, tc := range []struct {
		name    string
		want    string
		corrupt func(*canonicalDAOwnerFixture)
	}{
		{"C1 a retained member with no claim", "holds no owner claim", func(x *canonicalDAOwnerFixture) {
			token := x.tokenOf("a0")
			x.pending = clonePendingOutpointSnapshot(x.pending)
			x.pending.claims = slices.DeleteFunc(x.pending.claims, func(c pendingOutpointClaim) bool { return c.token == token })
		}},
		{"C2 a DA claim binding no retained member", "binds no retained member", func(x *canonicalDAOwnerFixture) {
			x.corruptClaim(x.standard, func(c *pendingOutpointClaim) { c.domain = PendingOutpointDA })
		}},
		{"C3 one token carried twice", "carries one token twice", func(x *canonicalDAOwnerFixture) {
			x.pending = clonePendingOutpointSnapshot(x.pending)
			x.pending.claims = append(x.pending.claims, x.pending.claims[0])
		}},
		{"C4 a DA claim owned by another owner", "foreign pending-outpoint token in snapshot", func(x *canonicalDAOwnerFixture) {
			foreign := newPendingOutpointOwner(PendingOutpointTip{})
			x.corruptClaim(x.standard, func(c *pendingOutpointClaim) {
				c.domain, c.token = PendingOutpointDA, PendingOutpointToken{owner: foreign, seq: 1}
			})
		}},
		{"C6 a token sequence above the snapshot high-water", "foreign pending-outpoint token in snapshot", func(x *canonicalDAOwnerFixture) { x.pending.tokenHighWater = 1 }},
		{"C7 a claim generation above the snapshot high-water", "generation above high-water", func(x *canonicalDAOwnerFixture) {
			x.corruptClaim(x.tokenOf("a0"), func(c *pendingOutpointClaim) { c.generation = x.pending.generationHighWater + 1 })
		}},
		{"C5b a malformed DA claim shape (nil inputs)", "malformed pending-outpoint claim in snapshot", func(x *canonicalDAOwnerFixture) {
			x.corruptClaim(x.tokenOf("a0"), func(c *pendingOutpointClaim) { c.inputs = nil })
		}},
		{"C12 a claim of an undefined domain", "malformed pending-outpoint claim in snapshot", func(x *canonicalDAOwnerFixture) {
			x.corruptClaim(x.standard, func(c *pendingOutpointClaim) { c.domain = PendingOutpointDomain(7) })
		}},
		{"C13 a standard claim with a foreign owner token", "foreign pending-outpoint token in snapshot", func(x *canonicalDAOwnerFixture) {
			foreign := newPendingOutpointOwner(PendingOutpointTip{})
			x.corruptClaim(x.standard, func(c *pendingOutpointClaim) { c.token.owner = foreign })
		}},
		{"C14 a standard claim with a zero txid", "malformed pending-outpoint claim in snapshot", func(x *canonicalDAOwnerFixture) {
			x.corruptClaim(x.standard, func(c *pendingOutpointClaim) { c.txid = [32]byte{} })
		}},
		{"C15 a standard claim with an empty input set", "malformed pending-outpoint claim in snapshot", func(x *canonicalDAOwnerFixture) {
			x.corruptClaim(x.standard, func(c *pendingOutpointClaim) { c.inputs = nil })
		}},
		{"H4b a later standard claim sharing an outpoint with a DA claim", "claims outpoint txid=", func(x *canonicalDAOwnerFixture) {
			x.corruptClaim(x.standard, func(c *pendingOutpointClaim) { c.inputs = slices.Clone(x.txs["a0"].inputs) })
		}},
		{"H4c two DA claims of different records sharing an outpoint", "claims outpoint txid=", func(x *canonicalDAOwnerFixture) {
			x.corruptClaim(x.tokenOf("b0"), func(c *pendingOutpointClaim) { c.inputs = slices.Clone(x.txs["a0"].inputs) })
		}},
		{"C8 a standard-domain claim under a member token", "is not described by its claim", func(x *canonicalDAOwnerFixture) {
			x.corruptClaim(x.tokenOf("a0"), func(c *pendingOutpointClaim) { c.domain = PendingOutpointStandardMempool })
		}},
		{"C9 a claim naming another txid", "is not described by its claim", func(x *canonicalDAOwnerFixture) {
			x.corruptClaim(x.tokenOf("a0"), func(c *pendingOutpointClaim) { c.txid[0] ^= 1 })
		}},
		{"C10a a claim covering another input set", "is not described by its claim", func(x *canonicalDAOwnerFixture) {
			x.corruptClaim(x.tokenOf("a0"), func(c *pendingOutpointClaim) { c.inputs[0].Vout ^= 1 })
		}},
		{"C10b a claim covering the inputs in another order", "is not described by its claim", func(x *canonicalDAOwnerFixture) {
			x.corruptClaim(x.tokenOf("b0"), func(c *pendingOutpointClaim) { c.inputs[0], c.inputs[1] = c.inputs[1], c.inputs[0] })
		}},
		{"C11 an unfinalized claim", "is not described by its claim", func(x *canonicalDAOwnerFixture) {
			x.corruptClaim(x.tokenOf("a0"), func(c *pendingOutpointClaim) { c.finalized = false })
		}},
		{"H4 two members sharing one token", "shares its token with an earlier retained member", func(x *canonicalDAOwnerFixture) {
			shared := x.retained.sets[x.stateA].chunks[0].member.token
			x.corruptChunk(x.stateA, 1, func(c *daRelayChunk) { c.member.token = shared })
		}},
		{"H4d a member of another record carrying this chunk's token", "shares its token with an earlier retained member", func(x *canonicalDAOwnerFixture) {
			shared := x.retained.sets[x.stateA].chunks[0].member.token
			x.corruptChunk(x.stateB, 0, func(c *daRelayChunk) { c.member.token = shared })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newCanonicalDAOwnerFixture(t)
			tc.corrupt(x)
			x.requireTerminal(tc.want)
		})
	}

	t.Run("A4 standard claims are preserved through a removal", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		x.included = []canonicalDASetIdentity{x.identityOf(x.stateB, "commit", "b0")}
		candidates := x.requirePair()
		standard := candidates.ownerIndex.byToken[x.standard]
		if standard == nil || standard.domain != PendingOutpointStandardMempool {
			t.Fatalf("standard claim=%+v, want it preserved", standard)
		}
		if candidates.pending.claims[len(candidates.pending.claims)-1].token != x.standard {
			t.Fatal("the standard claim left its original position")
		}
	})
}

// canonicalDAOwnerLockingFunctions are the only functions of the two seam files
// allowed to name a lock or a publisher: the LIVE canonical D image preparation
// and its publisher, both untouched by this slice.
var canonicalDAOwnerLockingFunctions = map[string]bool{"prepareCanonicalDAImage": true, "publish": true}

// canonicalDAOwnerForbiddenCalls are the selectors a dormant builder must never
// name: any mutex, any owner mutation and any publisher.
var canonicalDAOwnerForbiddenCalls = map[string]bool{
	"Lock": true, "Unlock": true, "RLock": true, "RUnlock": true, "TryLock": true,
	"Reserve": true, "Finalize": true, "Release": true, "dropClaimLocked": true,
	"publishAtomicBatchLocked": true, "publishRestoreLocked": true, "publishCanonicalMempoolPlan": true,
}

// canonicalDAOwnerClosingClauses are the callees the closing proof's body is
// required to name, one per clause: the survivor-claim resolution, the DA-claim
// count, the outpoint-row cardinality and the D1 locator/accounting closure.
var canonicalDAOwnerClosingClauses = []string{"canonicalDAOwnerSurvivingClaim", "canonicalDAOwnerDomainClaims", "canonicalDAOwnerClaimedInputs", "canonicalDARetainedImageClosed"}

// TestCanonicalDAOwnerCandidateBuilderRemainsDormant proves the pair builder is
// wired to nothing: exactly one definition, no production caller, exactly one
// production call of its intrinsic validation phase, and its closing proof still
// in the path with every clause. The source census covers the two seam files as
// a WHOLE — every function of theirs but the two live locking ones — so a later
// helper added beside the builder is covered without being named here.
//
// The behavioral half is stronger than any census: the builder runs to
// completion while the test holds the live owner lock and the handed snapshot's
// own mutex, which no implementation that acquired either could do.
func TestCanonicalDAOwnerCandidateBuilderRemainsDormant(t *testing.T) {
	definitions, calls, closingCalls := map[string]int{}, map[string]int{}, map[string]bool{}
	for _, file := range parseCanonicalDAOwnerPackage(t) {
		ast.Inspect(file.file, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.FuncDecl:
				definitions[typed.Name.Name]++
				if slices.Contains([]string{"sync_da_relay.go", "sync_da_relay_validate.go"}, file.name) && !canonicalDAOwnerLockingFunctions[typed.Name.Name] {
					requireDormantFunctionBody(t, typed)
				}
				if typed.Name.Name == "canonicalDAOwnerPairClosed" {
					closingCalls = canonicalDABodyCallees(typed)
				}
			case *ast.CallExpr:
				calls[canonicalDACalleeName(typed.Fun)]++
			}
			return true
		})
	}
	for _, clause := range canonicalDAOwnerClosingClauses {
		if !closingCalls[clause] {
			t.Fatalf("the closing proof no longer calls %s", clause)
		}
	}
	for name, want := range map[string]int{
		"prepareCanonicalDAOwnerCandidates":   0,
		"validateCanonicalDARetainedSnapshot": 1,
		"canonicalDAOwnerPairClosed":          1,
		"BeginDARemoval":                      0,
	} {
		if got := calls[name]; got != want {
			t.Fatalf("production calls of %s=%d, want %d", name, got, want)
		}
	}
	for _, name := range []string{"prepareCanonicalDAOwnerCandidates", "validateCanonicalDARetainedSnapshot", "canonicalDAOwnerPairClosed"} {
		if definitions[name] != 1 {
			t.Fatalf("production definitions of %s=%d, want 1", name, definitions[name])
		}
	}

	t.Run("D2 the builder runs while the owner lock and the snapshot's own mutex are held", func(t *testing.T) {
		x := newCanonicalDAOwnerFixture(t)
		x.retained.mu.Lock()
		defer x.retained.mu.Unlock()
		x.owner.mu.Lock()
		defer x.owner.mu.Unlock()
		done := make(chan error, 1)
		go func() {
			_, err := x.build()
			done <- err
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("prepareCanonicalDAOwnerCandidates: %v", err)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("the builder blocked on a lock held by its own caller")
		}
	})
}

func canonicalDABodyCallees(decl *ast.FuncDecl) map[string]bool {
	callees := map[string]bool{}
	ast.Inspect(decl.Body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			callees[canonicalDACalleeName(call.Fun)] = true
		}
		return true
	})
	return callees
}

type canonicalDAOwnerSourceFile struct {
	name string
	file *ast.File
}

func parseCanonicalDAOwnerPackage(t *testing.T) []canonicalDAOwnerSourceFile {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	fset := token.NewFileSet()
	var files []canonicalDAOwnerSourceFile
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", name, err)
		}
		files = append(files, canonicalDAOwnerSourceFile{name: name, file: parsed})
	}
	for _, seam := range []string{"sync_da_relay.go", "sync_da_relay_validate.go"} {
		if !slices.ContainsFunc(files, func(file canonicalDAOwnerSourceFile) bool { return file.name == seam }) {
			t.Fatalf("seam file %s was not parsed", seam)
		}
	}
	return files
}

func requireDormantFunctionBody(t *testing.T, decl *ast.FuncDecl) {
	t.Helper()
	ast.Inspect(decl.Body, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.GoStmt:
			t.Fatalf("%s starts a goroutine", decl.Name.Name)
		case *ast.CallExpr:
			if name := canonicalDACalleeName(typed.Fun); canonicalDAOwnerForbiddenCalls[name] {
				t.Fatalf("%s calls %s", decl.Name.Name, name)
			}
		}
		return true
	})
}

func canonicalDACalleeName(fun ast.Expr) string {
	switch typed := fun.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return typed.Sel.Name
	default:
		return ""
	}
}
