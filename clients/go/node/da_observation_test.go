package node

import (
	"crypto/sha3"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// daObservationCounts reads {reserveCalls, reservationsAcquired, finalizations, candidateReleases}.
func daObservationCounts(o *PendingOutpointOwner) [4]uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return [4]uint64{o.reserveCalls, o.reservationsAcquired, o.finalizations, o.candidateReleases}
}

// requireDAObservationDelta checks the counter delta since before and returns the new counts.
func requireDAObservationDelta(t *testing.T, o *PendingOutpointOwner, before, want [4]uint64, label string) [4]uint64 {
	t.Helper()
	got := daObservationCounts(o)
	if delta := [4]uint64{got[0] - before[0], got[1] - before[1], got[2] - before[2], got[3] - before[3]}; delta != want {
		t.Fatalf("%s: counter delta {reserve,acquired,finalize,release}=%v, want %v", label, delta, want)
	}
	return got
}

func TestDAObservationOwnerCounts(t *testing.T) {
	t.Run("owner sites", func(t *testing.T) {
		o := newPendingOutpointOwner(PendingOutpointTip{})
		context, _ := o.AdmissionContext()
		op := consensus.Outpoint{Txid: [32]byte{7}}
		c := daObservationCounts(o)
		token := mustReserve(t, o, [32]byte{1}, op)
		c = requireDAObservationDelta(t, o, c, [4]uint64{1, 1, 0, 0}, "Reserve success")
		if _, err := o.Reserve(context, PendingOutpointStandardMempool, [32]byte{2}, []consensus.Outpoint{op}); err == nil {
			t.Fatal("conflicting Reserve succeeded")
		}
		c = requireDAObservationDelta(t, o, c, [4]uint64{1, 0, 0, 0}, "Reserve conflict")
		if _, err := o.Reserve(context, PendingOutpointStandardMempool, [32]byte{}, []consensus.Outpoint{op}); err == nil {
			t.Fatal("malformed Reserve succeeded")
		}
		if _, err := (*PendingOutpointOwner)(nil).Reserve(context, PendingOutpointStandardMempool, [32]byte{3}, []consensus.Outpoint{op}); err == nil {
			t.Fatal("nil owner Reserve succeeded")
		}
		c = requireDAObservationDelta(t, o, c, [4]uint64{}, "request rejected before o.mu")
		for i, want := range [][4]uint64{{0, 0, 1, 0}, {}} {
			if err := o.Finalize(token); err != nil {
				t.Fatal(err)
			}
			c = requireDAObservationDelta(t, o, c, want, fmt.Sprintf("Finalize attempt %d", i))
		}
		snapshot := o.snapshot()
		if _, err := o.beginTransition(); err != nil {
			t.Fatal(err)
		}
		o.mu.Lock()
		candidate, err := o.buildRestoreLocked(snapshot)
		if err == nil {
			o.publishRestoreLocked(snapshot, candidate)
		}
		o.mu.Unlock()
		o.endTransitionAborted()
		if err != nil {
			t.Fatal(err)
		}
		c = requireDAObservationDelta(t, o, c, [4]uint64{}, "transition and restore")
		for i, want := range [][4]uint64{{0, 0, 0, 1}, {}} {
			if err := o.Release(token); err != nil {
				t.Fatal(err)
			}
			c = requireDAObservationDelta(t, o, c, want, fmt.Sprintf("Release attempt %d", i))
		}
		cleanup := mustReserve(t, o, [32]byte{4}, op)
		c = requireDAObservationDelta(t, o, c, [4]uint64{1, 1, 0, 0}, "standard candidate reserve")
		(&Mempool{pendingOutpoints: o}).releaseCandidateLocked(&mempoolEntry{token: cleanup}, nil, nil)
		requireDAObservationDelta(t, o, c, [4]uint64{0, 0, 0, 1}, "standard candidate cleanup")
	})
	t.Run("admission sites", func(t *testing.T) {
		f := newDANonReplayFixture(t, 10)
		o := f.mp.pendingOutpoints
		chunk := func(id byte) daNonReplayTx {
			return f.signed(daNonReplayTxSpec{kind: 2, daID: [32]byte{0x60, id}, payload: []byte{id}})
		}
		c := daObservationCounts(o)
		conflicted := chunk(3)
		admission := f.begin(conflicted)
		mustReserve(t, o, [32]byte{0x77}, conflicted.inputs[0])
		c = requireDAObservationDelta(t, o, c, [4]uint64{1, 1, 0, 0}, "standard reserve")
		if _, err := admission.BeginCommit(nil); relayDispositionOf(err) != RelayAdmissionConflict {
			t.Fatalf("DA reserve conflict err=%v", err)
		}
		admission.Close()
		c = requireDAObservationDelta(t, o, c, [4]uint64{1, 0, 0, 0}, "DA reserve conflict")
		first := chunk(1)
		_, firstToken := mustFinalizeDAAdmission(t, f.mp, first.raw)
		c = requireDAObservationDelta(t, o, c, [4]uint64{1, 1, 1, 0}, "DA admit that finalizes")
		admission = f.begin(chunk(2))
		commit, err := admission.BeginCommit([]DAAdmissionVictim{{TxID: first.txid, Inputs: first.inputs, Token: firstToken}})
		if err != nil {
			t.Fatal(err)
		}
		commit.Commit()
		admission.Close()
		if o.byToken[firstToken] != nil {
			t.Fatal("finalized victim claim survived")
		}
		c = requireDAObservationDelta(t, o, c, [4]uint64{1, 1, 1, 0}, "DA admit that finalizes and drops a victim")
		admission = f.begin(chunk(4))
		if _, err := admission.BeginCommit([]DAAdmissionVictim{{TxID: [32]byte{0x88}, Inputs: []consensus.Outpoint{{Txid: [32]byte{0x88}}}, Token: PendingOutpointToken{owner: o, seq: 1}}}); err == nil {
			t.Fatal("mismatched victim validated")
		}
		admission.Close()
		c = requireDAObservationDelta(t, o, c, [4]uint64{1, 1, 0, 1}, "DA post-reservation victim failure")
		admission = f.begin(chunk(5))
		if commit, err = admission.BeginCommit(nil); err != nil {
			t.Fatal(err)
		}
		commit.Abort()
		admission.Close()
		c = requireDAObservationDelta(t, o, c, [4]uint64{1, 1, 0, 1}, "DACommit.Abort")
		f.admit(chunk(6), daNonReplayPeer("gone"))
		c = requireDAObservationDelta(t, o, c, [4]uint64{1, 1, 1, 0}, "peer DA admit")
		if err := f.relay.ReleasePeerQuotaKey("gone"); err != nil {
			t.Fatal(err)
		}
		c = requireDAObservationDelta(t, o, c, [4]uint64{}, "peer-cleanup drop")
		input := f.outpoints[f.next]
		f.next++
		raw := mustBuildSignedTransferTx(t, f.state.Utxos, []consensus.Outpoint{input}, 100_000, 300_000, 1, f.signer, f.address, f.address)
		if err := f.mp.AddTx(raw); err != nil {
			t.Fatal(err)
		}
		c = requireDAObservationDelta(t, o, c, [4]uint64{1, 1, 1, 0}, "standard admission")
		_, txid, _, _, err := consensus.ParseTx(raw)
		if err != nil {
			t.Fatal(err)
		}
		f.mp.mu.Lock()
		err = f.mp.removeTxLocked(txid)
		f.mp.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		requireDAObservationDelta(t, o, c, [4]uint64{}, "standard removal")
	})
}

// daObservationHeld reports whether mu is held, without keeping it.
func daObservationHeld(mu *sync.Mutex) bool {
	if mu.TryLock() {
		mu.Unlock()
		return false
	}
	return true
}

// daObservationTwin returns a fresh mempool and relay over f's exact UTXO set,
// chain and signer, so transactions signed on f admit identically on both.
func daObservationTwin(t *testing.T, f *daNonReplayFixture) *daNonReplayFixture {
	state, outpoints := testSpendableChainState(f.address, slices.Repeat([]uint64{2_000_000}, len(f.outpoints)))
	cfg := DefaultMempoolConfig()
	cfg.PolicyMaxDaBytesPerBlock = consensus.MAX_DA_BYTES_PER_BLOCK
	mp, err := NewMempoolWithConfig(state, nil, devnetGenesisChainID, cfg)
	if err != nil {
		t.Fatal(err)
	}
	caps := defaultDARelayCaps()
	caps.orphanTTLBlocks = 7
	relay, err := newDARelayState(mp, caps)
	if err != nil {
		t.Fatal(err)
	}
	return &daNonReplayFixture{t: t, signer: f.signer, address: f.address, state: state, mp: mp, relay: relay, outpoints: outpoints}
}

// daObservationImage is every retained-state and owner-state observable of f,
// with the owner identity cleared so twin fixtures compare equal.
func daObservationImage(f *daNonReplayFixture) []any {
	view := daRelayStateSnapshot(f.relay)
	view.mempool = nil
	clearOwner := func(m *daRelayMemberIdentity) {
		if m != nil {
			m.token.owner = nil
		}
	}
	for _, r := range view.sets {
		clearOwner(r.commit.member)
		for _, chunk := range r.chunks {
			clearOwner(chunk.member)
		}
	}
	owner := cloneDAAdmissionOwner(f.mp.pendingOutpoints)
	claims, rows := map[uint64]pendingOutpointClaim{}, map[consensus.Outpoint]pendingOutpointRow{}
	for token, claim := range owner.byToken {
		claim.token.owner = nil
		claims[token.seq] = *claim
	}
	for op, row := range owner.byOutpoint {
		row.token.owner = nil
		rows[op] = row
	}
	owner.byToken, owner.byOutpoint = nil, nil
	return []any{view, claims, rows, owner, daObservationCounts(f.mp.pendingOutpoints), snapshotDARejectCache(&f.relay.rejectCache)}
}

// runDAObservationScript drives AdmitDA over txs and returns one signature per
// step. With observe it installs an observer that checks each call and a no-op
// plan hook, and returns the number of hook calls.
func runDAObservationScript(t *testing.T, f *daNonReplayFixture, txs []daNonReplayTx, observe bool) ([]string, int) {
	o := f.mp.pendingOutpoints
	var calls []daAdmitCall
	hooked := 0
	if observe {
		observer := func(call daAdmitCall) {
			if daObservationHeld(&f.relay.mu) || daObservationHeld(&o.mu) {
				t.Error("observer ran under the DA relay or owner mutex")
			}
			calls = append(calls, call)
		}
		f.relay.admitObserver.Store(&observer)
		f.relay.completeHook = func(daCompleteStage, *daCompleteCommitPlan) { hooked++ }
	}
	var signatures []string
	// want is the success disposition, or zero with the refusal's relay disposition.
	admit := func(label string, raw []byte, provenance DAProvenance, want DAAdmissionDisposition, refusal RelayAdmissionDisposition) {
		calls = nil
		got, err := f.relay.AdmitDA(raw, provenance)
		if want != 0 && (err != nil || got.Disposition != want) || want == 0 && relayDispositionOf(err) != refusal {
			t.Fatalf("%s: AdmitDA=(%+v,%v), want disposition %d or refusal %d", label, got, err, want, refusal)
		}
		if observe && (len(calls) != 1 || calls[0] != (daAdmitCall{provenance, got, err})) {
			t.Fatalf("%s: observed %+v, want exactly one {%+v %+v %v}", label, calls, provenance, got, err)
		}
		signatures = append(signatures, fmt.Sprintf("%s: %+v %v", label, got, err))
	}
	admit("retained", txs[0].raw, publicPeer(t, "observed"), DAAdmissionRetained, 0)
	admit("exact replay", txs[0].raw, LocalDAProvenance(), DAAdmissionDuplicate, 0)
	admit("policy rejection", append(slices.Clip(txs[0].raw), 0), LocalDAProvenance(), 0, RelayAdmissionStableTerminalReject)
	mustReserve(t, o, [32]byte{0x99}, txs[1].inputs[0])
	admit("owner conflict", txs[1].raw, LocalDAProvenance(), 0, RelayAdmissionConflict)
	if _, err := o.beginTransition(); err != nil {
		t.Fatal(err)
	}
	admit("hold unavailable", txs[2].raw, LocalDAProvenance(), 0, RelayAdmissionUnavailable)
	o.endTransitionAborted()
	admit("invalid provenance", txs[2].raw, DAProvenance{}, 0, RelayAdmissionStableTerminalReject)
	admit("local", txs[2].raw, LocalDAProvenance(), DAAdmissionRetained, 0)
	admit("detached reorg", txs[3].raw, DetachedReorgDAProvenance(), DAAdmissionRetained, 0)
	admit("staged commit", txs[4].raw, LocalDAProvenance(), DAAdmissionRetained, 0)
	admit("completing chunk", txs[5].raw, LocalDAProvenance(), DAAdmissionRetained, 0)
	f.relay.admitObserver.Store(nil)
	installed := observe
	observe = false
	admit("uninstalled", txs[6].raw, LocalDAProvenance(), DAAdmissionRetained, 0)
	if installed && len(calls) != 0 {
		t.Fatalf("uninstalled observer was called: %+v", calls)
	}
	return signatures, hooked
}

func TestDAObservationAdmitObserver(t *testing.T) {
	f := newDANonReplayFixture(t, 7)
	chunk := func(id byte, payload []byte) daNonReplayTx {
		return f.signed(daNonReplayTxSpec{kind: 2, daID: [32]byte{0x70, id}, payload: payload})
	}
	complete := []byte("observed complete")
	txs := []daNonReplayTx{chunk(1, []byte{1}), chunk(2, []byte{2}), chunk(3, []byte{3}), chunk(4, []byte{4}),
		f.signed(daNonReplayTxSpec{kind: 1, daID: [32]byte{0x70, 9}, chunkCount: 1, commitment: sha3.Sum256(complete), commitmentOutputs: 1}), chunk(9, complete), chunk(5, []byte{5})}
	twin := daObservationTwin(t, f)
	observed, hooked := runDAObservationScript(t, f, txs, true)
	unobserved, _ := runDAObservationScript(t, twin, txs, false)
	if !slices.Equal(observed, unobserved) || !reflect.DeepEqual(daObservationImage(f), daObservationImage(twin)) || hooked != 2 {
		t.Fatalf("observer and no-op hook (hook calls=%d) changed outcomes or state:\nobserved=%q\nunobserved=%q", hooked, observed, unobserved)
	}
	got, err := (*DARelayState)(nil).AdmitDA(nil, LocalDAProvenance())
	requirePublicDAFailure(t, got, err, TxAdmitUnavailable, "nil DA relay", RelayAdmissionUnavailable)
	observer := func(daAdmitCall) {}
	f.relay.admitObserver.Store(&observer)
	f.relay.mu.Lock()
	image := f.relay.cloneForAtomicBatchLocked()
	f.relay.mu.Unlock()
	if image.admitObserver.Load() != nil || image.completeHook != nil || f.relay.completeHook == nil {
		t.Fatal("retained-state image copied the observer or hook")
	}
}

type daObservationStage struct {
	stage                daCompleteStage
	relayHeld, ownerHeld bool
}

// daObservationCompleting stages a commit so the returned chunk completes it.
func daObservationCompleting(t *testing.T) (*daNonReplayFixture, daNonReplayTx) {
	f := newDANonReplayFixture(t, 4)
	id, payload := [32]byte{0x51}, []byte("observed payload")
	chunk := f.signed(daNonReplayTxSpec{kind: 2, daID: id, payload: payload})
	f.admit(f.signed(daNonReplayTxSpec{kind: 1, daID: id, chunkCount: 1, commitment: sha3.Sum256(payload), commitmentOutputs: 1}), DetachedReorgDAProvenance())
	return f, chunk
}

// hookDAObservation records each stage with the lock state it ran under and
// applies act (if any) at that stage.
func hookDAObservation(f *daNonReplayFixture, act func(daCompleteStage, *daCompleteCommitPlan)) *[]daObservationStage {
	stages := &[]daObservationStage{}
	f.relay.completeHook = func(stage daCompleteStage, plan *daCompleteCommitPlan) {
		*stages = append(*stages, daObservationStage{stage, daObservationHeld(&f.relay.mu), daObservationHeld(&f.mp.pendingOutpoints.mu)})
		if act != nil {
			act(stage, plan)
		}
	}
	return stages
}

func TestDAObservationPlanHook(t *testing.T) {
	planned, effects := daObservationStage{stage: daCompletePlanned}, daObservationStage{stage: daCompleteEffects, relayHeld: true}
	for _, row := range []struct {
		name    string
		act     func(*daNonReplayFixture, daNonReplayTx, daCompleteStage)
		wantErr string
		want    []daObservationStage
	}{
		{"completing admission", nil, "", []daObservationStage{planned, effects}},
		{"target mutated at PLANNED is stale", func(f *daNonReplayFixture, _ daNonReplayTx, stage daCompleteStage) {
			if stage == daCompletePlanned {
				f.mutateRelay(func(s *DARelayState) {
					mutateOwnerReadyRecord(s, [32]byte{0x51}, func(r *daRelaySetRecord) { r.ttlBlocksRemaining++ })
				})
			}
		}, "retained DA record moved while this admission was planned", []daObservationStage{planned}},
		{"duplicate exit after PLANNED", func(f *daNonReplayFixture, chunk daNonReplayTx, stage daCompleteStage) {
			if stage == daCompletePlanned {
				f.mutateRelay(func(s *DARelayState) {
					s.locators[chunk.txid] = daRelayLocator{daID: [32]byte{0x51}, kind: daRelayLocatorChunk}
				})
			}
		}, "", []daObservationStage{planned}},
		{"failed prepareEffects", func(f *daNonReplayFixture, _ daNonReplayTx, stage daCompleteStage) {
			if stage == daCompletePlanned {
				f.mutateRelay(func(s *DARelayState) { s.completeCount++ })
			}
		}, errDARelayImageIncompatible.Error(), []daObservationStage{planned}},
		{"nil map at EFFECTS", func(f *daNonReplayFixture, _ daNonReplayTx, stage daCompleteStage) {
			if stage == daCompleteEffects {
				f.relay.orphanBytesByDAID = nil
			}
		}, errDARelayImageIncompatible.Error(), []daObservationStage{planned, effects}},
		{"extra locator at EFFECTS", func(f *daNonReplayFixture, chunk daNonReplayTx, stage daCompleteStage) {
			if stage == daCompleteEffects {
				f.relay.locators[chunk.txid] = daRelayLocator{daID: [32]byte{0x51}, kind: daRelayLocatorChunk}
			}
		}, errDARelayImageIncompatible.Error(), []daObservationStage{planned, effects}},
	} {
		t.Run(row.name, func(t *testing.T) {
			f, chunk := daObservationCompleting(t)
			stages := hookDAObservation(f, func(stage daCompleteStage, _ *daCompleteCommitPlan) {
				if row.act != nil {
					row.act(f, chunk, stage)
				}
			})
			got, err := f.relay.AdmitDA(chunk.raw, LocalDAProvenance())
			if row.wantErr == "" && err != nil || row.wantErr != "" && (err == nil || !strings.Contains(err.Error(), row.wantErr)) {
				t.Fatalf("AdmitDA=(%+v,%v), want error %q", got, err, row.wantErr)
			}
			if !slices.Equal(*stages, row.want) {
				t.Fatalf("hook stages=%+v, want %+v", *stages, row.want)
			}
		})
	}
	t.Run("victim claim dropped at EFFECTS", func(t *testing.T) {
		f, chunk := daObservationCompleting(t)
		o := f.mp.pendingOutpoints
		hookDAObservation(f, func(stage daCompleteStage, _ *daCompleteCommitPlan) {
			if stage == daCompleteEffects {
				o.mu.Lock()
				o.dropClaimLocked(f.relay.sets[[32]byte{0x51}].commit.member.token)
				o.mu.Unlock()
			}
		})
		before := daObservationCounts(o)
		if _, err := f.relay.AdmitDA(chunk.raw, LocalDAProvenance()); relayDispositionOf(err) != RelayAdmissionInternal {
			t.Fatalf("victim failure err=%v", err)
		}
		requireDAObservationDelta(t, o, before, [4]uint64{1, 1, 0, 1}, "post-reservation victim failure")
	})
	t.Run("failed preparation", func(t *testing.T) {
		f, a, _ := daCompleteCommitMismatchFixture(t, false)
		stages := hookDAObservation(f, nil)
		if _, err := f.relay.AdmitDA(append([]byte(nil), a.snapshot.TxBytes...), LocalDAProvenance()); err != ErrDARelayPayloadCommitmentMismatch { //nolint:errorlint // The direct sentinel is the existing refusal.
			t.Fatalf("failed preparation err=%v", err)
		}
		if len(*stages) != 0 {
			t.Fatalf("hook ran after failed preparation: %+v", *stages)
		}
	})
	t.Run("EFFECTS carries the planner's ordered victims", func(t *testing.T) {
		f, chunk := daObservationCompleting(t)
		daCompleteCommitFillCountLimit(f, daCompleteSetMaxCount, 2_000_000)
		victimID := [32]byte{2}
		mutateOwnerReadyRecord(f.relay, victimID, func(r *daRelaySetRecord) {
			r.commit.member.fee, r.chunks[0].member.fee = consensus.Uint128{Lo: 1}, consensus.Uint128{Lo: 1}
			r.completeIntrinsic.fee = consensus.Uint128{Lo: 2}
		})
		var victims [][32]byte
		hookDAObservation(f, func(stage daCompleteStage, plan *daCompleteCommitPlan) {
			if stage == daCompleteEffects {
				victims = slices.Clone(plan.capacity.victims)
			}
		})
		got, err := f.relay.AdmitDA(chunk.raw, LocalDAProvenance())
		requirePublicDAResult(t, got, err, DAAdmissionResult{DAID: [32]byte{0x51}, Disposition: DAAdmissionRetained})
		if !slices.Equal(victims, [][32]byte{victimID}) {
			t.Fatalf("EFFECTS victims=%x, want [%x]", victims, victimID)
		}
	})
}

func TestDAObservationBuildSeparation(t *testing.T) {
	if daCompleteSetMaxCount != 65536 {
		t.Fatalf("COMPLETE_SET count bound=%d, want 65536", daCompleteSetMaxCount)
	}
	const tagged = "da_observer_conformance.go"
	source, err := os.ReadFile(tagged)
	if err != nil || !strings.HasPrefix(string(source), "//go:build rubin_da_observer\n") {
		t.Fatalf("%s first line changed (err=%v)", tagged, err)
	}
	defaultPkg, err := build.Default.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(defaultPkg.GoFiles) != 67 || slices.Contains(defaultPkg.GoFiles, tagged) || !slices.Contains(defaultPkg.IgnoredGoFiles, tagged) {
		t.Fatalf("default build selects %d files, tagged file selected=%v", len(defaultPkg.GoFiles), slices.Contains(defaultPkg.GoFiles, tagged))
	}
	context := build.Default
	context.BuildTags = []string{"rubin_da_observer"}
	if taggedPkg, err := context.ImportDir(".", 0); err != nil || !slices.Contains(taggedPkg.GoFiles, tagged) {
		t.Fatalf("tagged build omits %s (err=%v)", tagged, err)
	}
	for _, name := range defaultPkg.GoFiles {
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if id, ok := node.(*ast.Ident); ok && strings.HasPrefix(id.Name, "DAObserver") {
				t.Fatalf("default-build %s names %s", name, id.Name)
			}
			return true
		})
	}
	for _, typ := range []reflect.Type{reflect.TypeFor[DARelayState](), reflect.TypeFor[PendingOutpointOwner]()} {
		for i := range typ.NumField() {
			if typ.Field(i).IsExported() {
				t.Fatalf("%s exports field %s", typ.Name(), typ.Field(i).Name)
			}
		}
	}
}
