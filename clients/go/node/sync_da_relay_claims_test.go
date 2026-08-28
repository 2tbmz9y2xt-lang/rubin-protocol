package node

import (
	"errors"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// Seam: A9 and R6 — the canonical transition's DA-claim phase. Every live DA
// member must hold exactly one finalized DA claim in the SAME private O1
// candidate the M/O half prepared, the claims of D1's removals must leave that
// candidate, and every claim defect must be TERMINAL before the durable commit.

// canonicalClaimFixture is one engine with retained DA members and the prepared
// M/O plan the D phase edits.
type canonicalClaimFixture struct {
	f     *canonicalMOFixture
	relay *DARelayState
	chain canonicalFinalChainContext
	tr    *canonicalTransition
}

func newCanonicalClaimFixture(t *testing.T, inputs int) *canonicalClaimFixture {
	t.Helper()
	f := newCanonicalMOFixture(t, inputs, MempoolConfig{})
	return &canonicalClaimFixture{f: f, relay: f.engine.DARelayState(), chain: f.canonicalDATestChain(t)}
}

// beginTransition opens the REAL canonical transition the D phase runs inside:
// the admission write fence is held and the owner is in transition, which is
// what prepareCanonicalMempoolPlan's live preflight requires. The cleanup
// publishes truth OLD, which releases both without installing any image.
func (c *canonicalClaimFixture) beginTransition(t *testing.T) {
	t.Helper()
	tr, err := c.f.engine.beginCanonicalTransition(&diagnosticBatch{})
	mustCanonicalMO(t, "beginCanonicalTransition", err)
	c.tr = tr
	t.Cleanup(func() {
		tr.publishCanonicalTransition(&canonicalTransitionPlan{final: c.chain.final}, canonicalFenceImage{}, canonicalTruthOld, nil, "")
	})
}

// plan builds the M/O half exactly as prepareCanonicalFenceImage does, so the D
// phase below edits the real candidate rather than a stand-in.
func (c *canonicalClaimFixture) plan(t *testing.T) canonicalMempoolPlan {
	t.Helper()
	c.beginTransition(t)
	snapshot, err := snapshotMempool(c.f.mp)
	mustCanonicalMO(t, "snapshotMempool", err)
	mo, err := prepareCanonicalMempoolPlan(c.f.mp, snapshot, c.chain.final, c.chain.mtp, 0, devnetGenesisChainID)
	mustCanonicalMO(t, "prepareCanonicalMempoolPlan", err)
	mo.pending.stableTip = pendingOutpointTipOf(c.chain.final)
	return mo
}

// daClaimTokens reports the DA-domain claim tokens of one prepared candidate,
// which is what the publication would install.
func daClaimTokens(plan canonicalMempoolPlan) map[PendingOutpointToken][32]byte {
	tokens := map[PendingOutpointToken][32]byte{}
	for token, claim := range plan.ownerIndex.byToken {
		if claim.domain == PendingOutpointDA {
			tokens[token] = claim.txid
		}
	}
	return tokens
}

// firstDAClaim returns one DA-domain claim of the prepared candidate; every
// defect row below corrupts whichever member it happens to name, since each is
// an equally valid subject.
func firstDAClaim(t *testing.T, mo *canonicalMempoolPlan) (PendingOutpointToken, *pendingOutpointClaim) {
	t.Helper()
	for token, claim := range mo.ownerIndex.byToken {
		if claim.domain == PendingOutpointDA {
			return token, claim
		}
	}
	t.Fatal("no DA claim in the candidate")
	return PendingOutpointToken{}, nil
}

// TestCanonicalDAClaimPhaseDropsExactlyTheRemovedMembersClaims is A9: the claims
// of the removed record leave the candidate — from BOTH index halves and from the
// ordered claim list — and every surviving claim keeps its exact token identity.
func TestCanonicalDAClaimPhaseDropsExactlyTheRemovedMembersClaims(t *testing.T) {
	c := newCanonicalClaimFixture(t, 4)
	kept, dropped := daRelayTestID(0x71), daRelayTestID(0x72)
	c.f.daSet(t, c.relay, kept, c.f.ops[:2], 1600)
	droppedSet := c.f.daSet(t, c.relay, dropped, c.f.ops[2:4], 1610)
	// The dropped record's commit spends ops[2]; removing that outpoint from C1
	// makes exactly its record final-invalid.
	c.chain.final.mu.Lock()
	delete(c.chain.final.Utxos, c.f.ops[2])
	c.chain.final.mu.Unlock()

	mo := c.plan(t)
	beforeTokens := daClaimTokens(mo)
	image, err := prepareCanonicalDAImage(c.relay, nil, c.chain, &mo)
	mustCanonicalMO(t, "prepareCanonicalDAImage", err)
	if image == nil {
		t.Fatal("no prepared D image")
	}
	if _, present := image.projected.sets[dropped]; present {
		t.Fatal("the final-invalid record survived D1")
	}
	if _, present := image.projected.sets[kept]; !present {
		t.Fatal("D1 removed a chain-valid record")
	}

	afterTokens := daClaimTokens(mo)
	droppedTxIDs := map[[32]byte]struct{}{txID(t, droppedSet.commit): {}}
	for _, chunk := range droppedSet.chunks {
		droppedTxIDs[txID(t, chunk)] = struct{}{}
	}
	for token, txid := range beforeTokens {
		_, removedMember := droppedTxIDs[txid]
		_, stillClaimed := afterTokens[token]
		if removedMember == stillClaimed {
			t.Fatalf("claim for %x: removed_member=%v still_claimed=%v", txid, removedMember, stillClaimed)
		}
	}
	// Both index halves and the ordered list agree.
	for token, claim := range mo.ownerIndex.byToken {
		for _, input := range claim.inputs {
			if row := mo.ownerIndex.byOutpoint[input]; row.token != token {
				t.Fatalf("surviving claim %x lost its by-outpoint row", claim.txid)
			}
		}
	}
	listed := 0
	for _, claim := range mo.pending.claims {
		if claim.domain == PendingOutpointDA {
			listed++
		}
		if _, drop := droppedTxIDs[claim.txid]; drop && claim.domain == PendingOutpointDA {
			t.Fatalf("the ordered claim list kept removed DA claim %x", claim.txid)
		}
	}
	if listed != len(afterTokens) {
		t.Fatalf("ordered DA claims=%d, index DA claims=%d", listed, len(afterTokens))
	}
	for _, input := range c.f.ops[2:4] {
		if _, present := mo.ownerIndex.byOutpoint[input]; present {
			t.Fatalf("a removed member's outpoint row %x survived", input.Txid)
		}
	}
}

// TestCanonicalDAClaimPhaseIsTerminalForEveryClaimDefect is R6: each defect class
// is TERMINAL_LOCAL_INVARIANT before any publication, and the live retained
// image, the live owner and the prepared candidate are all left untouched.
func TestCanonicalDAClaimPhaseIsTerminalForEveryClaimDefect(t *testing.T) {
	for name, corrupt := range map[string]func(t *testing.T, c *canonicalClaimFixture, mo *canonicalMempoolPlan, daID [32]byte){
		"missing claim": func(t *testing.T, c *canonicalClaimFixture, mo *canonicalMempoolPlan, daID [32]byte) {
			token, _ := firstDAClaim(t, mo)
			delete(mo.ownerIndex.byToken, token)
		},
		"orphan claim": func(t *testing.T, c *canonicalClaimFixture, mo *canonicalMempoolPlan, daID [32]byte) {
			var txid [32]byte
			txid[0] = 0xaa
			// tokenHighWater+1: an EXTRA claim, never a collision with a live
			// member's token, so this row reaches checkNoOrphanCanonicalDAClaims
			// instead of corrupting an existing member's binding.
			token := PendingOutpointToken{owner: mo.owner, seq: mo.ownerIndex.tokenHighWater + 1}
			mo.ownerIndex.byToken[token] = &pendingOutpointClaim{
				token: token, domain: PendingOutpointDA, txid: txid,
				inputs: []consensus.Outpoint{{Txid: txid}}, finalized: true,
			}
		},
		"unfinalized claim": func(t *testing.T, c *canonicalClaimFixture, mo *canonicalMempoolPlan, daID [32]byte) {
			_, claim := firstDAClaim(t, mo)
			claim.finalized = false
		},
		"wrong domain": func(t *testing.T, c *canonicalClaimFixture, mo *canonicalMempoolPlan, daID [32]byte) {
			_, claim := firstDAClaim(t, mo)
			claim.domain = PendingOutpointStandardMempool
		},
		"txid mismatch": func(t *testing.T, c *canonicalClaimFixture, mo *canonicalMempoolPlan, daID [32]byte) {
			_, claim := firstDAClaim(t, mo)
			claim.txid[0] ^= 0xff
		},
		"input mismatch": func(t *testing.T, c *canonicalClaimFixture, mo *canonicalMempoolPlan, daID [32]byte) {
			// Every finalized DA claim carries 1..MAX_TX_INPUTS inputs
			// (validatePendingOutpointRequest), so inputs[0] always exists.
			_, claim := firstDAClaim(t, mo)
			claim.inputs[0].Vout ^= 0xff
		},
		"two members sharing one claim": func(t *testing.T, c *canonicalClaimFixture, mo *canonicalMempoolPlan, daID [32]byte) {
			// The record's commit and its first chunk both name the commit's
			// token: the duplicate is the retained image's defect, not the
			// candidate's, and the phase must refuse it all the same.
			c.relay.mu.Lock()
			defer c.relay.mu.Unlock()
			record := c.relay.sets[daID]
			chunk := record.chunks[0]
			chunk.token = record.commit.token
			record.chunks[0] = chunk
		},
		"member naming a token this owner never issued": func(t *testing.T, c *canonicalClaimFixture, mo *canonicalMempoolPlan, daID [32]byte) {
			c.relay.mu.Lock()
			defer c.relay.mu.Unlock()
			record := c.relay.sets[daID]
			chunk := record.chunks[0]
			chunk.token = PendingOutpointToken{owner: mo.owner, seq: mo.ownerIndex.tokenHighWater + 99}
			record.chunks[0] = chunk
		},
		"stored ordered inputs contradicting the member's own retained bytes": func(t *testing.T, c *canonicalClaimFixture, mo *canonicalMempoolPlan, daID [32]byte) {
			// The stored inputs and the CLAIM built from them are moved TOGETHER,
			// which is the only faithful shape of this defect: the claim phase
			// compares the member against the claim, so the two agree with each
			// other while neither is what the member's own bytes spend. Nothing
			// but a comparison against the parse can see it — D1 would otherwise
			// keep a transaction spending A under a claim protecting B.
			moved := consensus.Outpoint{Txid: [32]byte{0x5a}, Vout: 7}
			c.relay.mu.Lock()
			defer c.relay.mu.Unlock()
			record := c.relay.sets[daID]
			chunk := record.chunks[0]
			for _, input := range chunk.inputs {
				delete(mo.ownerIndex.byOutpoint, input)
			}
			chunk.inputs = []consensus.Outpoint{moved}
			mo.ownerIndex.byToken[chunk.token].inputs = []consensus.Outpoint{moved}
			mo.ownerIndex.byOutpoint[moved] = pendingOutpointRow{token: chunk.token, txid: chunk.txid}
			record.chunks[0] = chunk
		},
		"locator row mismatch": func(t *testing.T, c *canonicalClaimFixture, mo *canonicalMempoolPlan, daID [32]byte) {
			token, claim := firstDAClaim(t, mo)
			mo.ownerIndex.byOutpoint[claim.inputs[0]] = pendingOutpointRow{token: token, txid: [32]byte{0xbb}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := newCanonicalClaimFixture(t, 3)
			daID := daRelayTestID(0x73)
			c.f.daSet(t, c.relay, daID, c.f.ops[:3], 1620)
			mo := c.plan(t)
			corrupt(t, c, &mo, daID)
			liveBefore := daRelayStateSnapshot(c.relay)

			image, err := prepareCanonicalDAImage(c.relay, nil, c.chain, &mo)
			var terminal *canonicalDATerminalError
			if !errors.As(err, &terminal) {
				t.Fatalf("err=%v, want a retained-DA terminal invariant", err)
			}
			if image != nil {
				t.Fatal("a terminal claim defect still produced a publishable image")
			}
			requireDARelayStateUnchanged(t, c.relay, liveBefore)
		})
	}
}

// TestCanonicalDAPreparationIsTerminalForEveryLocatorAndIdentityDefect is the
// LOCATOR half of the one bijection D preparation proves, plus the stored member
// identity the role checks alone cannot bind.
//
// None of these defects is visible to the claim phase — a member the index
// forgot, a row pointing at no live member, and a member whose stored identity is
// not the one its own bytes produce all leave every member-to-claim binding
// intact. Each is TERMINAL during planning, before the durable commit, with the
// live image and the prepared candidate untouched.
//
// The nil-plan arm is deliberately included: the locator index exists whether or
// not an owner is bound, so the phase must not be skippable with the claim one.
func TestCanonicalDAPreparationIsTerminalForEveryLocatorAndIdentityDefect(t *testing.T) {
	for name, tt := range map[string]struct {
		owned   bool
		corrupt func(t *testing.T, c *canonicalClaimFixture, daID [32]byte)
	}{
		"member with no locator row": {true, func(t *testing.T, c *canonicalClaimFixture, daID [32]byte) {
			c.relay.mu.Lock()
			defer c.relay.mu.Unlock()
			delete(c.relay.locators, c.relay.sets[daID].chunks[0].txid)
		}},
		"member whose locator row names another slot": {true, func(t *testing.T, c *canonicalClaimFixture, daID [32]byte) {
			c.relay.mu.Lock()
			defer c.relay.mu.Unlock()
			c.relay.locators[c.relay.sets[daID].chunks[0].txid] = daRelayLocator{daID: daID, kind: daRelayLocatorCommit}
		}},
		"locator row resolving to no live member": {true, func(t *testing.T, c *canonicalClaimFixture, daID [32]byte) {
			c.relay.mu.Lock()
			defer c.relay.mu.Unlock()
			c.relay.locators[[32]byte{0xdd}] = daRelayLocator{daID: daID, kind: daRelayLocatorChunk, chunkIndex: 9}
		}},
		"stored payload commitment contradicting its own retained bytes": {true, func(t *testing.T, c *canonicalClaimFixture, daID [32]byte) {
			// The commit's cached copy of its own COV_TYPE_DA_COMMIT output. It
			// alone decides whether an arriving last chunk completes the set or
			// is refused, and no other phase compares it with the bytes.
			c.relay.mu.Lock()
			defer c.relay.mu.Unlock()
			record := c.relay.sets[daID]
			record.commit.payloadCommitment[0] ^= 0xff
			c.relay.sets[daID] = record
		}},
		"stored member identity contradicting its own retained bytes": {true, func(t *testing.T, c *canonicalClaimFixture, daID [32]byte) {
			c.relay.mu.Lock()
			defer c.relay.mu.Unlock()
			record := c.relay.sets[daID]
			chunk := record.chunks[0]
			chunk.wtxid[0] ^= 0xff
			record.chunks[0] = chunk
		}},
		"member with no locator row and no owner image": {false, func(t *testing.T, c *canonicalClaimFixture, daID [32]byte) {
			c.relay.mu.Lock()
			defer c.relay.mu.Unlock()
			delete(c.relay.locators, c.relay.sets[daID].chunks[0].txid)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			c := newCanonicalClaimFixture(t, 3)
			daID := daRelayTestID(0x78)
			c.f.daSet(t, c.relay, daID, c.f.ops[:3], 1670)
			var mo *canonicalMempoolPlan
			if tt.owned {
				prepared := c.plan(t)
				mo = &prepared
			}
			tt.corrupt(t, c, daID)
			liveBefore := daRelayStateSnapshot(c.relay)

			image, err := prepareCanonicalDAImage(c.relay, nil, c.chain, mo)
			var terminal *canonicalDATerminalError
			if !errors.As(err, &terminal) {
				t.Fatalf("err=%v, want a retained-DA terminal invariant", err)
			}
			if image != nil {
				t.Fatal("a terminal locator defect still produced a publishable image")
			}
			requireDARelayStateUnchanged(t, c.relay, liveBefore)
		})
	}
}

// TestCanonicalDAPreparationIsTerminalForEveryCorruptStoredRecordField covers
// the record-level fields no other walk binds: the closed state set, the cached
// chunk payload, and payloadBytes — the pinned charge and complete-set sizing
// input the accounting sweep cannot judge, deriving both sides from it. The
// subject is deliberately an INCOMPLETE record and every corruption keeps the
// payload LENGTH: on a COMPLETE_SET, or with a resize, the accounting sweep
// would keep the row terminal for a reason that is not the binding under test.
func TestCanonicalDAPreparationIsTerminalForEveryCorruptStoredRecordField(t *testing.T) {
	for name, corrupt := range map[string]func(record *daRelaySetRecord){
		"record state outside the closed set":                func(r *daRelaySetRecord) { r.state = daRelaySetState(0xff) },
		"record payload bytes contradicting its members":     func(r *daRelaySetRecord) { r.payloadBytes++ },
		"chunk payload contradicting its own retained bytes": func(r *daRelaySetRecord) { r.chunks[0].payload[0] ^= 0xff },
	} {
		t.Run(name, func(t *testing.T) {
			c := newCanonicalClaimFixture(t, 2)
			daID, owner := daRelayTestID(0x79), c.f.mp.PendingOutpointOwner()
			retainDAMemberForTest(t, c.relay, owner, c.f.daCommitTxCommitting(t, c.f.ops[0], daID, 2, 1680, [32]byte{0x01}), "peer-commit")
			retainDAMemberForTest(t, c.relay, owner, c.f.daChunkTx(t, c.f.ops[1], daID, 0, 1681, []byte("payload")), "peer-chunk")
			mo := c.plan(t)
			if _, err := prepareCanonicalDAImage(c.relay, nil, c.chain, &mo); err != nil {
				t.Fatalf("the uncorrupted State B record is already refused: %v", err)
			}

			c.relay.mu.Lock()
			record := c.relay.sets[daID]
			corrupt(&record)
			c.relay.sets[daID] = record
			c.relay.mu.Unlock()
			liveBefore := daRelayStateSnapshot(c.relay)

			image, err := prepareCanonicalDAImage(c.relay, nil, c.chain, &mo)
			var terminal *canonicalDATerminalError
			if !errors.As(err, &terminal) {
				t.Fatalf("err=%v, want a retained-DA terminal invariant", err)
			}
			if image != nil {
				t.Fatal("a corrupt stored record field still produced a publishable image")
			}
			requireDARelayStateUnchanged(t, c.relay, liveBefore)
		})
	}
}

// TestCanonicalDAClaimPhaseIsSkippedWithoutAnOwnerImage pins the nil-plan arm: an
// engine with no standard/owner image bound has no claim domain to bind to, so
// the phase is skipped rather than inventing one.
func TestCanonicalDAClaimPhaseIsSkippedWithoutAnOwnerImage(t *testing.T) {
	c := newCanonicalClaimFixture(t, 3)
	c.f.daSet(t, c.relay, daRelayTestID(0x74), c.f.ops[:3], 1630)
	image, err := prepareCanonicalDAImage(c.relay, nil, c.chain, nil)
	mustCanonicalMO(t, "prepareCanonicalDAImage(nil plan)", err)
	if image == nil {
		t.Fatal("no prepared D image without an owner plan")
	}
}

// TestCanonicalTransitionPublishesTheDropClaimImage is the end-to-end A9 row: a
// real transition removes a final-invalid retained record AND its DA claims from
// the LIVE owner, through the one existing M/O publisher.
func TestCanonicalTransitionPublishesTheDropClaimImage(t *testing.T) {
	f := newCanonicalMOFixture(t, 4, MempoolConfig{})
	relay := f.engine.DARelayState()
	// The commit spends an output the DISCONNECTED block creates: valid now,
	// final-invalid once that block leaves.
	created := consensus.Outpoint{Txid: txID(t, f.raw(t, f.ops[0], 3, false))}
	mustCanonicalMO(t, "ApplyBlock(spend)", f.applySpend(t, f.ops[0], 3))
	dropped, kept := daRelayTestID(0x75), daRelayTestID(0x76)
	droppedSet := f.daSet(t, relay, dropped, []consensus.Outpoint{created, f.ops[1]}, 1640)
	keptSet := f.daSet(t, relay, kept, f.ops[2:4], 1650)
	owner := f.mp.PendingOutpointOwner()
	owner.mu.Lock()
	claimsBefore := len(owner.byToken)
	owner.mu.Unlock()

	_, err := f.engine.DisconnectTip()
	mustCanonicalMO(t, "DisconnectTip", err)

	if _, present := relay.sets[dropped]; present {
		t.Fatal("the final-invalid record survived the transition")
	}
	if _, present := relay.sets[kept]; !present {
		t.Fatal("the transition removed a chain-valid record")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if got := claimsBefore - len(owner.byToken); got != len(droppedSet.chunks)+1 {
		t.Fatalf("live DA claims released=%d, want the removed record's %d members", got, len(droppedSet.chunks)+1)
	}
	for _, raw := range append([][]byte{keptSet.commit}, keptSet.chunks...) {
		found := false
		for _, claim := range owner.byToken {
			if claim.domain == PendingOutpointDA && claim.txid == txID(t, raw) && claim.finalized {
				found = true
			}
		}
		if !found {
			t.Fatalf("a surviving member lost its finalized DA claim: %x", txID(t, raw))
		}
	}
}

// TestClosingClaimBindingProofRunsOverTheEditedCandidate is the ORDERING row for
// prepareCanonicalFenceImage's final rebuild-and-preflight step: the closing
// validateRestoredClaimBinding speaks about the candidate AFTER the D phase
// edited it, so a D-phase edit that retires a claim a surviving record still
// needs is caught BEFORE publication.
//
// The edit is applied through the production helper the transition calls, and the
// proof is the production check the transition then runs, composed in the same
// order. On every REACHABLE input the D phase retires DA claims only, so this
// guard cannot fire from the transition itself; a row that damaged the candidate
// through the real call site would need a production seam the contract forbids.
func TestClosingClaimBindingProofRunsOverTheEditedCandidate(t *testing.T) {
	c := newCanonicalClaimFixture(t, 3)
	c.f.daSet(t, c.relay, daRelayTestID(0x77), c.f.ops[1:3], 1660)
	standard := c.f.add(t, c.f.ops[0], 7)
	mo := c.plan(t)
	if err := validateRestoredClaimBinding(mo.txs, mo.ownerIndex); err != nil {
		t.Fatalf("the prepared candidate is already unbound: %v", err)
	}
	entry, ok := mo.txs[standard]
	if !ok {
		t.Fatalf("the standard entry %x is not in the candidate", standard)
	}
	mo.dropCanonicalDAClaims(canonicalDAClaimProjection{entry.token: {}})
	if err := validateRestoredClaimBinding(mo.txs, mo.ownerIndex); err == nil {
		t.Fatal("the closing binding proof accepted a candidate whose D edit orphaned a retained entry")
	}
}
