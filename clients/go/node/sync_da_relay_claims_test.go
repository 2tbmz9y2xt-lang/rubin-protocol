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
			for token, claim := range mo.ownerIndex.byToken {
				if claim.domain == PendingOutpointDA {
					delete(mo.ownerIndex.byToken, token)
					return
				}
			}
			t.Fatal("no DA claim to remove")
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
			for _, claim := range mo.ownerIndex.byToken {
				if claim.domain == PendingOutpointDA {
					claim.finalized = false
					return
				}
			}
			t.Fatal("no DA claim to unfinalize")
		},
		"wrong domain": func(t *testing.T, c *canonicalClaimFixture, mo *canonicalMempoolPlan, daID [32]byte) {
			for _, claim := range mo.ownerIndex.byToken {
				if claim.domain == PendingOutpointDA {
					claim.domain = PendingOutpointStandardMempool
					return
				}
			}
			t.Fatal("no DA claim to redomain")
		},
		"txid mismatch": func(t *testing.T, c *canonicalClaimFixture, mo *canonicalMempoolPlan, daID [32]byte) {
			for _, claim := range mo.ownerIndex.byToken {
				if claim.domain == PendingOutpointDA {
					claim.txid[0] ^= 0xff
					return
				}
			}
			t.Fatal("no DA claim to retxid")
		},
		"input mismatch": func(t *testing.T, c *canonicalClaimFixture, mo *canonicalMempoolPlan, daID [32]byte) {
			for _, claim := range mo.ownerIndex.byToken {
				if claim.domain == PendingOutpointDA && len(claim.inputs) != 0 {
					claim.inputs[0].Vout ^= 0xff
					return
				}
			}
			t.Fatal("no DA claim to reinput")
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
		"locator row mismatch": func(t *testing.T, c *canonicalClaimFixture, mo *canonicalMempoolPlan, daID [32]byte) {
			for token, claim := range mo.ownerIndex.byToken {
				if claim.domain == PendingOutpointDA && len(claim.inputs) != 0 {
					mo.ownerIndex.byOutpoint[claim.inputs[0]] = pendingOutpointRow{token: token, txid: [32]byte{0xbb}}
					return
				}
			}
			t.Fatal("no DA claim to unbind")
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
	mo.dropCanonicalDAClaims(canonicalDAClaimProjection{
		dropped: map[PendingOutpointToken]struct{}{entry.token: {}},
	})
	if err := validateRestoredClaimBinding(mo.txs, mo.ownerIndex); err == nil {
		t.Fatal("the closing binding proof accepted a candidate whose D edit orphaned a retained entry")
	}
}
