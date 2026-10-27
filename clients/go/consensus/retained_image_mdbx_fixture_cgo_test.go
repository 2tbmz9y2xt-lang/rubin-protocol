//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

func TestRetainedImageMDBXCommitOutcomes(t *testing.T) {
	t.Run("D24-six-raw-classes", rifKinds)
	t.Run("D24-complete-key-frontier", rifNodeFrontier)
	t.Run("D15-G15-old-prefix", rifPrefix)
	t.Run("D15-G15-evidence-matrix", rifEvidence)
	t.Run("D10-G15-needed-frontiers", rifEdges)
	t.Run("D15-G15-earlier-groups", rifGroups)
	t.Run("D28-qualified-late-header", rifLate)
	t.Run("D7-D12-whole-undo", rifUndo)
	t.Run("D2-D17-per-kind-windows", rifWindows)
	t.Run("D12-native-acquisition-frontiers", rifResources)
	t.Run("D14-caller-unwind", rifUnwind)
	t.Run("D5-detached-frontier", rifDetached)
	t.Run("D8-role-origin", rifOrigins)
	t.Run("D9-checked-pre-arithmetic", rifOverflow)
	t.Run("D11-D14-D20-D27-first-source", rifSources)
}

func rifEdges(t *testing.T) {
	for _, name := range []string{"missing-prior-true", "wrong-hash-prior-true", "unverifiable-gap", "no-header-false", "unhealthy-header-true", "invalid-work-no-R", "R-before-body", "stronger-all-kinds-false", "orphan-R"} {
		t.Run(name, func(t *testing.T) {
			w := rifWorld(t, 3)
			z, _ := rifBody(t, w, 0)
			y := [32]byte{0xee}
			want, complete := uint64(622), false
			switch name {
			case "missing-prior-true":
				rifForward(t, w, 3, 1, z, [32]byte{})
				rifReverse(t, w, 3, 0, z)
			case "wrong-hash-prior-true":
				rifForward(t, w, 3, 0, y, [32]byte{})
				rifReverse(t, w, 3, 0, y)
				rifForward(t, w, 3, 1, z, [32]byte{})
				rifReverse(t, w, 3, 0, z)
				want = 734
			case "unverifiable-gap":
				key, _ := mdbx.HeightKey(3, 0)
				rifSeed(t, w, 2, append(key, 0), []byte{1})
				rifForward(t, w, 3, 2, z, [32]byte{})
				rifReverse(t, w, 3, 1, z)
				want = 0
			case "no-header-false":
				logicalMDBXAssert(t, mdbx.FixtureStartupDeleteRow(w.s, 3, z[:]) == nil, "remove optional projection")
				rifForward(t, w, 3, 0, z, [32]byte{})
				want = 176
			case "unhealthy-header-true":
				rifSeed(t, w, 3, z[:], []byte{1})
				rifForward(t, w, 3, 0, z, [32]byte{})
				rifReverse(t, w, 3, 0, z)
				want, complete = 176, true
			case "invalid-work-no-R":
				key, _ := mdbx.HeightKey(3, 0)
				rifSeed(t, w, 2, key, mdbx.ChainValue(z, [32]byte{}, [40]byte{}))
				want, complete = 176, true
			case "R-before-body":
				rifForward(t, w, 3, 0, z, [32]byte{})
				rifSeed(t, w, 4, z[:], initial148BlockGenesis(t)[:149])
				want = 0
			case "stronger-all-kinds-false":
				w, _, z = riGenesis(t)
				riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) { a.Authority.Phase, a.Authority.Cleanup = 2, &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: 1, GenerationID: 3}}} })
				rifForward(t, w, 3, 0, y, [32]byte{})
				rifForward(t, w, 3, 1, z, [32]byte{})
				want = 1003
			case "orphan-R":
				rifReverse(t, w, 3, 0, y)
				want, complete = 64, true
			}
			var out rifResult
			if name == "R-before-body" || name == "invalid-work-no-R" {
				key, _ := mdbx.CanonicalOwnerKey(3, z)
				evidence, harness := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageStartupPullEIO, 7, append(cleanupDrainPredecessor(key), 0), func() { out = rifRun(t, w, nil, "source") })
				if name == "R-before-body" {
					logicalMDBXAssert(t, harness == nil && evidence.Faults == 1 && evidence.OldGets[4] == 0, "protected body preceded needed R: %+v/%v", evidence, harness)
					f := riResource(t, out.source, "branch_data")
					btfEngine(t, f.Cause, "prefix-page", "IO", 5, "error 5")
					undoNativeConsumed(t, w.s, out.native.err)
					return
				}
				logicalMDBXAssert(t, harness != nil && evidence.Faults == 0 && harness.Error() == "selected damage fixture site was not reached exactly as armed", "inadmissible forward acquired R")
			} else {
				out = rifRun(t, w, nil, "source")
			}
			if want == 0 {
				f := riResource(t, out.source, "branch_data")
				logicalMDBXAssert(t, f.Cause.Error() == "retained exact range is unverifiable" && out.image == (retainedPreImageV1{}), "gap guessed absent: %+v/%v", out.image, f.Cause)
			} else {
				logicalMDBXAssert(t, out.source == nil && out.image.exactRet == want && out.image.complete[0] == (retainedCompleteV1{3, complete}), "cold edge proof: %+v/%v want%d/%v", out.image, out.source, want, complete)
			}
			rifOpen(t, w)
		})
	}
}

func rifDetached(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(fmt.Sprintf("cursor-malformed%v", malformed), func(t *testing.T) {
			w := rifWorld(t, 3)
			z, body := rifBody(t, w, 0)
			y, _ := rifBody(t, w, 1)
			encoded := riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) {
				a.Authority.DetachedSuffix = &mdbx.DetachedSuffixV1{Entries: []mdbx.DetachedSuffixEntryV1{{Height: 6, Hash: z, BlockBytesLen: 298}, {Height: 5, Hash: y, BlockBytesLen: 298}}, Cursor: mdbx.AuthorityPointV1{Height: 6, BlockHash: z}, EntryCount: 2, LogicalBytes: 596}
			})
			var out rifResult
			var evidence mdbx.SelectedDamageEvidence
			var harness error
			if malformed {
				rifSeed(t, w, 4, z[:], body[:149])
				evidence, harness = mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageGetEIO, 3, y[:], func() { out = rifRun(t, w, nil, "source") })
				riResource(t, out.source, "storage_capacity")
				logicalMDBXAssert(t, out.image == (retainedPreImageV1{}), "cursor refusal emitted scalar")
			} else {
				evidence, harness = mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageStartupPullEIO, 5, z[:], func() { out = rifRun(t, w, nil, "source") })
				logicalMDBXAssert(t, out.source == nil && out.image.exactRet == 956 && evidence.OldPulls[5] == 0, "detached charged undo or lost row: %+v/%v", out.image, out.source)
			}
			logicalMDBXAssert(t, harness != nil && harness.Error() == "selected damage fixture site was not reached exactly as armed" && evidence.Faults == 0 && evidence.NodePulls == 0, "detached order/undo frontier: %+v/%v", evidence, harness)
			w.read(t, 0, []byte{2}, encoded)
			rifOpen(t, w)
		})
	}
}

func rifOrigins(t *testing.T) {
	for _, member := range []string{"chain", "genesis", "counter-envelope", "CURRENT-counter", "CURRENT-root", "LAG-counter", "LAG-root"} {
		t.Run(member, func(t *testing.T) {
			w := btNew(t)
			if member == "chain" || member == "genesis" {
				var root mdbx.RootBindingV1
				logicalMDBXAssert(t, w.s.View(func(r *mdbx.Reader) error { var err error; root, _, err = r.ReadTreeRootBindingV1(2); return err }) == nil, "read origin source")
				if member == "chain" {
					root.ChainID[0] = 1
				} else {
					root.GenesisHash[0] = 1
				}
				encoded, err := root.Encode()
				logicalMDBXAssert(t, err == nil, "origin source encode")
				rifSeed(t, w, 0, btMeta(0x11, 2), encoded)
			} else if member == "counter-envelope" {
				rifSeed(t, w, 0, btMeta(0x10, 1), mdbx.LogicalCounterValue(55, 1))
			} else {
				g, tag := uint64(1), byte(0x10)
				if member[:3] == "LAG" {
					g = 2
				}
				if member == "CURRENT-root" || member == "LAG-root" {
					tag = 0x11
				}
				logicalMDBXAssert(t, mdbx.FixtureStartupDeleteRow(w.s, 0, btMeta(tag, g)) == nil, "delete role source")
			}
			var out rifResult
			if member == "CURRENT-counter" || member == "CURRENT-root" || member == "LAG-counter" {
				g, tag := uint64(1), byte(0x11)
				if member == "CURRENT-root" {
					g, tag = 2, 0x10
				}
				if member == "LAG-counter" {
					g = 2
				}
				evidence, harness := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageGetEIO, 0, btMeta(tag, g), func() { out = rifRun(t, w, nil, "source") })
				logicalMDBXAssert(t, harness != nil && harness.Error() == "selected damage fixture site was not reached exactly as armed" && evidence.Faults == 0, "later role preceded missing source: %+v/%v", evidence, harness)
			} else {
				out = rifRun(t, w, nil, "source")
			}
			var failure *logicalStateFailure
			logicalMDBXAssert(t, errors.As(out.source, &failure) && failure != nil && failure.kind == logicalStateFailureStoreIntegrity && failure.cause != nil && out.image == (retainedPreImageV1{}), "bound role refusal: %+v/%v", out.image, out.source)
			rifOpen(t, w)
		})
	}
}

// These scalar-domain corruption controls make no complete-map or attained-store claim.
func rifOverflow(t *testing.T) {
	for _, entries := range []uint64{^uint64(0) / 56, ^uint64(0)/65596 + 1} {
		w := btNew(t)
		rifSeed(t, w, 0, btMeta(0x10, 1), mdbx.LogicalCounterValue(^uint64(0), entries))
		out := rifRun(t, w, nil, "source")
		f := riResource(t, out.source, "storage_capacity")
		logicalMDBXAssert(t, f.Cause == errRetainedArithmetic && out.image == (retainedPreImageV1{}), "checked pre sum/tree: %+v/%v", out.image, out.source)
		rifOpen(t, w)
	}
}

func rifSeed(t *testing.T, w *btWorld, rank uint8, key, value []byte) {
	t.Helper()
	logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, rank, key, value) == nil, "raw seed rank%d key%x", rank, key)
}

func rifWorld(t *testing.T, generations ...uint64) *btWorld {
	t.Helper()
	w := btNew(t)
	riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) {
		a.Authority.Phase, a.Authority.Cleanup = 2, &mdbx.CleanupV1{}
		for _, g := range generations {
			a.Authority.Cleanup.Spans = append(a.Authority.Cleanup.Spans, mdbx.CleanupSpanV1{Kind: 1, GenerationID: g})
		}
	})
	return w
}

func rifBody(t *testing.T, w *btWorld, salt byte) ([32]byte, []byte) {
	t.Helper()
	raw := initial148BlockGenesis(t)
	raw[140] ^= salt
	hash := sha3.Sum256(raw[:148])
	logicalMDBXAssert(t, ValidateInitial148BlockBodyCommitments(raw) == nil, "fixed148 body fixture invalid")
	rifSeed(t, w, 3, hash[:], raw[:148])
	rifSeed(t, w, 4, hash[:], raw)
	return hash, raw
}

func rifForward(t *testing.T, w *btWorld, g, h uint64, hash, parent [32]byte) {
	t.Helper()
	key, _ := mdbx.HeightKey(g, h)
	rifSeed(t, w, 2, key, mdbx.ChainValue(hash, parent, [40]byte{39: 1}))
}

func rifReverse(t *testing.T, w *btWorld, g, h uint64, hash [32]byte) {
	t.Helper()
	key, _ := mdbx.CanonicalOwnerKey(g, hash)
	rifSeed(t, w, 7, key, mdbx.CanonicalOwnerValue(h))
}

type rifResult struct {
	native      btResult
	image       retainedPreImageV1
	source      error
	application error
}

// rifRun exercises the producer inside the real storage callback and original account.
func rifRun(t *testing.T, w *btWorld, late *[32]byte, mode string, share ...uint64) rifResult {
	t.Helper()
	var out rifResult
	rifPerform(t, w, late, mode, &out, share...)
	return out
}

func rifPerform(t *testing.T, w *btWorld, late *[32]byte, mode string, out *rifResult, share ...uint64) {
	t.Helper()
	err := w.owner.WithOperation(mdbx.TreeOperation, func(account *mdbx.OperationAccount) error {
		err := account.WithReservation(8192+2313928, func() error {
			out.native.truth, out.native.stage, out.native.index, out.native.err = w.s.UpdateTreeV1(account, func(reader *mdbx.Reader) (mdbx.TreeOperationV1, error) {
				var read retainedReadV1
				defer func() { read = retainedReadV1{} }()
				out.source = prepareRetainedReadV1(&read, reader, account, late)
				if out.source == nil {
					quantity := func() error { out.image, out.source = readDirectRetainedMDBXV1(&read); return out.source }
					if len(share) != 0 {
						out.source = account.WithReservation(402653184-8192-2313928-share[0], quantity)
					} else {
						_ = quantity()
					}
				}
				if out.source != nil {
					again, err := readDirectRetainedMDBXV1(&read)
					riLocal(t, err)
					logicalMDBXAssert(t, again == (retainedPreImageV1{}), "failed context was reread")
				}
				out.application = rifCallback(mode, out.source)
				return mdbx.TreeOperationV1{}, out.application
			})
			return nil
		})
		logicalMDBXAssert(t, err == nil, "fixture outer frame: %v", err)
		ran := 0
		err = account.WithReservation(402653184, func() error { ran++; return nil })
		logicalMDBXAssert(t, err == nil && ran == 1, "fixture account restoration: %v", err)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "fixture original account: %v", err)
	btReservationsReleased(t, w.owner)
}

var rifComplete = errors.New("retained fixture complete callback refusal")

func rifCallback(mode string, source error) error {
	switch mode {
	case "nil":
		return nil
	case "wrapped":
		return fmt.Errorf("returned producer: %w", source)
	case "panic":
		panic("retained callback unwind")
	case "goexit":
		runtime.Goexit()
	}
	if source != nil {
		return source
	}
	return rifComplete
}

func rifOpen(t *testing.T, w *btWorld) {
	t.Helper()
	ran := 0
	err := w.s.View(func(*mdbx.Reader) error { ran++; return nil })
	logicalMDBXAssert(t, err == nil && ran == 1, "legal next operation did not run: %d/%v", ran, err)
}

func rifKinds(t *testing.T) {
	for _, row := range []struct {
		name   string
		class  uint8
		kind   mdbx.TreeNodeKindV1
		value  []byte
		charge uint64
	}{
		{"leaf", 8, 1, make([]byte, 32), 132}, {"branch", 8, 2, make([]byte, 140), 166},
		{"malformed-key", 8, 0, []byte{1}, 0}, {"leaf-malformed-value", 8, 1, []byte{1}, 132},
		{"branch-malformed-value", 8, 2, []byte{1}, 166},
		{"root-valid", 0, 0, nil, 96}, {"root-malformed-value", 0, 0, []byte{1}, 96},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := rifWorld(t, 3)
			key := btMeta(0x11, 3)
			value := row.value
			if row.class == 8 {
				key = binary.BigEndian.AppendUint64(nil, 3)
				if row.kind != 0 {
					id := mdbx.TreeNodeIDV1{Kind: row.kind, Depth: 288, RoutingKey: [36]byte{35: 1}}
					if row.kind == 2 {
						id.Depth, id.RoutingKey = 0, [36]byte{}
					}
					var err error
					key, err = mdbx.TreeNodeKey(3, id)
					logicalMDBXAssert(t, err == nil, "node key: %v", err)
					if row.name == "branch" {
						zero := mdbx.TreeNodeIDV1{Kind: 1, Depth: 288}
						one := mdbx.TreeNodeIDV1{Kind: 1, Depth: 288, RoutingKey: [36]byte{0x80}}
						value, err = (mdbx.TreeNodeV1{Zero: &mdbx.TreeChildV1{ID: zero}, One: &mdbx.TreeChildV1{ID: one}}).Encode(id)
						logicalMDBXAssert(t, err == nil && len(value) == 140, "healthy branch value: %v", err)
					}
				}
			} else if row.name == "root-valid" {
				root := mdbx.RootBindingV1{DatabaseID: [32]byte{7}, CommitmentVersion: 1, RootDigest: sha3.Sum256([]byte("RUBIN_UTXO_TREE_V1\x00")), Assurance: mdbx.TreeAssuranceV1{Kind: 1}}
				value, _ = root.Encode()
			}
			rifSeed(t, w, row.class, key, value)
			out := rifRun(t, w, nil, "source")
			out.native.want(t, 1, 1, -1)
			if row.charge == 0 {
				riResource(t, out.source, "storage_capacity")
				logicalMDBXAssert(t, out.image == (retainedPreImageV1{}), "malformed key emitted quantity")
			} else {
				logicalMDBXAssert(t, out.source == nil && out.image.exactRet == row.charge && out.image.complete[0] == (retainedCompleteV1{3, true}), "raw kind tariff %+v/%v", out.image, out.source)
			}
			rifOpen(t, w)
		})
	}
	t.Run("partial-remnants202-100-68-0", func(t *testing.T) {
		w := rifWorld(t, 3)
		leaf, _ := mdbx.TreeNodeKey(3, mdbx.TreeNodeIDV1{Kind: 1, Depth: 288})
		branch, _ := mdbx.TreeNodeKey(3, mdbx.TreeNodeIDV1{Kind: 2})
		root := btMeta(0x11, 3)
		for _, key := range [][]byte{leaf, branch} {
			rifSeed(t, w, 8, key, []byte{1})
		}
		rifSeed(t, w, 0, root, []byte{1})
		for _, step := range []struct {
			rank uint8
			key  []byte
			want uint64
		}{{0, nil, 266}, {8, branch, 164}, {0, root, 132}, {8, leaf, 64}} {
			if step.key != nil {
				logicalMDBXAssert(t, mdbx.FixtureStartupDeleteRow(w.s, step.rank, step.key) == nil, "remove exactly one partial term")
			}
			out := rifRun(t, w, nil, "source")
			logicalMDBXAssert(t, out.source == nil && out.image.exactRet == step.want && out.image.complete[0] == (retainedCompleteV1{3, true}), "actual remaining202/100/68/0: %+v/%v want%d", out.image, out.source, step.want)
			rifOpen(t, w)
		}
	})
}

func rifNodeFrontier(t *testing.T) {
	for _, valid := range []bool{false, true} {
		t.Run(fmt.Sprintf("first-valid%v", valid), func(t *testing.T) {
			w := rifWorld(t, 3)
			key := binary.BigEndian.AppendUint64(nil, 3)
			if valid {
				key, _ = mdbx.TreeNodeKey(3, mdbx.TreeNodeIDV1{Kind: 1, Depth: 288, RoutingKey: [36]byte{35: 1}})
			}
			rifSeed(t, w, 8, key, []byte{1})
			var out rifResult
			evidence, harness := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageStartupPullEIO, 8, append(bytes.Clone(key), 0), func() { out = rifRun(t, w, nil, "source") })
			out.native.want(t, 1, 1, -1)
			logicalMDBXAssert(t, out.image == (retainedPreImageV1{}) && evidence.BeginWrite == 0 && evidence.Commits == 0 && evidence.Deletes == 0 && evidence.OldAborts == 1, "node frontier native effects: %+v/%+v", out, evidence)
			if !valid {
				logicalMDBXAssert(t, harness != nil && harness.Error() == "selected damage fixture site was not reached exactly as armed" && evidence.NodePulls == 1 && evidence.Faults == 0, "deliberate unreached arm: %+v/%v", evidence, harness)
				riResource(t, out.source, "storage_capacity")
				rifOpen(t, w)
			} else {
				logicalMDBXAssert(t, harness == nil && evidence.NodePulls == 2 && evidence.Faults == 1, "next node pull: %+v/%v", evidence, harness)
				f := riResource(t, out.source, "branch_data")
				btfEngine(t, f.Cause, "prefix-page", "IO", 5, "error 5")
				undoNativeConsumed(t, w.s, out.native.err)
			}
		})
	}
	t.Run("failure-before-complete-key", func(t *testing.T) {
		w := rifWorld(t, 3)
		var out rifResult
		evidence, harness := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageStartupPullEIO, 8, binary.BigEndian.AppendUint64(nil, 3), func() { out = rifRun(t, w, nil, "source") })
		logicalMDBXAssert(t, harness == nil && evidence.NodePulls == 1 && evidence.Faults == 1 && out.image == (retainedPreImageV1{}), "pre-key native frontier: %+v/%v", evidence, harness)
		out.native.want(t, 1, 1, -1)
		f := riResource(t, out.source, "branch_data")
		btfEngine(t, f.Cause, "prefix-page", "IO", 5, "error 5")
		undoNativeConsumed(t, w.s, out.native.err)
	})
}

// One real forward family distinguishes each negative-evidence sibling under both old-prefix states.
func rifEvidence(t *testing.T) {
	for _, complete := range []bool{true, false} {
		for _, kind := range []string{"missing", "malformed", "out-of-domain", "self", "future", "absent-prior", "inadmissible-prior", "wrong-hash", "wrong-parent", "positive"} {
			t.Run(fmt.Sprintf("oldP%v/%s", complete, kind), func(t *testing.T) {
				w := rifWorld(t, 3)
				z, _ := rifBody(t, w, 0)
				y := [32]byte{0xee}
				want := uint64(622)
				hasPrior := kind == "inadmissible-prior" || kind == "wrong-hash" || kind == "wrong-parent" || kind == "positive"
				if hasPrior {
					want += 112
					switch kind {
					case "inadmissible-prior":
						key, _ := mdbx.HeightKey(3, 0)
						rifSeed(t, w, 2, key, mdbx.ChainValue(z, [32]byte{}, [40]byte{}))
					case "wrong-hash":
						rifForward(t, w, 3, 0, y, [32]byte{})
						rifReverse(t, w, 3, 0, y)
					case "wrong-parent":
						rifForward(t, w, 3, 0, z, [32]byte{1})
					case "positive":
						rifForward(t, w, 3, 0, z, [32]byte{})
					}
				}
				if !complete {
					rifForward(t, w, 3, 1, y, [32]byte{})
					// A separate absent optional header clears P without itself needing firstness.
					if kind == "wrong-hash" {
						key, _ := mdbx.CanonicalOwnerKey(3, y)
						logicalMDBXAssert(t, mdbx.FixtureStartupDeleteRow(w.s, 7, key) == nil, "clear earlier reciprocal")
					}
					want += 112
				}
				rifForward(t, w, 3, 2, z, [32]byte{})
				key, _ := mdbx.CanonicalOwnerKey(3, z)
				switch kind {
				case "missing":
				case "malformed":
					rifSeed(t, w, 7, key, make([]byte, 7))
				case "out-of-domain":
					rifSeed(t, w, 7, key, binary.BigEndian.AppendUint64(nil, 1<<32))
				case "self":
					rifReverse(t, w, 3, 2, z)
				case "future":
					rifReverse(t, w, 3, 3, z)
				default:
					rifReverse(t, w, 3, 0, z)
				}
				var out rifResult
				if complete && kind == "self" {
					evidence, harness := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageProbeOnly, 7, nil, func() { out = rifRun(t, w, nil, "source") })
					logicalMDBXAssert(t, harness == nil && evidence.Faults == 0 && evidence.OldPulls[7] == 2, "needed R fetched again for completeness: %+v/%v", evidence, harness)
				} else {
					out = rifRun(t, w, nil, "source")
				}
				if !complete && kind != "positive" {
					f := riResource(t, out.source, "branch_data")
					logicalMDBXAssert(t, f.Cause.Error() == "retained prefix membership is inconclusive" && out.image == (retainedPreImageV1{}), "FALSE negative inferred absence: %+v/%v", out.image, out.source)
				} else {
					final := kind == "self"
					logicalMDBXAssert(t, out.source == nil && out.image.exactRet == want && out.image.complete[0] == (retainedCompleteV1{3, final}), "old-prefix evidence: %+v/%v want%d/%v", out.image, out.source, want, final)
				}
				rifOpen(t, w)
			})
		}
	}
}

func rifPrefix(t *testing.T) {
	for _, row := range []struct {
		name        string
		reverse     int
		yReverse    bool
		wrongParent bool
		want        uint64
	}{
		{"missing-nonadjacent", -1, false, false, 0}, {"first-positive-false-prefix", 0, false, false, 846},
		{"self", 2, false, false, 0}, {"future", 3, false, false, 0}, {"malformed-R", -2, false, false, 0},
		{"wrong-parent-true", 0, true, true, 846}, {"wrong-parent-false", 0, false, true, 0},
		{"wrong-hash-false", 1, true, false, 0},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := rifWorld(t, 3)
			z, _ := rifBody(t, w, 0)
			y := [32]byte{0xee}
			parent := [32]byte{}
			if row.wrongParent {
				parent[0] = 1
			}
			rifForward(t, w, 3, 0, z, parent)
			rifForward(t, w, 3, 1, y, [32]byte{})
			rifForward(t, w, 3, 2, z, [32]byte{})
			if row.reverse >= 0 {
				rifReverse(t, w, 3, uint64(row.reverse), z)
			} else if row.reverse == -2 {
				key, _ := mdbx.CanonicalOwnerKey(3, z)
				rifSeed(t, w, 7, key, make([]byte, 7))
			}
			if row.yReverse {
				rifReverse(t, w, 3, 1, y)
			}
			out := rifRun(t, w, nil, "source")
			if row.want == 0 {
				riResource(t, out.source, "branch_data")
				logicalMDBXAssert(t, out.image == (retainedPreImageV1{}), "uncertain prefix emitted tuple: %+v", out.image)
			} else {
				logicalMDBXAssert(t, out.source == nil && out.image.exactRet == row.want && out.image.complete[0] == (retainedCompleteV1{3, false}), "positive prior/physical indexes: %+v/%v", out.image, out.source)
			}
			rifOpen(t, w)
		})
	}
}

func rifGroups(t *testing.T) {
	for _, name := range []string{"empty-negative", "positive-false", "negative-false", "wrong-parent-true", "wrong-parent-false", "new-group-prefix"} {
		t.Run(name, func(t *testing.T) {
			w := rifWorld(t, 3, 4)
			z, _ := rifBody(t, w, 0)
			y := [32]byte{0xee}
			want, firstComplete, secondComplete := uint64(622), true, true
			switch name {
			case "positive-false":
				rifForward(t, w, 3, 0, z, [32]byte{})
				rifForward(t, w, 3, 1, y, [32]byte{})
				rifForward(t, w, 3, 2, z, [32]byte{})
				rifReverse(t, w, 3, 0, z)
				want, firstComplete = 958, false
			case "negative-false":
				rifForward(t, w, 3, 0, z, [32]byte{})
				want = 0
			case "wrong-parent-true", "wrong-parent-false":
				rifForward(t, w, 3, 0, z, [32]byte{1})
				rifReverse(t, w, 3, 0, z)
				want = 734
				if name == "wrong-parent-false" {
					rifForward(t, w, 3, 1, y, [32]byte{})
					want = 0
				}
			case "new-group-prefix":
				secondComplete = false
			}
			rifForward(t, w, 4, 0, z, [32]byte{})
			if secondComplete {
				rifReverse(t, w, 4, 0, z)
			}
			var out rifResult
			if name == "negative-false" {
				key, _ := mdbx.CanonicalOwnerKey(4, z)
				evidence, harness := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageStartupPullEIO, 7, append(cleanupDrainPredecessor(key), 0), func() { out = rifRun(t, w, nil, "source") })
				logicalMDBXAssert(t, harness != nil && harness.Error() == "selected damage fixture site was not reached exactly as armed" && evidence.Faults == 0, "current R preceded earlier-group refusal: %+v/%v", evidence, harness)
			} else {
				out = rifRun(t, w, nil, "source")
			}
			if want == 0 {
				riResource(t, out.source, "branch_data")
				logicalMDBXAssert(t, out.image == (retainedPreImageV1{}), "earlier-group refusal emitted facts")
			} else {
				facts := [2]retainedCompleteV1{{3, firstComplete}, {4, secondComplete}}
				logicalMDBXAssert(t, out.source == nil && out.image.exactRet == want && out.image.complete == facts, "group proof/reset: %+v/%v want%d/%+v", out.image, out.source, want, facts)
			}
			rifOpen(t, w)
		})
	}
}

func rifLate(t *testing.T) {
	w := rifWorld(t, 3)
	x, body := rifBody(t, w, 0)
	logicalMDBXAssert(t, mdbx.FixtureStartupDeleteRow(w.s, 3, x[:]) == nil, "remove unowned header x")
	rifForward(t, w, 3, 0, x, [32]byte{})
	rifReverse(t, w, 3, 0, x)
	key, _ := mdbx.HeightKey(4, 0)
	rifSeed(t, w, 6, key, mdbx.ChainValue(x, [32]byte{}, [40]byte{39: 1}))
	riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) {
		a.Authority.Cleanup.Spans = append(a.Authority.Cleanup.Spans, mdbx.CleanupSpanV1{Kind: 4, GenerationID: 4})
	})
	// Actual stored BodyKind2 qualification occurs before giving the initializer its trusted late hash.
	err := riContext(t, w, nil, func(read *retainedReadV1) error {
		var source blockTreeSourceV1
		request := btRequest(body, 0)
		request.Kind, request.BodyKind, request.Raw = 1, 2, nil
		effect, err := prepareBlockTreeEffectV1(&source, read.reader, read.account, request)
		logicalMDBXAssert(t, err == nil && source.Raw == nil && effect.Primitive.Coverage.CurrentBody == nil && effect.CurrentBody.AfterKind == 0, "stored-source qualification: %+v/%v", effect, err)
		return err
	})
	logicalMDBXAssert(t, err == nil, "qualify late header source: %v", err)
	var out rifResult
	evidence, harness := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageGetEIO, 3, x[:], func() { out = rifRun(t, w, &x, "source") })
	logicalMDBXAssert(t, harness != nil && harness.Error() == "selected damage fixture site was not reached exactly as armed" && evidence.Faults == 0 && evidence.OldGets[3] == 0, "header x read before native slot: %+v/%v", evidence, harness)
	logicalMDBXAssert(t, out.source == nil && out.image.exactRet == 474 && out.image.complete[0] == (retainedCompleteV1{3, true}), "x zero pre-header/reciprocity: %+v/%v", out.image, out.source)
	rifOpen(t, w)
}

func rifFamily(t *testing.T, w *btWorld, hash [32]byte, height uint64, spent uint32, variant string) {
	t.Helper()
	manifest := mdbx.UndoManifestValue(height, [16]byte{}, 3, spent)
	if variant == "height" {
		manifest = mdbx.UndoManifestValue(height+1, [16]byte{}, 3, spent)
	}
	if variant == "malformed" {
		manifest = []byte{1}
	}
	if variant != "absent" {
		rifSeed(t, w, 5, mdbx.UndoManifestKey(hash), manifest)
	}
	if spent > 722 || variant == "zero" || variant == "absent" || variant == "malformed" {
		return
	}
	for i := uint32(0); i < spent; i++ {
		var txid [32]byte
		binary.BigEndian.PutUint32(txid[28:], i+1)
		coordinate, vout := i, i
		if variant == "duplicate" || variant == "coordinate" {
			txid, vout = [32]byte{1}, 0
		}
		if variant == "coordinate" {
			coordinate = 0
			vout = i
		}
		value := make([]byte, 20)
		if variant == "113" && i == 1 {
			value = append(make([]byte, 10), 1, 7)
			value = append(value, make([]byte, 9)...)
		}
		key := mdbx.UndoEntryKey(hash, txid, 1+coordinate/1024, coordinate%1024, vout)
		rifSeed(t, w, 5, key, value)
	}
	if variant == "extra" {
		rifSeed(t, w, 5, mdbx.UndoEntryKey(hash, [32]byte{9}, 2, 0, 9), make([]byte, 20))
	}
}

func rifUndo(t *testing.T) {
	for _, row := range []struct {
		name  string
		spent uint32
		want  uint64
	}{
		{"113", 2, 735}, {"zero", 0, 622}, {"722", 722, 41054},
		{"duplicate", 2, 0}, {"coordinate", 2, 0}, {"extra", 1, 0}, {"height", 1, 0},
		{"malformed", 0, 0}, {"envelope414634", 414634, 0}, {"envelope414635", 414635, 0},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := rifWorld(t, 3)
			z, _ := rifBody(t, w, 0)
			rifForward(t, w, 3, 5, z, [32]byte{})
			rifReverse(t, w, 3, 5, z)
			rifFamily(t, w, z, 5, row.spent, row.name)
			out := rifRun(t, w, nil, "source")
			if row.want != 0 {
				logicalMDBXAssert(t, out.source == nil && out.image.exactRet == row.want, "whole family sum: %+v/%v want%d", out.image, out.source, row.want)
			} else {
				f := riResource(t, out.source, "storage_capacity")
				logicalMDBXAssert(t, out.image == (retainedPreImageV1{}), "malformed family emitted scalar")
				if row.spent == 414634 {
					logicalMDBXAssert(t, f.Cause.Error() == "retained undo family is absent or incomplete", "maximum manifest rejected before whole-family count: %v", f.Cause)
				}
				if row.spent == 414635 {
					logicalMDBXAssert(t, f.Cause.Error() == "invalid cleanup canonical undo", "oversized manifest reached later family slot: %v", f.Cause)
				}
			}
			rifOpen(t, w)
		})
	}
	// Absence belongs to the required owner and must not equal the valid zero-spent family above.
	w, _, hash := riGenesis(t)
	logicalMDBXAssert(t, mdbx.FixtureStartupDeleteRow(w.s, 5, mdbx.UndoManifestKey(hash)) == nil, "delete required manifest")
	out := rifRun(t, w, nil, "source")
	var integrity *logicalStateFailure
	logicalMDBXAssert(t, errors.As(out.source, &integrity) && integrity != nil && integrity.kind == logicalStateFailureStoreIntegrity && out.image == (retainedPreImageV1{}), "required manifest absence: %+v/%v", out.image, out.source)
	rifOpen(t, w)
}

func rifSources(t *testing.T) {
	for _, mode := range []string{"nil", "source", "wrapped"} {
		for _, cleanup := range []bool{false, true} {
			t.Run(fmt.Sprintf("required-IO/%s/cleanup%v", mode, cleanup), func(t *testing.T) {
				w, _, hash := riGenesis(t)
				var out rifResult
				scenario := mdbx.SelectedDamageGetEIO
				if cleanup {
					scenario = mdbx.SelectedDamageGetAbortEIO
				}
				evidence, harness := mdbx.FixtureSelectedDamage(w.s, w.owner, scenario, 4, hash[:], func() { out = rifRun(t, w, nil, mode) })
				logicalMDBXAssert(t, harness == nil && evidence.Faults == 1+uint64(riBool(cleanup)) && evidence.BeginWrite == 0 && evidence.Commits == 0 && out.image == (retainedPreImageV1{}), "required source frontier: %+v/%v", evidence, harness)
				f := riResource(t, out.source, "canonical_artifact_read")
				btfEngine(t, f.Cause, "get", "IO", 5, "error 5")
				parts := genesisMDBXCauses(out.native.err)
				if mode == "nil" {
					logicalMDBXAssert(t, parts[0] == f.Cause, "ignored Reader failure changed primary")
				} else {
					logicalMDBXAssert(t, len(parts) >= 2 && errors.Is(parts[0], f.Cause) && parts[1] == f.Cause, "application/read source order: %v", parts)
				}
				if cleanup {
					btfEngine(t, parts[len(parts)-1], "abort", "IO", 5, "error 5")
				}
				undoNativeConsumed(t, w.s, out.native.err)
			})
		}
	}
	for _, source := range []string{"body-absent-before-SIDE", "counter-width", "active-binding", "required-header-before-R", "malformed-required-header-before-R"} {
		t.Run(source, func(t *testing.T) {
			w, genesis, hash := riGenesis(t)
			var evidence mdbx.SelectedDamageEvidence
			var harness error
			var out rifResult
			switch source {
			case "body-absent-before-SIDE":
				logicalMDBXAssert(t, mdbx.FixtureStartupDeleteRow(w.s, 4, hash[:]) == nil, "delete required body")
				child := bytes.Clone(genesis)
				child[140] ^= 1
				x := riSide(t, w, child, 3, 1)
				riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) { a.Authority.Phase, a.Authority.Cleanup = 2, &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: 4, GenerationID: 3, FirstHeight: 1, NextHeight: 1, LastHeight: 1}}} })
				evidence, harness = mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageGetEIO, 4, x[:], func() { out = rifRun(t, w, nil, "source") })
			case "counter-width":
				rifSeed(t, w, 0, btMeta(0x10, 1), make([]byte, 15))
				out = rifRun(t, w, nil, "source")
			case "active-binding":
				var healthy []byte
				logicalMDBXAssert(t, w.s.View(func(r *mdbx.Reader) error { healthy, _, _ = r.Get(mdbx.TreeSchemaV1DBIs()[0], btMeta(0x11, 1)); return nil }) == nil, "capture active binding")
				riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) { a.Authority.Phase, a.Authority.Cleanup = 2, &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: 1, GenerationID: 3}}} })
				rifSeed(t, w, 0, btMeta(0x11, 3), healthy)
				rifSeed(t, w, 0, btMeta(0x11, 1), []byte{0})
				out = rifRun(t, w, nil, "source")
			case "required-header-before-R", "malformed-required-header-before-R":
				riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) { a.Authority.ActiveProfile, a.Authority.U, a.Authority.Phase, a.Authority.Cleanup = 2, 1, 2, &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: 1, GenerationID: 3}}} })
				rifForward(t, w, 3, 0, hash, [32]byte{})
				if source == "required-header-before-R" {
					logicalMDBXAssert(t, mdbx.FixtureStartupDeleteRow(w.s, 3, hash[:]) == nil, "delete required header")
				} else {
					header := bytes.Clone(genesis[:148])
					header[140] ^= 1
					rifSeed(t, w, 3, hash[:], header)
				}
				key, _ := mdbx.CanonicalOwnerKey(3, hash)
				seek := append(cleanupDrainPredecessor(key), 0)
				evidence, harness = mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageStartupPullEIO, 7, seek, func() { out = rifRun(t, w, nil, "source") })
			}
			var integrity *logicalStateFailure
			logicalMDBXAssert(t, errors.As(out.source, &integrity) && integrity != nil && integrity.kind == logicalStateFailureStoreIntegrity && integrity.cause != nil && out.image == (retainedPreImageV1{}), "typed first integrity: %T %v/%+v", out.source, out.source, out.image)
			out.native.want(t, 1, 1, -1)
			if source == "body-absent-before-SIDE" || source == "required-header-before-R" || source == "malformed-required-header-before-R" {
				logicalMDBXAssert(t, harness != nil && harness.Error() == "selected damage fixture site was not reached exactly as armed" && evidence.Faults == 0 && evidence.OldGets[6] == 0 && evidence.OldPulls[7] == 0, "later source was observed: %+v/%v", evidence, harness)
				var invented *mdbx.EngineError
				logicalMDBXAssert(t, !errors.As(integrity.cause, &invented), "nil-error absence invented native error")
				rifOpen(t, w)
			} else {
				var native *mdbx.EngineError
				logicalMDBXAssert(t, errors.As(integrity.cause, &native) && native != nil && native.Operation == "get" && native.Class == "Integrity" && native.Code == -30796 && native.Diagnostic == "invalid tree native representation" && native.Cause != nil && !native.ReopenRequired, "actual required representation cause: %T %v", integrity.cause, integrity.cause)
				undoNativeConsumed(t, w.s, out.native.err)
			}
			btReservationsReleased(t, w.owner)
		})
	}
	for _, source := range []string{"SIDE-link-absent", "SIDE-link-malformed", "SIDE-link-IO"} {
		t.Run(source, func(t *testing.T) {
			w := btNew(t)
			riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) { a.Authority.Phase, a.Authority.Cleanup = 2, &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: 4, GenerationID: 3}}} })
			key, _ := mdbx.HeightKey(3, 0)
			if source == "SIDE-link-malformed" {
				rifSeed(t, w, 6, key, []byte{1})
			}
			var out rifResult
			if source == "SIDE-link-IO" {
				evidence, harness := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageGetEIO, 6, key, func() { out = rifRun(t, w, nil, "source") })
				logicalMDBXAssert(t, harness == nil && evidence.Faults == 1 && evidence.OldGets[3] == 0 && evidence.OldGets[4] == 0, "SideLink source frontier: %+v/%v", evidence, harness)
			} else {
				out = rifRun(t, w, nil, "source")
			}
			f := riResource(t, out.source, "branch_data")
			var native *mdbx.EngineError
			logicalMDBXAssert(t, errors.As(f.Cause, &native) && native != nil && native.Operation == "get" && out.image == (retainedPreImageV1{}), "unverifiable SideLink promoted or completed: %+v/%v", out.image, out.source)
			if source == "SIDE-link-IO" {
				btfEngine(t, native, "get", "IO", 5, "error 5")
			} else if source == "SIDE-link-absent" {
				logicalMDBXAssert(t, native.Class == "Integrity" && native.Code == -30793 && native.Diagnostic == "selected side link is absent" && native.Cause == nil && native.ReopenRequired, "actual absent link cause changed: %v", native)
			} else {
				logicalMDBXAssert(t, native.Class == "Integrity" && native.Code == -30796 && native.Diagnostic == "invalid tree native representation" && native.Cause != nil && !native.ReopenRequired, "actual malformed link cause changed: %v", native)
			}
			out.native.want(t, 1, 1, -1)
			undoNativeConsumed(t, w.s, out.native.err)
		})
	}
	// No process-wide latch was installed by any refusal above.
	w, _, _ := riGenesis(t)
	got, err := riRead(t, w, nil)
	logicalMDBXAssert(t, err == nil && got.exactRet == 779, "later healthy process operation: %+v/%v", got, err)
}

func riBool(v bool) int {
	if v {
		return 1
	}
	return 0
}

func rifWindows(t *testing.T) {
	w := riChain(t, 20001)
	var root mdbx.RootBindingV1
	var lagHash, lowerHash, lowerParent [32]byte
	err := w.s.View(func(reader *mdbx.Reader) error {
		var err error
		root, _, err = reader.ReadTreeRootBindingV1(1)
		if err != nil {
			return err
		}
		key, _ := mdbx.HeightKey(1, 4320)
		entry, _, err := reader.Get(mdbx.TreeSchemaV1DBIs()[2], key)
		if err != nil {
			return err
		}
		lagHash, lowerHash, lowerParent = [32]byte(entry[:32]), [32]byte(entry[:32]), [32]byte(entry[32:64])
		return nil
	})
	logicalMDBXAssert(t, err == nil, "window source binding: %v", err)
	// The same one-entry map/root is complete under a separate generation; index identities stay independent.
	op := Outpoint{Txid: initial148Array(t, initial148GenesisTxidHex), Vout: 0}
	// Reuse the exact codec value and stored node digest, not a second tree derivation.
	var value, node []byte
	logicalMDBXAssert(t, w.s.View(func(r *mdbx.Reader) error {
		var err error
		value, _, err = r.Get(mdbx.TreeSchemaV1DBIs()[1], btUTXOKey(1, op))
		if err != nil {
			return err
		}
		key, _ := mdbx.TreeNodeKey(1, *root.Top.Node)
		node, _, err = r.Get(mdbx.TreeSchemaV1DBIs()[8], key)
		return err
	}) == nil && len(value) == 53 && len(node) == 32, "capture exact complete map row/node")
	rifSeed(t, w, 1, btUTXOKey(2, op), value)
	nodeKey, _ := mdbx.TreeNodeKey(2, *root.Top.Node)
	rifSeed(t, w, 8, nodeKey, node)
	root.Endpoint.Height, root.Endpoint.BlockHash = 4320, lagHash
	binary.BigEndian.PutUint64(root.Endpoint.CumulativeChainwork[32:], 4321)
	encodedRoot, err := root.Encode()
	logicalMDBXAssert(t, err == nil, "LAG binding encode: %v", err)
	rifSeed(t, w, 0, btMeta(0x11, 2), encodedRoot)
	rifSeed(t, w, 0, btMeta(0x10, 2), mdbx.LogicalCounterValue(89, 1))
	for h := uint64(0); h <= 4320; h++ {
		var entry []byte
		logicalMDBXAssert(t, w.s.View(func(r *mdbx.Reader) error { key, _ := mdbx.HeightKey(1, h); entry, _, _ = r.Get(mdbx.TreeSchemaV1DBIs()[2], key); return nil }) == nil, "LAG index source")
		key, _ := mdbx.HeightKey(2, h)
		hash := [32]byte(entry[:32])
		reverse, _ := mdbx.CanonicalOwnerKey(2, hash)
		rifSeed(t, w, 2, key, entry)
		rifSeed(t, w, 7, reverse, mdbx.CanonicalOwnerValue(h))
	}
	for h := uint64(18000); h <= 20000; h++ {
		var hash [32]byte
		logicalMDBXAssert(t, w.s.View(func(r *mdbx.Reader) error { key, _ := mdbx.HeightKey(1, h); entry, _, _ := r.Get(mdbx.TreeSchemaV1DBIs()[2], key); hash = [32]byte(entry[:32]); return nil }) == nil, "undo range source")
		rifSeed(t, w, 5, mdbx.UndoManifestKey(hash), mdbx.UndoManifestValue(h, [16]byte{}, 1, 0))
	}
	riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) {
		a.Authority.B, a.Authority.U, a.Authority.Phase = 4881, 18561, 2
		a.Authority.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: 1, GenerationID: 3}}}
	})
	rifForward(t, w, 3, 4320, lowerHash, lowerParent)
	rifReverse(t, w, 3, 4320, lowerHash)
	rifFamily(t, w, lowerHash, 4320, 1, "one")
	got, err := riRead(t, w, nil)
	logicalMDBXAssert(t, err == nil && got.exactRet == 10357696, "H20000/B4881/L_body4321 lower body/undo: %+v/%v", got, err)
	sideKey, _ := mdbx.HeightKey(4, 1)
	rifSeed(t, w, 6, sideKey, mdbx.ChainValue(lowerHash, lowerParent, [40]byte{39: 1}))
	riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) { a.Authority.Cleanup.Spans = append(a.Authority.Cleanup.Spans, mdbx.CleanupSpanV1{Kind: 4, GenerationID: 4, FirstHeight: 1, LastHeight: 1, NextHeight: 1}) })
	got, err = riRead(t, w, nil)
	logicalMDBXAssert(t, err == nil && got.exactRet == 10357696, "SIDE body-only overlap: %+v/%v", got, err)
	riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) {
		a.Authority.Cleanup.Spans = []mdbx.CleanupSpanV1{
			{Kind: 1, GenerationID: 3}, {Kind: 2, GenerationID: 1, FirstHeight: 4000, NextHeight: 4000, LastHeight: 4880},
			{Kind: 3, GenerationID: 1, FirstHeight: 18000, NextHeight: 18000, LastHeight: 18560},
			{Kind: 4, GenerationID: 4, FirstHeight: 1, NextHeight: 1, LastHeight: 1},
		}
	})
	got, err = riRead(t, w, nil)
	logicalMDBXAssert(t, err == nil && got.exactRet == 10453056, "remaining BLOCKS/UNDO duties: %+v/%v", got, err)
	for _, source := range []struct {
		name   string
		height uint64
		rank   uint8
	}{{"canonical-body", 4321, 4}, {"owed-BLOCKS", 4000, 4}, {"canonical-undo", 18561, 5}, {"owed-UNDO", 18000, 5}} {
		for _, absent := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/absent%v", source.name, absent), func(t *testing.T) {
				var key, original, authority []byte
				logicalMDBXAssert(t, w.s.View(func(r *mdbx.Reader) error {
					heightKey, _ := mdbx.HeightKey(1, source.height)
					entry, present, err := r.Get(mdbx.TreeSchemaV1DBIs()[2], heightKey)
					if err != nil || !present {
						return errors.New("required damage setup lost actual canonical identity")
					}
					hash := [32]byte(entry[:32])
					key = bytes.Clone(hash[:])
					if source.rank == 5 {
						key = mdbx.UndoManifestKey(hash)
					}
					original, present, err = r.Get(mdbx.TreeSchemaV1DBIs()[source.rank], key)
					if err != nil || !present {
						return errors.New("required damage setup lost healthy row")
					}
					authority, _, err = r.Get(mdbx.TreeSchemaV1DBIs()[0], []byte{2})
					return err
				}) == nil, "capture independent healthy required source")
				if absent {
					logicalMDBXAssert(t, mdbx.FixtureStartupDeleteRow(w.s, source.rank, key) == nil, "delete single required source")
				} else {
					damaged := []byte{1}
					if source.rank == 4 {
						damaged = original[:149]
					}
					rifSeed(t, w, source.rank, key, damaged)
				}
				out := rifRun(t, w, nil, "source")
				var failure *logicalStateFailure
				logicalMDBXAssert(t, errors.As(out.source, &failure) && failure != nil && failure.kind == logicalStateFailureStoreIntegrity && failure.cause != nil && out.image == (retainedPreImageV1{}), "required positive absence/malformation: %T %v/%+v", out.source, out.source, out.image)
				var native *mdbx.EngineError
				logicalMDBXAssert(t, !errors.As(failure.cause, &native), "semantic required evidence invented native failure")
				out.native.want(t, 1, 1, -1)
				w.read(t, 0, []byte{2}, authority)
				rifOpen(t, w)
				rifSeed(t, w, source.rank, key, original)
			})
		}
	}
}

func rifResources(t *testing.T) {
	for _, share := range []uint64{663575, 663576} {
		t.Run(fmt.Sprintf("page-decoder-share%d", share), func(t *testing.T) {
			w := rifWorld(t, 3)
			value, err := (mdbx.UTXOValue{CovenantData: make([]byte, 65536)}).Encode()
			logicalMDBXAssert(t, err == nil && len(value) == 65560, "maximum native suffix")
			decoded, err := mdbx.DecodeUTXOValue(value)
			logicalMDBXAssert(t, err == nil && len(decoded.CovenantData) == 65536 && cap(decoded.CovenantData) == 65536, "separate decoder backing: %d/%d/%v", len(decoded.CovenantData), cap(decoded.CovenantData), err)
			key, _ := mdbx.UTXOKey(3, [32]byte{1}, 0)
			rifSeed(t, w, 1, key, value)
			value, decoded = nil, mdbx.UTXOValue{}
			var out rifResult
			evidence, harness := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageProbeOnly, 1, nil, func() { out = rifRun(t, w, nil, "source", share) })
			logicalMDBXAssert(t, harness == nil && evidence.Faults == 0 && evidence.BeginWrite == 0, "page acquisition evidence: %+v/%v", evidence, harness)
			if share == 663575 {
				logicalMDBXAssert(t, evidence.OldPulls[1] == 0 && out.image == (retainedPreImageV1{}), "cost-1 page acquired source: %+v", evidence)
				riResource(t, out.source, "storage_capacity")
			} else {
				logicalMDBXAssert(t, out.source == nil && out.image.exactRet == 65660 && evidence.OldPulls[1] == 2, "maximum suffix accounting: %+v/%+v", out, evidence)
			}
			rifOpen(t, w)
		})
	}
	for _, share := range []uint64{15328255, 15328256} {
		t.Run(fmt.Sprintf("whole-family-share%d", share), func(t *testing.T) {
			w := btNew(t)
			hash := [32]byte{1}
			rifFamily(t, w, hash, 5, 2, "113")
			var charge uint64
			var source error
			evidence, harness := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageProbeOnly, 5, nil, func() {
				source = riContext(t, w, nil, func(read *retainedReadV1) error {
					return read.account.WithReservation(402653184-8192-2313928-share, func() error {
						walk := retainedWalkV1{read: read}
						err := walk.undoV1(retainedArtifactV1{hash: hash, height: 5, bits: 4, required: 4})
						charge = walk.pre.exactRet
						logicalMDBXAssert(t, read.account.WithReservation(share, func() error { return nil }) == nil, "family frame not released")
						return err
					})
				})
			})
			logicalMDBXAssert(t, harness == nil, "whole-family evidence: %+v/%v", evidence, harness)
			if share == 15328255 {
				riResource(t, source, "storage_capacity")
				logicalMDBXAssert(t, charge == 0 && evidence.OldPulls[5] == 0, "whole-family denied after visit: %+v", evidence)
			} else {
				logicalMDBXAssert(t, source == nil && charge == 113 && evidence.OldPulls[5] == 4, "whole-family exact charge/frontier: %d/%v/%+v", charge, source, evidence)
			}
		})
	}
}

func rifUnwind(t *testing.T) {
	for _, readerFailure := range []bool{false, true} {
		for _, cleanup := range []uint32{0, 9, 10} {
			for _, mode := range []string{"source", "wrapped", "nil", "panic", "goexit"} {
				if !readerFailure && mode == "nil" {
					continue // Ignoring a semantic refusal without a Reader failure is the future consumer's unsupported composition.
				}
				t.Run(fmt.Sprintf("ReaderF%v/cleanup%d/%s", readerFailure, cleanup, mode), func(t *testing.T) {
					w := rifWorld(t, 3)
					var hash [32]byte
					if readerFailure {
						w, _, hash = riGenesis(t)
					} else {
						rifSeed(t, w, 1, append(binary.BigEndian.AppendUint64(nil, 3), make([]byte, 36)...), []byte{1})
					}
					var out rifResult
					var recovered any
					post := false
					run := func() {
						defer func() { recovered = recover() }()
						_, _, err := mdbx.FixtureStartupCleanup(w.s, cleanup, false, func() {
							if readerFailure {
								_, harness := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageGetEIO, 4, hash[:], func() { rifPerform(t, w, nil, mode, &out) })
								logicalMDBXAssert(t, harness == nil, "actual Reader-failure arm: %v", harness)
							} else {
								rifPerform(t, w, nil, mode, &out)
							}
						})
						logicalMDBXAssert(t, err == nil, "cleanup fixture: %v", err)
						post = true
					}
					if mode == "goexit" {
						done := make(chan struct{})
						go func() { defer close(done); run() }()
						<-done
					} else {
						run()
					}
					btReservationsReleased(t, w.owner)
					resource := "storage_capacity"
					if readerFailure {
						resource = "canonical_artifact_read"
					}
					f := riResource(t, out.source, resource)
					logicalMDBXAssert(t, out.image == (retainedPreImageV1{}), "unwind failure emitted quantity")
					unwind := mode == "panic" || mode == "goexit"
					logicalMDBXAssert(t, post != unwind && (mode != "panic" || recovered == "retained callback unwind"), "original delivery changed: %v/post%v", recovered, post)
					if !unwind {
						out.native.want(t, 1, 1, -1)
					}
					if cleanup == 0 && !readerFailure {
						if !unwind {
							logicalMDBXAssert(t, out.native.err == out.application, "clean semantic callback wrapper changed")
						}
						rifOpen(t, w)
						return
					}
					terminal := w.s.View(func(*mdbx.Reader) error { t.Fatal("failed native owner reused Reader"); return nil })
					if !unwind {
						logicalMDBXAssert(t, terminal == out.native.err, "cached native terminal error differs from actual result")
					}
					primary := out.application
					if readerFailure {
						btfEngine(t, f.Cause, "get", "IO", 5, "error 5")
						if primary == nil {
							primary = f.Cause
						} else {
							parts := genesisMDBXCauses(terminal)
							if cleanup == 10 {
								parts = genesisMDBXCauses(terminal.(*mdbx.EngineError).Cause)
							}
							logicalMDBXAssert(t, len(parts) >= 2 && parts[0] == out.application && parts[1] == f.Cause, "application/Reader cause order: %v", parts)
							if cleanup == 10 {
								primary = terminal.(*mdbx.EngineError).Cause
							} else if cleanup == 9 {
								primary = terminal.(interface{ Unwrap() []error }).Unwrap()[0]
							} else {
								primary = terminal
							}
						}
					}
					if cleanup == 0 {
						logicalMDBXAssert(t, terminal == primary, "clean consumed source identity changed")
					} else {
						btfAbortResult(t, terminal, cleanup, primary)
					}
					if cleanup == 10 {
						logicalMDBXAssert(t, mdbx.FixtureStartupRelease(w.s) == nil, "release actual retained native handle")
					}
				})
			}
		}
	}
}
