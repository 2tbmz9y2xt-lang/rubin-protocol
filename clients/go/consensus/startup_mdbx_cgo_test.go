//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// startupWorld uses the actual published genesis and replay-entry owners, then
// seeds the committed target prefix with paired index writes before Close/Open.
func startupWorld(t *testing.T, active, cursor int) *replayWorld {
	t.Helper()
	w := newReplayWorld(t, active)
	full := max(1, max(active, cursor)+1)
	extra, hashes := replayChain(t, w.hashes[len(w.hashes)-1], w.lastTime, full-len(w.headers)+1)
	w.headers, w.hashes = append(w.headers, extra...), append(w.hashes, hashes...)
	w.pending(mdbx.StorageProfilePrunedV1, 2)
	view := &replayView{inv: replayComplete([][32]byte{w.hashes[full]}, w.headers)}
	out := w.enter(view, replayIdentityOnly())
	logicalMDBXAssert(t, out.Err == nil && out.Truth == mdbx.CommitTruthNew && out.Replay != nil, "real startup replay entry: %+v", out)
	a := w.authority()
	for from := 0; from <= cursor; from += 1000 {
		var rows []mdbx.Mutation
		for h := from; h <= min(from+999, cursor); h++ {
			var parent [32]byte
			if h > 0 {
				parent = w.hashes[h-1]
			}
			if h > active {
				rows = append(rows, mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: bytes.Clone(w.hashes[h][:]), AfterKind: mdbx.AfterLiteral, Literal: bytes.Clone(w.headers[h][:])})
			}
			rows = append(rows,
				mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(a.Replay.TargetGenerationID, uint64(h))), AfterKind: mdbx.AfterLiteral, Literal: mdbx.ChainValue(w.hashes[h], parent, sideWorldWork(uint64(h)+1))},
				mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: logicalMDBXMust(mdbx.CanonicalOwnerKey(a.Replay.TargetGenerationID, w.hashes[h])), AfterKind: mdbx.AfterLiteral, Literal: mdbx.CanonicalOwnerValue(uint64(h))})
		}
		w.apply(rows...)
	}
	if cursor >= 0 {
		w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
			a.Replay.Cursor = mdbx.ReplayCursorV1{Kind: 2, Height: uint64(cursor), BlockHash: w.hashes[cursor]}
		})
	}
	return w
}

func startupRun(w *replayWorld) ReplayStartupOutcomeV1 {
	return VerifyPersistedReplayStartupMDBX(w.store, w.owner, w.genesis.ChainID, w.genesis.GenesisHash)
}

func startupTuple(t testing.TB, out ReplayStartupOutcomeV1, verified bool, decision uint8, result string) {
	t.Helper()
	if out.Verified != verified || uint8(out.Decision) != decision || out.Result != result || out.CanonicalTruth != "OLD" || (out.Err == nil) != verified {
		t.Fatalf("startup tuple=%+v, want %v/%d/%q/OLD/error=%v", out, verified, decision, result, !verified)
	}
}

func startupFreshGuard(t testing.TB, w *replayWorld, verified bool) {
	t.Helper()
	check := func(r *mdbx.Reader) error {
		guard := r.RequireCanonicalOwnerVerificationV1()
		if verified {
			logicalMDBXAssert(t, guard == nil, "fresh verified guard: %v", guard)
		} else {
			e, ok := any(guard).(*mdbx.EngineError)
			logicalMDBXAssert(t, ok && e.Class == "InvalidInput" && e.Operation == "get" && e.Code == 22 && e.Diagnostic == "canonical owner index is not verified" && e.Cause == nil && !e.ReopenRequired, "fresh false guard: %v", guard)
		}
		return nil
	}
	logicalMDBXAssert(t, w.store.View(check) == nil, "fresh View")
	application := errors.New("fresh startup Update readonly abort")
	truth, stage, err := w.store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
		check(r)
		return mdbx.Batch{}, application
	})
	logicalMDBXAssert(t, truth == 1 && stage == 1 && any(err) == any(application), "fresh Update truth/stage/raw identity")
}

func startupPreserved(t *testing.T, w *replayWorld, wantDecision uint8, wantResult string) ReplayStartupOutcomeV1 {
	t.Helper()
	before := w.image()
	w.store = w.reopen()
	startupFreshGuard(t, w, false)
	out := startupRun(w)
	startupTuple(t, out, wantDecision == 1, wantDecision, wantResult)
	logicalMDBXAssert(t, w.store.View(func(*mdbx.Reader) error { return nil }) == nil, "semantic startup rejection consumed original Store")
	replaySameImage(t, before, w.image(), "startup readonly image")
	startupFreshGuard(t, w, out.Verified)
	replaySameImage(t, before, w.image(), "startup fresh Update image")
	switch wantDecision {
	case 3:
		repeated := startupRun(w)
		startupTuple(t, repeated, false, 3, wantResult)
		logicalMDBXAssert(t, any(repeated.Err) != any(out.Err) && repeated.Err.Error() == out.Err.Error(), "clean semantic repeat must be a fresh observation")
	case 1:
		repeated := startupRun(w)
		startupTuple(t, repeated, false, 0, "")
		e, ok := any(repeated.Err).(*mdbx.EngineError)
		logicalMDBXAssert(t, ok && e.Class == "InvalidInput" && e.Operation == "view" && e.Code == 22 && e.Diagnostic == "canonical owner index is already verified", "accepted observation preserves already verified refusal")
		startupFreshGuard(t, w, true)
	}
	must := w.owner.WithReservation(154611151, func() error { return nil })
	logicalMDBXAssert(t, must == nil, "startup grant leaked: %v", must)
	return out
}

func TestReplayStartupMDBXV1(t *testing.T) {
	for _, row := range []struct {
		active, cursor int
		profile        mdbx.StorageProfileV1
	}{
		{-1, -1, 1},
		{-1, -1, 2},
		{0, -1, 1},
		{0, -1, 2},
		{3, 0, 1},
		{3, 2, 2},
		{0, 0, 1},
		{0, 1438, 1},
		{0, 1439, 1},
		{0, 1440, 2},
	} {
		t.Run(fmt.Sprintf("A01-A04 active%d cursor%d profile%d", row.active, row.cursor, row.profile), func(t *testing.T) {
			w := startupWorld(t, row.active, row.cursor)
			w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.ActiveProfile = row.profile })
			startupPreserved(t, w, 1, "")
			a := w.authority()
			for _, g := range []uint64{a.ActiveGenerationID, a.Replay.TargetGenerationID} {
				check := func(r *mdbx.Reader) error {
					absent, err := r.CanonicalOwnerV1(g, [32]byte{0x83})
					logicalMDBXAssert(t, err == nil && !absent.Owned && len(absent.Rows) == 1, "fresh absent owner: %+v/%v", absent, err)
					if g == a.ActiveGenerationID && row.active >= 0 || g == a.Replay.TargetGenerationID && row.cursor >= 0 {
						present, err := r.CanonicalOwnerV1(g, w.genesis.GenesisHash)
						logicalMDBXAssert(t, err == nil && present.Owned && present.Height == 0 && len(present.Entry) == 104 && len(present.Rows) == 2, "fresh present owner: %+v/%v", present, err)
					}
					return nil
				}
				logicalMDBXAssert(t, w.store.View(check) == nil, "fresh View owner")
				before := w.image()
				application := errors.New("fresh Update owner readonly abort")
				truth, stage, err := w.store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
					check(r)
					return mdbx.Batch{}, application
				})
				logicalMDBXAssert(t, any(err) == any(application) && truth == 1 && stage == 1, "fresh Update owner: %v/%v/%v", truth, stage, err)
				replaySameImage(t, before, w.image(), "fresh Update readonly image")
				startupFreshGuard(t, w, true)
			}
			out := startupRun(w)
			startupTuple(t, out, false, 0, "")
			e := any(out.Err).(*mdbx.EngineError)
			logicalMDBXAssert(t, e.Class == "InvalidInput" && e.Operation == "view" && e.Code == 22 && e.Diagnostic == "canonical owner index is already verified", "already true refusal: %v", e)
			startupFreshGuard(t, w, true)
			w.store = w.reopen()
			startupFreshGuard(t, w, false)
			startupTuple(t, startupRun(w), true, 1, "")
		})
	}
	t.Run("A05 R09 mixed profiles at active15120", func(t *testing.T) {
		for _, profile := range []mdbx.StorageProfileV1{1, 2} {
			w := startupWorld(t, 15120, 0)
			w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
				a.ActiveProfile, a.Replay.TargetProfile = profile, 3-profile
				a.B, a.U = [3]uint64{0, 1, 0}[profile], 13681
			})
			startupPreserved(t, w, 1, "")
		}
		w := startupWorld(t, 15120, 0)
		w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
			a.ActiveProfile, a.Replay.TargetProfile, a.B, a.U = 1, 2, 0, 13680
		})
		out := startupPreserved(t, w, 3, "TERMINAL_STORE_INTEGRITY(canonical)")
		logicalMDBXAssert(t, out.Err.Error() == "startup active bounds mismatch", "B/U-pair boundary owner: %v", out.Err)
	})
	t.Run("A05 bounds literals", func(t *testing.T) {
		for _, row := range []struct {
			present bool
			h, b, u uint64
		}{
			{false, 0, 0, 0},
			{true, 0, 0, 0},
			{true, 1439, 0, 0},
			{true, 1440, 0, 1},
			{true, 15119, 0, 13680},
			{true, 15120, 1, 13681},
			{true, 0xffffffff, 4294952176, 4294965856},
		} {
			for _, profile := range []mdbx.StorageProfileV1{1, 2} {
				b, u := startupBounds(&startupIndexTipV1{Present: row.present, Height: row.h}, profile)
				wantB := map[mdbx.StorageProfileV1]uint64{1: row.b, 2: 0}[profile]
				logicalMDBXAssert(t, b == wantB && u == row.u, "bounds present%v/h%d/profile%d=%d/%d, want%d/%d", row.present, row.h, profile, b, u, wantB, row.u)
			}
		}
	})
	t.Run("A05 independent work bytes", func(t *testing.T) {
		for _, row := range []struct {
			target   [32]byte
			expected [40]byte
		}{
			{[32]byte{31: 1}, [40]byte{7: 1}},
			{[32]byte{31: 2}, [40]byte{8: 0x80}},
			{[32]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, [40]byte{39: 1}},
		} {
			c := replayStartupCheck{}
			got, err := c.work(row.expected[:], row.target, &[40]byte{})
			logicalMDBXAssert(t, err == nil && got == row.expected, "independent work=%x/%v, want%x", got, err, row.expected)
		}
	})
	t.Run("A07 full exclusion domain", func(t *testing.T) {
		for _, code := range strings.Fields(`TX_ERR_PARSE TX_ERR_VALUE_CONSERVATION TX_ERR_TX_NONCE_INVALID TX_ERR_SEQUENCE_INVALID TX_ERR_NONCE_REPLAY TX_ERR_SIG_INVALID TX_ERR_SIG_ALG_INVALID TX_ERR_SIGHASH_TYPE_INVALID TX_ERR_SIG_NONCANONICAL TX_ERR_TIMELOCK_NOT_MET TX_ERR_WITNESS_OVERFLOW TX_ERR_COVENANT_TYPE_INVALID TX_ERR_VAULT_MALFORMED TX_ERR_VAULT_PARAMS_INVALID TX_ERR_VAULT_KEYS_NOT_CANONICAL TX_ERR_VAULT_WHITELIST_NOT_CANONICAL TX_ERR_VAULT_OWNER_DESTINATION_FORBIDDEN TX_ERR_VAULT_OWNER_AUTH_REQUIRED TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN TX_ERR_VAULT_MULTI_INPUT_FORBIDDEN TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED TX_ERR_SIMPLICITY_PROGRAM_TOO_LARGE TX_ERR_SIMPLICITY_ENVELOPE_TOO_LARGE TX_ERR_SIMPLICITY_CMR_MISMATCH TX_ERR_SIMPLICITY_DECODE TX_ERR_SIMPLICITY_JET_DISALLOWED TX_ERR_SIMPLICITY_BUDGET_EXCEEDED TX_ERR_SIMPLICITY_REJECTED TX_ERR_MISSING_UTXO TX_ERR_COINBASE_IMMATURE BLOCK_ERR_LINKAGE_INVALID BLOCK_ERR_MERKLE_INVALID BLOCK_ERR_WITNESS_COMMITMENT BLOCK_ERR_POW_INVALID BLOCK_ERR_TARGET_INVALID BLOCK_ERR_TIMESTAMP_OLD BLOCK_ERR_TIMESTAMP_FUTURE BLOCK_ERR_COINBASE_INVALID BLOCK_ERR_SUBSIDY_EXCEEDED BLOCK_ERR_STATE_CAP_EXCEEDED BLOCK_ERR_WEIGHT_EXCEEDED BLOCK_ERR_ANCHOR_BYTES_EXCEEDED BLOCK_ERR_DA_INCOMPLETE BLOCK_ERR_DA_CHUNK_HASH_INVALID BLOCK_ERR_DA_SET_INVALID BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID BLOCK_ERR_DA_BATCH_EXCEEDED BLOCK_ERR_PARSE`) {
			t.Run(code, func(t *testing.T) {
				w := startupWorld(t, 0, 0)
				w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
					a.ExcludedInvalidBranch = &mdbx.InvalidBranchV1{FirstInvalidHeight: 1, FirstInvalidBlockHash: [32]byte{0x91}, ExactConsensusError: []byte(code)}
				})
				startupPreserved(t, w, 1, "")
			})
		}
	})
	for _, token := range []string{"TX_ERR_PARSEsuffix", "TX_ERR_SIG_HASH_INVALID", "CONSENSUS_INVALID(TX_ERR_PARSE)", "TX_ERR_", "tx_err_parse", " TX_ERR_PARSE", "TX_ERR_PARSE\n", "TX_ERR_PARSE\x00", "x", strings.Repeat("x", 512)} {
		t.Run("R02 token "+token, func(t *testing.T) {
			w := startupWorld(t, 0, 0)
			w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
				a.ExcludedInvalidBranch = &mdbx.InvalidBranchV1{FirstInvalidHeight: 1, FirstInvalidBlockHash: [32]byte{0x91}, ExactConsensusError: []byte(token)}
			})
			for _, g := range []uint64{1, 2} {
				w.apply(
					mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(g, 0)), BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: mdbx.ChainValue(w.hashes[0], [32]byte{}, sideWorldWork(2))},
					mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: logicalMDBXMust(mdbx.CanonicalOwnerKey(g, w.hashes[0])), BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: mdbx.CanonicalOwnerValue(0)})
			}
			out := startupPreserved(t, w, 3, "TERMINAL_STORE_INTEGRITY(canonical)")
			logicalMDBXAssert(t, out.Err.Error() == "invalid startup exclusion token", "exclusion did not precede active/target: %v", out.Err)
		})
	}
	t.Run("A07 legal other phases", func(t *testing.T) {
		for _, row := range []struct{ phase, lifecycle uint8 }{{1, 1}, {1, 2}, {2, 1}, {2, 2}, {4, 2}} {
			for _, badToken := range []bool{false, true} {
				t.Run(fmt.Sprintf("%v invalid-token%v", row, badToken), func(t *testing.T) {
					w := newReplayWorld(t, 0)
					w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
						a.Phase, a.Lifecycle = mdbx.StoragePhaseV1(row.phase), mdbx.StorageLifecycleV1(row.lifecycle)
						if row.lifecycle == 2 && row.phase != 4 {
							p := mdbx.StorageProfilePrunedV1
							a.PendingTargetProfile = &p
						}
						if row.phase == 2 {
							a.NextGenerationID = 3
							a.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: 1, GenerationID: 2}}}
						}
						if row.phase == 4 {
							a.NextGenerationID = 3
							a.Ordinary = &mdbx.OrdinaryApplyV1{
								Stage: 2, Target: mdbx.AuthorityPointV1{Height: 2, BlockHash: [32]byte{2}},
								NewSuffix:            []mdbx.AuthorityPointV1{{Height: 1, BlockHash: [32]byte{1}}, {Height: 2, BlockHash: [32]byte{2}}},
								CapturedSelectedSide: &mdbx.SelectedSideV1{GenerationID: 2, F: 0, TipHeight: 2, TipHash: [32]byte{2}, CumulativeChainwork: sideWorldWork(3), RowCount: 2, LogicalBytes: 240},
							}
						}
						if badToken {
							a.ExcludedInvalidBranch = &mdbx.InvalidBranchV1{FirstInvalidHeight: 1, ExactConsensusError: []byte("TX_ERR_PARSEsuffix")}
						}
					})
					if badToken {
						out := startupPreserved(t, w, 3, "TERMINAL_STORE_INTEGRITY(canonical)")
						logicalMDBXAssert(t, out.Err.Error() == "invalid startup exclusion token", "token did not precede legal phase refusal: %v", out.Err)
						return
					}
					out := startupPreserved(t, w, 0, "")
					e := any(out.Err).(*mdbx.EngineError)
					logicalMDBXAssert(t, e.Class == "InvalidInput" && e.Operation == "view" && e.Code == 22 && e.Diagnostic == "persisted authority is not REPLAY" && e.Cause == nil, "other phase refusal: %v", e)
				})
			}
		}
	})
	for _, row := range []struct {
		name           string
		active, cursor int
		tip            uint64
		work           [40]byte
		prepare, edit  string
		excluded       int
		want           string
	}{
		{"R02-R09 chainID", 0, 0, 1, [40]byte{39: 2}, "", "chainID", -1, "network"},
		{"R02-R09 genesisHash", 0, 0, 1, [40]byte{39: 2}, "", "genesisHash", -1, "network"},
		{"R02-R09 U", 0, 0, 1, [40]byte{39: 2}, "", "U", -1, "bounds"},
		{"R11 PRE lower", -1, -1, 1, [40]byte{39: 1}, "", "", -1, "work"},
		{"A11 PRE lower", -1, -1, 1, [40]byte{39: 2}, "", "", -1, ""},
		{"A11 PRE upper", -1, -1, 1, [40]byte{7: 2}, "", "", -1, ""},
		{"R11 PRE upper", -1, -1, 1, [40]byte{7: 2, 39: 1}, "", "", -1, "work"},
		{"A11 PRE max lower", -1, -1, 0xffffffff, [40]byte{35: 1}, "", "", -1, ""},
		{"A11 PRE max upper", -1, -1, 0xffffffff, [40]byte{3: 1}, "", "", -1, ""},
		{"R17 G1 upper", 0, -1, 1, [40]byte{7: 2}, "", "", -1, "work"},
		{"A11 G1 lower", 0, -1, 1, [40]byte{39: 2}, "", "", -1, ""},
		{"A11 G1 upper", 0, -1, 1, [40]byte{7: 1, 39: 1}, "", "", -1, ""},
		{"A11 unknown unattainable sum", 0, -1, 1, [40]byte{7: 1}, "", "", -1, ""},
		{"A11 known G max lower", 0, -1, 0xffffffff, [40]byte{35: 1}, "", "", -1, ""},
		{"A11 known G max upper", 0, -1, 0xffffffff, [40]byte{4: 255, 5: 255, 6: 255, 7: 255, 39: 1}, "", "", -1, ""},
		{"R17 Gmax lower", 0, -1, 1, [40]byte{39: 2}, "target1 genesis", "", -1, "work"},
		{"A11 Gmax lower", 0, -1, 1, [40]byte{7: 1, 39: 1}, "target1 genesis", "", -1, ""},
		{"A11 Gmax upper", 0, -1, 1, [40]byte{7: 2}, "target1 genesis", "", -1, ""},
		{"A12 max lower", 0, 0, 0xffffffff, [40]byte{35: 1}, "", "", -1, ""},
		{"A12 max upper", 0, 0, 0xffffffff, [40]byte{4: 255, 5: 255, 6: 255, 7: 255, 39: 1}, "", "", -1, ""},
		{"R12 max earlier G", 0, 0, 0xffffffff, [40]byte{3: 1}, "", "", -1, "work"},
		{"R12 partial no remainder", 0, 1, 3, [40]byte{7: 1, 39: 1}, "target1 later", "", -1, "work"},
		{"R12 partial insufficient", 0, 1, 3, [40]byte{7: 1, 39: 2}, "target1 later", "", -1, "work"},
		{"A12 partial lower", 0, 1, 3, [40]byte{7: 1, 39: 3}, "target1 later", "", -1, ""},
		{"A12 partial half lower", 0, 1, 3, [40]byte{8: 128, 39: 3}, "target2 later", "", -1, ""},
		{"A12 partial upper", 0, 1, 3, [40]byte{7: 2, 8: 128, 39: 1}, "target2 later", "", -1, ""},
		{"R12 partial upper", 0, 1, 3, [40]byte{7: 2, 8: 128, 39: 2}, "target2 later", "", -1, "work"},
		{"R13 tip genesis", 0, -1, 1, [40]byte{39: 2}, "", "tip genesis", -1, "repeat"},
		{"R13 tip cursor", 0, 1, 3, [40]byte{39: 4}, "", "tip cursor", -1, "repeat"},
		{"R13 cursor genesis", 0, 1, 3, [40]byte{39: 4}, "", "cursor genesis", -1, "repeat"},
		{"H11 generic before repeat exclusion", -1, -1, 1, [40]byte{39: 1}, "", "tip genesis", 0, "work"},
		{"H11 repeat before exclusion", 0, -1, 1, [40]byte{39: 2}, "", "tip genesis", 0, "repeat"},
		{"H11 network before work", 0, -1, 1, [40]byte{39: 1}, "", "chainID", -1, "network"},
		{"H11 token before work", 0, -1, 1, [40]byte{39: 1}, "", "token", 5, "token"},
		{"R14 excluded genesis", 0, 1, 3, [40]byte{39: 4}, "", "", 0, "excluded"},
		{"R14 excluded tip", 0, 1, 3, [40]byte{39: 4}, "", "", 1, "excluded"},
		{"R14 excluded cursor", 0, 1, 3, [40]byte{39: 4}, "", "", 2, "excluded"},
		{"A13 unrelated recorded heights", 2, 2, 3, [40]byte{39: 4}, "", "", 5, ""},
		{"R15 interior target exclusion", 0, 2, 3, [40]byte{39: 4}, "", "", 3, "excluded"},
		{"R16 active cursor prefix exclusion", 2, 2, 3, [40]byte{39: 4}, "", "", 3, "excluded"},
		{"R16 active tip prefix exclusion", 3, -1, 3, [40]byte{39: 4}, "", "active tip", 3, "excluded"},
		{"R16 active known tip work", 3, -1, 3, [40]byte{39: 5}, "", "active tip", -1, "known tip"},
		{"R16 active known tip height", 2, -1, 3, [40]byte{39: 4}, "", "tip interior", -1, "known tip"},
		{"R13 target tip height", 0, 2, 3, [40]byte{39: 4}, "", "tip interior", -1, "repeat"},
		{"R13 active cursor height", 2, 2, 3, [40]byte{39: 4}, "", "cursor interior", -1, "repeat"},
		{"R13 target cursor height", 0, 2, 3, [40]byte{39: 4}, "", "cursor interior", -1, "repeat"},
		{"A14 unrelated OLD exclusion", 3, 0, 4, [40]byte{39: 5}, "", "", 3, ""},
		{"A14 exclusion above known shorter cursor", 3, 1, 4, [40]byte{39: 5}, "", "", 4, ""},
		{"A14 exclusion above known shorter tip", 3, -1, 1, [40]byte{39: 2}, "", "tip interior", 4, ""},
		{"A14 unknown tip cursor fork", 3, 1, 4, [40]byte{39: 5}, "fork cursor", "", -1, ""},
		{"R16 fixed tip cursor fork", 3, 1, 3, [40]byte{39: 4}, "fork cursor", "active tip", -1, "ancestry"},
		{"H12 known tip work before ancestry exclusion", 3, 1, 3, [40]byte{39: 5}, "fork cursor", "active tip", 3, "known tip"},
		{"H12 known ancestry before exclusion", 3, 1, 3, [40]byte{39: 4}, "fork cursor", "active tip", 3, "ancestry"},
	} {
		heights := []uint64{0}
		if row.excluded >= 0 {
			heights = []uint64{0, 1, 3, 4, 0xffffffff}
		}
		for _, recordedHeight := range heights {
			name := row.name
			if row.excluded >= 0 {
				name = fmt.Sprintf("%s height%d", row.name, recordedHeight)
			}
			t.Run(name, func(t *testing.T) {
				w := startupWorld(t, row.active, row.cursor)
				if row.prepare != "" {
					generation := uint64(2)
					if row.prepare == "target1 genesis" {
						generation = 1
					}
					startupSemanticEdit(t, w, generation, row.prepare)
				}
				w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
					target := &a.Replay.Target
					target.TipHeight, target.CumulativeChainwork = row.tip, row.work
					switch row.edit {
					case "chainID":
						target.ChainID[0] ^= 1
					case "genesisHash":
						target.GenesisHash[0] ^= 1
						a.Replay.Cursor.BlockHash = target.GenesisHash
					case "U":
						a.ActiveProfile, a.U = 2, 1
					case "tip genesis":
						target.TipHash = target.GenesisHash
					case "tip cursor":
						target.TipHash = a.Replay.Cursor.BlockHash
					case "cursor genesis":
						a.Replay.Cursor.BlockHash = target.GenesisHash
					case "active tip":
						target.TipHash = w.hashes[row.active]
					case "tip interior":
						target.TipHash = w.hashes[1]
					case "cursor interior":
						a.Replay.Cursor.BlockHash = w.hashes[1]
					}
					if row.excluded >= 0 {
						hash := [32]byte{0x91}
						switch row.excluded {
						case 0:
							hash = target.GenesisHash
						case 1:
							hash = target.TipHash
						case 2:
							hash = a.Replay.Cursor.BlockHash
						case 3, 4:
							hash = w.hashes[row.excluded-2]
						}
						a.ExcludedInvalidBranch = &mdbx.InvalidBranchV1{FirstInvalidHeight: recordedHeight, FirstInvalidBlockHash: hash, ExactConsensusError: []byte("BLOCK_ERR_PARSE")}
						if row.edit == "token" {
							a.ExcludedInvalidBranch.ExactConsensusError = []byte("CONSENSUS_INVALID(BLOCK_ERR_PARSE)")
						}
					}
				})
				decision, result := uint8(1), ""
				if row.want != "" {
					decision, result = 3, "TERMINAL_STORE_INTEGRITY(canonical)"
				}
				out := startupPreserved(t, w, decision, result)
				if row.want != "" {
					want := map[string]string{"network": "startup replay network identity mismatch", "bounds": "startup active bounds mismatch", "work": "startup replay target work outside consistency bounds", "repeat": "startup replay target repeats a known hash", "excluded": "startup replay target contains excluded hash", "known tip": "startup known target tip mismatch", "ancestry": "startup known target cursor ancestry mismatch", "token": "invalid startup exclusion token"}[row.want]
					logicalMDBXAssert(t, out.Err.Error() == want, "observed point owner/order: %v, want%s", out.Err, want)
				}
			})
		}
	}
	t.Run("H3 owner below R_MIN refuses as storage capacity", func(t *testing.T) {
		w := startupWorld(t, 0, 0)
		w.store = w.reopen()
		before := w.image()
		below, err := mdbx.NewOperationReservationOwner(805306367)
		logicalMDBXAssert(t, err == nil && below != nil, "below-floor owner: %v", err)
		out := VerifyPersistedReplayStartupMDBX(w.store, below, w.genesis.ChainID, w.genesis.GenesisHash)
		startupTuple(t, out, false, 2, "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)")
		logicalMDBXAssert(t, mdbx.IsOperationReservationCapacity(out.Err) && out.Decision == ReplayStartupRetryV1, "H3 capacity identity: %+v", out)
		startupFreshGuard(t, w, false)
		replaySameImage(t, before, w.image(), "H3 below-floor image")
		out = VerifyPersistedReplayStartupMDBX(w.store, below, [32]byte{}, w.genesis.GenesisHash)
		startupTuple(t, out, false, 0, "")
		logicalMDBXAssert(t, any(out.Err) == any(errInvalidStartupNetworkContext), "H3 earlier context result: %v", out.Err)
	})
	t.Run("A09 H09 admission and exact release", func(t *testing.T) {
		for _, free := range []uint64{4096, 4095} {
			w := startupWorld(t, 0, 0)
			w.store = w.reopen()
			before := w.image()
			err := w.owner.WithReservation(154611151-free, func() error {
				out := startupRun(w)
				if free == 4096 {
					startupTuple(t, out, true, 1, "")
				} else {
					startupTuple(t, out, false, 2, "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)")
					logicalMDBXAssert(t, mdbx.IsOperationReservationCapacity(out.Err), "direct capacity identity: %v", out.Err)
					startupFreshGuard(t, w, false)
				}
				return nil
			})
			logicalMDBXAssert(t, err == nil && w.owner.WithReservation(154611151, func() error { return nil }) == nil, "reservation release: %v", err)
			replaySameImage(t, before, w.image(), "capacity image")
		}
		w := startupWorld(t, 0, 0)
		for _, owner := range []*mdbx.OperationReservationOwner{nil, {}} {
			out := VerifyPersistedReplayStartupMDBX(w.store, owner, w.genesis.ChainID, w.genesis.GenesisHash)
			startupTuple(t, out, false, 0, "")
			logicalMDBXAssert(t, out.Err.Error() == "invalid storage operation reservation input", "owner error: %v", out.Err)
		}
		for _, context := range [][2][32]byte{{{}, w.genesis.GenesisHash}, {w.genesis.ChainID, {}}} {
			out := VerifyPersistedReplayStartupMDBX(nil, nil, context[0], context[1])
			startupTuple(t, out, false, 0, "")
			logicalMDBXAssert(t, any(out.Err) == any(errInvalidStartupNetworkContext) && out.Err.Error() == "invalid startup network context", "context precedence")
			before := w.image()
			out = VerifyPersistedReplayStartupMDBX(w.store, w.owner, context[0], context[1])
			startupTuple(t, out, false, 0, "")
			logicalMDBXAssert(t, any(out.Err) == any(errInvalidStartupNetworkContext), "valid Store changed context precedence")
			replaySameImage(t, before, w.image(), "invalid context image")
		}
		for _, owner := range []*mdbx.OperationReservationOwner{nil, {}} {
			out := VerifyPersistedReplayStartupMDBX(nil, owner, w.genesis.ChainID, w.genesis.GenesisHash)
			startupTuple(t, out, false, 0, "")
			e := any(out.Err).(*mdbx.EngineError)
			logicalMDBXAssert(t, e.Class == "InvalidInput" && e.Operation == "view" && e.Code == 22 && e.Diagnostic == "nil Store", "nil Store precedence")
		}
	})
	startupSemanticDefects(t)
	startupProjectionCases(t)
	t.Run("H06 failed target then fresh complete retry", func(t *testing.T) {
		w := startupWorld(t, 0, 1)
		startupSemanticEdit(t, w, 2, "work later")
		startupPreserved(t, w, 3, "TERMINAL_STORE_INTEGRITY(canonical)")
		// Repair only the prepared fixture, through a real paired Update. The
		// failed attempt contributes neither permission nor rolling facts.
		w.apply(
			mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(2, 1)), BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: mdbx.ChainValue(w.hashes[1], w.hashes[0], sideWorldWork(2))},
			mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: logicalMDBXMust(mdbx.CanonicalOwnerKey(2, w.hashes[1])), BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: mdbx.CanonicalOwnerValue(1)})
		before := w.image()
		startupFreshGuard(t, w, false)
		startupTuple(t, startupRun(w), true, 1, "")
		replaySameImage(t, before, w.image(), "fresh retry readonly image")
		startupFreshGuard(t, w, true)
	})
	t.Run("R03 genesis header parent with agreeing row", func(t *testing.T) {
		w := startupWorld(t, 0, -1)
		startupSemanticEdit(t, w, 1, "genesis header parent")
		out := startupPreserved(t, w, 3, "TERMINAL_STORE_INTEGRITY(canonical)")
		logicalMDBXAssert(t, out.Err.Error() == "startup parent mismatch", "genesis parent owner was not reached: %v", out.Err)
	})
	t.Run("R03 first uint64 height must not truncate", func(t *testing.T) {
		w := startupWorld(t, -1, -1)
		w.apply(
			mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: bytes.Clone(w.hashes[0][:]), AfterKind: mdbx.AfterLiteral, Literal: bytes.Clone(w.headers[0][:])},
			mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(nil, 1), 0x100000000), AfterKind: mdbx.AfterLiteral, Literal: mdbx.ChainValue(w.hashes[0], [32]byte{}, sideWorldWork(1))},
			mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: logicalMDBXMust(mdbx.CanonicalOwnerKey(1, w.hashes[0])), AfterKind: mdbx.AfterLiteral, Literal: binary.BigEndian.AppendUint64(nil, 0x100000000)})
		out := startupPreserved(t, w, 3, "TERMINAL_STORE_INTEGRITY(canonical)")
		logicalMDBXAssert(t, out.Err.Error() == "startup canonical height mismatch", "u64 height was narrowed before its domain owner: %v", out.Err)
	})
	t.Run("R06 committed defect after window", func(t *testing.T) {
		w := startupWorld(t, 0, 1441)
		f := mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(2, 1441)), BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: mdbx.ChainValue(w.hashes[1441], w.hashes[1440], sideWorldWork(1443))}
		i := mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: logicalMDBXMust(mdbx.CanonicalOwnerKey(2, w.hashes[1441])), BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: mdbx.CanonicalOwnerValue(1441)}
		w.apply(f, i)
		out := startupPreserved(t, w, 3, "TERMINAL_STORE_INTEGRITY(canonical)")
		logicalMDBXAssert(t, out.Err.Error() == "startup cumulative work mismatch", "late committed work owner: %v", out.Err)
	})
	t.Run("A04 entire target at declared tip", func(t *testing.T) {
		// A one-row APPLIED0 prefix is the legal partial control above: the
		// existing authority owner requires the declared full tip height >=1.
		for _, cursor := range []int{1, 1438, 1439, 1440, 1441} {
			w := startupWorld(t, 0, cursor)
			w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
				a.Replay.Target.TipHeight, a.Replay.Target.TipHash, a.Replay.Target.CumulativeChainwork = uint64(cursor), w.hashes[cursor], sideWorldWork(uint64(cursor)+1)
			})
			startupPreserved(t, w, 1, "")
		}
	})
}

// Every edit preserves width and native pairing so the named semantic owner is
// reached. Width/invalid authority and misbound-header rows use the tagged raw
// transport because the public Update validates header hash binding at setup.
func startupSemanticDefects(t *testing.T) {
	for _, generation := range []uint64{1, 2} {
		for _, defect := range []string{"missing genesis", "gap", "height too large", "wrong genesis", "genesis parent", "row parent", "later parent", "zero target", "work genesis", "work later", "zero work genesis", "zero work later", "overflow work genesis", "overflow work later", "cursor short", "cursor hash", "cursor work", "beyond cursor", "PRE_GENESIS forward"} {
			if generation == 1 && (strings.HasPrefix(defect, "cursor") || defect == "beyond cursor" || defect == "PRE_GENESIS forward") {
				continue
			}
			t.Run(fmt.Sprintf("R03-R07 g%d %s", generation, defect), func(t *testing.T) {
				active, cursor := map[uint64]int{1: 2, 2: 0}[generation], 2
				if defect == "wrong genesis" {
					active, cursor = 0, 0
				}
				w := startupWorld(t, active, cursor)
				startupSemanticEdit(t, w, generation, defect)
				out := startupPreserved(t, w, 3, "TERMINAL_STORE_INTEGRITY(canonical)")
				if defect == "wrong genesis" {
					logicalMDBXAssert(t, out.Err.Error() == "startup genesis identity mismatch", "genesis owner was not the first reached refusal: %v", out.Err)
				}
				if defect == "missing genesis" || defect == "gap" {
					logicalMDBXAssert(t, out.Err.Error() == "startup canonical height mismatch", "height owner was not first: %v", out.Err)
				}
				if defect == "cursor work" {
					logicalMDBXAssert(t, out.Err.Error() == "startup replay target tip mismatch", "full-cursor owner: %v", out.Err)
				}
			})
		}
	}
}

func startupSemanticEdit(t *testing.T, w *replayWorld, generation uint64, defect string) {
	t.Helper()
	if defect == "missing genesis" || defect == "gap" {
		// Move the legal paired row while retaining the original admitted cursor.
		// The exact height diagnostic must precede later cursor disagreement.
		from, destination := 0, uint64(1)
		if defect == "gap" {
			from, destination = 1, 2
		}
		var parent [32]byte
		if from > 0 {
			parent = w.hashes[from-1]
		}
		var rows []mdbx.Mutation
		for h := from; h <= 2; h++ {
			f := mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(generation, uint64(h))), BeforePresent: true, AfterKind: mdbx.AfterAbsent}
			i := mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: logicalMDBXMust(mdbx.CanonicalOwnerKey(generation, w.hashes[h])), BeforePresent: true, AfterKind: mdbx.AfterAbsent}
			if uint64(h) == destination {
				f.AfterKind, f.Literal = mdbx.AfterLiteral, mdbx.ChainValue(w.hashes[from], parent, sideWorldWork(uint64(from)+1))
			}
			if h == from {
				i.AfterKind, i.Literal = mdbx.AfterLiteral, mdbx.CanonicalOwnerValue(destination)
			}
			rows = append(rows, f, i)
		}
		w.apply(rows...)
		return
	}
	height := uint64(0)
	if defect == "gap" || defect == "row parent" || defect == "later parent" || defect == "zero target" || strings.HasSuffix(defect, "later") || defect == "inverse height" || defect == "target1 later" || defect == "target2 later" || defect == "fork cursor" {
		height = 1
	}
	hash := w.hashes[height]
	var parent [32]byte
	if height > 0 {
		parent = w.hashes[height-1]
	}
	f := mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(generation, height)), BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: mdbx.ChainValue(hash, parent, sideWorldWork(height+1))}
	i := mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: logicalMDBXMust(mdbx.CanonicalOwnerKey(generation, hash)), BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: mdbx.CanonicalOwnerValue(height)}
	switch defect {
	case "cursor short":
		f.Key, i.Key = logicalMDBXMust(mdbx.HeightKey(generation, 2)), logicalMDBXMust(mdbx.CanonicalOwnerKey(generation, w.hashes[2]))
		f.AfterKind, i.AfterKind, f.Literal, i.Literal = mdbx.AfterAbsent, mdbx.AfterAbsent, nil, nil
	case "height too large":
		f.BeforePresent, i.BeforePresent = false, false
		f.Key = binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(nil, generation), 0x100000000)
		f.Literal[0] ^= 0x73
		i.Key = append(binary.BigEndian.AppendUint64(nil, generation), f.Literal[:32]...)
		i.Literal = binary.BigEndian.AppendUint64(nil, 0x100000000)
	case "wrong genesis", "genesis header parent", "later parent", "zero target", "target1 genesis", "target1 later", "target2 later", "fork cursor":
		header := bytes.Clone(w.headers[height][:])
		switch defect {
		case "wrong genesis", "fork cursor":
			header[115] ^= 1
		case "zero target":
			clear(header[76:108])
		case "target1 genesis", "target1 later", "target2 later":
			clear(header[76:108])
			header[107] = map[string]byte{"target1 genesis": 1, "target1 later": 1, "target2 later": 2}[defect]
			work := map[string][40]byte{"target1 genesis": {7: 1}, "target1 later": {7: 1, 39: 1}, "target2 later": {8: 128, 39: 1}}[defect]
			copy(f.Literal[64:], work[:])
		default:
			header[4] ^= 1
		}
		newHash, _ := BlockHash(header)
		w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: newHash[:], AfterKind: mdbx.AfterLiteral, Literal: header})
		w.hashes, w.headers = append(w.hashes, newHash), append(w.headers, [116]byte(header))
		copy(f.Literal[:32], newHash[:])
		if defect == "later parent" || defect == "genesis header parent" {
			copy(f.Literal[32:64], header[4:36])
		}
		i.Key, i.BeforePresent = logicalMDBXMust(mdbx.CanonicalOwnerKey(generation, newHash)), false
		if defect == "genesis header parent" || defect == "target1 genesis" {
			w.genesis.GenesisHash = newHash
			w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.Replay.Target.GenesisHash = newHash })
		}
		if generation == 2 && (strings.HasPrefix(defect, "target") || defect == "fork cursor") {
			w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.Replay.Cursor.BlockHash = newHash })
		}
	case "genesis parent", "row parent":
		f.Literal[32] ^= 1
	case "work genesis", "work later":
		f.Literal[103]++
	case "zero work genesis", "zero work later":
		clear(f.Literal[64:])
	case "overflow work genesis", "overflow work later":
		clear(f.Literal[64:])
		f.Literal[67], f.Literal[103] = 1, 1
	case "inverse height":
		i.Literal = binary.BigEndian.AppendUint64(nil, height+1)
	case "cursor hash":
		w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.Replay.Cursor.BlockHash[0] ^= 1 })
		return
	case "cursor work":
		w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
			a.Replay.Target.TipHeight, a.Replay.Target.TipHash, a.Replay.Target.CumulativeChainwork = 2, w.hashes[2], sideWorldWork(4)
		})
		return
	case "beyond cursor":
		w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
			a.Replay.Cursor = mdbx.ReplayCursorV1{Kind: 2, Height: 1, BlockHash: w.hashes[1]}
		})
		return
	case "PRE_GENESIS forward":
		w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.Replay.Cursor = mdbx.ReplayCursorV1{Kind: 1} })
		return
	}
	var rows []mdbx.Mutation
	if !bytes.Equal(f.Literal[:min(32, len(f.Literal))], hash[:]) && f.AfterKind == mdbx.AfterLiteral && f.BeforePresent {
		rows = append(rows, mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: logicalMDBXMust(mdbx.CanonicalOwnerKey(generation, hash)), BeforePresent: true, AfterKind: mdbx.AfterAbsent})
	}
	w.apply(append(rows, f, i)...)
}

type startupCustomJoin struct {
	calls    int
	children []error
}

func (*startupCustomJoin) Error() string     { return "custom application" }
func (e *startupCustomJoin) Unwrap() []error { e.calls++; return e.children }

func startupProjectionCases(t *testing.T) {
	t.Run("H10 exact native projection", func(t *testing.T) {
		for _, resource := range []string{"LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read)", "LOCAL_RESOURCE_UNAVAILABLE(recovery_artifact)"} {
			for _, abort := range []struct {
				class    mdbx.EngineClass
				code     int
				terminal string
				decision uint8
			}{
				{"IO", 5, resource, 2},
				{"LocalInvariant", -30782, "TERMINAL_LOCAL_INVARIANT(evidence)", 0},
				{"LocalInvariant", -30779, "TERMINAL_LOCAL_INVARIANT(evidence)", 0},
				{"Integrity", -30796, "TERMINAL_STORE_INTEGRITY(canonical)", 3},
			} {
				read := &mdbx.EngineError{Class: "IO", Operation: "get", Code: 5, Diagnostic: "read", ReopenRequired: true}
				a := &mdbx.EngineError{Class: abort.class, Operation: "abort", Code: abort.code, Diagnostic: "abort", ReopenRequired: true}
				join := errors.Join(read, a)
				busy := &mdbx.EngineError{Class: "Concurrency", Operation: "close", Code: -30778, Diagnostic: "busy", ReopenRequired: true, Cause: join}
				for _, raw := range []error{join, busy} {
					c := replayStartupCheck{observedErr: read, observedResult: resource, readResource: resource}
					want, decision := abort.terminal, abort.decision
					if any(raw) == any(busy) && abort.class == "IO" {
						want = "LOCAL_RESOURCE_UNAVAILABLE(storage_concurrency)"
					}
					out := startupOutcome(raw, c.projectResult(raw))
					startupTuple(t, out, false, decision, want)
					children := join.(interface{ Unwrap() []error }).Unwrap()
					logicalMDBXAssert(t, any(out.Err) == any(raw) && any(busy.Cause) == any(join) && busy.Class == "Concurrency" && busy.Operation == "close" && busy.Code == -30778 && len(children) == 2 && any(children[0]) == any(read) && any(children[1]) == any(a), "raw tree identity/order changed")
					c.completedCanonicalPositive = true
					logicalMDBXAssert(t, c.projectResult(raw) == "TERMINAL_STORE_INTEGRITY(canonical)", "completed positive lost after cleanup")
				}
			}
		}
		read := &mdbx.EngineError{Class: "IO", Operation: "get", Code: 5}
		for _, class := range []mdbx.EngineClass{"IO", "Concurrency", "Transaction"} {
			for _, operation := range []string{"get", "prefix-page"} {
				for _, resource := range []string{"LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read)", "LOCAL_RESOURCE_UNAVAILABLE(recovery_artifact)"} {
					bound := &mdbx.EngineError{Class: class, Operation: operation, Code: 5}
					lookalike := &mdbx.EngineError{Class: class, Operation: operation, Code: 5}
					c := replayStartupCheck{readResource: resource}
					logicalMDBXAssert(t, any(c.observed(bound)) == any(bound) && any(c.observedErr) == any(bound) && c.observedResult == resource && c.projectResult(bound) == resource, "exact reached object lost binding")
					// Each lookalike has an independent literal classification.
					want := map[mdbx.EngineClass]string{"IO": "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", "Concurrency": "LOCAL_RESOURCE_UNAVAILABLE(storage_concurrency)", "Transaction": "LOCAL_RESOURCE_UNAVAILABLE(storage_transaction)"}[class]
					logicalMDBXAssert(t, bound != lookalike && c.projectResult(lookalike) == want, "lookalike inherited current read suffix")
					fresh := replayStartupCheck{}
					logicalMDBXAssert(t, fresh.projectResult(bound) == want, "prior invocation binding leaked")
				}
			}
		}
		foreign := &startupCustomJoin{children: []error{read, &mdbx.EngineError{Class: "Integrity"}}}
		c := replayStartupCheck{}
		logicalMDBXAssert(t, c.projectResult(foreign) == "TERMINAL_LOCAL_INVARIANT(evidence)" && foreign.calls == 0, "foreign multi-Unwrap invoked/admitted")
		for _, raw := range []error{errors.New("foreign"), &mdbx.CommitError{Truth: 1, Cause: read}, errors.Join(read, errors.New("foreign")), &mdbx.EngineError{Class: "foreign"}} {
			logicalMDBXAssert(t, c.projectResult(raw) == "TERMINAL_LOCAL_INVARIANT(evidence)", "foreign application admitted: %T", raw)
		}
		diagnostic := &startupCustomJoin{children: []error{&mdbx.EngineError{Class: "Integrity"}}}
		release := &mdbx.EngineError{Class: "IO", Operation: "release", Code: 5, Cause: diagnostic}
		logicalMDBXAssert(t, c.projectResult(release) == "LOCAL_RESOURCE_UNAVAILABLE(storage_io)" && diagnostic.calls == 0, "OS diagnostic Cause expanded")
		c.observedErr, c.observedResult = diagnostic, "TERMINAL_STORE_INTEGRITY(canonical)"
		logicalMDBXAssert(t, c.projectResult(diagnostic) == "TERMINAL_STORE_INTEGRITY(canonical)" && diagnostic.calls == 0, "bound application diagnostic expanded")
		var typedNil *startupCustomJoin
		logicalMDBXAssert(t, c.projectResult(typedNil) == "" && c.projectResult(nil) == "", "nil projection normalized incorrectly")
		four := []error{
			read,
			&mdbx.EngineError{Class: "IO", Operation: "abort", Code: 5},
			&mdbx.EngineError{Class: "Transaction", Operation: "view", Code: -30788},
			&mdbx.EngineError{Class: "Integrity", Operation: "prefix-page", Code: -30796},
		}
		c = replayStartupCheck{readResource: "LOCAL_RESOURCE_UNAVAILABLE(recovery_artifact)"}
		logicalMDBXAssert(t, any(c.observed(read)) == any(read), "four-child reached read binding")
		joined := errors.Join(four...)
		out := startupOutcome(joined, c.projectResult(joined))
		startupTuple(t, out, false, 3, "TERMINAL_STORE_INTEGRITY(canonical)")
		children := joined.(interface{ Unwrap() []error }).Unwrap()
		logicalMDBXAssert(t, any(out.Err) == any(joined) && len(children) == 4 && any(children[0]) == any(four[0]) && any(children[1]) == any(four[1]) && any(children[2]) == any(four[2]) && any(children[3]) == any(four[3]), "accepted four-child identity/order changed")
		logicalMDBXAssert(t, c.projectResult(errors.Join(append(four, &mdbx.EngineError{Class: "IO", Operation: "get", Code: 5})...)) == "TERMINAL_LOCAL_INVARIANT(evidence)", "native pending shape overflow accepted")
	})
}
