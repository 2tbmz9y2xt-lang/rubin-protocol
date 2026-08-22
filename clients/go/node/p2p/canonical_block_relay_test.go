package p2p

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

type canonicalRelayFixture struct {
	SchemaVersion  int                          `json:"schema_version"`
	Artifact       string                       `json:"artifact"`
	FrameCatalog   map[string]string            `json:"frame_catalog"`
	OwnerSnapshots map[string]relayOwnerFixture `json:"owner_snapshots"`
	Cases          []relayCaseFixture           `json:"cases"`
}

type relayOwnerFixture struct {
	ObservedHandles []struct {
		HandleID      string `json:"handle_id"`
		OwnerID       string `json:"owner_id"`
		AddressKey    string `json:"address_key"`
		PostHandshake bool   `json:"post_handshake"`
	} `json:"observed_handles"`
}

type relayCaseFixture struct {
	ID         string `json:"id"`
	Snapshot   string `json:"snapshot"`
	Transition struct {
		CanonicalAppliedBlocks []string `json:"canonical_applied_blocks"`
	} `json:"transition"`
	IBD struct {
		HasTip       bool   `json:"has_tip"`
		TipTimestamp uint64 `json:"tip_timestamp"`
		SystemTime   int64  `json:"system_time"`
	} `json:"ibd"`
	RowSource *struct {
		OwnerID           string `json:"owner_id"`
		SuppliedBlockHash string `json:"supplied_block_hash"`
	} `json:"row_source"`
	FailureIndexByOwner map[string]*int     `json:"failure_index_by_owner"`
	ExpectedAttempts    map[string][]string `json:"expected_attempts"`
	Publications        []struct {
		CanonicalAppliedBlocks []string `json:"canonical_applied_blocks"`
		RowSource              *struct {
			OwnerID           string `json:"owner_id"`
			SuppliedBlockHash string `json:"supplied_block_hash"`
		} `json:"row_source"`
	} `json:"publications"`
}

type canonicalRelayConn struct {
	scriptedConn
	closed bool
}

func (c *canonicalRelayConn) Close() error {
	c.closed = true
	return nil
}

func loadCanonicalRelayFixture(t *testing.T) canonicalRelayFixture {
	t.Helper()
	root := os.Getenv("RUBIN_SPEC_ROOT")
	if root == "" {
		t.Skip("RUBIN_SPEC_ROOT is required for fixture-conformance evidence")
	}
	raw, err := os.ReadFile(filepath.Join(strings.TrimSuffix(filepath.Clean(root), string(os.PathSeparator)+"spec"), "conformance", "CV-P2P-CANONICAL-BLOCK-RELAY.json"))
	if err != nil {
		t.Fatalf("read canonical relay fixture: %v", err)
	}
	var fixture canonicalRelayFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode canonical relay fixture: %v", err)
	}
	if fixture.SchemaVersion != 1 || fixture.Artifact != "CV-P2P-CANONICAL-BLOCK-RELAY" {
		t.Fatalf("unexpected fixture identity: version=%d artifact=%q", fixture.SchemaVersion, fixture.Artifact)
	}
	return fixture
}

func fixtureHash(t *testing.T, encoded string) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != 32 {
		t.Fatalf("invalid fixture hash %q", encoded)
	}
	var hash [32]byte
	copy(hash[:], raw)
	return hash
}

func TestCanonicalBlockRelayFixtureRows(t *testing.T) {
	fixture := loadCanonicalRelayFixture(t)
	required := map[string]bool{"C1": false, "C2": false, "C3": false, "C4": false, "C4I": false, "G1": false, "G2": false, "G3": false, "P1": false, "I1": false, "I2": false, "I3": false, "I4": false, "S1": false, "S2": false, "S3": false, "F1": false, "H8": false, "H9": false, "H10": false}
	for _, tc := range fixture.Cases {
		if _, ok := required[tc.ID]; !ok {
			continue
		}
		required[tc.ID] = true
		if tc.ID == "H9" {
			continue
		}
		t.Run(tc.ID, func(t *testing.T) {
			blockCount := 0
			if tc.IBD.HasTip {
				blockCount = 2
			}
			h := newTestHarness(t, blockCount, "127.0.0.1:0", nil)
			tipTimestamp := uint64(0)
			if tc.IBD.HasTip {
				_, tipBytes := testHarnessBlockAtHeight(t, h, uint64(blockCount-1))
				parsed, err := consensus.ParseBlockBytes(tipBytes)
				if err != nil {
					t.Fatalf("parse harness tip: %v", err)
				}
				tipTimestamp = parsed.Header.Timestamp
			}
			now := int64(tipTimestamp) + tc.IBD.SystemTime - int64(tc.IBD.TipTimestamp)
			nowCalls := 0
			h.service.cfg.Now = func() time.Time {
				nowCalls++
				return time.Unix(now, 0)
			}

			owners := make(map[string]*peer)
			connections := make(map[string]*canonicalRelayConn)
			for _, handle := range fixture.OwnerSnapshots[tc.Snapshot].ObservedHandles {
				current := owners[handle.OwnerID]
				if current == nil {
					conn := &canonicalRelayConn{}
					if failure := tc.FailureIndexByOwner[handle.OwnerID]; failure != nil {
						conn.writeErr = os.ErrClosed
						conn.writeErrAt = (*failure + 1) * 2
					}
					current = &peer{conn: conn, service: h.service, state: node.PeerState{Addr: handle.AddressKey, HandshakeComplete: handle.PostHandshake}}
					owners[handle.OwnerID] = current
					connections[handle.OwnerID] = conn
				}
				h.service.peers[handle.HandleID] = current
			}
			if tc.ID == "H10" {
				old := connections["owner-h10-old"]
				old.writeHook = func(write int) {
					if write != 1 {
						return
					}
					reconnectConn := &canonicalRelayConn{}
					reconnected := &peer{conn: reconnectConn, service: h.service, state: node.PeerState{Addr: "addr-aba", HandshakeComplete: true}}
					h.service.peersMu.Lock()
					h.service.peers["addr-aba"] = reconnected
					h.service.peersMu.Unlock()
					connections["owner-h10-reconnect"] = reconnectConn
				}
			}

			rows := make([]node.CanonicalAppliedBlock, 0, len(tc.Transition.CanonicalAppliedBlocks))
			for _, encoded := range tc.Transition.CanonicalAppliedBlocks {
				rows = append(rows, node.CanonicalAppliedBlock{Hash: fixtureHash(t, encoded)})
			}
			source, suppliedHash := (*peer)(nil), [32]byte{}
			if tc.RowSource != nil {
				source = owners[tc.RowSource.OwnerID]
				suppliedHash = fixtureHash(t, tc.RowSource.SuppliedBlockHash)
			}
			if len(tc.Publications) == 0 {
				summary := &node.ChainStateConnectSummary{CanonicalAppliedBlocks: rows}
				if tc.ID == "P1" {
					if got, gotErr := (&peer{service: h.service}).acceptRelayedBlockResult(rows[0].Hash, summary, os.ErrPermission); got != summary || !errors.Is(gotErr, os.ErrPermission) {
						t.Fatalf("terminal result=(%+v,%v), want preserved tuple", got, gotErr)
					}
				} else {
					h.service.relayCanonicalAppliedBlocks(source, suppliedHash, summary)
				}
			} else {
				for _, publication := range tc.Publications {
					publicationRows := make([]node.CanonicalAppliedBlock, 0, len(publication.CanonicalAppliedBlocks))
					for _, encoded := range publication.CanonicalAppliedBlocks {
						publicationRows = append(publicationRows, node.CanonicalAppliedBlock{Hash: fixtureHash(t, encoded)})
					}
					publicationSource, publicationHash := (*peer)(nil), [32]byte{}
					if publication.RowSource != nil {
						publicationSource = owners[publication.RowSource.OwnerID]
						publicationHash = fixtureHash(t, publication.RowSource.SuppliedBlockHash)
					}
					h.service.relayCanonicalAppliedBlocks(publicationSource, publicationHash, &node.ChainStateConnectSummary{CanonicalAppliedBlocks: publicationRows})
				}
			}
			wantNowCalls := 0
			if len(rows) != 0 {
				wantNowCalls = 1
			} else {
				wantNowCalls = len(tc.Publications)
			}
			if nowCalls != wantNowCalls {
				t.Fatalf("Now calls=%d, want %d", nowCalls, wantNowCalls)
			}

			for ownerID, expectedIDs := range tc.ExpectedAttempts {
				conn := connections[ownerID]
				if conn == nil {
					if len(expectedIDs) != 0 {
						t.Fatalf("owner %s missing with expected attempts", ownerID)
					}
					continue
				}
				var want []byte
				for _, frameID := range expectedIDs {
					frame, err := hex.DecodeString(fixture.FrameCatalog[frameID])
					if err != nil {
						t.Fatalf("decode frame %s: %v", frameID, err)
					}
					want = append(want, frame...)
				}
				if got := conn.Bytes(); string(got) != string(want) {
					t.Fatalf("owner %s bytes=%x, want %x", ownerID, got, want)
				}
				if failure := tc.FailureIndexByOwner[ownerID]; failure != nil {
					if !conn.closed || owners[ownerID].snapshotState().LastError == "" {
						t.Fatalf("failing owner %s cleanup: closed=%v state=%+v", ownerID, conn.closed, owners[ownerID].snapshotState())
					}
				}
			}
		})
	}
	for id, found := range required {
		if !found {
			t.Errorf("fixture missing required case %s", id)
		}
	}
}

func TestCanonicalBlockRelayNegativeClockSamplesOnce(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	calls := 0
	h.service.cfg.Now = func() time.Time {
		calls++
		return time.Unix(-1, 0)
	}
	h.service.relayCanonicalAppliedBlocks(nil, [32]byte{}, &node.ChainStateConnectSummary{CanonicalAppliedBlocks: []node.CanonicalAppliedBlock{{Hash: [32]byte{1}}}})
	if calls != 1 {
		t.Fatalf("clock calls=%d, want 1", calls)
	}
	h.service.relayCanonicalAppliedBlocks(nil, [32]byte{}, nil)
	if calls != 1 {
		t.Fatalf("empty summary sampled clock: calls=%d", calls)
	}
}

func assertCanonicalRelayFixtureShape(t *testing.T, fixture canonicalRelayFixture, frameID string, raw []byte, wantHash [32]byte) {
	t.Helper()
	literal, err := hex.DecodeString(fixture.FrameCatalog[frameID])
	if err != nil {
		t.Fatalf("decode fixture frame %s: %v", frameID, err)
	}
	if len(raw) != len(literal) || len(raw) != 57 || string(raw[:20]) != string(literal[:20]) || raw[24] != literal[24] {
		t.Fatalf("frame shape=%x, fixture=%x", raw, literal)
	}
	items, err := decodeInventoryVectors(raw[wireHeaderSize:])
	if err != nil || len(items) != 1 || items[0].Type != MSG_BLOCK || items[0].Hash != wantHash {
		t.Fatalf("inventory=%+v err=%v, want one MSG_BLOCK %x", items, err, wantHash)
	}
}

func TestCanonicalBlockRelayOwningIngress(t *testing.T) {
	fixture := loadCanonicalRelayFixture(t)
	t.Run("C1 full", func(t *testing.T) {
		source := newTestHarness(t, 2, "127.0.0.1:0", nil)
		sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
		sink.service.cfg.Now = func() time.Time { return time.Unix(0, 0) }
		hash, block := testHarnessBlockAtHeight(t, source, 1)
		conn := &scriptedConn{}
		destination := &peer{conn: conn, service: sink.service, state: node.PeerState{Addr: "full-destination", HandshakeComplete: true}}
		sink.service.peers[destination.addr()] = destination
		origin := testPeerForService(sink.service, "full-origin", 1)
		summary, err := origin.processRelayedBlock(block)
		if err != nil || summary == nil || summary.BlockHash != hash {
			t.Fatalf("summary=%+v err=%v", summary, err)
		}
		assertCanonicalRelayFixtureShape(t, fixture, "f11", conn.Bytes(), hash)
	})

	t.Run("C2 reconstructed compact", func(t *testing.T) {
		for _, mode := range []struct {
			name            string
			fallbackOnApply bool
		}{{"prefilled", false}, {"short-id", true}} {
			t.Run(mode.name, func(t *testing.T) {
				source := newTestHarness(t, 2, "127.0.0.1:0", nil)
				sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
				sink.service.cfg.Now = func() time.Time { return time.Unix(0, 0) }
				hash, block := testHarnessBlockAtHeight(t, source, 1)
				header, compactHash, txs := compactPartsFromBlockBytes(t, block)
				if compactHash != hash {
					t.Fatalf("compact hash=%x, want %x", compactHash, hash)
				}
				conn := &scriptedConn{}
				destination := &peer{conn: conn, service: sink.service, state: node.PeerState{Addr: "compact-destination", HandshakeComplete: true}}
				sink.service.peers[destination.addr()] = destination
				origin := testPeerForService(sink.service, "compact-origin", 1)
				if err := origin.processCompactTransactions(hash, header, txs, mode.fallbackOnApply); err != nil {
					t.Fatalf("processCompactTransactions: %v", err)
				}
				assertCanonicalRelayFixtureShape(t, fixture, "f22", conn.Bytes(), hash)
			})
		}
	})

	t.Run("H9 immediate orphan resolution", func(t *testing.T) {
		fork := newTestHarness(t, 1, "127.0.0.1:0", nil)
		minerCfg := node.DefaultMinerConfig()
		minerCfg.MineAddress = append([]byte(nil), minerCfg.MineAddress...)
		minerCfg.MineAddress[len(minerCfg.MineAddress)-1] ^= 5
		miner, err := node.NewMiner(fork.chainState, fork.blockStore, fork.syncEngine, minerCfg)
		if err != nil {
			t.Fatalf("new fork miner: %v", err)
		}
		minedB, err := miner.MineOne(context.Background(), nil)
		if err != nil {
			t.Fatalf("mine B: %v", err)
		}
		blockB, err := fork.blockStore.GetBlockByHash(minedB.Hash)
		if err != nil {
			t.Fatalf("read B: %v", err)
		}
		blockC := fork.mineNextBlockBytes(t)
		blockD := fork.mineNextBlockBytes(t)
		hashB, _ := testHarnessBlockAtHeight(t, fork, 1)
		hashC, _ := testHarnessBlockAtHeight(t, fork, 2)
		hashD, _ := testHarnessBlockAtHeight(t, fork, 3)

		sink := newTestHarness(t, 2, "127.0.0.1:0", nil)
		sink.service.cfg.Now = func() time.Time { return time.Unix(0, 0) }
		hashA, _ := testHarnessBlockAtHeight(t, sink, 1)
		if summary, err := sink.syncEngine.ApplyBlockWithReorg(blockB, nil); err != nil || summary == nil || len(summary.CanonicalAppliedBlocks) != 0 {
			t.Fatalf("store prefix B: A=%x B=%x summary=%+v err=%v", hashA, hashB, summary, err)
		}
		if _, found, err := sink.blockStore.FindCanonicalHeight(hashB); err != nil || found {
			t.Fatalf("stored prefix B canonical before C: A=%x B=%x found=%v err=%v", hashA, hashB, found, err)
		}
		sourceConn, otherConn := &scriptedConn{}, &scriptedConn{}
		sourcePeer := &peer{conn: sourceConn, service: sink.service, state: node.PeerState{Addr: "addr-h9-source", HandshakeComplete: true}}
		otherPeer := &peer{conn: otherConn, service: sink.service, state: node.PeerState{Addr: "addr-h9-other", HandshakeComplete: true}}
		sink.service.peers[sourcePeer.addr()] = sourcePeer
		sink.service.peers[otherPeer.addr()] = otherPeer
		sink.service.retainOrResolveOrphanFrom("stored-descendant", hashD, hashC, blockD)
		sink.service.retainOrResolveOrphan(sourcePeer, hashC, hashB, blockC)

		var h9 relayCaseFixture
		for _, tc := range fixture.Cases {
			if tc.ID == "H9" {
				h9 = tc
				break
			}
		}
		connections := map[string]*scriptedConn{"owner-h9-source": sourceConn, "owner-h9-other": otherConn}
		for ownerID, frameIDs := range h9.ExpectedAttempts {
			raw := connections[ownerID].Bytes()
			if len(raw) != len(frameIDs)*57 {
				t.Fatalf("owner %s bytes=%x, want %d frames", ownerID, raw, len(frameIDs))
			}
			for i, frameID := range frameIDs {
				var wantHash [32]byte
				switch frameID {
				case "f11":
					wantHash = hashB
				case "f22":
					wantHash = hashC
				case "f33":
					wantHash = hashD
				default:
					t.Fatalf("unexpected H9 frame %q", frameID)
				}
				assertCanonicalRelayFixtureShape(t, fixture, frameID, raw[i*57:(i+1)*57], wantHash)
			}
		}
	})
}
