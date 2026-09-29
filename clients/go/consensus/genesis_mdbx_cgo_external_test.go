//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func TestGenesisMDBXPublishedProducer(t *testing.T) {
	data, err := os.ReadFile("../../../conformance/fixtures/CV-DEVNET-GENESIS.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Block string `json:"block_hex"`
			Chain string `json:"chain_id"`
			Hash  string `json:"block_hash"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil || len(fixture.Vectors) != 1 {
		t.Fatalf("published fixture: %v", err)
	}
	pinned := fixture.Vectors[0]
	block, chain, hash := node.DevnetGenesisBlockBytes(), node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash()
	if len(block) != 266 || hex.EncodeToString(block) != pinned.Block || hex.EncodeToString(chain[:]) != pinned.Chain || pinned.Chain != "88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103" || hex.EncodeToString(hash[:]) != pinned.Hash || pinned.Hash != "8d48b863805b96e5fcb79ee9652cd6257ae352b2f52088af921212039f9e8aff" {
		t.Fatal("genesis published producer drifted")
	}
	path := filepath.Join(t.TempDir(), "db")
	cfg := mdbx.ConfigV1{Lower: 1 << 20, Now: 2 << 20, Upper: 256 << 20, Growth: 1 << 20, Shrink: 2 << 20, PageSize: 4096, MaxReaders: 492}
	store, err := mdbx.Create(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	owner, err := mdbx.NewOperationReservationOwner(154_611_151)
	if err != nil {
		t.Fatal(err)
	}
	if truth, stage, err := store.BootstrapStorageV1(2, owner); err != nil || truth != 2 || stage != 3 {
		t.Fatalf("bootstrap: %v/%v/%v", truth, stage, err)
	}
	wrong := bytes.Clone(block)
	wrong[190] ^= 1
	refused := consensus.ConnectPublishedGenesisMDBX(store, owner, wrong, block, chain, hash)
	e, ok := refused.Err.(*consensus.TxError) //nolint:errorlint // The public refusal must be the direct consensus error.
	if refused.Result != "CONSENSUS_INVALID" || refused.Truth != 1 || refused.Stage != 1 || !ok || e.Code != "BLOCK_ERR_LINKAGE_INVALID" || refused.State != nil || refused.Summary != nil {
		t.Fatalf("published identity refusal: %+v", refused)
	}
	out := consensus.ConnectPublishedGenesisMDBX(store, owner, block, block, chain, hash)
	if out.Result != "ACCEPTED" || out.Truth != 2 || out.Stage != 3 || out.Err != nil || out.State == nil || out.Summary == nil || len(out.State.Utxos) != 1 || out.State.AlreadyGenerated.Sign() != 0 {
		t.Fatalf("published operation: %+v", out)
	}
	genesisMDBXRequireOwner(t, store, hash)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = mdbx.Open(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	inspection, err := store.Inspect()
	if err != nil {
		t.Fatal(err)
	}
	for i, count := range []uint64{4, 1, 1, 1, 1, 1, 0, 1} {
		if inspection.DBIs[i].Entries != count {
			t.Fatalf("published reopened image rank%d: %+v", i, inspection.DBIs[i])
		}
	}
	if err := store.View(func(reader *mdbx.Reader) error {
		body, present, err := reader.Get(mdbx.SchemaV2DBIs()[4], hash[:])
		if err != nil || !present || !bytes.Equal(body, block) {
			t.Fatalf("published reopened body: %v/%v", present, err)
		}
		counter, present, err := reader.Get(mdbx.SchemaV2DBIs()[0], []byte{0x10, 0, 0, 0, 0, 0, 0, 0, 1})
		if err != nil || !present || !bytes.Equal(counter, []byte{0, 0, 0, 0, 0, 0, 0, 89, 0, 0, 0, 0, 0, 0, 0, 1}) {
			t.Fatalf("published reopened counter: %x/%v", counter, err)
		}
		owner, present, err := reader.Get(mdbx.DBI{Name: "canonical-owner-v1", Rank: 7}, append([]byte{0, 0, 0, 0, 0, 0, 0, 1}, hash[:]...))
		if err != nil || !present || !bytes.Equal(owner, make([]byte, 8)) {
			t.Fatalf("published reopened owner: %x/%v", owner, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// genesisMDBXRequireOwner observes the genesis pair through CanonicalOwnerV1 inside View and inside Update on the
// Create'd, bootstrapped handle; every expected key, entry and row is a literal independent of the producer.
func genesisMDBXRequireOwner(t *testing.T, store *mdbx.Store, hash [32]byte) {
	t.Helper()
	ownerDBI, forwardDBI := mdbx.DBI{Name: "canonical-owner-v1", Rank: 7}, mdbx.DBI{Name: "canonical-v1", Rank: 2}
	other := hash
	other[0] ^= 1
	entry := append(append([]byte(nil), hash[:]...), make([]byte, 72)...)
	entry[103] = 1
	owned := []mdbx.ConsultedRow{{DBI: forwardDBI, Key: []byte{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0}}, {DBI: ownerDBI, Key: append([]byte{0, 0, 0, 0, 0, 0, 0, 1}, hash[:]...)}}
	none := []mdbx.ConsultedRow{{DBI: ownerDBI, Key: append([]byte{0, 0, 0, 0, 0, 0, 0, 1}, other[:]...)}}
	check := func(reader *mdbx.Reader, label string) {
		got, err := reader.CanonicalOwnerV1(1, hash)
		if err != nil || !got.Owned || got.Height != 0 || !bytes.Equal(got.Entry, entry) || !reflect.DeepEqual(got.Rows, owned) {
			t.Fatalf("%s genesis owner: %+v/%v", label, got, err)
		}
		absent, err := reader.CanonicalOwnerV1(1, other)
		if err != nil || absent.Owned || absent.Height != 0 || absent.Entry != nil || !reflect.DeepEqual(absent.Rows, none) {
			t.Fatalf("%s absent genesis owner: %+v/%v", label, absent, err)
		}
	}
	if err := store.View(func(reader *mdbx.Reader) error { check(reader, "View"); return nil }); err != nil {
		t.Fatal(err)
	}
	inspected := errors.New("genesis owner inspected")
	truth, stage, err := store.Update(func(reader *mdbx.Reader) (mdbx.Batch, error) { check(reader, "Update"); return mdbx.Batch{}, inspected })
	if truth != mdbx.CommitTruthOld || stage != mdbx.UpdateStagePrewrite || err != inspected { //nolint:errorlint // The callback sentinel must survive unchanged.
		t.Fatalf("genesis owner Update: %v/%v/%v", truth, stage, err)
	}
}
