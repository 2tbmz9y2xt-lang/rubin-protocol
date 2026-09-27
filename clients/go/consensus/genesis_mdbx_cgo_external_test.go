//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
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
	for i, count := range []uint64{4, 1, 1, 1, 1, 1, 0} {
		if inspection.DBIs[i].Entries != count {
			t.Fatalf("published reopened image rank%d: %+v", i, inspection.DBIs[i])
		}
	}
	if err := store.View(func(reader *mdbx.Reader) error {
		body, present, err := reader.Get(mdbx.SchemaV1DBIs()[4], hash[:])
		if err != nil || !present || !bytes.Equal(body, block) {
			t.Fatalf("published reopened body: %v/%v", present, err)
		}
		counter, present, err := reader.Get(mdbx.SchemaV1DBIs()[0], []byte{0x10, 0, 0, 0, 0, 0, 0, 0, 1})
		if err != nil || !present || !bytes.Equal(counter, []byte{0, 0, 0, 0, 0, 0, 0, 89, 0, 0, 0, 0, 0, 0, 0, 1}) {
			t.Fatalf("published reopened counter: %x/%v", counter, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
