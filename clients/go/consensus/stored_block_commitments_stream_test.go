//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"fmt"
	"slices"
	"testing"
	"unsafe"
)

// storedCommitmentsOracle is the independent public differential oracle: the full parser plus the stored-block check.
func storedCommitmentsOracle(block []byte) error {
	parsed, err := ParseBlockBytes(block)
	if err != nil {
		return err
	}
	return ValidateStoredBlockCommitments(parsed)
}

func storedCommitmentsRoot(t *testing.T, txs [][]byte) [32]byte {
	t.Helper()
	txids := make([][32]byte, 0, len(txs))
	for _, tx := range txs {
		_, txid, _, _, err := ParseTx(tx)
		if err != nil {
			t.Fatalf("ParseTx: %v", err)
		}
		txids = append(txids, txid)
	}
	root, err := MerkleRootTxids(txids)
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	return root
}

func storedCommitmentsAssemble(t *testing.T, coinbase []byte, txs [][]byte) []byte {
	t.Helper()
	all := append([][]byte{coinbase}, txs...)
	return buildBlockBytes(t, [32]byte{}, storedCommitmentsRoot(t, all), POW_LIMIT, 0, all)
}

func storedCommitmentsTxs(count int, value uint64) [][]byte {
	txs := make([][]byte, 0, count)
	for i := range count {
		txs = append(txs, txWithOneOutput(value+uint64(i), COV_TYPE_P2PK, validP2PKCovenantData()))
	}
	return txs
}

func storedCommitmentsBlock(t *testing.T, count int) []byte {
	t.Helper()
	txs := storedCommitmentsTxs(count, 10)
	return storedCommitmentsAssemble(t, coinbaseWithWitnessCommitment(t, txs...), txs)
}

func storedCommitmentsSame(got, want error) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}
	gotTx, gotOK := got.(*TxError)    //nolint:errorlint // Both producers return direct *TxError values.
	wantTx, wantOK := want.(*TxError) //nolint:errorlint // Both producers return direct *TxError values.
	return gotOK && wantOK && gotTx.Code == wantTx.Code && gotTx.Msg == wantTx.Msg
}

func TestStoredBlockCommitmentsStreamDifferential(t *testing.T) {
	type vector struct {
		name  string
		block []byte
		valid bool
	}
	vectors := []vector{{"published genesis", genesisMDBXHex(genesisMDBXPublishedHex), true}}
	for _, count := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 17} {
		block := storedCommitmentsBlock(t, count)
		badRoot := slices.Clone(block)
		badRoot[36] ^= 1
		zeroCount := append(slices.Clone(block[:BLOCK_HEADER_BYTES]), 0x00)
		zeroCount = append(zeroCount, block[BLOCK_HEADER_BYTES+1:]...)
		vectors = append(vectors,
			vector{fmt.Sprintf("valid %d transactions", count+1), block, true},
			vector{fmt.Sprintf("trailing byte %d", count+1), append(slices.Clone(block), 0), false},
			vector{fmt.Sprintf("short final transaction %d", count+1), block[:len(block)-1], false},
			vector{fmt.Sprintf("merkle root mismatch %d", count+1), badRoot, false},
			vector{fmt.Sprintf("trailing byte wins over root %d", count+1), append(slices.Clone(badRoot), 0), false},
			vector{fmt.Sprintf("zero tx count %d", count+1), zeroCount, false})
	}
	txs := storedCommitmentsTxs(3, 50)
	commit := coinbaseWithWitnessCommitment(t, txs...)
	anchor := commit[len(commit)-38 : len(commit)-6]
	duplicated := coinbaseTxWithOutputs(0, []testOutput{{value: 0, covenantType: COV_TYPE_ANCHOR, covenantData: anchor}, {value: 0, covenantType: COV_TYPE_ANCHOR, covenantData: anchor}})
	vectors = append(vectors,
		vector{"header only", genesisMDBXHex(genesisMDBXPublishedHex)[:BLOCK_HEADER_BYTES], false},
		vector{"non-coinbase first", storedCommitmentsAssemble(t, txs[0], txs[1:]), false},
		vector{"witness commitment absent", storedCommitmentsAssemble(t, coinbaseTxWithOutputs(0, []testOutput{{value: 0, covenantType: COV_TYPE_ANCHOR, covenantData: make([]byte, 32)}}), txs), false},
		vector{"witness commitment duplicated", storedCommitmentsAssemble(t, duplicated, txs), false})
	for _, v := range vectors {
		got, want := verifyStoredBlockCommitmentsStream(v.block), storedCommitmentsOracle(v.block)
		if !storedCommitmentsSame(got, want) || (got == nil) != v.valid {
			t.Fatalf("%s: stream=%v oracle=%v valid=%v", v.name, got, want, v.valid)
		}
	}
}

// TestStoredCommitmentPublishedLiterals reuses the pinned published genesis: its header merkle root and its coinbase
// anchor are literal commitments, so the frontiers must reproduce both from the parsed coinbase alone.
func TestStoredCommitmentPublishedLiterals(t *testing.T) {
	block := genesisMDBXHex(genesisMDBXPublishedHex)
	root := genesisMDBXHex("6f732e615e2f43337a53e9884adba7da32257d5bb5701adc7ed0bd406f2df913")
	anchor := genesisMDBXHex("b716a4b7f4c0fab665298ab9b8199b601ab9fa7e0a27f0713383f34cf37071a8")
	_, txid, _, n, err := ParseTx(block[BLOCK_HEADER_BYTES+1:])
	if err != nil || BLOCK_HEADER_BYTES+1+n != len(block) || !bytes.Equal(block[36:68], root) || !bytes.Contains(block, anchor) {
		t.Fatalf("published genesis framing: n=%d err=%v", n, err)
	}
	txids := storedCommitmentFrontier{leafTag: 0x00, nodeTag: 0x01}
	txids.add(txid)
	witness := storedCommitmentFrontier{leafTag: 0x02, nodeTag: 0x03}
	witness.add([32]byte{})
	gotRoot, gotAnchor := txids.root(), WitnessCommitmentHash(witness.root())
	if !bytes.Equal(gotRoot[:], root) || !bytes.Equal(gotAnchor[:], anchor) {
		t.Fatalf("published commitments root=%x anchor=%x", gotRoot, gotAnchor)
	}
}

// TestStoredCommitmentFrontierPromotion compares the frontier with roots spelled from the tagged-hash definition:
// pairs combine left to right and an odd node is promoted unchanged, never duplicated.
func TestStoredCommitmentFrontierPromotion(t *testing.T) {
	ids := make([][32]byte, 7)
	for i := range ids {
		ids[i][0], ids[i][31] = byte(i+1), 0xa5
	}
	for _, tags := range [][2]byte{{0x00, 0x01}, {0x02, 0x03}} {
		l := make([][32]byte, len(ids))
		for i := range ids {
			l[i] = sha3_256(append([]byte{tags[0]}, ids[i][:]...))
		}
		n := func(a, b [32]byte) [32]byte { return sha3_256(append(append([]byte{tags[1]}, a[:]...), b[:]...)) }
		want := map[int][32]byte{
			1: l[0],
			2: n(l[0], l[1]),
			3: n(n(l[0], l[1]), l[2]),
			4: n(n(l[0], l[1]), n(l[2], l[3])),
			5: n(n(n(l[0], l[1]), n(l[2], l[3])), l[4]),
			6: n(n(n(l[0], l[1]), n(l[2], l[3])), n(l[4], l[5])),
			7: n(n(n(l[0], l[1]), n(l[2], l[3])), n(n(l[4], l[5]), l[6])),
		}
		for count, root := range want {
			f := storedCommitmentFrontier{leafTag: tags[0], nodeTag: tags[1]}
			for _, id := range ids[:count] {
				f.add(id)
			}
			if got := f.root(); !bytes.Equal(got[:], root[:]) {
				t.Fatalf("tags %x count %d root %x, want %x", tags, count, got, root)
			}
		}
	}
}

// TestStoredBlockCommitmentsStreamManyTransactions keeps a large in-bound many-transaction body valid: nothing refuses
// a body by transaction count alone.
func TestStoredBlockCommitmentsStreamManyTransactions(t *testing.T) {
	block := storedCommitmentsBlock(t, 20_000)
	if len(block) > 68_000_125 {
		t.Fatalf("fixture body %d exceeds the block bound", len(block))
	}
	if got, want := verifyStoredBlockCommitmentsStream(block), storedCommitmentsOracle(block); got != nil || want != nil {
		t.Fatalf("many-transaction body: stream=%v oracle=%v", got, want)
	}
}

// TestStoredCommitmentChargeInventory checks the element sizes behind the named first/current Tx charge
// 1024*(64+40+56) against MAX_TX_INPUTS/MAX_TX_OUTPUTS/MAX_WITNESS_ITEMS, the frontier size behind 64*32, and the
// selected-side lane arithmetic 136332026 + 8388608 = 144720634.
func TestStoredCommitmentChargeInventory(t *testing.T) {
	if MAX_TX_INPUTS != 1024 || MAX_TX_OUTPUTS != 1024 || MAX_WITNESS_ITEMS != 1024 || unsafe.Sizeof(TxInput{}) > 64 || unsafe.Sizeof(TxOutput{}) > 40 || unsafe.Sizeof(WitnessItem{}) > 56 {
		t.Fatalf("Tx element inventory: %d %d %d", unsafe.Sizeof(TxInput{}), unsafe.Sizeof(TxOutput{}), unsafe.Sizeof(WitnessItem{}))
	}
	if unsafe.Sizeof(storedCommitmentFrontier{}.pending) != 64*32 || selectedSideBodyCharge != 136_332_026 || selectedSideBodyCharge+selectedSideTransferBytes != 144_720_634 {
		t.Fatalf("lane inventory: %d %d", unsafe.Sizeof(storedCommitmentFrontier{}.pending), selectedSideBodyCharge)
	}
	// The 128-byte record and the maximal legal transfer charge at n=1440 with 116-byte
	// headers, 4*M + 131072 + 2304*1440 + 1440*116 = 7810176, stays within the 8 MiB share.
	if unsafe.Sizeof(selectedSideCachedRow{}) != 128 || selectedSideAuthorityCharge+selectedSideFixedCharge+1440*selectedSideHeightCharge+1440*116 != 7_810_176 {
		t.Fatalf("transfer inventory: record %d", unsafe.Sizeof(selectedSideCachedRow{}))
	}
}
