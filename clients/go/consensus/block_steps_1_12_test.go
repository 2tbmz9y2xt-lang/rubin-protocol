package consensus

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
	"testing"
	"unsafe"
)

// Standard supplied context: height 12 with the 11 parent timestamps 1000..1100, whose lower median is 1050.
var (
	blockStepsParent = [32]byte{0xa1, 0xb2, 0xc3}
	blockStepsOther  = [32]byte{0x0d}
	blockStepsTimes  = []uint64{1_060, 1_000, 1_090, 1_010, 1_100, 1_020, 1_080, 1_030, 1_070, 1_040, 1_050}
	blockStepsIDs    = [...][32]byte{{0x10}, {0x20}, {0x30}}
)

const (
	blockStepsHeight = 12
	blockStepsMedian = 1_050
)

// blockStepsHead is one header's fields; mine searches the first nonce satisfying target.
type blockStepsHead struct {
	parent, root, target [32]byte
	timestamp            uint64
	mine                 bool
}

func blockStepsMine(t *testing.T, h blockStepsHead) []byte {
	t.Helper()
	for nonce := uint64(0); nonce < 1<<20; nonce++ {
		header := AppendU32le(make([]byte, 0, BLOCK_HEADER_BYTES), 1)
		header = append(header, h.parent[:]...)
		header = append(header, h.root[:]...)
		header = AppendU64le(header, h.timestamp)
		header = append(header, h.target[:]...)
		header = AppendU64le(header, nonce)
		if !h.mine || PowCheck(header, h.target) == nil {
			return header
		}
	}
	t.Fatal("no nonce satisfies the header target")
	return nil
}

// blockStepsRaw frames a header and transactions without parsing them.
func blockStepsRaw(header []byte, txs [][]byte) []byte {
	raw := AppendCompactSize(slices.Clone(header), uint64(len(txs)))
	for _, tx := range txs {
		raw = append(raw, tx...)
	}
	return raw
}

// blockStepsMake builds a mined standard block over txs (first included); edit may change any header field.
func blockStepsMake(t *testing.T, txs [][]byte, edit func(*blockStepsHead)) []byte {
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
	h := blockStepsHead{parent: blockStepsParent, root: root, target: POW_LIMIT, timestamp: blockStepsMedian + 1, mine: true}
	if edit != nil {
		edit(&h)
	}
	return blockStepsRaw(blockStepsMine(t, h), txs)
}

// blockStepsStd prepends a coinbase carrying the exact witness commitment of the other transactions.
func blockStepsStd(t *testing.T, edit func(*blockStepsHead), txs ...[]byte) []byte {
	t.Helper()
	return blockStepsMake(t, append([][]byte{coinbaseWithWitnessCommitment(t, txs...)}, txs...), edit)
}

// blockStepsCommitment is WitnessCommitmentHash over a zero coinbase wtxid and the other transactions' wtxids.
func blockStepsCommitment(t *testing.T, txs [][]byte) [32]byte {
	t.Helper()
	wtxids := make([][32]byte, 1, 1+len(txs))
	for _, tx := range txs {
		_, _, wtxid, _, err := ParseTx(tx)
		if err != nil {
			t.Fatalf("ParseTx: %v", err)
		}
		wtxids = append(wtxids, wtxid)
	}
	root, err := WitnessMerkleRootWtxids(wtxids)
	if err != nil {
		t.Fatalf("WitnessMerkleRootWtxids: %v", err)
	}
	return WitnessCommitmentHash(root)
}

func blockStepsHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 && len(b) != 19 {
		t.Fatalf("literal %q: %v", s, err)
	}
	return b
}

func blockStepsRun(raw []byte) (BlockBasicSummary, error) {
	return ValidateBlockSteps1To12(raw, blockStepsParent, POW_LIMIT, blockStepsHeight, blockStepsTimes)
}

// blockStepsOracle is the existing full parser plus public weight accounting, independent of the new passes.
func blockStepsOracle(t *testing.T, raw []byte) BlockBasicSummary {
	t.Helper()
	parsed, err := ParseBlockBytes(raw)
	if err != nil {
		t.Fatalf("ParseBlockBytes: %v", err)
	}
	var weight, da uint64
	for _, tx := range parsed.Txs {
		w, d, _, err := TxWeightAndStats(tx)
		if err != nil {
			t.Fatalf("TxWeightAndStats: %v", err)
		}
		weight, da = weight+w, da+d
	}
	hash, err := BlockHash(parsed.HeaderBytes)
	if err != nil {
		t.Fatalf("BlockHash: %v", err)
	}
	return BlockBasicSummary{TxCount: parsed.TxCount, SumWeight: weight, SumDa: da, BlockHash: hash}
}

func blockStepsWantOK(t *testing.T, label string, raw []byte, summary BlockBasicSummary, err error) {
	t.Helper()
	if want := blockStepsOracle(t, raw); err != nil || summary != want {
		t.Fatalf("%s: got %+v/%v, want %+v", label, summary, err, want)
	}
}

// blockStepsWantCode asserts the exact code and, when msg is nonempty, the exact diagnostic plus a zero summary.
func blockStepsWantCode(t *testing.T, label string, summary BlockBasicSummary, err error, code ErrorCode, msg string) {
	t.Helper()
	var txErr *TxError
	if !errors.As(err, &txErr) || txErr.Code != code || (msg != "" && txErr.Msg != msg) || summary != (BlockBasicSummary{}) {
		t.Fatalf("%s: got %+v/%v, want %s %q with zero summary", label, summary, err, code, msg)
	}
}

func blockStepsPlain(count int) [][]byte {
	txs := make([][]byte, 0, count)
	for i := range count {
		txs = append(txs, txWithOneOutput(uint64(10+i), COV_TYPE_P2PK, validP2PKCovenantData()))
	}
	return txs
}

func blockStepsCommit(id [32]byte, count uint16, outputs ...testOutput) []byte {
	b := append(AppendU32le(nil, 1), 0x01)
	b = AppendCompactSize(AppendU64le(b, 1), 0)
	b = AppendCompactSize(b, uint64(len(outputs)))
	for _, out := range outputs {
		b = AppendCompactSize(AppendU16le(AppendU64le(b, out.value), out.covenantType), uint64(len(out.covenantData)))
		b = append(b, out.covenantData...)
	}
	b = append(AppendU32le(b, 0), id[:]...)
	b = append(AppendU16le(b, count), make([]byte, 32)...)
	b = append(AppendU64le(b, 0), make([]byte, 96)...)
	b = AppendCompactSize(append(b, 0), 0)
	return AppendCompactSize(AppendCompactSize(b, 0), 0)
}

func blockStepsChunk(id [32]byte, index uint16, payload []byte, hash [32]byte) []byte {
	b := append(AppendU32le(nil, 1), 0x02)
	b = AppendCompactSize(AppendCompactSize(AppendU64le(b, 1), 0), 0)
	b = append(AppendU32le(b, 0), id[:]...)
	b = append(AppendU16le(b, index), hash[:]...)
	b = AppendCompactSize(AppendCompactSize(b, 0), uint64(len(payload)))
	return append(b, payload...)
}

func blockStepsDAOut(hash [32]byte) testOutput {
	return testOutput{covenantType: COV_TYPE_DA_COMMIT, covenantData: hash[:]}
}

// blockStepsSet is one complete set: its commit, then chunk i carrying payloads[i] in the given index order.
func blockStepsSet(id [32]byte, order []uint16, payloads [][]byte) [][]byte {
	txs := [][]byte{blockStepsCommit(id, uint16(len(payloads)), blockStepsDAOut(sha3_256(bytes.Join(payloads, nil))))} //nolint:gosec // test sets hold at most 61 chunks.
	for _, i := range order {
		txs = append(txs, blockStepsChunk(id, i, payloads[i], sha3_256(payloads[i])))
	}
	return txs
}

// blockStepsSets is n one-chunk complete sets whose IDs 1..n appear in descending transaction order; set i carries
// payload byte(i). With literal hashes, hashes[i-1] is both its chunk hash and its commitment output.
func blockStepsSets(n int, hashes [][32]byte) [][]byte {
	var txs [][]byte
	for i := n; i >= 1; i-- {
		id, payload := [32]byte{0x40, byte(i >> 8), byte(i)}, []byte{byte(i)}
		if hashes == nil {
			txs = append(txs, blockStepsSet(id, []uint16{0}, [][]byte{payload})...)
			continue
		}
		txs = append(txs, blockStepsCommit(id, 1, blockStepsDAOut(hashes[i-1])), blockStepsChunk(id, 0, payload, hashes[i-1]))
	}
	return txs
}

// blockStepsSetHashes are the independently authored SHA3 literals of the one-byte payloads 1..128.
func blockStepsSetHashes(t *testing.T) [][32]byte {
	t.Helper()
	hashes := make([][32]byte, 0, 128)
	for _, s := range strings.Fields(`
2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7 0a1e2736777f80a62beb2df72b649878481c0ca10194b832b5136befbae54017
e3ed56bd086d8958483a12734fa0ae7f5c8bb160ef9092c67e82ed9b19e4c7b2 989216075a288af2c12f115557518d248f93c434965513f5f739df8c9d6e1932
3b0c4d506212cd7e7b88bc93b5b1811ab5de6796d2780e9de7378c87fe9a80a6 5a3442340ee31fa728f182f7dbaef4825025f40378061428bcc9f859aa4c294a
5223f7670b3b9ba04f57d477478ae77a58190d89f21da0b0be774735e23f9c96 04058b18052fd86b2a3032bcc55c823c48bf5810a3726f538a1d01ebb42584c5
8bf02b8b238233453488311be9b316e58ab7e1356ce948cb90dfef1af56992eb a78f2c566b2439463a2e7ca515bbfa3f92948506583cbadaebdd507f277542bd
962f8420917d7fa5479f4a767bf9b9a30a4ab377af26d72dbcff167d6ce3f6f5 9150274889a799f4e795088f93ee134dd9571c6fa7940370d3e05692c6fe217f
cc7fd2d0b9381e25d5f1394227a8a4df0f82d374567632ddae402323ac71427b 470301436d8bdf0e9ac28f33a05da66135cd405782cb5ccf32280807f44b0988
b83ec7cb1f722c090e14cdb557e673bf1826afd11e224d6e94ab48112f07633a ce8d4b29e9ff2dd381325b72551323368210da7c4a84d0e3e55dd029031a4e4c
8d5cc459ce36eda1a075fb2a80696f455c96693ca7e619d1ebaa384c56ce4436 bf931c9eed1d7d81c3ab815ea4150d5f9efe357f32dbece862c15cf4ed92ed67
1594a22d1e1dd176e6f35ae26d8efa294589e23676e1fdc917423a1282546528 f9ef4b52b4f8d87cbc3d50c981470099656f957e5b56dc109b8ec9ea0df31f7e
6e102fab5ab09de44a9ec4c6374d040fdec8492d06acb06d24aaa97d34f4248c 2c418d79b706e10f30ca8f908188f6543b836d8808ad96f32d4364e677e7616c
c6b91a3f82559066a81f3308f01a5a10f2f12b4dabc22b219977bd02886a7449 282e60e3d3159a68c70b220d794a361aeb4b40de1def66e6bb62984903993bcc
ff30ec4a3001b576d2ce0b81b948c0d27756f433f0a17d15ded2d416abb2fa40 f790118e6b020d24d925c7e88ff066d6e423dad4f199f9fc1c8c02aad2771c7a
137c2c0431e8f35541aa04817c8d865699a368c89c50addee08c9da39923b4d4 045fe5716b0ff6293c1e984a3b699dfd628f2b5cab47cf67f021297276c778d7
6621ea09fdc34b62ea0e541b4b5b4781779382d1eedf425319b0c70a6f3049f7 64c0d3363a7dac64da9dab189b7291d94cd58622c5c7232865dc8ba06b7e3375
69e6918d691d7826b04c799901f838bc779024fed79956490301c495080dfb74 60e893e6d54d8526e55a81f98bfac5da236bb203e84ed5967a8f527d5bf3d4a4
69557d9030b514d23c3fa89a760aefaf668a3597f85d343d76bdcdc4fb46fab2 19c556a59db63fa18f94b23908e29e09507de62cb4fa71cf10184120389e519d
415733a38975da5f451d27a3c42aa6ecb9b49e55466875b6c794606b7435083f 5ecdbae446010644dd235353f132c03fa21a1e6020a86e1672cbf1a693db5428
b2cc85d9e0dfa0f499ea90331043d79998ba91613930b6c9fed30860e5f9c566 7c4aeccd828f584d77f59f3f3f1f56c8bccd2910909bfd75cde01dfd40ad0dbd
63b09dc43798fff6456d57c5179f853d71d89c13c759c1cb39bfb011933e4930 71f6371d545b5237edc05a8ea1dcaaf5a18ec336fa6bc847dba2e6b4c841573b
b9401340161a1a40671bd617732ce24df2b28ddfb3852d43983832da59797bc3 82283b4b030589a7aa0ca28b8e933ac0bd89738a0df509806c864366deec31d7
797d7bc8705bcd69863385ecfa78454d6dd6cab3822a1a49d837a60e8845bc4a 45445e2157145217e6fd68388490e3c17a5ca24cf1b9353b579aca37f6aa0860
a7327aa627ec3566be2a4a0c62e9b90c339b85dbe13d04977536d6ba4c2db8f6 6890427a1f51a3e7e1dfb1f57449c5f2a24a9bed6b5d82973df1d78e765ea227
1236e9a3b6c8bbc889679c68af4372b7d68e2f2343c03ae7aaa4b25fbb8257c3 f9e2eaaa42d9fe9e558a9b8ef1bf366f190aacaa83bad2641ee106e9041096e4
67b176705b46206614219f47a05aee7ae6a3edbe850bbbe214c536b989aea4d2 b1b1bd1ed240b1496c81ccf19ceccf2af6fd24fac10ae42023628abbe2687310
1bf0b26eb2090599dd68cbb42c86a674cb07ab7adc103ad3ccdf521bb79056b9 b410677b84ed73fac43fcf1abd933151dd417d932a0ef9b0260ecf8b7b72ecb9
86bc56fc56af4c3cde021282f6b727ee9f90dd636e0b0c712a85d416c75e652d 0c67354981e9068905680b57898ad4f04b993c63eb66aa3f19cdfdc71d88077e
8f9b51ce624f01b0a40c9f68ba8bb0a2c06aa7f95d1ed27d6b1b5e1e99ee5e4d d14a329a1924592faf2d4ba6dc727d59af6afae983a0c208bf980237b63a5a6a
7609430974b087595488c154bf5c079887ead0e8efd4055cd136fda96a5ccbf8 763c38be0664691418d38f5ccde0162c9ff11fbda1b946d56476bdaa90fd13d6
36f2899dda755f20a4cba7bd395a95a4a3ae186206fc781ae5b00a8b6b138b32 c03cdc484ad76e2ff295f5f4dea5e5a17ef7c3b5e7726c9473957dd4a47f74d5
ef95447405babdf85baa7c4f0059e687df4e4ff1dfb90f62be64d406301e4317 660038bc754b4ff023f4e4c672cfc031a3d5f7348fb262a124c4fe1e1460f5a5
d827feb7bdb2df079c4d896ee5fdabad3b6258ad2049919bf822317e91d89bbf 053edf8c54e1067887e92964d9e856a4d0f31c730dba8575d80355ceadecf03e
1c9ebd6caf02840a5b2b7f0fc870ec1db154886ae9fe621b822b14fd0bf513d6 521ec18851e17bbba961bc46c70baf03ee67ebdea11a8306de39c15a90e9d2e5
2248e6be26f60c9baa59adbda2a136a4a5305d7b475d8465ba4911b4886e39a5 037f4095baddc6f37fde4740c304b1691512d2fc9cf7ede8a93b8c9ec3d1fe07
e63a84c18447bfca5c67b20a58fc6a4fefa762e4fa0e6b3b2e46f64daba345e5 caf04597f01603582b91c53d5dad9c6c481445b5160a976a44c35ed428b439d7
25c69eebe727567130b3e3320395e3ec854138e6ea5034dc79eebcbeb86da200 2cee232f0cf383960ac375e090a647e2afd4ebeb12b4cecb1bf91c2e0f4b3408
c837f30e97185c362830b324e58a3e6782095ee8457109b27f03819ff516e121 5445d3d5a46c7a99219705ea5b6daa7f870b83e721da6f252f2304b94a6d7d05
078773c4efc5ce946952e92d25f89d0cdd1603fc21842df386fa55855613e8cb 266ddf27cb4fb4223962ef29090bcc4f50e363bca75c581756f605fb91f9c7e8
6920014bef534e7eea89545a50d6aef0921f1972efcddce9f22f04a45b47d472 345baaa13bbe3a40695db7697fbe3f64206323b77cf3635902106f9f29667361
60c4004508ddcd8d1b0ea1c56ed1e5679d756d72e40f1a00820dbe5d9f69ff63 e5a73514ffed2f2f59b5112f4ae50cb138f1658633d354ac36c7c1bc019259d2
ba86a2a6dac23e336a34b4337eb740d40d900fae703bf55dcde8430208bb82e8 d034b2b544e4ffb619a9c156ae578fe21f38eb0997f097ca9569807ca157f4f6
164a93c6619015a4ed2d50a49c0d98252296e3e4c7fa5277656188edb3fe71b7 b3291957374e0a836351d5129cf45a5e0f73a92edff7b2c85ef159062301829e
78fe1396dda648dcbccc3c17af4cd29de873f2cdf5e4c5eb04e0ef08e86cc267 3eecb4a5c11c8bab18ddad1d268c827aaabb17c83f51869832a5af15efdedfcb
4cea338a15eccf7f51d8297c2873b1c5d0e5bea7d52eb7e984500b0759937d0d 31660a8aa8b0991f2d115272fecba9f9fe21e0798377c2b965405039319a1452
08ad231c95c5b60ab9757d6f95672f4e8731910a8f4573a90a1798ee8127ee94 1fb80b3947f9fa50760bc627a0341d53715fb79013184b34f4c0a306b62fdf05
a44269e96af4e6b2905af7ada5d04e6638f454b166e70f508364c9f8b2d0a321 803c621a10c78b864f94a5cf0426bcb72d0fcce9a9279f915fc3089554abcac3
9977908d483ef0469047a111c03426cb1577ab1d0f3163d71be9890181eff870 1b5c1c2a9ba8cbfa56a190b1a1d9bebb263e213006b9a8a51de1778346f9e661
b72b73f756be409451724bff061b449eb98785b2b5f9f77d9a68851e1b408199 74d0f5345a69a317de61309dd68507e8f17945cbf0762f81c2186e304bcef2a0
80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b b039179a8a4ce2c252aa6f2f25798251c19b75fc1508d9d511a191e0487d64a7
263ab762270d3b73d3e2cddf9acc893bb6bd41110347e5d5e4bd1d3c128ea90a 4ce8765e720c576f6f5a34ca380b3de5f0912e6e3cc5355542c363891e54594b
42538602949f370aa331d2c07a1ee7ff26caac9cc676288f94b82eb2188b8465 a0b37b8bfae8e71330bd8e278e4a45ca916d00475dd8b85e9352533454c9fec8
9f2898da52dedaca29f05bcac0c8e43e4b9f7cb5707c14cc3f35a567232cec7c 5a082c81a7e4d5833ee20bd67d2f4d736f679da33e4bebd3838217cb27bec1d3
bf872d20c4ef70ab19c9d413f172ce399a30ddeca771658561b1443111069c9e f35e560e05de779f2669b9f513c2a7ab81dfeb100e2f4ee1fb17354bfa2740ca
7c712596135d13a73c0dd366151b9440f3e9072371b436371107f12b3d850180 3e5e3e723953551a2ba2e7c5584bcc4ce407414af1ab2569051e7c9bfa33164d
1b42f48aa4371867a7c51ae6f237f35626e02c12eefa592614e1b10af7769370 8ee93ceda95bbe450f7fb53a700c56dfac4387e48eb127881a2a68727bc7810c
12c6debe02a118f89049700e723650d269838a76024a826607b163bc2a237031 14c68e20d8ddb4dbd248ed14bdb2012cfcee23530af0f71328009d1e90bb36ac
8a5e1d339fafc39350fd8cf1d7ca7982091c27f6b77f75bd4ddab3df425b4f8c f695d5fe6e2c67fe29ccf09341c29ad58154c568c5917a919c31936a3c96d607
cdc56a5028e51232cb28194fb1eb93e7014d60fb7afb447a49a1e1aaa640c9a4 889729e8d2d8864a59db1e195ad67c76949578ff2b4637388564a81dd68fc01e
d7e9468290673221249673d2b82c3cb316819a8496c2f2dba3eaebd9477af44c 453c8391bbd41309b79d7acc1382c2b0fb5f6b67f686d77c410666336ff9dabb
f1cfdca558ac0c00464ca0f3e265ec6fb32c57caeb106fbfed9f174f6b814642 741efa311f97686956946758e0d95f70f11ff2da4f2feb7c54314f44134ac49f
9d0f3db671f9fb22104b984763616732d383154a7a0dcdbb9ec17ab647b64961 3b4aed1c401f71809c93e713f4b86fb6d56c5b668f4ad8b474cb8884756aac46
fdce65e59494d92ac51f0e66404353bd53f4d2c3af800800c6dfb2be4d48e329 687111e80e745704574be9ab7d591cea66ac90cf9d7a56ef413b3e6f446e4ec9
5bf60471f2106089a88d2d95b0460d4a0ee215a54f08f73aae45afe86f72f12e aab7e55cbe6cb705810bdc48b60ed00fa2e158e1a7a816a611272e81b3e677d6
aac68691d102829ac973f5b44c26165aa4e29cd498aff642a08944645d6ca5bd bc2071a4de846f285702447f2589dd163678e0972a8a1b0d28b04ed5c094547f`) {
		hashes = append(hashes, [32]byte(blockStepsHex(t, s)))
	}
	if len(hashes) != 128 {
		t.Fatalf("%d payload literals, want 128", len(hashes))
	}
	return hashes
}

// blockStepsFiller is one kind-0 transaction with a P2PK output of length bytes and sentinels empty witness items.
func blockStepsFiller(length, sentinels int) []byte {
	b := append(AppendU32le(nil, 1), 0x00)
	b = AppendCompactSize(AppendCompactSize(AppendU64le(b, 1), 0), 1)
	b = AppendCompactSize(AppendU16le(AppendU64le(b, 0), COV_TYPE_P2PK), uint64(length))
	b = AppendCompactSize(AppendU32le(append(b, make([]byte, length)...), 0), uint64(sentinels))
	for range sentinels {
		b = append(b, SUITE_ID_SENTINEL, 0, 0)
	}
	return AppendCompactSize(b, 0)
}

func blockStepsWeight(t *testing.T, tx []byte) uint64 {
	t.Helper()
	parsed, _, _, _, err := ParseTx(tx)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	weight, _, _, err := TxWeightAndStats(parsed)
	if err != nil {
		t.Fatalf("TxWeightAndStats: %v", err)
	}
	return weight
}

// blockStepsWeighted returns non-coinbase fillers whose weight plus the standard coinbase's is exactly total.
func blockStepsWeighted(t *testing.T, total uint64) [][]byte {
	t.Helper()
	remaining := total - blockStepsWeight(t, coinbaseTxWithOutputs(0, []testOutput{{covenantType: COV_TYPE_ANCHOR, covenantData: make([]byte, 32)}}))
	full := blockStepsFiller(65_535, 0)
	fullWeight := blockStepsWeight(t, full)
	var txs [][]byte
	for remaining >= fullWeight+10_000 {
		txs, remaining = append(txs, full), remaining-fullWeight
	}
	if remaining > fullWeight {
		half := blockStepsFiller(32_768, 0)
		txs, remaining = append(txs, half), remaining-blockStepsWeight(t, half)
	}
	for sentinels := range 4 {
		base := blockStepsWeight(t, blockStepsFiller(253, sentinels))
		if remaining >= base && (remaining-base)%4 == 0 {
			tail := blockStepsFiller(253+int((remaining-base)/4), sentinels) //nolint:gosec // remaining is below one filler weight.
			if got := blockStepsWeight(t, tail); got != remaining {
				t.Fatalf("tail weight %d, want %d", got, remaining)
			}
			return append(txs, tail)
		}
	}
	t.Fatalf("no tail of weight %d", remaining)
	return nil
}

// blockStepsDABytes is chunk transactions with exactly total payload bytes and a wrong chunk hash each.
func blockStepsDABytes(total int) [][]byte {
	var txs [][]byte
	for i := 0; total > 0; i++ {
		n := min(total, CHUNK_BYTES)
		txs = append(txs, blockStepsChunk([32]byte{byte(1 + i/61)}, uint16(i%61), make([]byte, n), [32]byte{})) //nolint:gosec // i%61 < 61.
		total -= n
	}
	return txs
}

// blockStepsAnchors is one transaction whose ANCHOR outputs carry exactly total bytes (at most two outputs).
func blockStepsAnchors(total int) []byte {
	return txWithOutputs([]testOutput{
		{covenantType: COV_TYPE_ANCHOR, covenantData: make([]byte, 65_536)},
		{covenantType: COV_TYPE_ANCHOR, covenantData: make([]byte, total-65_536)},
	})
}

// blockStepsRecount appends extra bytes as one more declared transaction after raw's transactions.
func blockStepsRecount(t *testing.T, raw, extra []byte) []byte {
	t.Helper()
	off := BLOCK_HEADER_BYTES
	count, _, err := readCompactSize(raw, &off)
	if err != nil {
		t.Fatalf("readCompactSize: %v", err)
	}
	out := AppendCompactSize(slices.Clone(raw[:BLOCK_HEADER_BYTES]), count+1)
	return append(append(out, raw[off:]...), extra...)
}

func TestBlockSteps1To12Boundary(t *testing.T) {
	// Independently authored literals for the mined (first nonce 0) standard 1/3/5-Tx blocks.
	for _, c := range []struct {
		count                       int
		root, witness, commit, hash string
		weight                      uint64
	}{
		{
			1, "02e66000bf8ce870908df4a8689554852ccef681ee0b5df32246162a53e36e29", "99cf9696fc58d571713aee26dbbb172d460f77d10f139505fe06fd802e402403",
			"b716a4b7f4c0fab665298ab9b8199b601ab9fa7e0a27f0713383f34cf37071a8", "ee416a14b5a16a5fff3486e69b9c977bb61a3354a21ecd282666b25c7381c301", 414,
		},
		{
			3, "a1580040b77ca37ea9892aebb5c420b5066b575e5450c848b146ce7aba62e0ac", "c524fdc450a5dedf2455acdbff7d7a5d8e01b8479cef55d8edc4ca94f853a654",
			"3c9e6b805531978600f2972136bd4f8ca71921d3d459e53ab74fda8a6ecaaac0", "634cd83304788cb1ce48c852562445cc16c8f0be35a6f8c5e0005f2dcc1fab10", 922,
		},
		{
			5, "e589bd8f2c0b68a2331adb772d219090336c95064f66d3c4fb4598aeda9d50d8", "9d0fd1234a1d7abef579897ad69e19e049f13e4ffd8c8169aad551f4ee3b2cae",
			"f93a5eb5f312edc23583a42e74a4146ac7e3e18a2f4f4be2ef474b3d8a366edc", "eb6693cd7843401d492f8fcd22ad9d43b23eff9a73ce4c9b60c37e7b3a9a2869", 1430,
		},
	} {
		raw := blockStepsStd(t, nil, blockStepsPlain(c.count-1)...)
		summary, err := blockStepsRun(raw)
		blockStepsWantOK(t, "coinbase block", raw, summary, err)
		commit := [32]byte(blockStepsHex(t, c.commit))
		want := BlockBasicSummary{TxCount: uint64(c.count), SumWeight: c.weight, BlockHash: [32]byte(blockStepsHex(t, c.hash))} //nolint:gosec // count is 1, 3 or 5.
		if summary != want || [32]byte(raw[36:68]) != [32]byte(blockStepsHex(t, c.root)) || binary.LittleEndian.Uint64(raw[108:116]) != 0 ||
			WitnessCommitmentHash([32]byte(blockStepsHex(t, c.witness))) != commit || !bytes.Contains(raw[BLOCK_HEADER_BYTES:], commit[:]) {
			t.Fatalf("%d-tx literal summary %+v", c.count, summary)
		}
		if err := ValidateBlockBodyCommitments(raw); err != nil {
			t.Fatalf("%d-tx commitments: %v", c.count, err)
		}
	}
	// A first transaction without inputs is not a coinbase (step 13) but carries the exact witness commitment.
	txs := blockStepsPlain(2)
	commitment := blockStepsCommitment(t, txs)
	first := txWithOutputs([]testOutput{{covenantType: COV_TYPE_ANCHOR, covenantData: commitment[:]}})
	if weight := blockStepsWeight(t, first); weight != 250 {
		t.Fatalf("step13-invalid first tx weight %d, want literal 250 (base 62)", weight)
	}
	raw := blockStepsMake(t, append([][]byte{first}, txs...), nil)
	summary, err := blockStepsRun(raw)
	blockStepsWantOK(t, "step13-invalid block", raw, summary, err)
	if summary.TxCount != 3 {
		t.Fatalf("step13-invalid TxCount=%d, want 3", summary.TxCount)
	}
	if err := ValidateBlockBodyCommitments(raw); err != nil {
		t.Fatalf("step13-invalid commitments: %v", err)
	}
	target := POW_LIMIT
	_, err = ValidateBlockBasicWithContextAtHeight(raw, &blockStepsParent, &target, blockStepsHeight, blockStepsTimes)
	blockStepsWantCode(t, "full validator", BlockBasicSummary{}, err, BLOCK_ERR_COINBASE_INVALID, "first tx must be canonical coinbase")
	parsed, err := ParseBlockBytes(raw)
	if err != nil {
		t.Fatalf("ParseBlockBytes: %v", err)
	}
	if err := ValidateStoredBlockCommitments(parsed); err != nil {
		t.Fatalf("stored checker keeps a step13-invalid first tx bound: %v", err)
	}
	// The commitment-only entry checks the raw bound, the complete parse, the root, the witness commitment and both pins.
	blockStepsWantCode(t, "commitments trailing", BlockBasicSummary{}, ValidateBlockBodyCommitments(append(slices.Clone(raw), 0)), BLOCK_ERR_PARSE, "trailing bytes after tx list")
	if err := ValidateBlockBodyCommitments(make([]byte, blockSteps1To12MaxBytes+1)); !errors.Is(err, ErrBlockSteps1To12Capacity) {
		t.Fatalf("commitments capacity: %v", err)
	}
	wrongRoot := blockStepsMake(t, append([][]byte{first}, txs...), func(h *blockStepsHead) { h.root = [32]byte{1} })
	blockStepsWantCode(t, "commitments root", BlockBasicSummary{}, ValidateBlockBodyCommitments(wrongRoot), BLOCK_ERR_MERKLE_INVALID, "merkle_root mismatch")
	noWitness := blockStepsMake(t, append([][]byte{txWithOutputs(nil)}, txs...), nil)
	blockStepsWantCode(t, "commitments witness", BlockBasicSummary{}, ValidateBlockBodyCommitments(noWitness), BLOCK_ERR_WITNESS_COMMITMENT, "coinbase witness commitment missing or duplicated")
}

func TestBlockSteps1To12Timestamp(t *testing.T) {
	type row struct {
		name      string
		height    uint64
		window    []uint64
		timestamp uint64
		code      ErrorCode
		msg       string
	}
	const maxU64 = math.MaxUint64
	rows := []row{
		{"h1 above", 1, []uint64{500}, 501, "", ""},
		{"h1 at median", 1, []uint64{500}, 500, BLOCK_ERR_TIMESTAMP_OLD, "timestamp <= MTP median"},
		{"h2 even lower median", 2, []uint64{900, 500}, 501, "", ""},
		{"h2 at upper median", 2, []uint64{900, 500}, 900, "", ""},
		{"h11 duplicates", 11, []uint64{7, 3, 7, 1, 7, 9, 3, 3, 7, 2, 8}, 8, "", ""},
		{"h11 duplicate median", 11, []uint64{7, 3, 7, 1, 7, 9, 3, 3, 7, 2, 8}, 7, BLOCK_ERR_TIMESTAMP_OLD, "timestamp <= MTP median"},
		{"h12 median plus one", blockStepsHeight, blockStepsTimes, blockStepsMedian + 1, "", ""},
		{"h12 at median", blockStepsHeight, blockStepsTimes, blockStepsMedian, BLOCK_ERR_TIMESTAMP_OLD, "timestamp <= MTP median"},
		{"h12 future bound", blockStepsHeight, blockStepsTimes, blockStepsMedian + MAX_FUTURE_DRIFT, "", ""},
		{"h12 above future bound", blockStepsHeight, blockStepsTimes, blockStepsMedian + MAX_FUTURE_DRIFT + 1, BLOCK_ERR_TIMESTAMP_FUTURE, "timestamp exceeds future drift"},
		{"saturated upper bound", 1, []uint64{maxU64 - 10}, maxU64, "", ""},
	}
	for _, r := range rows {
		txs := blockStepsPlain(1)
		raw := blockStepsStd(t, func(h *blockStepsHead) { h.timestamp = r.timestamp }, txs...)
		rawCopy, windowCopy := slices.Clone(raw), slices.Clone(r.window)
		summary, err := ValidateBlockSteps1To12(raw, blockStepsParent, POW_LIMIT, r.height, r.window)
		if r.code == "" {
			blockStepsWantOK(t, r.name, raw, summary, err)
		} else {
			blockStepsWantCode(t, r.name, summary, err, r.code, r.msg)
		}
		if !bytes.Equal(raw, rawCopy) || !slices.Equal(r.window, windowCopy) {
			t.Fatalf("%s: inputs changed", r.name)
		}
	}
	// The future bound is step 7, before the step-9 anchor limit.
	raw := blockStepsStd(t, func(h *blockStepsHead) { h.timestamp = blockStepsMedian + MAX_FUTURE_DRIFT + 1 }, blockStepsAnchors(131_072-32+1))
	summary, err := blockStepsRun(raw)
	blockStepsWantCode(t, "future with anchor excess", summary, err, BLOCK_ERR_TIMESTAMP_FUTURE, "timestamp exceeds future drift")
}

func TestBlockSteps1To12DA(t *testing.T) {
	// Independently authored payload commitments: SHA3("B"), SHA3("BC") and the 61 index-ordered payloads {i,0x5a,3i}.
	lit := func(s string) [32]byte { return [32]byte(blockStepsHex(t, s)) }
	hashB := lit("521ec18851e17bbba961bc46c70baf03ee67ebdea11a8306de39c15a90e9d2e5")
	one := [][]byte{blockStepsCommit(blockStepsIDs[0], 1, blockStepsDAOut(hashB)), blockStepsChunk(blockStepsIDs[0], 0, []byte("B"), hashB)}
	// Chunk index 1 ("C") precedes index 0 ("B") in transaction order; the commitment is over index order "BC".
	pair := [][]byte{
		blockStepsChunk(blockStepsIDs[2], 1, []byte("C"), sha3_256([]byte("C"))), blockStepsChunk(blockStepsIDs[2], 0, []byte("B"), hashB),
		blockStepsCommit(blockStepsIDs[2], 2, blockStepsDAOut(lit("39e9f23897e642374a8e9c3a15faeed4ce77d3c698cc3e2c2d28de1499003204"))),
	}
	payloads := make([][]byte, 61)
	order := make([]uint16, 61)
	for i := range payloads {
		payloads[i], order[i] = []byte{byte(i), 0x5a, byte(3 * i)}, uint16(60-i) //nolint:gosec // i < 61.
	}
	// The commit follows its chunks, which appear in descending index order; the commitment is the literal over index order.
	full := blockStepsSet(blockStepsIDs[1], order, payloads)
	full = append(full[1:], blockStepsCommit(blockStepsIDs[1], 61, blockStepsDAOut(lit("b99b912810494b28895700b888312ead3821d8fff8c7942be30baef55d214bff"))))
	for _, c := range []struct {
		name string
		txs  [][]byte
	}{{"one chunk", one}, {"two chunks out of order", pair}, {"61 chunks out of order", full}, {"three sets", slices.Concat(full, one, pair)}, {"128 sets", blockStepsSets(128, blockStepsSetHashes(t))}} {
		raw := blockStepsStd(t, nil, c.txs...)
		summary, err := blockStepsRun(raw)
		blockStepsWantOK(t, c.name, raw, summary, err)
	}
}

func TestBlockSteps1To12ResourceBounds(t *testing.T) {
	for _, c := range []struct {
		name      string
		got, want uintptr
	}{
		{"TxInput", unsafe.Sizeof(TxInput{}), 64},
		{"TxOutput", unsafe.Sizeof(TxOutput{}), 40},
		{"WitnessItem", unsafe.Sizeof(WitnessItem{}), 56},
		{"Tx", unsafe.Sizeof(Tx{}), 136},
		{"DaCommitCore", unsafe.Sizeof(DaCommitCore{}), 200},
		{"frontier", unsafe.Sizeof(storedCommitmentFrontier{}), 2_064},
		{"DA record", unsafe.Sizeof(step12DARecord{}), 56},
	} {
		if c.got != c.want {
			t.Fatalf("%s ABI size %d, want %d", c.name, c.got, c.want)
		}
	}
	parser := 3 * (1_024*(unsafe.Sizeof(TxInput{})+unsafe.Sizeof(TxOutput{})+unsafe.Sizeof(WitnessItem{})) + unsafe.Sizeof(Tx{}) + unsafe.Sizeof(DaCommitCore{}))
	streaming := parser + 65_716 + 2*unsafe.Sizeof(storedCommitmentFrontier{}) + 16_384
	if parser != 492_528 || streaming != 578_756 || streaming > 589_824 {
		t.Fatalf("parser %d streaming %d exceed P", parser, streaming)
	}
	const m, a, n, k, p = 68_000_125, 1_048_576, 16_384, 10_080, 589_824
	charge := a + n*(48+40+72+40+116) + k*(32+8) + p + 4_096
	if charge != 7_223_040 || 2*m+charge != 143_223_290 || 2*m+charge >= 154_611_151 || m+a+116*n != 70_949_245 {
		t.Fatalf("C=%d Q(M)=%d OLD=%d", charge, 2*m+charge, m+a+116*n)
	}
	// The minimum DA transaction is an 88-byte one-byte chunk, bounding D and the record array below M.
	if got := len(blockStepsChunk(blockStepsIDs[0], 0, []byte{1}, [32]byte{})); got != 88 {
		t.Fatalf("minimum DA transaction %d bytes, want 88", got)
	}
	d := (m - 117) / 88
	record := int(unsafe.Sizeof(step12DARecord{}))
	if d != 772_727 || d*record != 43_272_712 || d*record >= m || record*128*62+32_000_000 >= d*record {
		t.Fatalf("D=%d records=%d", d, d*record)
	}
	// Parse-domain counterexamples: complete parse, valid header/root/context, no witness output.
	minimal := AppendCompactSize(AppendCompactSize(AppendU32le(AppendCompactSize(AppendCompactSize(AppendU64le(append(AppendU32le(nil, 1), 0x00), 0), 0), 0), 0), 0), 0)
	sentinel := AppendCompactSize(AppendU32le(AppendCompactSize(AppendCompactSize(AppendU64le(append(AppendU32le(nil, 1), 0x00), 0), 0), 0), 0), 1_024)
	sentinel = AppendCompactSize(append(sentinel, bytes.Repeat([]byte{SUITE_ID_SENTINEL, 0, 0}, 1_024)...), 0)
	// Independently authored literals (fixture-authoring-literals.json): the minimal core and txid, and each
	// counterexample's tagged Merkle root; the root is never produced by the frontier under test.
	if !bytes.Equal(minimal[:19], blockStepsHex(t, "01000000000000000000000000000000000000")) {
		t.Fatalf("minimal core %x", minimal[:19])
	}
	if _, txid, _, _, err := ParseTx(minimal); err != nil || txid != [32]byte(blockStepsHex(t, "d205b2f6296a4cc1e4ec65d1b80309ed98d3a1c03d241c675ff761c6a4502bc0")) {
		t.Fatalf("minimal txid %x (%v)", txid, err)
	}
	for _, c := range []struct {
		tx      []byte
		count   int
		wantLen int
		root    string
	}{
		{minimal, 2_500_000, 52_500_121, "d2f1e358069d82e7999eb9427b1e19004afcf8d9686ba0eb4a78a3363ed434f1"},
		{sentinel, 2_697, 8_347_334, "02b41b12e79a6f4415d273b0f3973416c7b8c95add90de8aba5cfd4c404cc910"},
	} {
		header := blockStepsMine(t, blockStepsHead{parent: blockStepsParent, root: [32]byte(blockStepsHex(t, c.root)), target: POW_LIMIT, timestamp: blockStepsMedian + 1, mine: true})
		raw := AppendCompactSize(slices.Clone(header), uint64(c.count)) //nolint:gosec // counts are positive literals.
		raw = append(raw, bytes.Repeat(c.tx, c.count)...)
		if len(raw) != c.wantLen {
			t.Fatalf("counterexample length %d, want %d", len(raw), c.wantLen)
		}
		summary, err := blockStepsRun(raw)
		blockStepsWantCode(t, "counterexample", summary, err, BLOCK_ERR_WITNESS_COMMITMENT, "coinbase witness commitment missing or duplicated")
	}
}

func TestBlockSteps1To12Input(t *testing.T) {
	std := blockStepsStd(t, nil, blockStepsPlain(1)...)
	oversized := make([]byte, blockSteps1To12MaxBytes+1)
	for _, c := range []struct {
		name   string
		raw    []byte
		height uint64
		target [32]byte
		times  []uint64
		want   error
	}{
		{"oversized with bad context", oversized, 0, [32]byte{}, nil, ErrBlockSteps1To12Capacity},
		{"zero height", []byte{1}, 0, POW_LIMIT, []uint64{}, ErrBlockSteps1To12Context},
		{"zero target", []byte{1}, blockStepsHeight, [32]byte{}, blockStepsTimes, ErrBlockSteps1To12Context},
		{"nil timestamps", []byte{1}, blockStepsHeight, POW_LIMIT, nil, ErrBlockSteps1To12Context},
		{"short timestamps", []byte{1}, blockStepsHeight, POW_LIMIT, blockStepsTimes[:10], ErrBlockSteps1To12Context},
		{"extra timestamps", []byte{1}, 3, POW_LIMIT, []uint64{1, 2, 3, 4}, ErrBlockSteps1To12Context},
	} {
		summary, err := ValidateBlockSteps1To12(c.raw, blockStepsParent, c.target, c.height, c.times)
		if !errors.Is(err, c.want) || summary != (BlockBasicSummary{}) {
			t.Fatalf("%s: got %+v/%v, want %v", c.name, summary, err, c.want)
		}
	}
	for _, n := range []int{0, BLOCK_HEADER_BYTES} {
		summary, err := blockStepsRun(std[:n])
		blockStepsWantCode(t, "short raw", summary, err, BLOCK_ERR_PARSE, "block too short")
	}
	// n == M reaches the content result: a zero header, then tx_count 0.
	summary, err := blockStepsRun(make([]byte, blockSteps1To12MaxBytes))
	blockStepsWantCode(t, "raw at M", summary, err, BLOCK_ERR_COINBASE_INVALID, "empty block tx list")
}

func TestBlockSteps1To12Parse(t *testing.T) {
	coinbase := coinbaseWithWitnessCommitment(t)
	std := blockStepsStd(t, nil)
	header := std[:BLOCK_HEADER_BYTES]
	kindTx := func(kind byte, tail []byte) []byte {
		b := AppendCompactSize(AppendCompactSize(AppendU64le(append(AppendU32le(nil, 1), kind), 1), 0), 0)
		return append(AppendU32le(b, 0), tail...)
	}
	for _, c := range []struct {
		name string
		raw  []byte
		code ErrorCode
	}{
		{"truncated header", std[:100], BLOCK_ERR_PARSE},
		{"nonminimal count", append(slices.Clone(header), 0xfd, 0x01, 0x00), BLOCK_ERR_PARSE},
		{"truncated count", append(slices.Clone(header), 0xfd), BLOCK_ERR_PARSE},
		{"count zero with trailing", append(slices.Clone(header), 0x00, 0x01), BLOCK_ERR_COINBASE_INVALID},
		{"tx boundary truncation", blockStepsRaw(header, [][]byte{coinbase, nil}), BLOCK_ERR_PARSE},
		{"mid-tx truncation", std[:len(std)-2], TX_ERR_PARSE},
		{"trailing", append(slices.Clone(std), 0), BLOCK_ERR_PARSE},
		{"kind0 payload", blockStepsRaw(header, [][]byte{kindTx(0x00, []byte{0, 1, 7})}), TX_ERR_PARSE},
		{"kind1 missing core", blockStepsRaw(header, [][]byte{kindTx(0x01, nil)}), TX_ERR_PARSE},
		{"kind2 empty payload", blockStepsRaw(header, [][]byte{blockStepsChunk(blockStepsIDs[0], 0, nil, [32]byte{})}), TX_ERR_PARSE},
		{"unknown kind", blockStepsRaw(header, [][]byte{kindTx(0x03, []byte{0, 0})}), TX_ERR_PARSE},
		{"chunk_count zero", blockStepsRaw(header, [][]byte{coinbase, blockStepsCommit(blockStepsIDs[0], 0)}), TX_ERR_PARSE},
	} {
		_, want := ParseBlockBytes(c.raw)
		var wantErr *TxError
		if !errors.As(want, &wantErr) || wantErr.Code != c.code {
			t.Fatalf("%s: oracle %v, want code %s", c.name, want, c.code)
		}
		// Parse precedes every later step: a wrong parent and a mismatched target change nothing.
		summary, err := ValidateBlockSteps1To12(c.raw, blockStepsOther, [32]byte{0x7f}, blockStepsHeight, blockStepsTimes)
		blockStepsWantCode(t, c.name, summary, err, wantErr.Code, wantErr.Msg)
	}
}

func TestBlockSteps1To12HeaderOrder(t *testing.T) {
	var one, half [32]byte
	one[31] = 1
	half = POW_LIMIT
	half[0] = 0x7f
	txs := blockStepsPlain(1)
	noCommitment := append([][]byte{coinbaseTxWithOutputs(0, []testOutput{{covenantType: COV_TYPE_P2PK, covenantData: validP2PKCovenantData()}})}, txs...)
	commitment := blockStepsCommitment(t, txs)
	anchor := testOutput{covenantType: COV_TYPE_ANCHOR, covenantData: commitment[:]}
	wrong := testOutput{covenantType: COV_TYPE_ANCHOR, covenantData: make([]byte, 32)}
	old := func(h *blockStepsHead) { h.timestamp = blockStepsMedian }
	for _, c := range []struct {
		name             string
		raw              []byte
		parent, expected [32]byte
		code             ErrorCode
		msg              string
	}{
		{"target range before parent", blockStepsStd(t, func(h *blockStepsHead) { h.target, h.mine = [32]byte{}, false }, txs...), blockStepsOther, POW_LIMIT, BLOCK_ERR_TARGET_INVALID, "target out of range"},
		{"isolated bad pow", blockStepsStd(t, func(h *blockStepsHead) { h.target, h.mine = one, false }, txs...), blockStepsParent, one, BLOCK_ERR_POW_INVALID, "pow invalid"},
		{"expected target before parent", blockStepsStd(t, nil, txs...), blockStepsOther, half, BLOCK_ERR_TARGET_INVALID, "target mismatch"},
		{"parent only", blockStepsStd(t, nil, txs...), blockStepsOther, POW_LIMIT, BLOCK_ERR_LINKAGE_INVALID, "prev_block_hash mismatch"},
		{"root before witness and time", blockStepsMake(t, noCommitment, func(h *blockStepsHead) { h.root, h.timestamp = [32]byte{1}, blockStepsMedian }), blockStepsParent, POW_LIMIT, BLOCK_ERR_MERKLE_INVALID, "merkle_root mismatch"},
		{"missing witness before time", blockStepsMake(t, noCommitment, old), blockStepsParent, POW_LIMIT, BLOCK_ERR_WITNESS_COMMITMENT, "coinbase witness commitment missing or duplicated"},
		{"duplicate witness before time", blockStepsMake(t, append([][]byte{coinbaseTxWithOutputs(0, []testOutput{anchor, anchor})}, txs...), old), blockStepsParent, POW_LIMIT, BLOCK_ERR_WITNESS_COMMITMENT, "coinbase witness commitment missing or duplicated"},
		{"wrong witness before time", blockStepsMake(t, append([][]byte{coinbaseTxWithOutputs(0, []testOutput{wrong})}, txs...), old), blockStepsParent, POW_LIMIT, BLOCK_ERR_WITNESS_COMMITMENT, "coinbase witness commitment missing or duplicated"},
	} {
		summary, err := ValidateBlockSteps1To12(c.raw, c.parent, c.expected, blockStepsHeight, blockStepsTimes)
		blockStepsWantCode(t, c.name, summary, err, c.code, c.msg)
	}
}

func TestBlockSteps1To12Resources(t *testing.T) {
	exact := blockStepsStd(t, nil, blockStepsWeighted(t, MAX_BLOCK_WEIGHT)...)
	summary, err := blockStepsRun(exact)
	blockStepsWantOK(t, "exact weight", exact, summary, err)
	if summary.SumWeight != MAX_BLOCK_WEIGHT {
		t.Fatalf("exact weight summary %d", summary.SumWeight)
	}
	over := blockStepsStd(t, nil, blockStepsWeighted(t, MAX_BLOCK_WEIGHT+1)...)
	summary, err = blockStepsRun(over)
	blockStepsWantCode(t, "weight+1", summary, err, BLOCK_ERR_WEIGHT_EXCEEDED, "block weight exceeded")
	// A completely parsed overweight prefix followed by trailing bytes or a malformed transaction is a parse error.
	summary, err = blockStepsRun(append(slices.Clone(over), 0))
	blockStepsWantCode(t, "overweight trailing", summary, err, BLOCK_ERR_PARSE, "trailing bytes after tx list")
	summary, err = blockStepsRun(blockStepsRecount(t, over, []byte{1, 0, 0, 0, 0x07}))
	blockStepsWantCode(t, "overweight malformed tx", summary, err, TX_ERR_PARSE, "unsupported tx_kind")
	daExact := blockStepsStd(t, nil, blockStepsDABytes(MAX_DA_BYTES_PER_BLOCK)...)
	summary, err = blockStepsRun(daExact)
	blockStepsWantCode(t, "exact DA reaches step 10", summary, err, BLOCK_ERR_DA_CHUNK_HASH_INVALID, "chunk_hash mismatch")
	summary, err = blockStepsRun(blockStepsStd(t, nil, blockStepsDABytes(MAX_DA_BYTES_PER_BLOCK+1)...))
	blockStepsWantCode(t, "DA+1", summary, err, BLOCK_ERR_WEIGHT_EXCEEDED, "DA bytes exceeded")
	anchorExact := blockStepsStd(t, nil, blockStepsAnchors(MAX_ANCHOR_BYTES_PER_BLOCK-32))
	summary, err = blockStepsRun(anchorExact)
	blockStepsWantOK(t, "exact anchor", anchorExact, summary, err)
	summary, err = blockStepsRun(blockStepsStd(t, nil, blockStepsAnchors(MAX_ANCHOR_BYTES_PER_BLOCK-32+1)))
	blockStepsWantCode(t, "anchor+1", summary, err, BLOCK_ERR_ANCHOR_BYTES_EXCEEDED, "anchor bytes exceeded")
}

func TestBlockSteps1To12DAOrder(t *testing.T) {
	a, b := blockStepsIDs[0], blockStepsIDs[1]
	p := []byte{0x42}
	good := func(id [32]byte, index uint16) []byte { return blockStepsChunk(id, index, p, sha3_256(p)) }
	commit := func(id [32]byte, count uint16) []byte {
		return blockStepsCommit(id, count, blockStepsDAOut(sha3_256(p)))
	}
	incomplete := slices.Concat(blockStepsSets(128, nil), [][]byte{commit([32]byte{0x50}, 2), good([32]byte{0x50}, 0)})
	for _, c := range []struct {
		name string
		txs  [][]byte
		code ErrorCode
		msg  string
	}{
		{"chunk hash before orphan", [][]byte{blockStepsChunk(a, 0, p, [32]byte{})}, BLOCK_ERR_DA_CHUNK_HASH_INVALID, "chunk_hash mismatch"},
		{"chunk hash before incomplete", [][]byte{commit(a, 2), blockStepsChunk(a, 0, p, [32]byte{})}, BLOCK_ERR_DA_CHUNK_HASH_INVALID, "chunk_hash mismatch"},
		{"orphan", [][]byte{good(a, 0)}, BLOCK_ERR_DA_SET_INVALID, "DA chunks without DA commit"},
		{"orphan before earlier duplicate", [][]byte{commit(a, 1), commit(a, 1), good(a, 0), good(b, 0)}, BLOCK_ERR_DA_SET_INVALID, "DA chunks without DA commit"},
		{"duplicate before earlier incomplete", [][]byte{commit(a, 2), good(a, 0), commit(b, 1), commit(b, 1), good(b, 0)}, BLOCK_ERR_DA_SET_INVALID, "duplicate DA commit for da_id"},
		{"duplicate index", [][]byte{commit(a, 2), good(a, 0), good(a, 0)}, BLOCK_ERR_DA_INCOMPLETE, "duplicate DA chunk index"},
		{"count mismatch", [][]byte{commit(a, 2), good(a, 0)}, BLOCK_ERR_DA_INCOMPLETE, "DA chunk count mismatch"},
		{"missing index zero", [][]byte{commit(a, 1), good(a, 1)}, BLOCK_ERR_DA_INCOMPLETE, "missing DA chunk index"},
		{"incomplete before set cap", incomplete, BLOCK_ERR_DA_INCOMPLETE, "DA chunk count mismatch"},
		{"set cap", blockStepsSets(129, nil), BLOCK_ERR_DA_BATCH_EXCEEDED, "too many DA commits in block"},
	} {
		summary, err := blockStepsRun(blockStepsStd(t, nil, c.txs...))
		blockStepsWantCode(t, c.name, summary, err, c.code, c.msg)
	}
}

func TestBlockSteps1To12DAPayload(t *testing.T) {
	a, b := blockStepsIDs[0], blockStepsIDs[1]
	p := []byte{0x42, 0x43}
	chunk := func(id [32]byte) []byte { return blockStepsChunk(id, 0, p, sha3_256(p)) }
	right := blockStepsDAOut(sha3_256(p))
	short := testOutput{covenantType: COV_TYPE_DA_COMMIT, covenantData: make([]byte, 31)}
	for _, c := range []struct {
		name string
		txs  [][]byte
		msg  string
	}{
		{"length before count", [][]byte{blockStepsCommit(a, 1, short, right), chunk(a)}, "DA commitment output has invalid length"},
		{"missing output", [][]byte{blockStepsCommit(a, 1), chunk(a)}, "DA commitment output missing or duplicated"},
		{"duplicate correct outputs", [][]byte{blockStepsCommit(a, 1, right, right), chunk(a)}, "DA commitment output missing or duplicated"},
		{"hash mismatch", [][]byte{blockStepsCommit(a, 1, blockStepsDAOut([32]byte{9})), chunk(a)}, "payload commitment mismatch"},
		{"lexical ID first", [][]byte{blockStepsCommit(b, 1), chunk(b), blockStepsCommit(a, 1, blockStepsDAOut([32]byte{9})), chunk(a)}, "payload commitment mismatch"},
	} {
		summary, err := blockStepsRun(blockStepsStd(t, nil, c.txs...))
		blockStepsWantCode(t, c.name, summary, err, BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID, c.msg)
	}
}

func TestBlockSteps1To12MixedOrder(t *testing.T) {
	a, b := blockStepsIDs[0], blockStepsIDs[1]
	p := []byte{0x42}
	good := blockStepsChunk(a, 0, p, sha3_256(p))
	anchorOver := blockStepsStd(t, nil, blockStepsAnchors(MAX_ANCHOR_BYTES_PER_BLOCK-32+1))
	noCommitment := blockStepsMake(t, append([][]byte{coinbaseTxWithOutputs(0, nil)}, blockStepsPlain(1)...), func(h *blockStepsHead) { h.timestamp = blockStepsMedian })
	short := testOutput{covenantType: COV_TYPE_DA_COMMIT, covenantData: make([]byte, 31)}
	for _, c := range []struct {
		name string
		raw  []byte
		code ErrorCode
		msg  string
	}{
		{"late parse and early resource", append(slices.Clone(anchorOver), 0), BLOCK_ERR_PARSE, "trailing bytes after tx list"},
		{"witness and time", noCommitment, BLOCK_ERR_WITNESS_COMMITMENT, "coinbase witness commitment missing or duplicated"},
		{"chunk hash and orphan", blockStepsStd(t, nil, blockStepsChunk(b, 0, p, [32]byte{})), BLOCK_ERR_DA_CHUNK_HASH_INVALID, "chunk_hash mismatch"},
		{"orphan and incomplete", blockStepsStd(t, nil, blockStepsCommit(a, 2, blockStepsDAOut(sha3_256(p))), good, blockStepsChunk(b, 0, p, sha3_256(p))), BLOCK_ERR_DA_SET_INVALID, "DA chunks without DA commit"},
		{"payload length and duplicate", blockStepsStd(t, nil, blockStepsCommit(a, 1, short, short), good), BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID, "DA commitment output has invalid length"},
		{"payload length and hash", blockStepsStd(t, nil, blockStepsCommit(a, 1, blockStepsDAOut([32]byte{9}), short), good), BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID, "DA commitment output has invalid length"},
	} {
		summary, err := blockStepsRun(c.raw)
		blockStepsWantCode(t, c.name, summary, err, c.code, c.msg)
	}
	// Target before parent is the header-order row; incomplete before set cap and duplicate before incomplete are DAOrder rows.
	summary, err := ValidateBlockSteps1To12(blockStepsStd(t, func(h *blockStepsHead) { h.target, h.mine = [32]byte{}, false }), blockStepsOther, POW_LIMIT, blockStepsHeight, blockStepsTimes)
	blockStepsWantCode(t, "target and parent", summary, err, BLOCK_ERR_TARGET_INVALID, "target out of range")
}

const (
	bindingWitnessMsg = "coinbase witness commitment missing or duplicated"
	bindingRootMsg    = "merkle_root mismatch"
	bindingPinMsg     = "first tx must be canonical coinbase"
)

// bindingFrame is one explicitly selected header width with every raw partial entry and its steps1-12 validator.
type bindingFrame struct {
	name      string
	headerLen int
	build     func(*testing.T, [][]byte, uint64, bool) []byte
	partials  map[string]func([]byte) error
	q         func([]byte) (BlockBasicSummary, error)
}

func bindingFrames() []bindingFrame {
	return []bindingFrame{
		{
			name: "116", headerLen: BLOCK_HEADER_BYTES,
			build: func(t *testing.T, txs [][]byte, timestamp uint64, wrongRoot bool) []byte {
				return blockStepsMake(t, txs, func(h *blockStepsHead) {
					h.timestamp = timestamp
					if wrongRoot {
						h.root = [32]byte{1}
					}
				})
			},
			partials: map[string]func([]byte) error{
				"parsed": func(raw []byte) error {
					parsed, err := ParseBlockBytes(raw)
					if err != nil {
						return err
					}
					return ValidateStoredBlockCommitments(parsed)
				},
				"body":   ValidateBlockBodyCommitments,
				"stream": verifyStoredBlockCommitmentsStream,
			},
			q: blockStepsRun,
		},
		{
			name: "148", headerLen: Initial148HeaderBytes,
			build: func(t *testing.T, txs [][]byte, timestamp uint64, wrongRoot bool) []byte {
				return initial148BlockFrame(t, txs, func(h *initial148BlockHead) {
					h.timestamp = timestamp
					h.root = [32]byte{0xde, 0xad}
					if wrongRoot {
						h.merkle = [32]byte{1}
					}
				})
			},
			partials: map[string]func([]byte) error{"body": ValidateInitial148BlockBodyCommitments},
			q: func(raw []byte) (BlockBasicSummary, error) {
				return ValidateInitial148BlockSteps1To12(raw, blockStepsParent, POW_LIMIT, blockStepsHeight, blockStepsTimes)
			},
		},
	}
}

func bindingAnchor(data []byte, value uint64) testOutput {
	return testOutput{value: value, covenantType: COV_TYPE_ANCHOR, covenantData: data}
}

// bindingWithWitness appends one sentinel witness item; the wire stays canonical and txid is unchanged.
func bindingWithWitness(tx []byte) []byte { return bindingWithWitnessItems(tx, 1) }

// bindingWithWitnessItems appends count sentinel witness items.
func bindingWithWitnessItems(tx []byte, count byte) []byte {
	out := append(slices.Clone(tx[:len(tx)-2]), count)
	for range count {
		out = append(out, SUITE_ID_SENTINEL, 0, 0)
	}
	return append(out, 0)
}

func bindingWithPayload(tx []byte, payload ...byte) []byte {
	return append(AppendCompactSize(slices.Clone(tx[:len(tx)-1]), uint64(len(payload))), payload...)
}

func bindingWithNonce(tx []byte, nonce byte) []byte {
	out := slices.Clone(tx)
	out[5] = nonce
	return out
}

// bindingChunkAnchored is a position-zero tx_kind 0x02 carrying the sole matching anchor, so only its payload is defective.
func bindingChunkAnchored(commit []byte) []byte {
	payload := []byte{0x42}
	hash := sha3_256(payload)
	b := append(AppendU32le(nil, 1), 0x02)
	b = AppendCompactSize(AppendCompactSize(AppendU64le(b, 1), 0), 1)
	b = AppendCompactSize(AppendU16le(AppendU64le(b, 0), COV_TYPE_ANCHOR), uint64(len(commit)))
	b = append(b, commit...)
	b = append(AppendU32le(b, 0), blockStepsIDs[0][:]...)
	b = append(AppendU16le(b, 0), hash[:]...)
	b = AppendCompactSize(AppendCompactSize(b, 0), uint64(len(payload)))
	return append(b, payload...)
}

// bindingCoreEdits are the coinbase-core defects of step 13 that stay parse-valid and leave the root inputs, singleton
// and pins untouched. Offsets are those of coinbaseTxWithOutputs; msg is the ordered step-13 refusal.
func bindingCoreEdits() []struct {
	name string
	edit func([]byte) []byte
	msg  string
} {
	const inputStart, inputEnd = 14, 55
	return []struct {
		name string
		edit func([]byte) []byte
		msg  string
	}{
		{"nonce", func(tx []byte) []byte { return bindingWithNonce(tx, 1) }, bindingPinMsg},
		{"prevout", bindingWithPrevout, bindingPinMsg},
		{"prev_vout", func(tx []byte) []byte { out := slices.Clone(tx); out[46] = 0; return out }, bindingPinMsg},
		{"script_sig", func(tx []byte) []byte { out := slices.Clone(tx); out[50] = 1; return slices.Insert(out, 51, 0x00) }, bindingPinMsg},
		{"sequence", func(tx []byte) []byte { out := slices.Clone(tx); out[51] = 0; return out }, bindingPinMsg},
		{"no input", func(tx []byte) []byte {
			out := slices.Clone(tx)
			out[13] = 0
			return slices.Delete(out, inputStart, inputEnd)
		}, bindingPinMsg},
		{"two inputs", func(tx []byte) []byte {
			out := slices.Clone(tx)
			out[13] = 2
			return slices.Insert(out, inputEnd, slices.Clone(tx[inputStart:inputEnd])...)
		}, bindingPinMsg},
		{"locktime", func(tx []byte) []byte { out := slices.Clone(tx); out[len(out)-6] ^= 1; return out }, "coinbase locktime must equal block height"},
	}
}

func bindingWithPrevout(tx []byte) []byte {
	out := slices.Clone(tx)
	out[14] = 1
	return out
}

func bindingCheck(t *testing.T, label string, err error, code ErrorCode, msg string) {
	t.Helper()
	if code == "" {
		if err != nil {
			t.Fatalf("%s: unexpected refusal %v", label, err)
		}
		return
	}
	initial148BlockWantError(t, label, err, code, msg)
}

func bindingCheckPartials(t *testing.T, f bindingFrame, label string, raw []byte, code ErrorCode, msg string) {
	t.Helper()
	before := slices.Clone(raw)
	failed := false
	for _, name := range slices.Sorted(maps.Keys(f.partials)) {
		failed = !t.Run(f.name+"/"+name, func(t *testing.T) {
			bindingCheck(t, label+" ["+f.name+"/"+name+"]", f.partials[name](raw), code, msg)
		}) || failed
	}
	if !bytes.Equal(raw, before) {
		t.Errorf("%s: input mutated", label)
		failed = true
	}
	if failed {
		t.FailNow()
	}
}

// TestGoBlockBodyBindingShapes owns B01-B03, B05 and B07: the commitment comes from the written tagged-root and SHA3
// definition, never from the selector under test.
func TestGoBlockBodyBindingShapes(t *testing.T) {
	others := blockStepsPlain(1)
	commit := initial148BlockWitnessCommit(t, others...)
	other := [32]byte{0x77}
	cb := func(outs ...testOutput) []byte { return coinbaseTxWithOutputs(0, outs) }
	sole := bindingAnchor(commit[:], 0)
	wrong := bindingAnchor(other[:], 0)
	clean := cb(sole)
	p2pk32 := testOutput{covenantType: COV_TYPE_P2PK, covenantData: other[:]}
	short, long := bindingAnchor(make([]byte, 31), 0), bindingAnchor(make([]byte, 33), 0)

	id, payload := blockStepsIDs[0], []byte{0x42}
	hash := sha3_256(payload)
	chunk := blockStepsChunk(id, 0, payload, hash)
	daCommit := initial148BlockWitnessCommit(t, chunk)
	daFirst := blockStepsCommit(id, 1, blockStepsDAOut(hash), bindingAnchor(daCommit[:], 0))

	const anyQ = ErrorCode("*")
	for _, c := range []struct {
		name   string
		first  []byte
		others [][]byte
		code   ErrorCode
		msg    string
		qCode  ErrorCode
		qMsg   string
	}{
		{name: "binding B01 clean", first: clean, others: others},
		{name: "binding B02 shape ignores value", first: cb(bindingAnchor(commit[:], 9)), others: others},
		{name: "binding B02 excluded output non-anchor", first: cb(p2pk32, sole), others: others},
		{name: "binding B02 excluded output length31", first: cb(short, sole), others: others},
		{name: "binding B02 excluded output length33", first: cb(sole, long), others: others},
		{name: "binding B03 core remains bound zero-payload DA_COMMIT", first: daFirst, others: [][]byte{chunk}, qCode: anyQ},
		{name: "binding B05 singleton cardinality zero", first: cb(p2pk32), others: others, code: BLOCK_ERR_WITNESS_COMMITMENT, msg: bindingWitnessMsg, qCode: BLOCK_ERR_WITNESS_COMMITMENT, qMsg: bindingWitnessMsg},
		{name: "binding B05 singleton cardinality equal/equal", first: cb(sole, sole), others: others, code: BLOCK_ERR_WITNESS_COMMITMENT, msg: bindingWitnessMsg, qCode: BLOCK_ERR_WITNESS_COMMITMENT, qMsg: bindingWitnessMsg},
		{name: "binding B05 singleton cardinality equal/distinct", first: cb(sole, wrong), others: others, code: BLOCK_ERR_WITNESS_COMMITMENT, msg: bindingWitnessMsg, qCode: BLOCK_ERR_WITNESS_COMMITMENT, qMsg: bindingWitnessMsg},
		{name: "binding B05 singleton cardinality distinct/equal", first: cb(wrong, sole), others: others, code: BLOCK_ERR_WITNESS_COMMITMENT, msg: bindingWitnessMsg, qCode: BLOCK_ERR_WITNESS_COMMITMENT, qMsg: bindingWitnessMsg},
		{name: "binding B05 singleton cardinality distinct/distinct", first: cb(wrong, bindingAnchor(make([]byte, 32), 0)), others: others, code: BLOCK_ERR_WITNESS_COMMITMENT, msg: bindingWitnessMsg, qCode: BLOCK_ERR_WITNESS_COMMITMENT, qMsg: bindingWitnessMsg},
		{name: "binding B05 sole payload", first: cb(wrong), others: others, code: BLOCK_ERR_WITNESS_COMMITMENT, msg: bindingWitnessMsg, qCode: BLOCK_ERR_WITNESS_COMMITMENT, qMsg: bindingWitnessMsg},
		{name: "binding B07 witness pin", first: bindingWithWitness(clean), others: others, code: BLOCK_ERR_COINBASE_INVALID, msg: bindingPinMsg},
		{name: "binding B07 payload pin", first: bindingWithPayload(daFirst, 0x42), others: [][]byte{chunk}, code: BLOCK_ERR_COINBASE_INVALID, msg: bindingPinMsg, qCode: anyQ},
	} {
		for _, f := range bindingFrames() {
			raw := f.build(t, append([][]byte{c.first}, c.others...), blockStepsMedian+1, false)
			bindingCheckPartials(t, f, c.name, raw, c.code, c.msg)
			if c.qCode == anyQ {
				continue
			}
			_, err := f.q(raw)
			bindingCheck(t, c.name+" ["+f.name+"/Q]", err, c.qCode, c.qMsg)
		}
	}
	for _, core := range bindingCoreEdits() {
		label := "binding B03 core remains bound " + core.name
		for _, f := range bindingFrames() {
			raw := f.build(t, append([][]byte{core.edit(clean)}, others...), blockStepsMedian+1, false)
			bindingCheckPartials(t, f, label, raw, "", "")
			_, err := f.q(raw)
			bindingCheck(t, label+" ["+f.name+"/Q]", err, "", "")
		}
	}
	// A parse-canonical witness on a later transaction is ordinary: it only enters the witness root.
	witnessed := bindingWithWitness(txWithOneOutput(10, COV_TYPE_P2PK, validP2PKCovenantData()))
	for _, f := range bindingFrames() {
		raw := f.build(t, [][]byte{initial148BlockCoinbase(t, witnessed), witnessed}, blockStepsMedian+1, false)
		bindingCheckPartials(t, f, "binding B07 later witness allowed", raw, "", "")
	}
}

// bindingChunkOutputs is a position-zero tx_kind 0x02 with the given outputs; its parser requires the payload, so only
// the witness range varies.
func bindingChunkOutputs(outs []testOutput, witnesses byte, payload ...byte) []byte {
	hash := sha3_256(payload)
	b := append(AppendU32le(nil, 1), 0x02)
	b = AppendCompactSize(AppendCompactSize(AppendU64le(b, 1), 0), uint64(len(outs)))
	for _, out := range outs {
		b = AppendCompactSize(AppendU16le(AppendU64le(b, out.value), out.covenantType), uint64(len(out.covenantData)))
		b = append(b, out.covenantData...)
	}
	b = append(AppendU32le(b, 0), blockStepsIDs[0][:]...)
	b = append(AppendU16le(b, 0), hash[:]...)
	b = append(b, witnesses)
	for range witnesses {
		b = append(b, SUITE_ID_SENTINEL, 0, 0)
	}
	return append(AppendCompactSize(b, uint64(len(payload))), payload...)
}

type bindingKindRow struct {
	name  string
	first func([]testOutput) []byte
	dirty bool
}

type bindingShapeRow struct {
	name  string
	outs  []testOutput
	bound bool
}

// bindingKindRows is every legal position-zero kind and pin state. A tx_kind 0x00 payload (B13) and a tx_kind 0x02 without
// payload do not parse; TestGoBlockBodyBindingFirstError owns both refusals.
func bindingKindRows() []bindingKindRow {
	cb := func(outs []testOutput) []byte { return coinbaseTxWithOutputs(0, outs) }
	commitTx := func(outs []testOutput) []byte {
		return blockStepsCommit(blockStepsIDs[0], 1, append([]testOutput{blockStepsDAOut(sha3_256([]byte{0x42}))}, outs...)...)
	}
	return []bindingKindRow{
		{"kind0 clean", cb, false},
		{"kind0 witness", func(o []testOutput) []byte { return bindingWithWitness(cb(o)) }, true},
		{"kind0 two witness", func(o []testOutput) []byte { return bindingWithWitnessItems(cb(o), 2) }, true},
		{"kind1 clean", commitTx, false},
		{"kind1 witness", func(o []testOutput) []byte { return bindingWithWitness(commitTx(o)) }, true},
		{"kind1 two witness", func(o []testOutput) []byte { return bindingWithWitnessItems(commitTx(o), 2) }, true},
		{"kind1 payload", func(o []testOutput) []byte { return bindingWithPayload(commitTx(o), 0x42) }, true},
		{"kind1 two byte payload", func(o []testOutput) []byte { return bindingWithPayload(commitTx(o), 0x42, 0x43) }, true},
		{"kind1 witness and payload", func(o []testOutput) []byte { return bindingWithPayload(bindingWithWitness(commitTx(o)), 0x42) }, true},
		{"kind2 payload", func(o []testOutput) []byte { return bindingChunkOutputs(o, 0, 0x42) }, true},
		{"kind2 two byte payload", func(o []testOutput) []byte { return bindingChunkOutputs(o, 0, 0x42, 0x43) }, true},
		{"kind2 witness and payload", func(o []testOutput) []byte { return bindingChunkOutputs(o, 1, 0x42) }, true},
		{"kind2 two witness and payload", func(o []testOutput) []byte { return bindingChunkOutputs(o, 2, 0x42) }, true},
	}
}

// bindingShapeRows spells the qualified-anchor domain. Only the bound column decides: exactly one qualified anchor,
// with the committed data, at any value.
func bindingShapeRows(commit [32]byte) []bindingShapeRow {
	other := [32]byte{0x77}
	eq := func(v uint64) testOutput { return bindingAnchor(commit[:], v) }
	ne := func(v uint64) testOutput { return bindingAnchor(other[:], v) }
	zero := bindingAnchor(make([]byte, 32), 0)
	rows := []bindingShapeRow{
		{"k0", nil, false},
		{"k1 wrong v0", []testOutput{ne(0)}, false},
		{"k1 wrong v9", []testOutput{ne(9)}, false},
		{"k1 wrong v1", []testOutput{ne(1)}, false},
		{"k1 wrong vmax", []testOutput{ne(math.MaxUint64)}, false},
		{"k1 right v0", []testOutput{eq(0)}, true},
		{"k1 right v9", []testOutput{eq(9)}, true},
		{"k1 right v1", []testOutput{eq(1)}, true},
		{"k1 right vmax", []testOutput{eq(math.MaxUint64)}, true},
		{"k3 equal/distinct/distinct", []testOutput{eq(0), ne(0), ne(0)}, false},
		{"k3 distinct/equal/distinct", []testOutput{ne(0), eq(0), ne(0)}, false},
		{"k3 distinct/distinct/equal", []testOutput{ne(0), ne(0), eq(0)}, false},
		{"k3 equal/equal/equal", []testOutput{eq(0), eq(0), eq(0)}, false},
		{"k3 distinct/distinct/equal mixed values", []testOutput{ne(9), ne(1), eq(math.MaxUint64)}, false},
		{"k4 distinct/distinct/distinct/equal", []testOutput{ne(0), ne(0), ne(0), eq(0)}, false},
		{"k4 equal/equal/equal/equal", []testOutput{eq(0), eq(0), eq(0), eq(0)}, false},
		{"k5 distinct/distinct/distinct/distinct/equal", []testOutput{ne(0), ne(0), ne(0), ne(0), eq(0)}, false},
	}
	for _, v := range [][2]uint64{{0, 0}, {0, 9}, {9, 0}, {9, 9}, {0, 1}, {1, 0}, {0, math.MaxUint64}, {math.MaxUint64, 0}} {
		suffix := fmt.Sprintf(" v%d/v%d", v[0], v[1])
		last := ne(v[1])
		last.covenantData = zero.covenantData
		rows = append(rows,
			bindingShapeRow{"k2 equal/equal" + suffix, []testOutput{eq(v[0]), eq(v[1])}, false},
			bindingShapeRow{"k2 equal/distinct" + suffix, []testOutput{eq(v[0]), ne(v[1])}, false},
			bindingShapeRow{"k2 distinct/equal" + suffix, []testOutput{ne(v[0]), eq(v[1])}, false},
			bindingShapeRow{"k2 distinct/distinct" + suffix, []testOutput{ne(v[0]), last}, false})
	}
	return rows
}

// TestGoBlockBodyBindingKindMatrix owns the closed domain of position-zero kind x anchor shape x value x pins on the raw
// partial entries and the ordered step-6 family: no kind or value escapes the singleton, and the pins follow it.
func TestGoBlockBodyBindingKindMatrix(t *testing.T) {
	others := blockStepsPlain(1)
	commit := initial148BlockWitnessCommit(t, others...)
	for _, kind := range bindingKindRows() {
		for _, shape := range bindingShapeRows(commit) {
			label := "binding B05 kind matrix " + kind.name + " " + shape.name
			code, msg := ErrorCode(BLOCK_ERR_WITNESS_COMMITMENT), bindingWitnessMsg
			if shape.bound {
				code, msg = "", ""
				if kind.dirty {
					code, msg = BLOCK_ERR_COINBASE_INVALID, bindingPinMsg
				}
			}
			for _, f := range bindingFrames() {
				raw := f.build(t, append([][]byte{kind.first(shape.outs)}, others...), blockStepsMedian+1, false)
				bindingCheckPartials(t, f, label, raw, code, msg)
				if shape.bound {
					continue
				}
				_, err := f.q(raw)
				bindingCheck(t, label+" ["+f.name+"/Q]", err, BLOCK_ERR_WITNESS_COMMITMENT, bindingWitnessMsg)
				if f.headerLen == BLOCK_HEADER_BYTES {
					target := POW_LIMIT
					_, err = ValidateBlockBasicWithContextAtHeight(raw, &blockStepsParent, &target, blockStepsHeight, blockStepsTimes)
					bindingCheck(t, label+" [ordered]", err, BLOCK_ERR_WITNESS_COMMITMENT, bindingWitnessMsg)
				}
			}
		}
	}
}

// TestGoBlockBodyBindingFirstError owns B06, B09 and B13 for the raw partial entries: parsing first, then txid root,
// singleton and the pins.
func TestGoBlockBodyBindingFirstError(t *testing.T) {
	others := blockStepsPlain(1)
	commit := initial148BlockWitnessCommit(t, others...)
	clean := coinbaseTxWithOutputs(0, []testOutput{bindingAnchor(commit[:], 0)})
	noAnchor := coinbaseTxWithOutputs(0, []testOutput{{covenantType: COV_TYPE_P2PK, covenantData: validP2PKCovenantData()}})
	zeroOutputs := coinbaseTxWithOutputs(0, nil)
	dirty := bindingWithWitness(clean)
	dirtyNoAnchor := bindingWithWitness(noAnchor)
	for _, f := range bindingFrames() {
		build := func(first []byte, wrongRoot bool) []byte {
			return f.build(t, append([][]byte{first}, others...), blockStepsMedian+1, wrongRoot)
		}
		header := build(clean, false)[:f.headerLen]
		for _, c := range []struct {
			name string
			raw  []byte
			code ErrorCode
			msg  string
		}{
			{"binding B09 commitment order root before witness", build(noAnchor, true), BLOCK_ERR_MERKLE_INVALID, bindingRootMsg},
			{"binding B09 commitment order root before pin", build(dirty, true), BLOCK_ERR_MERKLE_INVALID, bindingRootMsg},
			{"binding B09 commitment order witness before pin", build(dirtyNoAnchor, false), BLOCK_ERR_WITNESS_COMMITMENT, bindingWitnessMsg},
			{"binding B09 commitment order zero outputs", build(zeroOutputs, false), BLOCK_ERR_WITNESS_COMMITMENT, bindingWitnessMsg},
			{"binding B09 commitment order zero outputs wrong root", build(zeroOutputs, true), BLOCK_ERR_MERKLE_INVALID, bindingRootMsg},
			{"binding B06 trailing before root", append(build(noAnchor, true), 0), BLOCK_ERR_PARSE, "trailing bytes after tx list"},
			{"binding B06 truncated tx", func() []byte { r := build(noAnchor, true); return r[:len(r)-1] }(), TX_ERR_PARSE, "unexpected EOF (u8)"},
			{"binding B06 header only", slices.Clone(header), BLOCK_ERR_PARSE, "block too short"},
			{"binding B06 boundary EOF", append(append(slices.Clone(header), 2), clean...), BLOCK_ERR_PARSE, "unexpected EOF in tx list"},
			{"binding B06 nonminimal count", append(append(slices.Clone(header), 0xfd, 1, 0), clean...), BLOCK_ERR_PARSE, "invalid tx_count"},
			{"binding B06 incomplete count", append(slices.Clone(header), 0xfd, 1), BLOCK_ERR_PARSE, "invalid tx_count"},
			{"binding B07 DA_CHUNK payload pin", build(bindingChunkAnchored(commit[:]), false), BLOCK_ERR_COINBASE_INVALID, bindingPinMsg},
			{"binding B06 zero count", append(slices.Clone(header), 0), BLOCK_ERR_COINBASE_INVALID, "empty block tx list"},
			{"binding B13 kind0 payload", blockStepsRaw(header, [][]byte{bindingWithPayload(clean, 0x07)}), TX_ERR_PARSE, "da_payload_len must be 0 for tx_kind=0x00"},
			{"binding B09 raw parsing first kind2 empty payload", blockStepsRaw(header, [][]byte{blockStepsChunk(blockStepsIDs[0], 0, nil, [32]byte{})}), TX_ERR_PARSE, "da_payload_len out of range for tx_kind=0x02"},
		} {
			bindingCheckPartials(t, f, c.name, c.raw, c.code, c.msg)
		}
	}
}

// TestGoBlockBodyBindingSection25Order owns the ordered side of B09: a pin defect is step 13 only.
func TestGoBlockBodyBindingSection25Order(t *testing.T) {
	const late = blockStepsMedian
	cb := func(txs ...[]byte) []byte {
		commit := initial148BlockWitnessCommit(t, txs...)
		return coinbaseTxWithOutputs(0, []testOutput{bindingAnchor(commit[:], 0)})
	}
	plain := blockStepsPlain(1)
	badWitness := coinbaseTxWithOutputs(0, []testOutput{{covenantType: COV_TYPE_P2PK, covenantData: validP2PKCovenantData()}})
	payload := []byte{0x42}
	orphan := blockStepsChunk(blockStepsIDs[0], 0, payload, sha3_256(payload))
	heavy := blockStepsWeighted(t, MAX_BLOCK_WEIGHT+1)
	for _, f := range bindingFrames() {
		for _, c := range []struct {
			name      string
			first     []byte
			others    [][]byte
			timestamp uint64
			code      ErrorCode
			msg       string
		}{
			{"binding B09 Section25 order pin behind timestamp", bindingWithWitness(cb(plain...)), plain, late, BLOCK_ERR_TIMESTAMP_OLD, "timestamp <= MTP median"},
			{"binding B09 Section25 order pin behind weight", bindingWithWitness(cb(heavy...)), heavy, blockStepsMedian + 1, BLOCK_ERR_WEIGHT_EXCEEDED, "block weight exceeded"},
			{"binding B09 Section25 order pin behind DA", bindingWithWitness(cb(orphan)), [][]byte{orphan}, blockStepsMedian + 1, BLOCK_ERR_DA_SET_INVALID, "DA chunks without DA commit"},
			{"binding B09 Section25 order witness before timestamp", bindingWithWitness(badWitness), plain, late, BLOCK_ERR_WITNESS_COMMITMENT, bindingWitnessMsg},
			{"binding B09 Section25 order witness before weight", badWitness, heavy, blockStepsMedian + 1, BLOCK_ERR_WITNESS_COMMITMENT, bindingWitnessMsg},
			{"binding B09 Section25 order witness before DA", badWitness, [][]byte{orphan}, blockStepsMedian + 1, BLOCK_ERR_WITNESS_COMMITMENT, bindingWitnessMsg},
			{"binding B09 Section25 order Q admits pin-only", bindingWithWitness(cb(plain...)), plain, blockStepsMedian + 1, "", ""},
		} {
			raw := f.build(t, append([][]byte{c.first}, c.others...), c.timestamp, false)
			_, err := f.q(raw)
			bindingCheck(t, c.name+" ["+f.name+"/Q]", err, c.code, c.msg)
		}
	}
	// The complete 116 validator runs step 13 only after every earlier step.
	target := POW_LIMIT
	dirty := bindingWithWitness(coinbaseWithWitnessCommitmentAtHeight(t, blockStepsHeight, plain...))
	old := blockStepsMake(t, append([][]byte{dirty}, plain...), func(h *blockStepsHead) { h.timestamp = late })
	_, err := ValidateBlockBasicWithContextAtHeight(old, &blockStepsParent, &target, blockStepsHeight, blockStepsTimes)
	initial148BlockWantError(t, "binding B09 Section25 order full timestamp", err, BLOCK_ERR_TIMESTAMP_OLD, "timestamp <= MTP median")
	pinOnly := blockStepsMake(t, append([][]byte{dirty}, plain...), nil)
	_, err = ValidateBlockBasicWithContextAtHeight(pinOnly, &blockStepsParent, &target, blockStepsHeight, blockStepsTimes)
	initial148BlockWantError(t, "binding B09 Section25 order full step13", err, BLOCK_ERR_COINBASE_INVALID, bindingPinMsg)
	for _, c := range []struct {
		name   string
		others [][]byte
		code   ErrorCode
		msg    string
	}{
		{"binding B09 Section25 order full pin behind weight", heavy, BLOCK_ERR_WEIGHT_EXCEEDED, "block weight exceeded"},
		{"binding B09 Section25 order full pin behind DA", [][]byte{orphan}, BLOCK_ERR_DA_SET_INVALID, "DA chunks without DA commit"},
	} {
		first := bindingWithWitness(coinbaseWithWitnessCommitmentAtHeight(t, blockStepsHeight, c.others...))
		mixed := blockStepsMake(t, append([][]byte{first}, c.others...), nil)
		_, err = ValidateBlockBasicWithContextAtHeight(mixed, &blockStepsParent, &target, blockStepsHeight, blockStepsTimes)
		initial148BlockWantError(t, c.name, err, c.code, c.msg)
	}
	for _, core := range bindingCoreEdits() {
		first := core.edit(coinbaseWithWitnessCommitmentAtHeight(t, blockStepsHeight, plain...))
		block := blockStepsMake(t, append([][]byte{first}, plain...), nil)
		_, err = ValidateBlockBasicWithContextAtHeight(block, &blockStepsParent, &target, blockStepsHeight, blockStepsTimes)
		initial148BlockWantError(t, "binding B03 full step13 "+core.name, err, BLOCK_ERR_COINBASE_INVALID, core.msg)
	}
}

// bindingPinKinds are the position-zero transactions the parser admits with a dirty pin half, each with the DA set that
// makes the block's DA rules pass. A kind0 payload is a parse refusal and a kind2 always carries its payload (B07).
func bindingPinKinds() []struct {
	name  string
	set   [][]byte
	first func(t *testing.T, extra []testOutput, others ...[]byte) []byte
} {
	payload := []byte{0x42}
	hash := sha3_256(payload)
	id := blockStepsIDs[0]
	commit := func(t *testing.T, extra []testOutput, others ...[]byte) []byte {
		anchor := initial148BlockWitnessCommit(t, others...)
		return blockStepsCommit(id, 1, append(slices.Clone(extra), blockStepsDAOut(hash), bindingAnchor(anchor[:], 0))...)
	}
	return []struct {
		name  string
		set   [][]byte
		first func(t *testing.T, extra []testOutput, others ...[]byte) []byte
	}{
		{"kind1 payload", [][]byte{blockStepsChunk(id, 0, payload, hash)}, func(t *testing.T, extra []testOutput, others ...[]byte) []byte {
			return bindingWithPayload(commit(t, extra, others...), 0x42)
		}},
		{"kind1 witness", [][]byte{blockStepsChunk(id, 0, payload, hash)}, func(t *testing.T, extra []testOutput, others ...[]byte) []byte {
			return bindingWithWitness(commit(t, extra, others...))
		}},
		{"kind2 payload", [][]byte{blockStepsCommit(id, 1, blockStepsDAOut(hash))}, func(t *testing.T, extra []testOutput, others ...[]byte) []byte {
			anchor := initial148BlockWitnessCommit(t, others...)
			return bindingChunkOutputs(append(slices.Clone(extra), bindingAnchor(anchor[:], 0)), 0, 0x42)
		}},
	}
}

// TestGoBlockBodyBindingPinKindOrder owns the ordered side of B09 for every parser-admitted dirty pin outside kind0: an
// earlier Section 25 violation wins in Q and in the full validator, and Q admits the pin alone. The full validator
// refuses that lone body at step 13 through its tx_kind, before any pin is read.
func TestGoBlockBodyBindingPinKindOrder(t *testing.T) {
	const late = blockStepsMedian
	payload := []byte{0x77}
	orphan := blockStepsChunk(blockStepsIDs[1], 0, payload, sha3_256(payload))
	heavy := blockStepsWeighted(t, MAX_BLOCK_WEIGHT+1)
	target := POW_LIMIT
	for _, kind := range bindingPinKinds() {
		for _, c := range []struct {
			name      string
			others    [][]byte
			timestamp uint64
			code      ErrorCode
			msg       string
			fullCode  ErrorCode
			fullMsg   string
		}{
			{"pin behind timestamp", kind.set, late, BLOCK_ERR_TIMESTAMP_OLD, "timestamp <= MTP median", BLOCK_ERR_TIMESTAMP_OLD, "timestamp <= MTP median"},
			{"pin behind weight", append(slices.Clone(kind.set), heavy...), blockStepsMedian + 1, BLOCK_ERR_WEIGHT_EXCEEDED, "block weight exceeded", BLOCK_ERR_WEIGHT_EXCEEDED, "block weight exceeded"},
			{"pin behind DA", append(slices.Clone(kind.set), orphan), blockStepsMedian + 1, BLOCK_ERR_DA_SET_INVALID, "DA chunks without DA commit", BLOCK_ERR_DA_SET_INVALID, "DA chunks without DA commit"},
			{"pin only", kind.set, blockStepsMedian + 1, "", "", BLOCK_ERR_COINBASE_INVALID, bindingPinMsg},
		} {
			label := "binding B09 Section25 order " + kind.name + " " + c.name
			txs := append([][]byte{kind.first(t, nil, c.others...)}, c.others...)
			for _, f := range bindingFrames() {
				_, err := f.q(f.build(t, txs, c.timestamp, false))
				bindingCheck(t, label+" ["+f.name+"/Q]", err, c.code, c.msg)
			}
			full := blockStepsMake(t, txs, func(h *blockStepsHead) { h.timestamp = c.timestamp })
			_, err := ValidateBlockBasicWithContextAtHeight(full, &blockStepsParent, &target, blockStepsHeight, blockStepsTimes)
			fullLabel := label + " [full]"
			if c.code == "" {
				fullLabel = "binding B09 Section25 order " + kind.name + " step13 tx_kind refusal [full]"
			}
			initial148BlockWantError(t, fullLabel, err, c.fullCode, c.fullMsg)
		}
	}
}

// TestGoBlockBodyBindingCapacity owns B08: the local sentinel precedes parsing at M+1 and is absent at M.
func TestGoBlockBodyBindingCapacity(t *testing.T) {
	if blockSteps1To12MaxBytes != 68_000_125 {
		t.Fatalf("116 bound %d", blockSteps1To12MaxBytes)
	}
	atBound := make([]byte, 68_000_125)
	if err := ValidateBlockBodyCommitments(atBound); errors.Is(err, ErrBlockSteps1To12Capacity) || err == nil {
		t.Fatalf("binding B08 M: %v", err)
	}
	if err := ValidateBlockBodyCommitments(make([]byte, 68_000_126)); any(err) != any(ErrBlockSteps1To12Capacity) {
		t.Fatalf("binding B08 M+1: %v", err)
	}
}
