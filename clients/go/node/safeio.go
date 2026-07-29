package node

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// errStoreFileTooLarge is the typed local error for a store file whose size
// exceeds its class bound (RUB-1057). It must never be, wrap, or satisfy
// fs.ErrNotExist: absent-file fallbacks (fresh chainstate, empty block store
// index, write-if-absent probes) must not trigger on an over-bound file.
var errStoreFileTooLarge = errors.New("store file exceeds size bound")

// Per-class local store read bounds (RUB-1057), enforced BEFORE the file's
// contents are allocated. The numbers are a cross-client contract mirrored
// byte-for-byte by the Rust client; each derivation, growth model, and margin
// is recorded here and must not drift from the Rust copy. All measured
// per-entry figures below are pinned by TestReadFileBoundDerivationEntrySizes.
const (
	// Block blobs hold exactly one wire block, capped by the P2P layer at
	// MAX_BLOCK_BYTES. Growth: none per file (fixed consensus constant).
	blockFileMaxBytes = consensus.MAX_BLOCK_BYTES

	// Header blobs hold exactly one wire header. Growth: none.
	headerFileMaxBytes = consensus.BLOCK_HEADER_BYTES

	// Undo files hold one block's spent-entry JSON. Worst legitimate case
	// (measured on this repo's MarshalIndent encoding): inputs_max =
	// MAX_BLOCK_BYTES / min-wire-per-spend (41B input + 4627B ML-DSA-87
	// sig, ignoring the mandatory 2592B pubkey reveal and the weight cap,
	// both of which only shrink it) = 72_000_000/4_668 = 15_424 spends;
	// worst per-entry JSON = 66_707B (max spendable covenant_data is
	// CORE_VAULT at 33_188B, hex-doubled) -> 15_424*66_707 ~= 1.029GB.
	// 2_000_000_000 covers that with ~1.94x margin (~3x vs the proven
	// pubkey+sig floor of ~661MB) and stays below 2^31 so the size never
	// narrows unsafely on any build. Growth: per block, not cumulative.
	undoFileMaxBytes = 2_000_000_000

	// Index marker (index.json): one canonical entry costs exactly 72B
	// (measured: `    "<64 hex>",` + newline). TARGET_BLOCK_INTERVAL=120s
	// -> ~262_800 blocks/year -> ~18.9MB/year. 256_000_000 admits ~13.5
	// years of continuous chain, over an order of magnitude beyond a
	// realistic devnet/testnet deployment. Growth: linear in chain length.
	// RUB-1053 strict-open re-buffers each top-level marker value through
	// json.RawMessage before decoding, so an in-bound marker transiently
	// costs up to ~3x its on-disk size in memory during open (raw bytes +
	// RawMessage copy + decoded strings); the on-disk bound is unchanged.
	indexFileMaxBytes = 256_000_000

	// Chainstate snapshot: one utxoDiskEntry costs 359B in a digit-width-
	// conservative P2PK shape (max-width numeric fields; real entries are
	// smaller, so admitted counts are a floor) and 66_671B in the worst
	// spendable shape (CORE_VAULT max covenant_data 33_188B, measured).
	// 1_000_000_000 admits >=2.8M P2PK-shaped or ~15K worst-shape UTXOs;
	// a realistic devnet/testnet population (low hundreds of thousands,
	// overwhelmingly P2PK/HTLC-shaped) fits with >=10x margin. Growth:
	// linear in UTXO count.
	chainStateFileMaxBytes = 1_000_000_000

	// storeVerifyReadMaxBytes bounds the write-if-absent existing-
	// destination verify reads (blockstore_write_if_absent.go), one seam
	// serving block, header, and undo destinations: the coarsest class
	// served (undo). The tighter per-class bounds hold on the live read
	// paths (GetBlockByHash/GetHeaderByHash/GetUndo).
	storeVerifyReadMaxBytes = undoFileMaxBytes
)

func readFileByPath(path string, maxBytes int64) ([]byte, error) {
	dir := filepath.Dir(path)
	name := filepath.Base(path)
	return readFileFromDir(dir, name, maxBytes)
}

func readFileFromDir(dir, name string, maxBytes int64) ([]byte, error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return nil, fmt.Errorf("invalid file name: %q", name)
	}
	f, err := os.DirFS(dir).Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readAllCapped(f, name, maxBytes)
}

// readAllCapped enforces maxBytes before allocating the file's contents: it
// stats the OPEN handle (no path re-stat) and refuses an over-bound size
// without reading any content. The read itself goes through a maxBytes+1
// limiter, so a file that grows between Stat and read is still refused
// (stat/read race pin) and at most maxBytes+1 bytes are ever read.
func readAllCapped(f fs.File, name string, maxBytes int64) ([]byte, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxBytes {
		return nil, errFileTooLarge(name, info.Size(), maxBytes)
	}
	buf, err := readCapped(f, name, capHint(info.Size(), maxBytes), maxBytes)
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > maxBytes {
		return nil, errFileTooLarge(name, int64(len(buf)), maxBytes)
	}
	return buf, nil
}

// readCapped reads at most maxBytes+1 bytes into a buffer presized to
// capacity, growing geometrically (doubled per step, 512-byte floor, capped
// at maxBytes+1) if the stat size lied low — a small stat/read race costs a
// small reallocation, never a bound-sized allocation spike.
func readCapped(f fs.File, name string, capacity int, maxBytes int64) ([]byte, error) {
	buf := make([]byte, 0, capacity)
	limited := io.LimitReader(f, maxBytes+1)
	for {
		if len(buf) == cap(buf) {
			if int64(len(buf)) > maxBytes {
				return nil, errFileTooLarge(name, int64(len(buf)), maxBytes)
			}
			next := make([]byte, len(buf), growCapacity(cap(buf), maxBytes))
			copy(next, buf)
			buf = next
		}
		n, rerr := limited.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if rerr == io.EOF {
			return buf, nil
		}
		if rerr != nil {
			return nil, rerr
		}
	}
}

// growCapacity doubles the current capacity (512-byte floor so a tiny start
// still makes progress), capped at capHint(maxBytes, maxBytes) = maxBytes+1
// — the most the limiter can ever deliver. Progress is guaranteed: the grow
// branch only runs with len(buf) <= maxBytes < maxBytes+1, so the returned
// capacity always exceeds the current one. The negative check catches a
// doubling overflow on 32-bit int builds.
func growCapacity(current int, maxBytes int64) int {
	const growFloor = 512
	next := current * 2
	if next < growFloor {
		next = growFloor
	}
	if limit := capHint(maxBytes, maxBytes); next > limit || next < 0 {
		next = limit
	}
	return next
}

// capHint is min(size, maxBytes)+1 — the +1 gives the EOF probe room so an
// exact-size read never reallocates — clamped to the platform int range. It
// doubles as the growth ceiling in growCapacity.
func capHint(size, maxBytes int64) int {
	hint := min(size, maxBytes) + 1
	if hint > math.MaxInt {
		return math.MaxInt
	}
	return int(hint)
}

func errFileTooLarge(name string, observed, maxBytes int64) error {
	return fmt.Errorf("%s: %d bytes observed, class bound %d: %w", name, observed, maxBytes, errStoreFileTooLarge)
}
