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
// contents are allocated. Every class here holds exactly one wire item whose
// size a consensus rule already caps, so the bound is derived rather than
// invented. Artifacts that grow with chain length or UTXO-set size (the
// chainstate snapshot, the canonical index marker) admit no such ceiling and
// are deliberately NOT bounded here — they are owned by RUB-1062. The numbers
// are a cross-client contract mirrored byte-for-byte by the Rust client; each
// derivation and margin is recorded here and must not drift from the Rust
// copy. The measured per-entry figure below is pinned by
// TestReadFileBoundDerivationEntrySizes.
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
	// Decoding an undo file costs roughly twice the admitted on-disk bytes
	// in peak resident memory (raw buffer plus decoded structs), so this
	// bound governs the FILE, not the decode footprint. Enforced on both
	// ends (checkStoreSaveBound in PutUndo, readFileFromDir in GetUndo).
	undoFileMaxBytes = 2_000_000_000
)

// readFileByPath reads path in full with only the leaf-name guard. Its sole
// caller is the block store index marker loader: that artifact grows with
// chain length and admits no fixed ceiling a consensus-valid chain cannot
// reach, so RUB-1057 deliberately leaves it UNBOUNDED — RUB-1062 owns it.
// Bounded readers are readFileFromDir (per-class) and readFileByPathCapped.
func readFileByPath(path string) ([]byte, error) {
	dir := filepath.Dir(path)
	name := filepath.Base(path)
	if err := checkLeafName(name); err != nil {
		return nil, err
	}
	return fs.ReadFile(os.DirFS(dir), name)
}

// readFileByPathCapped is the bounded path-based reader behind the
// write-if-absent verify seam.
func readFileByPathCapped(path string, maxBytes int64) ([]byte, error) {
	dir := filepath.Dir(path)
	name := filepath.Base(path)
	return readFileFromDir(dir, name, maxBytes)
}

func checkLeafName(name string) error {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return fmt.Errorf("invalid file name: %q", name)
	}
	return nil
}

func readFileFromDir(dir, name string, maxBytes int64) ([]byte, error) {
	if err := checkLeafName(name); err != nil {
		return nil, err
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

// growCapacity doubles the current capacity, clamped to
// capHint(maxBytes, maxBytes) = maxBytes+1 (the most the limiter can ever
// deliver), then floored at 512 bytes so a tiny start still makes progress.
//
// ORDER MATTERS: the doubling overflow is detected and clamped BEFORE the
// floor is applied. Applying the floor first would rewrite an overflowed
// negative product (on a 32-bit int build, current*2 wrapping to MinInt32)
// into 512, and readCapped would then call make with a capacity below the
// buffer's current length and panic. Progress is still guaranteed: the grow
// branch only runs with len(buf) <= maxBytes < maxBytes+1 == limit, so the
// returned capacity always exceeds the current one.
func growCapacity(current int, maxBytes int64) int {
	const growFloor = 512
	limit := capHint(maxBytes, maxBytes)
	next := current * 2
	if next < 0 || next > limit || current > limit/2 {
		next = limit
	}
	if next < growFloor && next < limit {
		next = growFloor
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

// checkStoreSaveBound is the write/read symmetry guard for the growth
// classes (chainstate snapshot, index marker): the node must never persist a
// file it would refuse to load back. Same typed class as the read-side
// refusal; the message is clearly save-side. Rust twin:
// `check_store_save_bound` in io_utils.rs.
func checkStoreSaveBound(name string, size int, maxBytes int64) error {
	if int64(size) > maxBytes {
		return fmt.Errorf("refusing to save %s: %d bytes marshaled, class bound %d: %w",
			name, size, maxBytes, errStoreFileTooLarge)
	}
	return nil
}
