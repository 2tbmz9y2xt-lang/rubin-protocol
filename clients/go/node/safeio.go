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
// are deliberately left UNBOUNDED: no fixed byte number is defensible on
// them, which is a settled decision rather than missing work — readFileByPath
// carries the measurements and the alternative that was tried. The numbers
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

// readFileByPath reads path in full with only the leaf-name guard. It has TWO
// callers, both reading artifacts that grow with accumulated state and admit
// no fixed ceiling a consensus-valid chain cannot reach, so RUB-1057
// deliberately leaves both UNBOUNDED:
//
//   - loadBlockStoreIndex (blockstore.go) — the canonical index marker, which
//     grows with CHAIN LENGTH;
//   - LoadChainState (chainstate_io.go) — the chainstate snapshot, which
//     grows with UTXO-SET SIZE.
//
// Leaving them unbounded is a standing decision, not a gap awaiting an owner.
// No byte ceiling on either artifact is defensible: RUB-1057 measured a 1 GB
// chainstate bound as reachable in ~29 blocks of maximum-size CORE_VAULT
// outputs, and any marker ceiling is only a hard cap on chain length. A
// single bound at this helper would be worse still — the two grow along
// different axes, so one number would silently cover both and fit neither.
// Bounded readers are readFileFromDir (per-class) and readFileByPathCapped.
//
// An incremental-decode alternative to reading these whole was implemented
// and measured, then withdrawn; do not re-derive it. It does not close the
// finding — an oversized hostile file still kills the node — it is several
// times WORSE than the whole-buffer path on a document holding one huge
// value, and its equivalence to the whole-buffer decoders is only ever
// provable by sampling: a nesting-depth divergence hid in two call sites and
// was caught by a hand-written probe, not by the 70-plus-row corpus written
// to catch exactly that. RUB-1057 is the finding of record.
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
	// Fail closed on hostile metadata BEFORE any sizing arithmetic: a negative
	// reported size would make capHint return a negative capacity and `make`
	// panic ("makeslice: cap out of range"). The size is DATA — it comes off
	// the filesystem — so it gets a typed refusal rather than trust. The bound
	// is not: callers pass a non-negative bound well below the int64 ceiling
	// (a class constant or len(content)), so it is not re-validated here. (The
	// Rust twin cannot express this row: `metadata().len()` is u64.)
	if info.Size() < 0 {
		return nil, errFileTooLarge(name, info.Size(), maxBytes)
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
	// Saturate rather than +1 blindly: a wrapped negative LimitReader budget
	// reports EOF immediately — a silent truncation exactly where the bound is
	// supposed to refuse. Production bounds sit far below this edge (see the
	// caller invariant in readAllCapped); this keeps the arithmetic total
	// regardless.
	readBudget := maxBytes
	if readBudget < math.MaxInt64 {
		readBudget++
	}
	limited := io.LimitReader(f, readBudget)
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
// deliver), then floored at 512 bytes so a tiny start still makes progress —
// the floor itself is clamped to the limit, so a small class (header: limit
// 117) never gets a 512-byte buffer.
//
// ORDER MATTERS: the limit is the DEFAULT and the doubling is taken only when
// it provably fits (current <= limit/2), so an overflowed product can never be
// observed — rather than being produced and corrected afterwards. `current` is
// a slice capacity and therefore never negative, so `current <= limit/2`
// implies `current*2 <= limit` and no wrap on any int width. The floor is
// applied LAST and is itself clamped to the limit, so a class smaller than the
// floor (header: limit 117) never receives a 512-byte buffer. Progress is
// still guaranteed: the grow branch only runs with len(buf) <= maxBytes <
// maxBytes+1 == limit, so the returned capacity always exceeds the current one.
func growCapacity(current int, maxBytes int64) int {
	const growFloor = 512
	limit := capHint(maxBytes, maxBytes)
	next := limit
	if current <= limit/2 {
		next = current * 2
	}
	if next < growFloor {
		next = min(growFloor, limit)
	}
	return next
}

// capHint is min(size, maxBytes)+1 — the +1 gives the EOF probe room so an
// exact-size read never reallocates — clamped to the platform int range. It
// doubles as the growth ceiling in growCapacity.
//
// The clamp PRECEDES the increment: adding first would wrap
// min(size, maxBytes) == MaxInt64 to MinInt64, and the old `> math.MaxInt`
// test could never see it, so the ceiling returned a NEGATIVE capacity that
// propagated into growCapacity's limit. Clamping first saturates instead.
// A negative size still yields a negative hint by design — readAllCapped
// refuses that case before capHint is ever reached, so there is deliberately
// no second guard here.
func capHint(size, maxBytes int64) int {
	hint := min(size, maxBytes)
	if hint >= math.MaxInt {
		return math.MaxInt
	}
	return int(hint) + 1
}

func errFileTooLarge(name string, observed, maxBytes int64) error {
	return fmt.Errorf("%s: %d bytes observed, class bound %d: %w", name, observed, maxBytes, errStoreFileTooLarge)
}

// checkStoreSaveBound is the write/read symmetry guard for the undo class:
// the node must never persist an undo file it would refuse to load back. Its
// only production caller is PutUndo. Same typed class as the read-side
// refusal; the message is clearly save-side. Block and header writes need no
// guard — the wire format already fixes their size. The chainstate snapshot
// and index marker have NO guard on either end, deliberately and for good:
// they grow with accumulated state, so no ceiling is defensible on the save
// side either, and they are read whole and unbounded to match (the decision
// and its measurements live on readFileByPath). Rust twin:
// `check_store_save_bound` in io_utils.rs.
func checkStoreSaveBound(name string, size int, maxBytes int64) error {
	if int64(size) > maxBytes {
		return fmt.Errorf("refusing to save %s: %d bytes marshaled, class bound %d: %w",
			name, size, maxBytes, errStoreFileTooLarge)
	}
	return nil
}

// configFileMaxBytes bounds the two operator-supplied config files the Go
// node reads at startup: the featurebits deployments JSON
// (cmd/rubin-node --featurebits-deployments) and the genesis pack JSON
// (--genesis-file). Derivation (RUB-1062 rider A): both schemas are small
// and fixed —
//   - deployments: a JSON array of {name, bit, start_height, timeout_height,
//     activation_height}; bit is a uint8, so even an exhaustive table of all
//     256 bits with generous 64-char names and 20-digit heights is
//     ~256*400B ~= 100 KiB, and a realistic handful-of-deployments file is
//     under 8 KiB;
//   - genesis pack: four fixed hex fields, the largest the 116-byte header
//     hex-doubled — a well-formed pack is under 1 KiB.
//
// The bound is 16 MiB: >3 orders of magnitude above any legitimate config
// (~2000x the realistic deployments ceiling, >10^4 x a genesis pack) and
// still >160x the exhaustive 256-bit table. Reachability (the RUB-1057
// lesson): both files are operator-authored and do not grow with chain or
// UTXO state; an input actually filling 16 MiB would need ~40k deployment
// entries or megabytes of padding, which no legitimate config approaches —
// the ceiling cannot fire on honest use, while a mistakenly-pointed-at huge
// file is refused before allocation. Cross-client disposition: the
// DEPLOYMENTS surface is Go-only (the Rust node has no such flag; the
// born-bounded obligation for a future port is RUB-1065), while the
// GENESIS-FILE surface exists in Rust (load_genesis_config and
// load_chain_id_from_genesis_file in crates/rubin-node/src/genesis.rs) and
// is still unbounded there — the Rust mirror (RUB-1069) carries this same
// 16 MiB ceiling and the same typed pre-allocation refusal.
const configFileMaxBytes = 1 << 24

// ReadConfigFile reads an operator config file under configFileMaxBytes with
// the typed pre-allocation refusal from RUB-1057 (errStoreFileTooLarge).
func ReadConfigFile(path string) ([]byte, error) {
	return readFileByPathCapped(path, configFileMaxBytes)
}
