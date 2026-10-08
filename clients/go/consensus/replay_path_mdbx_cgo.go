//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"math"
	"sync"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// Dormant fixed-target replay ancestry producer (RUBIN_MEMPOOL_POLICY.md Section 6.4.1.8). No production caller.

// ReplayHeaderCandidateViewV1 is the header-candidate view with the replay point facet. VersionV1 is a race-safe scalar
// read with no enumeration, copy or allocation. HeaderV1 writes exactly the 116 raw admitted bytes named by hash into
// dst and returns true when present; it does not retain dst or write it after returning, gives no validity result, and
// dst content is meaningless on false. Both methods are callable while the caller holds the ProtectV1 guard.
type ReplayHeaderCandidateViewV1 interface {
	HeaderCandidateViewV1
	VersionV1() uint64
	HeaderV1(hash [32]byte, dst *[116]byte) bool
}

// replayPathHeaderSource is the origin of a header source, never its qualification.
type replayPathHeaderSource uint8

const (
	replayPathUnavailable replayPathHeaderSource = iota
	replayPathStored
	replayPathPoint
	replayPathSupplied
)

// replayPathOwn is the current visit's borrowed source facts; header and activeEntry alias the read backing.
type replayPathOwn struct {
	h             uint64
	x             [32]byte
	header        []byte
	activeEntry   []byte
	headerSource  replayPathHeaderSource
	resource      string
	missing       bool
	missingHeight uint64
	missingHash   [32]byte
}

type replayPathKey struct {
	generation mdbx.GenerationIDV1
	target     mdbx.RecoveryTargetV1
}

// replayPathSlot is one completed establishment: hashes[k-lo] is the expected hash at k for max(a, lo-1) < k <= tip.
type replayPathSlot struct {
	key      replayPathKey
	lo       uint64
	hashes   [][32]byte
	attached bool
	a        uint64
}

// replayPathOwner owns mu, the one completed slot, the retention limit, the view and the invocation guard release.
type replayPathOwner struct {
	mu      sync.Mutex
	view    ReplayHeaderCandidateViewV1
	limit   uint64
	slot    *replayPathSlot
	guarded bool
	release func()
	dst     [116]byte
}

func newReplayPathOwner(view ReplayHeaderCandidateViewV1, retentionLimit uint64) *replayPathOwner {
	return &replayPathOwner{view: view, limit: retentionLimit}
}

// replayPathCall is one ownLocked invocation; sameEntry/sameHeader hold the walk's own-height reads for reuse.
type replayPathCall struct {
	p          *replayPathOwner
	reader     *mdbx.Reader
	rp         *mdbx.ReplayV1
	old        *mdbx.AuthorityPointV1
	generation uint64
	genesis    PublishedGenesisContextV1
	supplied   []byte
	h          uint64
	out        replayPathOwn
	sameEntry  []byte
	sameHeader []byte
	sameSource replayPathHeaderSource
}

// ownLocked establishes or reuses the fixed target's ancestry and returns the own height's source facts. The caller
// holds p.mu, has validated the same-OLD authority, context and applicability and holds the full grant; oldActive is
// the committed active tip of authority.ActiveGenerationID (nil: PRE_GENESIS). It produces no Batch and no row effect;
// only a complete establishment publishes the slot, which survives every later failure until discard. finishLocked
// must follow the last consumer of the returned sources, before p.mu is unlocked.
func (p *replayPathOwner) ownLocked(reader *mdbx.Reader, authority mdbx.StorageAuthorityV1, oldActive *mdbx.AuthorityPointV1, genesis PublishedGenesisContextV1, supplied []byte) (replayPathOwn, error) {
	c, err := p.newCall(reader, authority, oldActive, genesis, supplied)
	if err != nil {
		return replayPathOwn{}, err
	}
	if err := c.establish(); err != nil {
		return c.out, err
	}
	return c.own()
}

// newCall is the caller precondition and the foreign-slot refusal, before any admission or read.
func (p *replayPathOwner) newCall(reader *mdbx.Reader, a mdbx.StorageAuthorityV1, old *mdbx.AuthorityPointV1, genesis PublishedGenesisContextV1, supplied []byte) (*replayPathCall, error) {
	if !replayPathApplicable(a) {
		return nil, replayRecoveryRefusal(selectedSideInvariant, "replay path invoked without a next replay height")
	}
	rp := a.Replay
	if p.slot != nil && p.slot.key != (replayPathKey{rp.TargetGenerationID, rp.Target}) {
		return nil, replayRecoveryRefusal(selectedSideCapacity, "replay path slot holds another target")
	}
	c := &replayPathCall{p: p, reader: reader, rp: rp, old: old, generation: uint64(a.ActiveGenerationID), genesis: genesis, supplied: supplied}
	if rp.Cursor.Kind == mdbx.ReplayCursorAppliedV1 {
		c.h = rp.Cursor.Height + 1
	}
	return c, nil
}

func replayPathApplicable(a mdbx.StorageAuthorityV1) bool {
	if a.Replay == nil || mdbx.ValidateStorageAuthorityV1(a) != nil {
		return false
	}
	return a.Replay.Cursor.Kind == mdbx.ReplayCursorPreGenesisV1 || a.Replay.Cursor.Height < a.Replay.Target.TipHeight
}

// replayPathAdmit is the checked 32*N <= limit admission with N = tip - lo + 1 (lo = h).
func replayPathAdmit(tip, lo, limit uint64) (uint64, bool) {
	n := tip - lo + 1
	return n, n <= math.MaxInt && n <= limit/32
}

// establish admits and allocates N hashes, walks from the target tip, and publishes the slot only on success. The
// target/genesis contradiction is checked on every invocation, before a completed slot is reused.
func (c *replayPathCall) establish() error {
	if c.p.slot != nil {
		return c.genesisBound()
	}
	target := c.rp.Target
	n, ok := replayPathAdmit(target.TipHeight, c.h, c.p.limit)
	if !ok {
		return replayRecoveryRefusal(selectedSideCapacity, "replay path retention exceeds its limit")
	}
	if err := c.genesisBound(); err != nil {
		return err
	}
	s := &replayPathSlot{key: replayPathKey{c.rp.TargetGenerationID, target}, lo: c.h, hashes: make([][32]byte, n)}
	if err := c.walk(s); err != nil {
		return err
	}
	c.p.slot = s
	return nil
}

func (c *replayPathCall) genesisBound() error {
	if c.rp.Target.ChainID != c.genesis.ChainID || c.rp.Target.GenesisHash != c.genesis.GenesisHash {
		return selectedSideDefect("replay target contradicts the genesis context")
	}
	return nil
}

// walk descends from the persisted tip to lo, stopping at the first (greatest) active attachment.
func (c *replayPathCall) walk(s *replayPathSlot) error {
	x := c.rp.Target.TipHash
	for k := c.rp.Target.TipHeight; ; k-- {
		s.hashes[k-s.lo] = x
		parent, attached, err := c.descend(k, x)
		if err != nil {
			return err
		}
		if attached {
			s.attached, s.a = true, k
			return nil
		}
		x = parent
		if k == s.lo {
			return c.below(s, x)
		}
	}
}

// descend is one height: the eligible active entry first, then the header named by x.
func (c *replayPathCall) descend(k uint64, x [32]byte) ([32]byte, bool, error) {
	c.out = replayPathOwn{h: k, x: x}
	if c.eligible(k) {
		entry, err := c.activeEntry(k)
		if err != nil {
			return [32]byte{}, false, err
		}
		if [32]byte(entry[:32]) == x {
			c.keepEntry(k, entry)
			return [32]byte{}, true, nil
		}
	}
	header, err := c.ancestryHeader(k, x)
	if err != nil {
		return [32]byte{}, false, err
	}
	if k == c.h {
		c.sameHeader, c.sameSource = header, c.out.headerSource
	}
	return [32]byte(header[4:36]), false, nil
}

func (c *replayPathCall) eligible(k uint64) bool {
	return c.old != nil && k <= c.old.Height
}

func (c *replayPathCall) keepEntry(k uint64, entry []byte) {
	if k == c.h {
		c.sameEntry = entry
	}
}

// below is the no-attachment proof: the derived cursor hash, or the target genesis at height 0.
func (c *replayPathCall) below(s *replayPathSlot, parent [32]byte) error {
	if c.rp.Cursor.Kind == mdbx.ReplayCursorAppliedV1 && parent != c.rp.Cursor.BlockHash {
		return selectedSideDefect("replay path ancestry does not reach the cursor")
	}
	if c.rp.Cursor.Kind == mdbx.ReplayCursorPreGenesisV1 && s.hashes[0] != c.rp.Target.GenesisHash {
		return selectedSideDefect("replay path ancestry does not reach the target genesis")
	}
	return nil
}

// activeEntry reads the complete 104-byte active canonical entry at k; absence or illegal work is canonical damage.
func (c *replayPathCall) activeEntry(k uint64) ([]byte, error) {
	key, err := mdbx.HeightKey(c.generation, k)
	if err != nil {
		return nil, err
	}
	c.out.resource = selectedSideCanonical
	value, present, err := c.reader.Get(mdbx.SchemaV2DBIs()[2], key)
	if err != nil {
		return nil, err
	}
	c.out.resource = ""
	if !present {
		return nil, selectedSideDefect("replay path active entry absent")
	}
	c.out.activeEntry = value
	if len(value) != 104 || !archiveSelectedSideWork(value[64:104]) {
		return nil, selectedSideDefect("replay path active entry invalid")
	}
	return value, nil
}

// storedHeader reads the stored header named by x; a present row that does not bind x is positive damage.
func (c *replayPathCall) storedHeader(x [32]byte, resource string) ([]byte, bool, error) {
	c.out.resource = resource
	raw, present, err := c.reader.Get(mdbx.SchemaV2DBIs()[3], x[:])
	if err != nil {
		return nil, false, err
	}
	c.out.resource = ""
	if !present {
		return nil, false, nil
	}
	c.out.header, c.out.headerSource = raw, replayPathStored
	if !replayPathBinds(raw, x) {
		return nil, true, selectedSideDefect("replay path stored header misnamed")
	}
	return raw, true, nil
}

func replayPathBinds(raw []byte, x [32]byte) bool {
	if _, err := ParseBlockHeaderBytes(raw); err != nil {
		return false
	}
	hash, err := BlockHash(raw)
	return err == nil && hash == x
}

// ancestryHeader is the stored row, then on definitive absence the guarded point, then the supplied artifact.
func (c *replayPathCall) ancestryHeader(k uint64, x [32]byte) ([]byte, error) {
	raw, present, err := c.storedHeader(x, replayEntryRecovery)
	if err != nil || present {
		return raw, err
	}
	raw, err = c.point(k, x)
	if err != nil || raw != nil {
		return raw, err
	}
	if len(c.supplied) >= BLOCK_HEADER_BYTES && replayPathBinds(c.supplied[:BLOCK_HEADER_BYTES], x) {
		c.out.header, c.out.headerSource = c.supplied[:BLOCK_HEADER_BYTES:BLOCK_HEADER_BYTES], replayPathSupplied
		return c.out.header, nil
	}
	return nil, c.missingHeader(k, x)
}

func (c *replayPathCall) missingHeader(k uint64, x [32]byte) error {
	c.out.missing, c.out.missingHeight, c.out.missingHash = true, k, x
	return replayRecoveryRefusal(replayEntryRecovery, "replay path ancestry header unavailable")
}

// point reads the guarded point into the owner's one reserved destination. Present bytes that do not bind x are
// discarded and end the visit as the missing header; only an absent point falls through to the supplied artifact.
func (c *replayPathCall) point(k uint64, x [32]byte) ([]byte, error) {
	p := c.p
	if p.view == nil {
		return nil, nil
	}
	if err := p.guard(); err != nil {
		return nil, err
	}
	if !p.view.HeaderV1(x, &p.dst) {
		return nil, nil
	}
	if !replayPathBinds(p.dst[:], x) {
		return nil, c.missingHeader(k, x)
	}
	c.out.header, c.out.headerSource = p.dst[:], replayPathPoint
	return c.out.header, nil
}

// guard calls ProtectV1 once per invocation before the first point access and holds it for either boolean result.
func (p *replayPathOwner) guard() error {
	if p.guarded {
		return nil
	}
	p.guarded = true
	_, release := p.view.ProtectV1(p.view.VersionV1())
	if release == nil {
		return replayRecoveryRefusal(selectedSideInvariant, "replay path producer returned no release")
	}
	p.release = release
	p.view.VersionV1()
	return nil
}

// own reads the own height h from the completed slot, reusing the walk's same-attempt reads.
func (c *replayPathCall) own() (replayPathOwn, error) {
	s := c.p.slot
	if c.h < s.lo {
		return replayPathOwn{}, replayRecoveryRefusal(selectedSideInvariant, "replay path cursor below its establishment")
	}
	if s.attached && c.h <= s.a {
		return c.ownCanonical()
	}
	x := s.hashes[c.h-s.lo]
	c.out = replayPathOwn{h: c.h, x: x}
	header, source := c.sameHeader, c.sameSource
	if header == nil {
		var err error
		if header, err = c.ancestryHeader(c.h, x); err != nil {
			return c.out, err
		}
		source = c.out.headerSource
	}
	c.out.header, c.out.headerSource = header, source
	return c.ownParent(header)
}

// ownCanonical is h <= a: the active entry, then its named header with the entry's parent.
func (c *replayPathCall) ownCanonical() (replayPathOwn, error) {
	c.out = replayPathOwn{h: c.h}
	entry := c.sameEntry
	if entry == nil {
		var err error
		if entry, err = c.activeEntry(c.h); err != nil {
			return c.out, err
		}
	}
	c.out.activeEntry, c.out.x = entry, [32]byte(entry[:32])
	header, present, err := c.storedHeader(c.out.x, selectedSideCanonical)
	switch {
	case err != nil:
		return c.out, err
	case !present:
		return c.out, selectedSideDefect("replay path canonical header absent")
	case [32]byte(header[4:36]) != [32]byte(entry[32:64]):
		return c.out, selectedSideDefect("replay path canonical header parent mismatch")
	}
	return c.ownParent(header)
}

// ownParent is the APPLIED own-parent link; height 0 under PRE_GENESIS is bound to the target genesis by the walk.
func (c *replayPathCall) ownParent(header []byte) (replayPathOwn, error) {
	if c.rp.Cursor.Kind == mdbx.ReplayCursorAppliedV1 && [32]byte(header[4:36]) != c.rp.Cursor.BlockHash {
		return c.out, selectedSideDefect("replay path own header does not name the cursor")
	}
	if c.rp.Cursor.Kind == mdbx.ReplayCursorPreGenesisV1 && c.out.x != c.rp.Target.GenesisHash {
		return c.out, selectedSideDefect("replay path height 0 is not the target genesis")
	}
	return c.out, nil
}

// finishLocked clears the release identity, runs a held release exactly once and retires the point destination.
// It keeps the completed slot.
func (p *replayPathOwner) finishLocked() {
	release := p.release
	p.release, p.guarded = nil, false
	if release != nil {
		release()
	}
	p.dst = [116]byte{}
}

// discardLocked clears the completed slot under the held mutex; true exactly when a slot was present.
func (p *replayPathOwner) discardLocked() bool {
	if p.slot == nil {
		return false
	}
	p.slot = nil
	return true
}

func (p *replayPathOwner) discard() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.discardLocked()
}
