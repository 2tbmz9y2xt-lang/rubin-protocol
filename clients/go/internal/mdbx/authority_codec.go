package mdbx

import "encoding/binary"

const authorityPointBytes, authorityDetachedBytes = 40, 48

// Collection views borrow only during synchronous literal inspection. Owned
// decoding and validation use the same accessors over their independent slices.
type authorityPoints struct {
	owned   []AuthorityPointV1
	encoded []byte
	count   int
}

func (v authorityPoints) len() int {
	if v.encoded != nil {
		return v.count
	}
	return len(v.owned)
}

func (v authorityPoints) at(i int) AuthorityPointV1 {
	if v.encoded == nil {
		return v.owned[i]
	}
	r := authorityReader{b: v.encoded[i*authorityPointBytes : (i+1)*authorityPointBytes], ok: true}
	return decodePoint(&r)
}

func (v authorityPoints) contains(point AuthorityPointV1) bool {
	for i := 0; i < v.len(); i++ {
		if v.at(i) == point {
			return true
		}
	}
	return false
}

func (v authorityPoints) hasHash(hash [32]byte, end int) bool {
	for i := 0; i < end; i++ {
		if v.at(i).BlockHash == hash {
			return true
		}
	}
	return false
}

type authoritySpans struct {
	owned   []CleanupSpanV1
	encoded []byte
	count   int
}

func (v authoritySpans) len() int {
	if v.encoded != nil {
		return v.count
	}
	return len(v.owned)
}

func (v authoritySpans) at(i int) CleanupSpanV1 {
	if v.encoded == nil {
		return v.owned[i]
	}
	r := authorityReader{b: v.encoded, ok: true}
	for n := 0; ; n++ {
		var span CleanupSpanV1
		decodeSpan(&r, &span)
		if n == i {
			return span
		}
	}
}

func (v authoritySpans) contains(span CleanupSpanV1) bool {
	for i := 0; i < v.len(); i++ {
		if v.at(i) == span {
			return true
		}
	}
	return false
}

type authorityDetached struct {
	owned   []DetachedSuffixEntryV1
	encoded []byte
	count   int
}

func (v authorityDetached) len() int {
	if v.encoded != nil {
		return v.count
	}
	return len(v.owned)
}

func (v authorityDetached) at(i int) DetachedSuffixEntryV1 {
	if v.encoded == nil {
		return v.owned[i]
	}
	r := authorityReader{b: v.encoded[i*authorityDetachedBytes : (i+1)*authorityDetachedBytes], ok: true}
	return decodeDetachedEntry(&r)
}

func (v authorityDetached) hasHash(hash [32]byte, end int) bool {
	for i := 0; i < end; i++ {
		if v.at(i).Hash == hash {
			return true
		}
	}
	return false
}

type authorityInspection struct {
	old, new       authorityPoints
	phase, carried authoritySpans
	detached       authorityDetached
}

type authorityDecodeControl struct {
	cleanup  CleanupV1
	replay   ReplayV1
	ordinary OrdinaryApplyV1
	pending  StorageProfileV1
	excluded InvalidBranchV1
	detached DetachedSuffixV1
	failure  RecordedFailureV1
	cursor   AuthorityPointV1
	hash     [32]byte
	selected SelectedSideV1
}

type authorityValidation struct {
	StorageAuthorityV1
	old, new       authorityPoints
	phase, carried authoritySpans
	detached       authorityDetached
}

func projectAuthority(a StorageAuthorityV1, inspection *authorityInspection) authorityValidation {
	v := authorityValidation{StorageAuthorityV1: a}
	if inspection != nil {
		v.old, v.new = inspection.old, inspection.new
		v.phase, v.carried, v.detached = inspection.phase, inspection.carried, inspection.detached
		return v
	}
	if a.Cleanup != nil {
		v.phase.owned = a.Cleanup.Spans
	}
	if a.Ordinary != nil {
		v.old.owned, v.new.owned = a.Ordinary.OldSuffix, a.Ordinary.NewSuffix
		if a.Ordinary.CarriedCleanup != nil {
			v.carried.owned = a.Ordinary.CarriedCleanup.Spans
		}
	}
	if a.DetachedSuffix != nil {
		v.detached.owned = a.DetachedSuffix.Entries
	}
	return v
}

type authoritySizer uint64

func (s *authoritySizer) add(value uint64) {
	if *s > MaxMetadataBytes || value > uint64(MaxMetadataBytes)-uint64(*s) {
		*s = MaxMetadataBytes + 1
		return
	}
	*s += authoritySizer(value)
}

func authoritySize(a StorageAuthorityV1) (int, bool) {
	s := authoritySizer(40) // Fixed header and four outer presence bytes.
	s.add(phaseSize(a))
	if a.ExcludedInvalidBranch != nil {
		s.add(44)
		s.add(uint64(len(a.ExcludedInvalidBranch.ExactConsensusError)))
	}
	if a.PendingTargetProfile != nil {
		s.add(1)
	}
	if a.SelectedSide != nil {
		s.add(106)
	}
	if a.DetachedSuffix != nil {
		s.add(52 + authorityDetachedBytes*uint64(len(a.DetachedSuffix.Entries)))
	}
	if a.Ordinary != nil && a.Ordinary.RecordedFailure != nil {
		f := a.Ordinary.RecordedFailure
		s.add(uint64(len(f.ExactResult)))
		s.add(uint64(len(f.Evidence)))
	}
	return int(s), s <= MaxMetadataBytes
}

func phaseSize(a StorageAuthorityV1) uint64 {
	switch a.Phase {
	case StoragePhasePruneGCV1:
		return cleanupSize(a.Cleanup)
	case StoragePhaseReplayV1:
		if a.Replay.Cursor.Kind == ReplayCursorAppliedV1 {
			return 194
		}
		return 154
	case StoragePhaseOrdinaryApplyV1:
		return ordinarySize(a.Ordinary)
	default:
		return 0
	}
}

func cleanupSize(c *CleanupV1) uint64 {
	n := uint64(1)
	for _, span := range c.Spans {
		n += 9
		if span.Kind != CleanupSpanGenerationV1 {
			n += 24
		}
	}
	return n
}

func ordinarySize(o *OrdinaryApplyV1) uint64 {
	n := uint64(49 + authorityPointBytes*(len(o.OldSuffix)+len(o.NewSuffix)))
	if o.Cursor != nil {
		n += authorityPointBytes
	}
	if o.CapturedSelectedSide != nil {
		n += 106
	}
	if o.CarriedCleanup != nil {
		n += cleanupSize(o.CarriedCleanup)
	}
	if o.RecordedFailure != nil {
		n += 10
		if o.RecordedFailure.FailedBlockHash != nil {
			n += 32
		}
	}
	return n
}

func (a StorageAuthorityV1) Encode() ([]byte, error) {
	if ValidateStorageAuthorityV1(a) != nil {
		return nil, errSchema
	}
	n, ok := authoritySize(a)
	if !ok {
		return nil, errSchema
	}
	out := make([]byte, 0, n)
	encodeAuthority(&out, a)
	return out, nil
}

func DecodeStorageAuthorityV1(b []byte) (StorageAuthorityV1, error) {
	if len(b) < 40 || len(b) > MaxMetadataBytes {
		return StorageAuthorityV1{}, errSchema
	}
	var control authorityDecodeControl
	r := authorityReader{b: b, ok: true, control: &control}
	a := decodeAuthority(&r)
	if !r.ok || r.off != len(b) || ValidateStorageAuthorityV1(a) != nil {
		return StorageAuthorityV1{}, errSchema
	}
	return a, nil
}

type authorityReader struct {
	b          []byte
	off        int
	ok         bool
	tree       bool
	control    *authorityDecodeControl
	inspection *authorityInspection
}

func (r *authorityReader) take(n int) []byte {
	if !r.ok || n < 0 || n > len(r.b)-r.off {
		r.ok = false
		return nil
	}
	b := r.b[r.off : r.off+n]
	r.off += n
	return b
}

func (r *authorityReader) u8() uint8 {
	b := r.take(1)
	if !r.ok {
		return 0
	}
	return b[0]
}

func (r *authorityReader) number(width int) uint64 {
	b := r.take(width)
	if !r.ok {
		return 0
	}
	var full [8]byte
	copy(full[8-width:], b)
	return binary.BigEndian.Uint64(full[:])
}
func (r *authorityReader) u16() uint16    { return uint16(r.number(2)) } // #nosec G115 -- number(2) zero-extends exactly two bytes.
func (r *authorityReader) u32() uint32    { return uint32(r.number(4)) } // #nosec G115 -- number(4) zero-extends exactly four bytes.
func (r *authorityReader) u64() uint64    { return r.number(8) }
func (r *authorityReader) remaining() int { return len(r.b) - r.off }
func (r *authorityReader) tag(max uint8) uint8 {
	tag := r.u8()
	if !r.ok || tag < 1 || tag > max {
		r.ok = false
	}
	return tag
}

func (r *authorityReader) count16(max, width int) int {
	n := int(r.u16())
	if !r.ok || n > max || n*width > r.remaining() {
		r.ok = false
	}
	return n
}

func (r *authorityReader) option() bool {
	tag := r.u8()
	if tag > 1 {
		r.ok = false
	}
	return tag == 1
}
func (r *authorityReader) hash32() (out [32]byte) { copy(out[:], r.take(32)); return }
func (r *authorityReader) work40() (out [40]byte) { copy(out[:], r.take(40)); return }
func (r *authorityReader) blob() []byte {
	n := uint64(r.u32())
	if !r.ok || n > uint64(r.remaining()) { // #nosec G115 -- take keeps 0 <= off <= len(b), so remaining is non-negative.
		r.ok = false
		return nil
	}
	b := r.take(int(n)) // #nosec G115 -- n <= remaining <= MaxMetadataBytes is proved above.
	if r.inspection != nil {
		return b
	}
	return append([]byte(nil), b...)
}
