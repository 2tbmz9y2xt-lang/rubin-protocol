package mdbx

import "encoding/binary"

const authorityPointBytes, authorityDetachedBytes = 40, 48

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
	r := authorityReader{b: b, ok: true}
	a := decodeAuthority(&r)
	if !r.ok || r.off != len(b) || ValidateStorageAuthorityV1(a) != nil {
		return StorageAuthorityV1{}, errSchema
	}
	return a, nil
}

type authorityReader struct {
	b   []byte
	off int
	ok  bool
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
func (r *authorityReader) u16() uint16    { return uint16(r.number(2)) }
func (r *authorityReader) u32() uint32    { return uint32(r.number(4)) }
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
	if !r.ok || n > uint64(r.remaining()) {
		r.ok = false
		return nil
	}
	return append([]byte(nil), r.take(int(n))...)
}
