package node

import (
	"bytes"
	"encoding/binary"
	"math"
	"slices"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/exclusionjournal"
)

const (
	journalPathPrefix148  = 292
	journalPathEntry148   = 32 + 148
	journalDurableSlot148 = 1 + 148
)

// JournalHeaderPathInput148V1 carries the original path, attachment and independently owned durable extent.
// Path contains packed hashes and Durable contains packed presence bytes and raw headers. Parts are the
// non-path views in manifest order. Origin -1 with zero offset and length omits OriginalProjection.
type JournalHeaderPathInput148V1 struct {
	Owner                                          *HeaderCandidateOwner148V1
	Incarnation, Version, Height, AttachmentHeight uint64
	Hash, AttachmentHash, Provenance               [32]byte
	HasExpected                                    bool
	Expected                                       [148]byte
	DurableExtent                                  uint64
	Path, Durable, OriginalProjection              exclusionjournal.SourceViewV1
	Origins                                        []exclusionjournal.SourceOriginV1
	Parts                                          []exclusionjournal.SourceViewV1
}

type journalPathSource148 struct {
	input         JournalHeaderPathInput148V1
	parts         []exclusionjournal.SourcePartSpecV1
	views         []exclusionjournal.SourceViewV1
	count, length uint64
	pathIndex     int
}

// NewJournalHeaderPathSource148V1 binds the supplied manifest and immutable backing to one path producer.
// It releases both candidate guards before delivering any part (RUBIN_MEMPOOL_POLICY.md Section 6.4.1.4).
func NewJournalHeaderPathSource148V1(manifest exclusionjournal.SourceManifestV1, input JournalHeaderPathInput148V1) (exclusionjournal.SourceExporterV1, error) {
	if _, err := manifest.SizeV1(); err != nil {
		return nil, err
	}
	count, length, err := journalPathFrames148(input)
	if err != nil {
		return nil, err
	}
	pathIndex := 4
	if manifest.Class == exclusionjournal.RecoveryCoreImpossibleV1 {
		pathIndex = 1
	}
	views, err := journalPathViews148(manifest.Parts, pathIndex, input, length)
	if err != nil {
		return nil, err
	}
	input.Origins = slices.Concat(input.Origins, []exclusionjournal.SourceOriginV1{{PlannedBytes: length}})
	input.Parts = nil
	source := journalPathSource148{input: input, parts: slices.Clone(manifest.Parts), views: views, count: count, length: length, pathIndex: pathIndex}
	return source.export, nil
}

// journalPathFrames148 checks the packed widths and the independently declared extent before sizing the snapshot.
func journalPathFrames148(in JournalHeaderPathInput148V1) (count, length uint64, err error) {
	count = in.Path.Length / 32
	if in.Path.Length%32 != 0 || in.Durable.Length%journalDurableSlot148 != 0 ||
		in.DurableExtent > count || in.Durable.Length/journalDurableSlot148 > in.DurableExtent {
		return 0, 0, exclusionjournal.ErrIntegrityV1
	}
	if count > (math.MaxInt-journalPathPrefix148)/journalPathEntry148 {
		return 0, 0, exclusionjournal.ErrCapacityV1
	}
	return count, journalPathPrefix148 + journalPathEntry148*count, nil
}

// journalPathViews148 binds original byte ranges and reserves one view for the independent projection.
func journalPathViews148(parts []exclusionjournal.SourcePartSpecV1, index int, in JournalHeaderPathInput148V1, length uint64) ([]exclusionjournal.SourceViewV1, error) {
	if len(in.Origins) > len(parts)+2 || len(in.Parts) != len(parts)-1 || parts[index].Length != length {
		return nil, exclusionjournal.ErrIntegrityV1
	}
	if !journalPathInputsFit148(in, length) {
		return nil, exclusionjournal.ErrIntegrityV1
	}
	views := make([]exclusionjournal.SourceViewV1, len(parts))
	copy(views[:index], in.Parts[:index])
	copy(views[index+1:], in.Parts[index:])
	views[index] = exclusionjournal.SourceViewV1{Origin: len(in.Origins), Length: length}
	for i, view := range views {
		if i != index && !journalPathViewFits148(view, in.Origins, parts[i].Length) {
			return nil, exclusionjournal.ErrIntegrityV1
		}
	}
	return views, nil
}

// journalPathInputsFit148 accepts complete actual origins and checks the original variable-sized views.
func journalPathInputsFit148(in JournalHeaderPathInput148V1, length uint64) bool {
	for _, origin := range in.Origins {
		if origin.PlannedBytes != 0 || len(origin.Bytes) == 0 || len(origin.Bytes) != cap(origin.Bytes) {
			return false
		}
	}
	return journalPathViewFits148(in.Path, in.Origins, in.Path.Length) &&
		journalPathViewFits148(in.Durable, in.Origins, in.Durable.Length) &&
		(in.OriginalProjection == (exclusionjournal.SourceViewV1{Origin: -1}) || journalPathViewFits148(in.OriginalProjection, in.Origins, length))
}

// journalPathViewFits148 validates the index and the exact range without wrapping the offset.
func journalPathViewFits148(view exclusionjournal.SourceViewV1, origins []exclusionjournal.SourceOriginV1, length uint64) bool {
	if view.Origin < 0 || view.Origin >= len(origins) {
		return length == 0 && view == (exclusionjournal.SourceViewV1{Origin: -1})
	}
	size := uint64(len(origins[view.Origin].Bytes))
	return view.Length == length && view.Offset <= size && view.Length <= size-view.Offset
}

// export applies the live limits and admits the originals and the planned copy together.
func (s journalPathSource148) export(op *exclusionjournal.SourceOperationV1, visit func(exclusionjournal.SourcePartV1) error) error {
	limits, err := op.LimitsV1()
	if err != nil {
		return err
	}
	scans := uint64(len(s.parts))*3 + limits.Files*2 + 4
	if s.count == 0 || s.count > limits.Headers || s.length > limits.Bytes || scans > limits.Scans || s.count > limits.Scans-scans {
		return exclusionjournal.ErrCapacityV1
	}
	return op.WithBackingV1(s.input.Origins, s.views, func() error {
		path, err := s.snapshot()
		if err != nil {
			return err
		}
		return s.deliver(path, visit)
	})
}

// snapshot ends candidate protection at the final nested check after the last copied point.
func (s journalPathSource148) snapshot() ([]byte, error) {
	in := s.input
	if in.Owner == nil {
		return nil, exclusionjournal.ErrUnavailableV1
	}
	current, release := in.Owner.ProtectV1(in.Version)
	defer release()
	if !in.current(current) {
		return nil, exclusionjournal.ErrUnavailableV1
	}
	path, err := s.copyPath()
	if err != nil {
		return nil, err
	}
	if original := in.viewBytes(in.OriginalProjection); original != nil && !bytes.Equal(path, original) {
		return nil, exclusionjournal.ErrIntegrityV1
	}
	current, finalRelease := in.Owner.ProtectV1(in.Version)
	defer finalRelease()
	if !in.current(current) {
		return nil, exclusionjournal.ErrUnavailableV1
	}
	return path, nil
}

// current binds a held guard to the original candidate incarnation and version.
func (in JournalHeaderPathInput148V1) current(protected bool) bool {
	return protected && in.Incarnation != 0 && in.Owner.IncarnationV1() == in.Incarnation && in.Owner.VersionV1() == in.Version
}

// copyPath associates each raw header with its original hash and ends at the supplied B.
func (s journalPathSource148) copyPath() ([]byte, error) {
	in := s.input
	if !in.hasOriginalPath() {
		return nil, exclusionjournal.ErrUnavailableV1
	}
	path, durable := in.viewBytes(in.Path), in.viewBytes(in.Durable)
	out := s.prefix()
	for i := range s.count {
		hash := [32]byte(path[32*i:])
		raw, err := in.point(durable, i, hash)
		if err != nil {
			return nil, err
		}
		out = append(out, hash[:]...)
		out = append(out, raw[:]...)
	}
	last := out[len(out)-journalPathEntry148:]
	if [32]byte(last) != in.Hash || [148]byte(last[32:]) != in.Expected {
		return nil, exclusionjournal.ErrIntegrityV1
	}
	return out, nil
}

func (in JournalHeaderPathInput148V1) hasOriginalPath() bool {
	return in.HasExpected && in.Hash != [32]byte{} && in.AttachmentHash != [32]byte{} && in.Provenance != [32]byte{}
}

// prefix serializes the original attachment, B and extent into the snapshot's fixed prefix.
func (s journalPathSource148) prefix() []byte {
	in := s.input
	out := make([]byte, 0, s.length)
	out = binary.LittleEndian.AppendUint64(out, in.Incarnation)
	out = binary.LittleEndian.AppendUint64(out, in.Version)
	out = binary.LittleEndian.AppendUint64(out, in.Height)
	out = append(out, in.Hash[:]...)
	out = binary.LittleEndian.AppendUint64(out, in.AttachmentHeight)
	out = append(out, in.AttachmentHash[:]...)
	out = append(out, in.Provenance[:]...)
	out = append(out, in.Expected[:]...)
	out = binary.LittleEndian.AppendUint64(out, s.count)
	return binary.LittleEndian.AppendUint64(out, in.DurableExtent)
}

// point reads only the original durable slot or the requested received point and checks its exact raw/hash binding.
func (in JournalHeaderPathInput148V1) point(durable []byte, index uint64, hash [32]byte) (raw [148]byte, err error) {
	if index < in.DurableExtent {
		raw, err = journalDurablePoint148(durable, index)
	} else if !in.Owner.Header148V1(hash, &raw) {
		err = exclusionjournal.ErrUnavailableV1
	}
	if err != nil {
		return raw, err
	}
	actual, err := consensus.Initial148BlockHash(raw[:])
	if err != nil || actual != hash {
		return raw, exclusionjournal.ErrIntegrityV1
	}
	return raw, nil
}

// journalDurablePoint148 preserves short or absent positions without reading their raw payload.
func journalDurablePoint148(durable []byte, index uint64) ([148]byte, error) {
	if index >= uint64(len(durable))/journalDurableSlot148 {
		return [148]byte{}, exclusionjournal.ErrUnavailableV1
	}
	slot := durable[index*journalDurableSlot148:]
	switch slot[0] {
	case 0:
		return [148]byte{}, exclusionjournal.ErrUnavailableV1
	case 1:
		return [148]byte(slot[1:]), nil
	default:
		return [148]byte{}, exclusionjournal.ErrIntegrityV1
	}
}

func (in JournalHeaderPathInput148V1) viewBytes(view exclusionjournal.SourceViewV1) []byte {
	if view.Origin == -1 {
		return nil
	}
	return in.Origins[view.Origin].Bytes[view.Offset : view.Offset+view.Length]
}

// deliver offers the immutable projection and the supplied original non-path parts in manifest order.
func (s journalPathSource148) deliver(path []byte, visit func(exclusionjournal.SourcePartV1) error) error {
	for i, spec := range s.parts {
		data := path
		if i != s.pathIndex {
			data = s.input.viewBytes(s.views[i])
		}
		part := exclusionjournal.SourcePartV1{Kind: spec.Kind, Length: spec.Length, ReadAt: func(dst []byte, offset int64) (int, error) {
			return copy(dst, data[offset:]), nil
		}}
		if err := visit(part); err != nil {
			return err
		}
	}
	return nil
}
