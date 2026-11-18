package node

import (
	"bytes"
	"encoding/binary"
	"math"
	"slices"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/exclusionjournal"
)

// JournalHeaderPathInput148V1 carries the original path, attachment and independently owned durable prefix.
type JournalHeaderPathInput148V1 struct {
	Owner                                          *HeaderCandidateOwner148V1
	Incarnation, Version, Height, AttachmentHeight uint64
	Hash, AttachmentHash, Provenance               [32]byte
	Expected                                       []byte
	Path                                           [][32]byte
	DurablePrefix                                  [][]byte
	Parts                                          [][]byte
}

// NewJournalHeaderPathSource148V1 exports an admitted independent snapshot of the original path.
// Provider guards end at its final current check, before any typed visitor or source filesystem work.
func NewJournalHeaderPathSource148V1(source *exclusionjournal.SourceOwnerV1, account exclusionjournal.OperationAccountV1, manifest exclusionjournal.SourceManifestV1, input JournalHeaderPathInput148V1) (exclusionjournal.SourceExporterV1, error) {
	if _, _, err := journalPathShape148(manifest, input); err != nil {
		return nil, err
	}
	return func(visit func(exclusionjournal.SourcePartV1) error) error {
		length, pathIndex, err := journalPathAdmission148(source.LimitsV1(), manifest, input)
		if err != nil {
			return err
		}
		if account == nil {
			return exclusionjournal.ErrCapacityV1
		}
		return account.WithReservation(length+1024, func() error {
			path, err := journalPathSnapshot148(input, length, manifest, pathIndex)
			if err != nil {
				return err
			}
			parts := append([][]byte(nil), input.Parts...)
			parts[pathIndex] = path
			return exclusionjournal.ExportSourceBytesV1(manifest, parts, visit)
		})
	}, nil
}

// journalPathAdmission148 applies manifest shape before finite count, work and RAM admission.
func journalPathAdmission148(limits exclusionjournal.SourceLimitsV1, m exclusionjournal.SourceManifestV1, in JournalHeaderPathInput148V1) (uint64, int, error) {
	length, index, err := journalPathShape148(m, in)
	if err != nil {
		return 0, 0, err
	}
	count := uint64(len(in.Path))
	if err := journalPathCapacity148(limits, m, count, length); err != nil {
		return 0, 0, err
	}
	return length, index, nil
}

// journalPathCapacity148 includes the source workspace and all snapshot visits in the same ceilings.
func journalPathCapacity148(limits exclusionjournal.SourceLimitsV1, m exclusionjournal.SourceManifestV1, count, length uint64) error {
	work := limits.WorkingBytesV1()
	if work > limits.RAM || length+1024 > limits.RAM-work {
		return exclusionjournal.ErrCapacityV1
	}
	scans := uint64(len(m.Parts))*3 + limits.Files*2 + 4
	if scans > limits.Scans || count > limits.Scans-scans {
		return exclusionjournal.ErrCapacityV1
	}
	if count == 0 || count > limits.Headers || length > limits.Bytes {
		return exclusionjournal.ErrCapacityV1
	}
	return nil
}

// journalPathShape148 checks all supplied lengths before capacity or provider protection.
func journalPathShape148(m exclusionjournal.SourceManifestV1, in JournalHeaderPathInput148V1) (uint64, int, error) {
	if _, err := m.SizeV1(); err != nil {
		return 0, 0, err
	}
	index := 4
	if m.Class == exclusionjournal.RecoveryCoreImpossibleV1 {
		index = 1
	}
	if len(in.Parts) != len(m.Parts) || len(in.DurablePrefix) > len(in.Path) {
		return 0, 0, exclusionjournal.ErrIntegrityV1
	}
	if err := journalSuppliedLengths148(m, in); err != nil {
		return 0, 0, err
	}
	count := uint64(len(in.Path))
	if count > (math.MaxInt-292-1024)/180 {
		return 0, 0, exclusionjournal.ErrCapacityV1
	}
	length := uint64(292) + 180*count
	if m.Parts[index].Length != length {
		return 0, 0, exclusionjournal.ErrIntegrityV1
	}
	return length, index, nil
}

// journalSuppliedLengths148 checks every present field before any proportional allocation.
func journalSuppliedLengths148(m exclusionjournal.SourceManifestV1, in JournalHeaderPathInput148V1) error {
	for i, p := range in.Parts {
		if p != nil && uint64(len(p)) != m.Parts[i].Length {
			return exclusionjournal.ErrIntegrityV1
		}
	}
	if slices.ContainsFunc(in.DurablePrefix, journalMalformedRaw148) || journalMalformedRaw148(in.Expected) {
		return exclusionjournal.ErrIntegrityV1
	}
	return nil
}

// journalMalformedRaw148 distinguishes absent raw headers from present malformed bytes.
func journalMalformedRaw148(raw []byte) bool { return raw != nil && len(raw) != 148 }

// journalPathSnapshot148 performs the final nested current check after the last point copy.
func journalPathSnapshot148(in JournalHeaderPathInput148V1, length uint64, manifest exclusionjournal.SourceManifestV1, pathIndex int) ([]byte, error) {
	release, err := journalPathProtect148(in)
	if err != nil {
		return nil, err
	}
	defer release()
	if err := journalPathRequired148(in, manifest, pathIndex); err != nil {
		return nil, err
	}
	path, err := journalPathCopy148(in, length)
	if err != nil {
		return nil, err
	}
	if in.Parts[pathIndex] != nil && !bytes.Equal(path, in.Parts[pathIndex]) {
		return nil, exclusionjournal.ErrIntegrityV1
	}
	current, finalRelease := in.Owner.ProtectV1(in.Version)
	defer finalRelease()
	if !current || in.Owner.IncarnationV1() != in.Incarnation {
		return nil, exclusionjournal.ErrUnavailableV1
	}
	return path, nil
}

// journalPathProtect148 protects the exact original version after immutable incarnation admission.
func journalPathProtect148(in JournalHeaderPathInput148V1) (func(), error) {
	if in.Owner == nil || in.Incarnation == 0 || in.Version == 0 || in.Owner.IncarnationV1() != in.Incarnation {
		return nil, exclusionjournal.ErrUnavailableV1
	}
	current, release := in.Owner.ProtectV1(in.Version)
	if !current || in.Owner.VersionV1() != in.Version {
		release()
		return nil, exclusionjournal.ErrUnavailableV1
	}
	return release, nil
}

// journalPathRequired148 refuses missing original payloads without an empty substitute.
func journalPathRequired148(in JournalHeaderPathInput148V1, manifest exclusionjournal.SourceManifestV1, pathIndex int) error {
	for i, part := range in.Parts {
		if i != pathIndex && part == nil && manifest.Parts[i].Length != 0 {
			return exclusionjournal.ErrUnavailableV1
		}
	}
	return nil
}

// journalPathCopy148 preserves original attachment fields and copies only the requested oldest-to-B headers.
func journalPathCopy148(in JournalHeaderPathInput148V1, length uint64) ([]byte, error) {
	out, err := journalPathMetadata148(in, length)
	if err != nil {
		return nil, err
	}
	for i, hash := range in.Path {
		raw, err := journalPathRaw148(in, i, hash)
		if err != nil {
			return nil, err
		}
		if i == len(in.Path)-1 && (hash != in.Hash || !bytes.Equal(raw[:], in.Expected)) {
			return nil, exclusionjournal.ErrIntegrityV1
		}
		out = append(out, hash[:]...)
		out = append(out, raw[:]...)
	}
	return out, nil
}

// journalPathMetadata148 copies all original attachment coordinates before header reads.
func journalPathMetadata148(in JournalHeaderPathInput148V1, length uint64) ([]byte, error) {
	if len(in.Expected) == 0 || in.Hash == [32]byte{} || in.AttachmentHash == [32]byte{} || in.Provenance == [32]byte{} {
		return nil, exclusionjournal.ErrUnavailableV1
	}
	out := make([]byte, 0, length)
	for _, n := range []uint64{in.Incarnation, in.Version, in.Height} {
		out = binary.LittleEndian.AppendUint64(out, n)
	}
	out = append(out, in.Hash[:]...)
	out = binary.LittleEndian.AppendUint64(out, in.AttachmentHeight)
	out = append(out, in.AttachmentHash[:]...)
	out = append(out, in.Provenance[:]...)
	out = append(out, in.Expected...)
	out = binary.LittleEndian.AppendUint64(out, uint64(len(in.Path)))
	out = binary.LittleEndian.AppendUint64(out, uint64(len(in.DurablePrefix)))
	return out, nil
}

// journalPathRaw148 reads one original durable or received point without invoking foreign code.
func journalPathRaw148(in JournalHeaderPathInput148V1, i int, hash [32]byte) (raw [148]byte, err error) {
	if i < len(in.DurablePrefix) {
		if in.DurablePrefix[i] == nil {
			return raw, exclusionjournal.ErrUnavailableV1
		}
		copy(raw[:], in.DurablePrefix[i])
		return raw, nil
	}
	if !in.Owner.Header148V1(hash, &raw) {
		return raw, exclusionjournal.ErrUnavailableV1
	}
	return raw, nil
}
