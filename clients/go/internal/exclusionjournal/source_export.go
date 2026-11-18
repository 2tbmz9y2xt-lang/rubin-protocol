package exclusionjournal

import (
	"io"
	"math"
	"reflect"
	"slices"
	"sync"
)

// SourceExporterV1 visits each original immutable part synchronously, in manifest order.
type SourceExporterV1 func(visit func(SourcePartV1) error) error

// SourcePartV1 is an exact bounded part. ReadAt is valid only during its visitor call.
type SourcePartV1 struct {
	Kind   PartKindV1
	Length uint64
	ReadAt func([]byte, int64) (int, error)
}

// OperationAccountV1 funds synchronous source work on the caller's existing account.
type OperationAccountV1 interface {
	WithReservation(uint64, func() error) error
}

type partScope struct {
	mu   sync.Mutex
	part SourcePartV1
}

// read serializes bounded reads with expiry and never exposes backing storage.
func (s *partScope) read(dst []byte, offset int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.part.ReadAt == nil {
		return 0, ErrUnavailableV1
	}
	if offset < 0 || uint64(offset) > s.part.Length {
		return 0, ErrIntegrityV1
	}
	if uint64(len(dst)) > s.part.Length-uint64(offset) {
		return 0, ErrIntegrityV1
	}
	return s.part.ReadAt(dst, offset)
}

// expire waits for an admitted read and clears every producer reference.
func (s *partScope) expire() {
	s.mu.Lock()
	s.part = SourcePartV1{}
	s.mu.Unlock()
}

// visitPart scopes the producer pin through the visitor and all its cleanup.
func visitPart(part SourcePartV1, visit func(SourcePartV1) error) error {
	s := &partScope{part: part}
	defer s.expire()
	return visit(SourcePartV1{Kind: part.Kind, Length: part.Length, ReadAt: s.read})
}

// ExportSourceBytesV1 exposes already-owned immutable byte views without copying or retaining them.
func ExportSourceBytesV1(manifest SourceManifestV1, parts [][]byte, visit func(SourcePartV1) error) error {
	if err := CheckSourceBytesV1(manifest, parts); err != nil {
		return err
	}
	if visit == nil {
		return ErrIntegrityV1
	}
	for i, data := range parts {
		part := SourcePartV1{Kind: manifest.Parts[i].Kind, Length: uint64(len(data))}
		part.ReadAt = func(dst []byte, off int64) (int, error) {
			if off < 0 || uint64(off) > uint64(len(data)) || uint64(len(dst)) > uint64(len(data))-uint64(off) {
				return 0, ErrIntegrityV1
			}
			return copy(dst, data[int(off):]), nil
		}
		if err := visitPart(part, visit); err != nil {
			return err
		}
	}
	return nil
}

// CheckSourceBytesV1 checks the complete immutable byte-view census without reading or allocating payloads.
func CheckSourceBytesV1(manifest SourceManifestV1, parts [][]byte) error {
	if _, err := manifest.SizeV1(); err != nil {
		return err
	}
	if len(parts) != len(manifest.Parts) {
		return ErrIntegrityV1
	}
	for i, part := range parts {
		if uint64(len(part)) != manifest.Parts[i].Length {
			return ErrIntegrityV1
		}
	}
	return nil
}

// SourceBackingBytesV1 counts the union of at most six immutable byte views, without copying them.
func SourceBackingBytesV1(parts [][]byte) (uint64, error) {
	if len(parts) > 6 {
		return 0, ErrIntegrityV1
	}
	var spans [6]struct{ start, end uint64 }
	for i, part := range parts {
		start := uint64(reflect.ValueOf(part).Pointer())
		if uint64(len(part)) > math.MaxUint64-start {
			return 0, ErrCapacityV1
		}
		spans[i].start, spans[i].end = start, start+uint64(len(part))
	}
	slices.SortFunc(spans[:len(parts)], func(a, b struct{ start, end uint64 }) int {
		if a.start < b.start {
			return -1
		}
		if a.start > b.start {
			return 1
		}
		return 0
	})
	var total, end uint64
	for _, span := range spans[:len(parts)] {
		start := max(span.start, end)
		if span.end > start {
			total += span.end - start
		}
		end = max(end, span.end)
	}
	return total, nil
}

type exportCursor struct {
	mu       sync.Mutex
	manifest SourceManifestV1
	visit    func(SourcePartV1) error
	next     int
	failure  error
}

// export checks every callback against the frozen census, including missing callbacks.
func export(m SourceManifestV1, producer SourceExporterV1, visit func(SourcePartV1) error) error {
	if producer == nil || visit == nil {
		return ErrIntegrityV1
	}
	cursor := &exportCursor{manifest: m, visit: visit}
	defer cursor.expire()
	return cursor.result(producer(cursor.part))
}

// part accepts only the next declared part and preserves the first callback refusal.
func (c *exportCursor) part(part SourcePartV1) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.visit == nil {
		return ErrUnavailableV1
	}
	if c.failure != nil {
		return c.failure
	}
	if c.next >= len(c.manifest.Parts) || part.ReadAt == nil {
		c.failure = ErrIntegrityV1
		return c.failure
	}
	expected := c.manifest.Parts[c.next]
	if part.Kind != expected.Kind || part.Length != expected.Length {
		c.failure = ErrIntegrityV1
		return c.failure
	}
	c.next++
	c.failure = visitPart(part, c.visit)
	return c.failure
}

// result waits for admitted callbacks and checks the completed ordered census.
func (c *exportCursor) result(err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failure != nil {
		return c.failure
	}
	if err != nil {
		return err
	}
	if c.next != len(c.manifest.Parts) {
		return ErrIntegrityV1
	}
	return nil
}

// expire clears foreign callback and manifest references on return, error and panic.
func (c *exportCursor) expire() {
	c.mu.Lock()
	c.visit = nil
	c.manifest = SourceManifestV1{}
	c.failure = nil
	c.next = 0
	c.mu.Unlock()
}

// WithSourceExportV1 holds source authority through the exact synchronous export.
// Scoped readers expire on success, error and panic; caller backing and funding remain owned by the caller.
// Escaped readers and callbacks retain only expired scope state without producer references.
func (o *SourceOwnerV1) WithSourceExportV1(account OperationAccountV1, m SourceManifestV1, producer SourceExporterV1, visit func(SourcePartV1) error) error {
	return o.operation(account, func() error {
		if err := o.admitManifest(m); err != nil {
			return err
		}
		return export(m, producer, visit)
	})
}

// admitManifest checks complete encoded bytes and prospective source work before callbacks.
func (o *SourceOwnerV1) admitManifest(m SourceManifestV1) error {
	size, err := m.SizeV1()
	if err != nil {
		return err
	}
	if size > o.limits.Bytes || uint64(len(m.Parts))*3+o.limits.Files*2+2 > o.limits.Scans {
		return ErrCapacityV1
	}
	return nil
}

// copyPart streams exact bytes with one admitted bounded scratch buffer.
func copyPart(part SourcePartV1, dst io.Writer, scratch []byte) error {
	for offset := uint64(0); offset < part.Length; {
		n := min(uint64(len(scratch)), part.Length-offset)
		chunk := scratch[:n]
		read, err := part.ReadAt(chunk, int64(offset))
		if read != len(chunk) || err != nil {
			return ErrIntegrityV1
		}
		written, err := dst.Write(chunk)
		if err != nil {
			return err
		}
		if written != len(chunk) {
			return io.ErrShortWrite
		}
		offset += n
	}
	return nil
}
