package treebody

import (
	"crypto/sha3"
	"encoding/binary"
	"math"
)

const (
	MaxDABytesPerBlock       = 32_000_000
	MaxDAManifestBytesPerTx  = 65_536
	ChunkBytes               = 524_288
	MaxDAChunkCount          = MaxDABytesPerBlock / ChunkBytes
	MaxAnchorPayloadSize     = 65_536
	MaxCovenantDataPerOutput = MaxAnchorPayloadSize
	MaxTxInputs              = 1024
	MaxTxOutputs             = 1024
	MaxWitnessItems          = 1024
	MaxWitnessBytesPerTx     = 100_000
	MaxScriptSigBytes        = 32
	TxWireVersion            = 1
	CovTypeAnchor            = 0x0002
	CovTypeDACommit          = 0x0103
)

// Source borrows Raw or reads the declared Length into the supplied Window.
// The scanner uses both forms synchronously and retains neither.
type Source struct {
	Raw    []byte
	ReadAt func([]byte, uint64) (int, error)
	Window []byte
	Length uint64
}

type EventKind uint8

const (
	EventSpend  EventKind = 1
	EventCreate EventKind = 2
)

type Outpoint struct {
	Txid [32]byte
	Vout uint32
}

type Event struct {
	Kind        EventKind
	Outpoint    Outpoint
	TxIndex     uint32
	InputIndex  uint32
	FrameOffset uint64
	FrameLength uint32
}

type Census struct {
	Parent     [32]byte
	TxCount    uint32
	EventCount uint32
	Malformed  bool
}

type framingError string

const errFraming framingError = "block body framing differs"

func (e framingError) Error() string { return string(e) }

// Scan reads a qualified header width and the body. With a nil emitter it
// counts events without hashing or revisiting outputs. Callback errors are
// returned unchanged; malformed framing is reported in Census.
func Scan(source Source, width uint16, height uint64, emit func(Event) error) (Census, error) {
	c := cursor{raw: source.Raw, readAt: source.ReadAt, window: source.Window, length: source.Length, emit: emit}
	if c.raw != nil {
		c.length = uint64(len(c.raw))
	}
	if emit != nil {
		c.digest = sha3.New256()
	}
	parent := c.blockV1(width, height)
	malformed := any(c.err) == any(errFraming)
	if malformed {
		c.err = nil
	}
	return Census{Parent: parent, TxCount: c.txs, EventCount: c.events, Malformed: malformed}, c.err
}

type cursor struct {
	raw         []byte
	readAt      func([]byte, uint64) (int, error)
	window      []byte
	emit        func(Event) error
	hash        *sha3.SHA3
	digest      *sha3.SHA3
	err         error
	length, off uint64
	txs, events uint32
	field       [40]byte
}

func (c *cursor) failV1() {
	if c.err == nil {
		c.err = errFraming
	}
}

func (c *cursor) spanV1(n uint64) bool {
	if c.err != nil {
		return false
	}
	if c.off > c.length || n > c.length-c.off {
		c.failV1()
		return false
	}
	return true
}

func (c *cursor) readV1(dst []byte) {
	if !c.spanV1(uint64(len(dst))) {
		clear(dst)
		return
	}
	if c.raw != nil {
		copy(dst, c.raw[c.off:c.off+uint64(len(dst))])
	} else {
		if len(dst) > len(c.window) {
			c.failV1()
			return
		}
		_, c.err = c.readAt(c.window[:len(dst)], c.off)
		copy(dst, c.window[:len(dst)])
	}
	if c.hash != nil && c.err == nil {
		_, _ = c.hash.Write(dst)
	}
	c.off += uint64(len(dst))
}

func (c *cursor) fixedV1(n int) []byte {
	c.readV1(c.field[:n])
	return c.field[:n]
}

func (c *cursor) skipV1(n uint64) {
	if !c.spanV1(n) {
		return
	}
	if c.raw != nil {
		if c.hash != nil {
			_, _ = c.hash.Write(c.raw[c.off : c.off+n])
		}
		c.off += n
		return
	}
	for n != 0 && c.err == nil {
		chunk := min(n, uint64(len(c.window)))
		if chunk == 0 {
			c.failV1()
			return
		}
		c.readV1(c.window[:chunk])
		n -= chunk
	}
}

func (c *cursor) compactV1(maximum uint64) uint64 {
	tag := c.fixedV1(1)[0]
	var n, minimum uint64
	switch tag {
	case 253:
		n, minimum = uint64(binary.LittleEndian.Uint16(c.fixedV1(2))), 253
	case 254:
		n, minimum = uint64(binary.LittleEndian.Uint32(c.fixedV1(4))), 65536
	case 255:
		n, minimum = binary.LittleEndian.Uint64(c.fixedV1(8)), 4294967296
	default:
		n = uint64(tag)
	}
	if n < minimum || n > maximum {
		c.failV1()
	}
	return n
}

func (c *cursor) blockV1(width uint16, height uint64) [32]byte {
	c.skipV1(4)
	var parent [32]byte
	copy(parent[:], c.fixedV1(32))
	c.skipV1(uint64(width) - 36)
	n := c.compactV1(math.MaxUint32)
	if n > math.MaxUint32 {
		c.failV1()
		return parent
	}
	if n == 0 || height == 0 && n != 1 {
		c.failV1()
	}
	c.txs = uint32(n)
	for tx := uint32(0); tx < c.txs && c.err == nil; tx++ {
		c.txV1(tx)
	}
	if c.off != c.length {
		c.failV1()
	}
	return parent
}

func (c *cursor) eventV1(e Event) {
	if c.err != nil {
		return
	}
	if c.events == math.MaxUint32 {
		c.failV1()
		return
	}
	c.events++
	if c.emit != nil {
		c.err = c.emit(e)
	}
}

func (c *cursor) inputV1(tx, input uint32) {
	var e Event
	e.Kind, e.TxIndex, e.InputIndex = EventSpend, tx, input
	copy(e.Outpoint.Txid[:], c.fixedV1(32))
	e.Outpoint.Vout = binary.LittleEndian.Uint32(c.fixedV1(4))
	c.skipV1(c.compactV1(MaxScriptSigBytes))
	c.skipV1(4)
	if tx != 0 {
		c.eventV1(e)
	}
}

func (c *cursor) outputV1(tx, vout uint32, id [32]byte, emit bool) {
	start := c.off
	c.skipV1(8)
	kind := binary.LittleEndian.Uint16(c.fixedV1(2))
	c.skipV1(c.compactV1(MaxCovenantDataPerOutput))
	if kind == CovTypeAnchor || kind == CovTypeDACommit || !emit {
		return
	}
	length := c.off - start
	if length > math.MaxUint32 {
		c.failV1()
		return
	}
	c.eventV1(Event{Kind: EventCreate, Outpoint: Outpoint{Txid: id, Vout: vout}, TxIndex: tx, FrameOffset: start, FrameLength: uint32(length)})
}

func (c *cursor) txV1(tx uint32) {
	if c.emit != nil {
		c.hash = c.digest
		c.hash.Reset()
	}
	kind, outputs, start, end := c.coreV1(tx)
	var id [32]byte
	if c.hash != nil {
		c.hash.Sum(id[:0])
		c.hash = nil
	}
	c.witnessV1()
	c.payloadV1(kind)
	if c.emit != nil && c.err == nil {
		c.outputsV1(tx, outputs, start, end, id)
	}
}

func (c *cursor) coreV1(tx uint32) (uint8, uint64, uint64, uint64) {
	if binary.LittleEndian.Uint32(c.fixedV1(4)) != TxWireVersion {
		c.failV1()
	}
	kind := c.fixedV1(1)[0]
	c.skipV1(8)
	inputs := c.compactV1(MaxTxInputs)
	for i := uint64(0); i < inputs && c.err == nil; i++ {
		c.inputV1(tx, uint32(i))
	}
	outputs := c.compactV1(MaxTxOutputs)
	start := c.off
	for i := uint64(0); i < outputs && c.err == nil; i++ {
		c.outputV1(tx, uint32(i), [32]byte{}, c.emit == nil)
	}
	end := c.off
	c.skipV1(4)
	c.daCoreV1(kind)
	return kind, outputs, start, end
}

func (c *cursor) outputsV1(tx uint32, outputs, start, end uint64, id [32]byte) {
	// Only the output region is revisited. The complete forward cursor remains
	// at the next transaction; no descriptor or input is retained or rescanned.
	r := *c
	r.off, r.length = start, end
	for i := uint64(0); i < outputs && r.err == nil; i++ {
		r.outputV1(tx, uint32(i), id, true)
	}
	c.events, c.err = r.events, r.err
}

func (c *cursor) daCoreV1(kind uint8) {
	switch kind {
	case 0:
		return
	case 1:
		c.skipV1(32)
		n := binary.LittleEndian.Uint16(c.fixedV1(2))
		if n == 0 || uint64(n) > MaxDAChunkCount {
			c.failV1()
		}
		c.skipV1(32 + 8 + 32 + 32 + 32 + 1)
		c.skipV1(c.compactV1(MaxDAManifestBytesPerTx))
	case 2:
		c.skipV1(32)
		if uint64(binary.LittleEndian.Uint16(c.fixedV1(2))) >= MaxDAChunkCount {
			c.failV1()
		}
		c.skipV1(32)
	default:
		c.failV1()
	}
}

func (c *cursor) witnessV1() {
	start := c.off
	n := c.compactV1(MaxWitnessItems)
	for i := uint64(0); i < n && c.err == nil; i++ {
		c.skipV1(1) // suite/signature semantics were qualified by the caller
		c.skipV1(c.compactV1(uint64(math.MaxInt)))
		c.skipV1(c.compactV1(uint64(math.MaxInt)))
		if c.off-start > MaxWitnessBytesPerTx {
			c.failV1()
		}
	}
}

func (c *cursor) payloadV1(kind uint8) {
	n := c.compactV1(math.MaxUint64)
	switch kind {
	case 0:
		if n != 0 {
			c.failV1()
		}
	case 1:
		if n > MaxDAManifestBytesPerTx {
			c.failV1()
		}
	case 2:
		if n == 0 || n > ChunkBytes {
			c.failV1()
		}
	}
	c.skipV1(n)
}
