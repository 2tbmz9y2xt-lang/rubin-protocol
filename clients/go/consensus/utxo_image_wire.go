package consensus

import "encoding/binary"

const (
	utxoImageChunkCommand    = "utxoimg\x00\x00\x00\x00\x00"
	utxoImageNegativeCommand = "utxonotavail"
	utxoImageMaxPayload      = 2097152
	utxoImageMaxEntries      = 37446
	utxoImageMaxEdges        = 288
)

// UTXOImageQuery is the exact 120-byte IMAGE tuple. Reply tuples are raw echoes;
// only the request APIs enforce request scalar domains.
type UTXOImageQuery struct {
	RequestID uint64
	Height    uint64
	BlockHash [32]byte
	Root      [32]byte
	StartKey  [36]byte
	ByteLimit uint32
}

// UTXOImageEntry preserves the complete original StateEntryBytes fields.
type UTXOImageEntry struct {
	Outpoint Outpoint
	Entry    UtxoEntry
}

// UTXOImageEdge carries an absolute bit depth and an opaque raw node digest.
type UTXOImageEdge struct {
	Depth uint16
	Hash  [32]byte
}

// UTXOImageReply owns a scalar-canonical payload, without authenticating entries.
// Its zero value is invalid. No accessor exposes its immutable backing.
type UTXOImageReply struct {
	valid         bool
	query         UTXOImageQuery
	command       [12]byte
	payloadLength uint32
	payload       []byte
}

func (reply UTXOImageReply) Query() UTXOImageQuery {
	return reply.query
}

func (reply UTXOImageReply) Command() [12]byte {
	return reply.command
}

func (reply UTXOImageReply) PayloadLength() uint32 {
	return reply.payloadLength
}

// UTXOImageRange is a whole verified interval. Predecessor is proof evidence,
// separate from Entries; all returned mutable data has independent ownership.
type UTXOImageRange struct {
	Entries     []UTXOImageEntry
	Predecessor *UTXOImageEntry
	RightEdge   []UTXOImageEdge
	Terminal    bool
}

func utxoImageRequestDomain(q UTXOImageQuery) bool {
	return q.RequestID != 0 && q.Height <= 0xffffffff &&
		q.ByteLimit >= 150905 && q.ByteLimit <= utxoImageMaxPayload
}

func utxoImageReadQuery(payload []byte) UTXOImageQuery {
	q := UTXOImageQuery{
		RequestID: binary.LittleEndian.Uint64(payload[:8]),
		Height:    binary.LittleEndian.Uint64(payload[8:16]),
		ByteLimit: binary.LittleEndian.Uint32(payload[116:120]),
	}
	copy(q.BlockHash[:], payload[16:48])
	copy(q.Root[:], payload[48:80])
	copy(q.StartKey[:], payload[80:116])
	return q
}

// DecodeUTXOImageRequest consumes exactly Q and rejects invalid request scalars.
func DecodeUTXOImageRequest(payload []byte) (UTXOImageQuery, bool) {
	if len(payload) != 120 {
		return UTXOImageQuery{}, false
	}
	q := utxoImageReadQuery(payload)
	if !utxoImageRequestDomain(q) {
		return UTXOImageQuery{}, false
	}
	return q, true
}

// EncodeUTXOImageRequest validates request scalars before returning any bytes.
func EncodeUTXOImageRequest(q UTXOImageQuery) ([120]byte, bool) {
	if !utxoImageRequestDomain(q) {
		return [120]byte{}, false
	}
	return EncodeUTXOImageNotAvailable(q), true
}

// EncodeUTXOImageNotAvailable echoes Q exactly; it makes no source decision.
func EncodeUTXOImageNotAvailable(q UTXOImageQuery) [120]byte {
	var payload [120]byte
	binary.LittleEndian.PutUint64(payload[:8], q.RequestID)
	binary.LittleEndian.PutUint64(payload[8:16], q.Height)
	copy(payload[16:48], q.BlockHash[:])
	copy(payload[48:80], q.Root[:])
	copy(payload[80:116], q.StartKey[:])
	binary.LittleEndian.PutUint32(payload[116:120], q.ByteLimit)
	return payload
}

// DecodeUTXOImageReply requires admitted complete framing and copy permission.
// It scans the entire scalar layout before one owned copy. Unknown commands or
// above-cap payloads retain the earlier framing owner's diagnostic boundary.
func DecodeUTXOImageReply(command [12]byte, payload []byte) (UTXOImageReply, bool, string) {
	capBytes := 120
	switch string(command[:]) {
	case utxoImageChunkCommand:
		capBytes = utxoImageMaxPayload
	case utxoImageNegativeCommand:
	default:
		return UTXOImageReply{}, false, ""
	}
	if len(payload) > capBytes {
		return UTXOImageReply{}, false, ""
	}
	if len(payload) < 120 {
		return UTXOImageReply{}, false, "image_encoding"
	}
	if string(command[:]) == utxoImageChunkCommand {
		if reason := utxoImageScanChunk(payload); reason != "" {
			return UTXOImageReply{}, false, reason
		}
	}
	return UTXOImageReply{
		valid:         true,
		query:         utxoImageReadQuery(payload),
		command:       command,
		payloadLength: uint32(len(payload)),
		payload:       append([]byte(nil), payload...),
	}, true, ""
}

func utxoImageScanChunk(payload []byte) string {
	off := 120
	if reason := utxoImageScanEntries(payload, &off); reason != "" {
		return reason
	}
	if reason := utxoImageScanPredecessor(payload, &off); reason != "" {
		return reason
	}
	for range 2 {
		if reason := utxoImageScanEdges(payload, &off); reason != "" {
			return reason
		}
	}
	if off != len(payload) {
		return "image_encoding"
	}
	return ""
}

func utxoImageScanEntries(payload []byte, off *int) string {
	if len(payload)-*off < 4 {
		return "image_encoding"
	}
	n := binary.LittleEndian.Uint32(payload[*off : *off+4])
	*off += 4
	if n > utxoImageMaxEntries || 56*uint64(n)+5 > uint64(len(payload)-*off) {
		return "image_count"
	}
	for range n {
		if _, ok := utxoImageReadEntry(payload, off); !ok {
			return "image_encoding"
		}
	}
	return ""
}

// utxoImageReadEntry borrows only during the synchronous scalar/proof pass.
// The existing CompactSize reader owns minimality; no TX_ERR escapes this core.
func utxoImageReadEntry(payload []byte, off *int) (UTXOImageEntry, bool) {
	if len(payload)-*off < 46 {
		return UTXOImageEntry{}, false
	}
	fixed := payload[*off : *off+46]
	*off += 46
	n, _, err := readCompactSize(payload, off)
	if err != nil || n > 65536 {
		return UTXOImageEntry{}, false
	}
	if n > uint64(len(payload)-*off) {
		return UTXOImageEntry{}, false
	}
	data := payload[*off : *off+int(n)]
	*off += int(n)
	if len(payload)-*off < 9 || payload[*off+8] > 1 {
		return UTXOImageEntry{}, false
	}
	var entry UTXOImageEntry
	copy(entry.Outpoint.Txid[:], fixed[:32])
	entry.Outpoint.Vout = binary.LittleEndian.Uint32(fixed[32:36])
	entry.Entry = UtxoEntry{
		Value:             binary.LittleEndian.Uint64(fixed[36:44]),
		CovenantType:      binary.LittleEndian.Uint16(fixed[44:46]),
		CovenantData:      data,
		CreationHeight:    binary.LittleEndian.Uint64(payload[*off : *off+8]),
		CreatedByCoinbase: payload[*off+8] == 1,
	}
	*off += 9
	return entry, true
}

func utxoImageScanPredecessor(payload []byte, off *int) string {
	if *off == len(payload) {
		return "image_encoding"
	}
	flag := payload[*off]
	*off++
	switch flag {
	case 0:
		return ""
	case 1:
		if _, ok := utxoImageReadEntry(payload, off); ok {
			return ""
		}
	}
	return "image_encoding"
}

func utxoImageScanEdges(payload []byte, off *int) string {
	if len(payload)-*off < 2 {
		return "image_encoding"
	}
	n := int(binary.LittleEndian.Uint16(payload[*off : *off+2]))
	*off += 2
	if n > utxoImageMaxEdges || 34*n > len(payload)-*off {
		return "image_count"
	}
	for range n {
		if binary.BigEndian.Uint16(payload[*off : *off+2]) >= 288 {
			return "image_encoding"
		}
		*off += 34
	}
	return ""
}

func utxoImageEntriesSize(entries []UTXOImageEntry, predecessor *UTXOImageEntry) (uint64, string) {
	var total uint64
	for _, entry := range entries {
		if len(entry.Entry.CovenantData) > 65536 {
			return 0, "image_encoding"
		}
		total += logicalStateEntryLength(entry.Entry)
	}
	if predecessor != nil {
		if len(predecessor.Entry.CovenantData) > 65536 {
			return 0, "image_encoding"
		}
		total += logicalStateEntryLength(predecessor.Entry)
	}
	return total, ""
}

func utxoImageTypedEdgesReason(edges []UTXOImageEdge) string {
	if len(edges) > utxoImageMaxEdges {
		return "image_count"
	}
	for _, edge := range edges {
		if edge.Depth >= 288 {
			return "image_encoding"
		}
	}
	return ""
}

func utxoImageChunkSize(entries []UTXOImageEntry, predecessor *UTXOImageEntry, left, right []UTXOImageEdge) (uint64, string) {
	if len(entries) > utxoImageMaxEntries {
		return 0, "image_count"
	}
	total, reason := utxoImageEntriesSize(entries, predecessor)
	if reason != "" {
		return 0, reason
	}
	// At most 37447 entries of 65596 bytes and 576 edges: this sum fits u64.
	total += 129
	for _, edges := range [2][]UTXOImageEdge{left, right} {
		if reason := utxoImageTypedEdgesReason(edges); reason != "" {
			return 0, reason
		}
		total += 34 * uint64(len(edges))
	}
	if total > utxoImageMaxPayload {
		return 0, "image_count"
	}
	return total, ""
}

// EncodeUTXOImageChunk serializes scalar-canonical shape only. It neither sorts
// entries nor constructs, repairs or authenticates a proof. Q is echoed raw.
func EncodeUTXOImageChunk(q UTXOImageQuery, entries []UTXOImageEntry, predecessor *UTXOImageEntry, left, right []UTXOImageEdge) ([]byte, bool, string) {
	total, reason := utxoImageChunkSize(entries, predecessor, left, right)
	if reason != "" {
		return nil, false, reason
	}
	// The cap proves both int conversion and complete output capacity safe.
	payload := make([]byte, 124, int(total))
	rawQ := EncodeUTXOImageNotAvailable(q)
	copy(payload[:120], rawQ[:])
	binary.LittleEndian.PutUint32(payload[120:124], uint32(len(entries)))
	for _, entry := range entries {
		payload = append(payload, logicalStateEntryBytes(entry.Outpoint, entry.Entry)...)
	}
	payload = append(payload, 0)
	if predecessor != nil {
		payload[len(payload)-1] = 1
		payload = append(payload, logicalStateEntryBytes(predecessor.Outpoint, predecessor.Entry)...)
	}
	payload = utxoImageAppendEdges(payload, left)
	payload = utxoImageAppendEdges(payload, right)
	return payload, true, ""
}

func utxoImageAppendEdges(payload []byte, edges []UTXOImageEdge) []byte {
	payload = AppendU16le(payload, uint16(len(edges)))
	for _, edge := range edges {
		payload = binary.BigEndian.AppendUint16(payload, edge.Depth)
		payload = append(payload, edge.Hash[:]...)
	}
	return payload
}
