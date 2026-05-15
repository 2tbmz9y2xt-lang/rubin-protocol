package p2p

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func encodeAddrPayload(addrs []string) ([]byte, error) {
	var buf bytes.Buffer
	buf.Write(consensus.EncodeCompactSize(uint64(len(addrs))))
	for _, addr := range addrs {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, fmt.Errorf("invalid addr host: %s", host)
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("invalid addr port: %s", portStr)
		}
		ip = ip.To16()
		if ip == nil {
			return nil, fmt.Errorf("invalid addr ip width: %s", host)
		}
		buf.Write(ip)
		var portBytes [2]byte
		binary.BigEndian.PutUint16(portBytes[:], uint16(port))
		buf.Write(portBytes[:])
	}
	return buf.Bytes(), nil
}

func decodeAddrPayload(payload []byte) ([]string, error) {
	if len(payload) == 0 {
		return nil, nil
	}
	count, consumed, err := decodeAddrCount(payload)
	if err != nil {
		return nil, err
	}
	remaining := len(payload) - consumed
	if remaining < 0 || count > uint64(remaining/addrPayloadEntrySize) {
		return nil, errors.New("addr payload width mismatch")
	}
	needed := consumed + int(count)*addrPayloadEntrySize // #nosec G115 -- count is bounded by remaining/addrPayloadEntrySize above.
	if len(payload) != needed {
		return nil, errors.New("addr payload width mismatch")
	}
	out := make([]string, 0, int(count)) // #nosec G115 -- count is bounded by remaining/addrPayloadEntrySize above.
	offset := consumed
	for i := uint64(0); i < count; i++ {
		addr, nextOffset, err := decodeAddrPayloadEntry(payload, offset)
		if err != nil {
			return nil, err
		}
		offset = nextOffset
		out = append(out, addr)
	}
	return out, nil
}

func decodeAddrCount(payload []byte) (uint64, int, error) {
	count, consumed, err := consensus.DecodeCompactSize(payload)
	if err != nil {
		return 0, 0, err
	}
	maxInt := int(^uint(0) >> 1)
	if count > uint64(maxInt) {
		return 0, 0, errors.New("addr count overflow")
	}
	if count > maxAddrPayloadEntries {
		return 0, 0, errors.New("addr count exceeds limit")
	}
	return count, consumed, nil
}

func decodeAddrPayloadEntry(payload []byte, offset int) (string, int, error) {
	ip := net.IP(payload[offset : offset+16])
	offset += 16
	port := binary.BigEndian.Uint16(payload[offset : offset+2])
	offset += 2
	addr := normalizeNetAddr(net.JoinHostPort(ip.String(), strconv.FormatUint(uint64(port), 10)))
	if addr == "" {
		return "", 0, errors.New("invalid addr payload entry")
	}
	return addr, offset, nil
}
