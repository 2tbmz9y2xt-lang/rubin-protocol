package p2p

import (
	"fmt"
	"unicode/utf8"
)

const (
	MaxRejectReasonBytes = 111
)

type RejectPayload struct {
	Message string
	Code    byte
	Reason  string
}

func EncodeRejectPayload(r RejectPayload) ([]byte, error) {
	if r.Message == "" {
		return nil, fmt.Errorf("p2p: reject: empty message")
	}
	if len(r.Message) > CommandBytes {
		// The spec uses an arbitrary string length, but for v1.1 we keep it bounded.
		return nil, fmt.Errorf("p2p: reject: message too long")
	}
	if len(r.Reason) > MaxRejectReasonBytes {
		return nil, fmt.Errorf("p2p: reject: reason too long")
	}
	if !utf8.ValidString(r.Reason) {
		return nil, fmt.Errorf("p2p: reject: reason must be UTF-8")
	}
	out := make([]byte, 0, 9+len(r.Message)+1+9+len(r.Reason))
	out = append(out, encodeCompactSize(uint64(len(r.Message)))...)
	out = append(out, []byte(r.Message)...)
	out = append(out, r.Code)
	out = append(out, encodeCompactSize(uint64(len(r.Reason)))...)
	out = append(out, []byte(r.Reason)...)
	return out, nil
}

func DecodeRejectPayload(b []byte) (*RejectPayload, error) {
	off := 0
	msgLenU64, used, err := readCompactSize(b)
	if err != nil {
		return nil, err
	}
	off += used
	if msgLenU64 > CommandBytes {
		return nil, fmt.Errorf("p2p: reject: message_len too large")
	}
	msgLen := int(msgLenU64)
	if len(b) < off+msgLen+1 {
		return nil, fmt.Errorf("p2p: reject: truncated message")
	}
	msg := string(b[off : off+msgLen])
	off += msgLen
	code := b[off]
	off++
	reasonLenU64, used, err := readCompactSize(b[off:])
	if err != nil {
		return nil, err
	}
	off += used
	if reasonLenU64 > MaxRejectReasonBytes {
		return nil, fmt.Errorf("p2p: reject: reason_len too large")
	}
	reasonLen := int(reasonLenU64)
	if len(b) < off+reasonLen {
		return nil, fmt.Errorf("p2p: reject: truncated reason")
	}
	reasonBytes := b[off : off+reasonLen]
	off += reasonLen
	if off != len(b) {
		return nil, fmt.Errorf("p2p: reject: trailing bytes")
	}
	if !utf8.Valid(reasonBytes) {
		return nil, fmt.Errorf("p2p: reject: reason must be UTF-8")
	}
	return &RejectPayload{Message: msg, Code: code, Reason: string(reasonBytes)}, nil
}
