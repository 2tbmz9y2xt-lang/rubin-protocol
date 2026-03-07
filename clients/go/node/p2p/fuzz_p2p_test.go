package p2p

import (
	"bytes"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func FuzzReadFrame(f *testing.F) {
	validVersionPayload, err := encodeVersionPayload(node.VersionPayloadV1{
		ProtocolVersion: ProtocolVersion,
		TxRelay:         true,
		UserAgent:       "rubin-fuzz",
		BestHeight:      7,
	})
	if err != nil {
		f.Fatalf("encodeVersionPayload seed: %v", err)
	}

	var validFrame bytes.Buffer
	if err := writeFrame(
		&validFrame,
		networkMagic("devnet"),
		message{Command: messageVersion, Payload: validVersionPayload},
		1<<20,
	); err != nil {
		f.Fatalf("writeFrame seed: %v", err)
	}
	f.Add(validFrame.Bytes(), uint32(1<<20))
	f.Add(append([]byte("RBDVtx\x00\x00\x00\x00\x00\x00\x00\x00"), 0x01), uint32(1024))
	f.Add([]byte{0x52, 0x42, 0x44, 0x56, 0x74, 0x78, 0x00, 0x00, 0x00, 0x00}, uint32(1024))

	f.Fuzz(func(t *testing.T, frameBytes []byte, maxMessageSize uint32) {
		if len(frameBytes) > (2 << 20) {
			return
		}
		if maxMessageSize == 0 {
			maxMessageSize = 1
		}

		got1, err1 := readFrame(bytes.NewReader(frameBytes), networkMagic("devnet"), maxMessageSize)
		got2, err2 := readFrame(bytes.NewReader(frameBytes), networkMagic("devnet"), maxMessageSize)

		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("readFrame error drift: %v vs %v", err1, err2)
		}
		if err1 != nil {
			if err1.Error() != err2.Error() {
				t.Fatalf("readFrame error text drift: %q vs %q", err1.Error(), err2.Error())
			}
			return
		}
		if got1.Command != got2.Command || !bytes.Equal(got1.Payload, got2.Payload) {
			t.Fatalf("readFrame result drift: %#v vs %#v", got1, got2)
		}
	})
}

func FuzzDecodeVersionPayload(f *testing.F) {
	seed, err := encodeVersionPayload(node.VersionPayloadV1{
		ProtocolVersion: ProtocolVersion,
		TxRelay:         true,
		UserAgent:       "rubin-fuzz",
		BestHeight:      7,
	})
	if err != nil {
		f.Fatalf("encodeVersionPayload seed: %v", err)
	}
	f.Add(seed)
	f.Add([]byte{0x00, 0x01})

	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > (1 << 20) {
			return
		}

		got1, err1 := decodeVersionPayload(payload)
		got2, err2 := decodeVersionPayload(payload)

		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("decodeVersionPayload error drift: %v vs %v", err1, err2)
		}
		if err1 != nil {
			if err1.Error() != err2.Error() {
				t.Fatalf("decodeVersionPayload error text drift: %q vs %q", err1.Error(), err2.Error())
			}
			return
		}
		if got1 != got2 {
			t.Fatalf("decodeVersionPayload result drift: %#v vs %#v", got1, got2)
		}

		roundtrip, err := encodeVersionPayload(got1)
		if err != nil {
			t.Fatalf("encodeVersionPayload after decode: %v", err)
		}
		got3, err := decodeVersionPayload(roundtrip)
		if err != nil {
			t.Fatalf("roundtrip decodeVersionPayload: %v", err)
		}
		if got3 != got1 {
			t.Fatalf("roundtrip drift: %#v vs %#v", got3, got1)
		}
	})
}
