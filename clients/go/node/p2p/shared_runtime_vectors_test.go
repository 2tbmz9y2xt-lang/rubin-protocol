package p2p

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

type sharedRuntimeVectors struct {
	VersionPayloadV1 struct {
		Hex               string `json:"hex"`
		ProtocolVersion   uint32 `json:"protocol_version"`
		TxRelay           bool   `json:"tx_relay"`
		PrunedBelowHeight uint64 `json:"pruned_below_height"`
		DaMempoolSize     uint32 `json:"da_mempool_size"`
		ChainIDHex        string `json:"chain_id_hex"`
		GenesisHashHex    string `json:"genesis_hash_hex"`
		BestHeight        uint64 `json:"best_height"`
	} `json:"version_payload_v1"`
	Frames []struct {
		ID             string `json:"id"`
		Network        string `json:"network"`
		MaxMessageSize uint32 `json:"max_message_size"`
		Hex            string `json:"hex"`
		ExpectCommand  string `json:"expect_command"`
		ExpectPayload  string `json:"expect_payload_hex"`
		ExpectErr      string `json:"expect_err"`
	} `json:"frames"`
	VersionValidation []struct {
		ID                    string `json:"id"`
		LocalProtocolVersion  uint32 `json:"local_protocol_version"`
		RemoteProtocolVersion uint32 `json:"remote_protocol_version"`
		TxRelay               bool   `json:"tx_relay"`
		PrunedBelowHeight     uint64 `json:"pruned_below_height"`
		DaMempoolSize         uint32 `json:"da_mempool_size"`
		ChainIDHex            string `json:"chain_id_hex"`
		GenesisHashHex        string `json:"genesis_hash_hex"`
		BestHeight            uint64 `json:"best_height"`
		ExpectOK              bool   `json:"expect_ok"`
		ExpectErr             string `json:"expect_err"`
	} `json:"version_validation"`
}

func TestSharedRuntimeVectorsVersionPayloadV1(t *testing.T) {
	vectors := loadSharedRuntimeVectors(t)
	expected := sharedVersionPayload(t, vectors)
	wantHex := mustDecodeHex(t, vectors.VersionPayloadV1.Hex)

	payload, err := encodeVersionPayload(expected)
	if err != nil {
		t.Fatalf("encodeVersionPayload: %v", err)
	}
	if !bytes.Equal(payload, wantHex) {
		t.Fatalf("payload hex mismatch: got %x want %x", payload, wantHex)
	}

	got, err := decodeVersionPayload(wantHex)
	if err != nil {
		t.Fatalf("decodeVersionPayload: %v", err)
	}
	if got != expected {
		t.Fatalf("decoded payload mismatch: got %+v want %+v", got, expected)
	}
}

func TestSharedRuntimeVectorsFrames(t *testing.T) {
	vectors := loadSharedRuntimeVectors(t)
	for _, frame := range vectors.Frames {
		raw := mustDecodeHex(t, frame.Hex)
		got, err := readFrame(bytes.NewReader(raw), networkMagic(frame.Network), frame.MaxMessageSize)
		if frame.ExpectErr != "" {
			if err == nil || err.Error() != frame.ExpectErr {
				t.Fatalf("%s: err=%v, want %q", frame.ID, err, frame.ExpectErr)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: readFrame: %v", frame.ID, err)
		}
		if got.Command != frame.ExpectCommand {
			t.Fatalf("%s: command=%q want %q", frame.ID, got.Command, frame.ExpectCommand)
		}
		if !bytes.Equal(got.Payload, mustDecodeHex(t, frame.ExpectPayload)) {
			t.Fatalf("%s: payload mismatch", frame.ID)
		}
		var encoded bytes.Buffer
		if err := writeFrame(&encoded, networkMagic(frame.Network), got, frame.MaxMessageSize); err != nil {
			t.Fatalf("%s: writeFrame: %v", frame.ID, err)
		}
		if !bytes.Equal(encoded.Bytes(), raw) {
			t.Fatalf("%s: roundtrip mismatch", frame.ID)
		}
	}
}

func TestSharedRuntimeVectorsVersionValidation(t *testing.T) {
	vectors := loadSharedRuntimeVectors(t)
	expected := sharedVersionPayload(t, vectors)
	for _, tc := range vectors.VersionValidation {
		state := node.PeerState{}
		remote := node.VersionPayloadV1{
			ProtocolVersion:   tc.RemoteProtocolVersion,
			TxRelay:           tc.TxRelay,
			PrunedBelowHeight: tc.PrunedBelowHeight,
			DaMempoolSize:     tc.DaMempoolSize,
			ChainID:           mustDecodeHex32(t, tc.ChainIDHex),
			GenesisHash:       mustDecodeHex32(t, tc.GenesisHashHex),
			BestHeight:        tc.BestHeight,
		}
		err := validateRemoteVersion(remote, tc.LocalProtocolVersion, expected.ChainID, expected.GenesisHash, 100, &state)
		if tc.ExpectErr != "" {
			if err == nil || err.Error() != tc.ExpectErr {
				t.Fatalf("%s: err=%v want %q", tc.ID, err, tc.ExpectErr)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: validateRemoteVersion: %v", tc.ID, err)
		}
		if state.LastError != "" || state.BanScore != 0 {
			t.Fatalf("%s: unexpected state mutation: %+v", tc.ID, state)
		}
	}
}

func loadSharedRuntimeVectors(t *testing.T) sharedRuntimeVectors {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", "..", "p2p", "testdata", "runtime_vectors.json"))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	var out sharedRuntimeVectors
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("Unmarshal(%s): %v", path, err)
	}
	return out
}

func sharedVersionPayload(t *testing.T, vectors sharedRuntimeVectors) node.VersionPayloadV1 {
	t.Helper()
	return node.VersionPayloadV1{
		ProtocolVersion:   vectors.VersionPayloadV1.ProtocolVersion,
		TxRelay:           vectors.VersionPayloadV1.TxRelay,
		PrunedBelowHeight: vectors.VersionPayloadV1.PrunedBelowHeight,
		DaMempoolSize:     vectors.VersionPayloadV1.DaMempoolSize,
		ChainID:           mustDecodeHex32(t, vectors.VersionPayloadV1.ChainIDHex),
		GenesisHash:       mustDecodeHex32(t, vectors.VersionPayloadV1.GenesisHashHex),
		BestHeight:        vectors.VersionPayloadV1.BestHeight,
	}
}

func mustDecodeHex(t *testing.T, raw string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		t.Fatalf("DecodeString(%q): %v", raw, err)
	}
	return decoded
}

func mustDecodeHex32(t *testing.T, raw string) [32]byte {
	t.Helper()
	decoded := mustDecodeHex(t, raw)
	if len(decoded) != 32 {
		t.Fatalf("hex32 len=%d want 32", len(decoded))
	}
	var out [32]byte
	copy(out[:], decoded)
	return out
}
