package consensus

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func decodeFeatureWindowCounts(raw []byte) []uint32 {
	count := len(raw) / 4
	if count > 32 {
		count = 32
	}
	out := make([]uint32, 0, count)
	for i := 0; i < count; i++ {
		start := i * 4
		out = append(out, binary.LittleEndian.Uint32(raw[start:start+4]))
	}
	return out
}

func decodeFlagDayDeployments(raw []byte) []FlagDayDeployment {
	const stride = 10
	count := len(raw) / stride
	if count > 8 {
		count = 8
	}
	out := make([]FlagDayDeployment, 0, count)
	for i := 0; i < count; i++ {
		chunk := raw[i*stride : (i+1)*stride]
		name := fmt.Sprintf("d%d", i)
		if chunk[0]&0x01 != 0 {
			name = ""
		}
		activationHeight := binary.LittleEndian.Uint64(chunk[2:10])
		var bit *uint8
		if chunk[0]&0x02 != 0 {
			b := chunk[1]
			bit = &b
		}
		out = append(out, FlagDayDeployment{
			Name:             name,
			ActivationHeight: activationHeight,
			Bit:              bit,
		})
	}
	return out
}

func FuzzFeatureBitStateAtHeightFromWindowCounts(f *testing.F) {
	f.Add("fb", uint8(1), uint64(0), uint64(SIGNAL_WINDOW*4), uint64(0), []byte{})
	f.Add("fb", uint8(1), uint64(0), uint64(SIGNAL_WINDOW), uint64(SIGNAL_WINDOW), []byte{0x17, 0x07, 0x00, 0x00})
	f.Add("", uint8(1), uint64(0), uint64(1), uint64(0), []byte{})
	f.Add("fb", uint8(32), uint64(0), uint64(1), uint64(0), []byte{})

	f.Fuzz(func(t *testing.T, name string, bit uint8, startHeight uint64, timeoutHeight uint64, height uint64, rawCounts []byte) {
		if len(name) > 32 || len(rawCounts) > 128 {
			return
		}

		deployment := FeatureBitDeployment{
			Name:          name,
			Bit:           bit,
			StartHeight:   startHeight,
			TimeoutHeight: timeoutHeight,
		}
		counts := decodeFeatureWindowCounts(rawCounts)

		ev1, err1 := FeatureBitStateAtHeightFromWindowCounts(deployment, height, counts)
		ev2, err2 := FeatureBitStateAtHeightFromWindowCounts(deployment, height, counts)

		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("non-deterministic error presence: %v vs %v", err1, err2)
		}
		if err1 != nil {
			if err1.Error() != err2.Error() {
				t.Fatalf("non-deterministic error text: %q vs %q", err1, err2)
			}
			return
		}
		if ev1 != ev2 {
			t.Fatalf("non-deterministic eval: %+v vs %+v", ev1, ev2)
		}

		expectedBoundary := height - (height % SIGNAL_WINDOW)
		if ev1.BoundaryHeight != expectedBoundary {
			t.Fatalf("boundary mismatch: got=%d want=%d", ev1.BoundaryHeight, expectedBoundary)
		}
		if expectedBoundary < SIGNAL_WINDOW && ev1.PrevWindowSignalCnt != 0 {
			t.Fatalf("prev window count should be zero below first boundary, got=%d", ev1.PrevWindowSignalCnt)
		}
		if ev1.SignalWindow != SIGNAL_WINDOW || ev1.SignalThreshold != SIGNAL_THRESHOLD {
			t.Fatalf("unexpected signal constants: %+v", ev1)
		}
	})
}

func FuzzFlagDayHelpers(f *testing.F) {
	f.Add("flag", uint64(100), uint64(99), true, uint8(7), []byte{})
	f.Add("flag", uint64(100), uint64(100), true, uint8(7), []byte{0x02, 0x07, 0xE8, 0x03, 0, 0, 0, 0, 0, 0})
	f.Add("", uint64(0), uint64(0), false, uint8(0), []byte{})
	f.Add("flag", uint64(0), uint64(0), true, uint8(32), []byte{})

	f.Fuzz(func(t *testing.T, name string, activationHeight uint64, height uint64, hasBit bool, bitValue uint8, rawDeployments []byte) {
		if len(name) > 32 || len(rawDeployments) > 160 {
			return
		}

		var bit *uint8
		if hasBit {
			b := bitValue
			bit = &b
		}
		deployment := FlagDayDeployment{
			Name:             name,
			ActivationHeight: activationHeight,
			Bit:              bit,
		}

		active1, err1 := FlagDayActiveAtHeight(deployment, height)
		active2, err2 := FlagDayActiveAtHeight(deployment, height)

		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("non-deterministic error presence: %v vs %v", err1, err2)
		}
		if err1 == nil && active1 != active2 {
			t.Fatalf("non-deterministic active result: %v vs %v", active1, active2)
		}
		if err1 != nil && err1.Error() != err2.Error() {
			t.Fatalf("non-deterministic error text: %q vs %q", err1, err2)
		}

		deployments := decodeFlagDayDeployments(rawDeployments)
		warnings1 := ValidateDeploymentBitUniqueness(deployments)
		warnings2 := ValidateDeploymentBitUniqueness(deployments)
		if !bytes.Equal([]byte(stringsJoin(warnings1)), []byte(stringsJoin(warnings2))) {
			t.Fatalf("non-deterministic warnings: %v vs %v", warnings1, warnings2)
		}
	})
}

func FuzzGovernanceReplayToken(f *testing.F) {
	f.Add(uint16(7), uint64(1), uint64(100), uint64(50), uint16(7), uint64(100), uint64(1), []byte{})
	f.Add(uint16(7), uint64(1), uint64(100), uint64(1), uint16(7), uint64(101), uint64(1), make([]byte, 10))
	f.Add(uint16(7), uint64(0), uint64(100), uint64(25), uint16(7), uint64(110), uint64(0), bytes.Repeat([]byte{0xAA}, governanceReplayTokenBytes))

	f.Fuzz(func(t *testing.T, extID uint16, nonce uint64, issuedAtHeight uint64, validityWindow uint64, expectedExtID uint16, currentHeight uint64, expectedNonce uint64, raw []byte) {
		if len(raw) > 256 {
			return
		}

		token := IssueGovernanceReplayToken(extID, nonce, issuedAtHeight, validityWindow)
		encoded := token.ToBytes()
		if len(encoded) != governanceReplayTokenBytes {
			t.Fatalf("encoded len=%d", len(encoded))
		}
		decoded, err := GovernanceReplayTokenFromBytes(encoded)
		if err != nil {
			t.Fatalf("roundtrip decode: %v", err)
		}
		if decoded != token {
			t.Fatalf("roundtrip mismatch: got=%+v want=%+v", decoded, token)
		}

		err1 := token.Validate(expectedExtID, currentHeight, expectedNonce)
		err2 := decoded.Validate(expectedExtID, currentHeight, expectedNonce)
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("validation mismatch: %v vs %v", err1, err2)
		}
		if err1 != nil && err1.Error() != err2.Error() {
			t.Fatalf("validation text mismatch: %q vs %q", err1, err2)
		}

		decodedRaw, rawErr := GovernanceReplayTokenFromBytes(raw)
		if rawErr == nil {
			reencoded := decodedRaw.ToBytes()
			if !bytes.Equal(reencoded, raw) {
				t.Fatalf("non-canonical roundtrip for raw token")
			}
		}
	})
}

func stringsJoin(items []string) string {
	if len(items) == 0 {
		return ""
	}
	out := items[0]
	for _, item := range items[1:] {
		out += "\n" + item
	}
	return out
}
