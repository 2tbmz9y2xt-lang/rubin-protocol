package node

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const mineAddressKeyIDBytes = 32

func defaultMineAddress() []byte {
	out := make([]byte, consensus.MAX_P2PK_COVENANT_DATA)
	out[0] = consensus.SUITE_ID_ML_DSA_87
	return out
}

func normalizeMineAddress(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return defaultMineAddress(), nil
	}
	if err := validateMineAddress(raw); err != nil {
		return nil, err
	}
	return append([]byte(nil), raw...), nil
}

func validateMineAddress(raw []byte) error {
	if len(raw) != consensus.MAX_P2PK_COVENANT_DATA {
		return fmt.Errorf("mine_address: expected %d bytes, got %d", consensus.MAX_P2PK_COVENANT_DATA, len(raw))
	}
	if raw[0] != consensus.SUITE_ID_ML_DSA_87 {
		return fmt.Errorf("mine_address: unsupported suite_id 0x%02x", raw[0])
	}
	return nil
}

func ParseMineAddress(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, nil
	}
	if strings.HasPrefix(trimmed, "0x") || strings.HasPrefix(trimmed, "0X") {
		trimmed = trimmed[2:]
	}

	if len(trimmed)%2 != 0 {
		return nil, fmt.Errorf("mine_address: odd-length hex")
	}
	raw, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("mine_address: %w", err)
	}
	switch len(raw) {
	case mineAddressKeyIDBytes:
		out := make([]byte, 0, consensus.MAX_P2PK_COVENANT_DATA)
		out = append(out, consensus.SUITE_ID_ML_DSA_87)
		out = append(out, raw...)
		return out, nil
	case consensus.MAX_P2PK_COVENANT_DATA:
		if err := validateMineAddress(raw); err != nil {
			return nil, err
		}
		return append([]byte(nil), raw...), nil
	default:
		return nil, fmt.Errorf(
			"mine_address: expected %d-byte key_id or %d-byte covenant_data, got %d bytes",
			mineAddressKeyIDBytes,
			consensus.MAX_P2PK_COVENANT_DATA,
			len(raw),
		)
	}
}
