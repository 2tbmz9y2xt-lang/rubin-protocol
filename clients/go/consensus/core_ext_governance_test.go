package consensus

import (
	"strings"
	"testing"
)

func TestGovernanceReplayTokenIssueAndValidate(t *testing.T) {
	token := IssueGovernanceReplayToken(7, 1, 100, 50)
	if err := token.Validate(7, 100, 1); err != nil {
		t.Fatalf("validate at issued_at: %v", err)
	}
	if err := token.Validate(7, 149, 1); err != nil {
		t.Fatalf("validate before expiry: %v", err)
	}
}

func TestGovernanceReplayTokenRejectsWrongNonce(t *testing.T) {
	token := IssueGovernanceReplayToken(7, 1, 100, 50)
	err := token.Validate(7, 120, 2)
	if err == nil || !strings.Contains(err.Error(), "nonce mismatch") {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestGovernanceReplayTokenRejectsWrongExtID(t *testing.T) {
	token := IssueGovernanceReplayToken(7, 1, 100, 50)
	err := token.Validate(9, 120, 1)
	if err == nil || !strings.Contains(err.Error(), "ext_id mismatch") {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestGovernanceReplayTokenRejectsBeforeIssued(t *testing.T) {
	token := IssueGovernanceReplayToken(7, 1, 100, 50)
	err := token.Validate(7, 99, 1)
	if err == nil || !strings.Contains(err.Error(), "not yet valid") {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestGovernanceReplayTokenRejectsExpired(t *testing.T) {
	token := IssueGovernanceReplayToken(7, 1, 100, 50)
	err := token.Validate(7, 150, 1)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestGovernanceReplayTokenBoundaryAtExpiry(t *testing.T) {
	token := IssueGovernanceReplayToken(7, 1, 100, 1)
	if err := token.Validate(7, 100, 1); err != nil {
		t.Fatalf("height=100 should be valid: %v", err)
	}
	err := token.Validate(7, 101, 1)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestGovernanceReplayTokenRoundtripBytes(t *testing.T) {
	token := IssueGovernanceReplayToken(42, 7, 1000, 500)
	bytes := token.ToBytes()
	if len(bytes) != governanceReplayTokenBytes {
		t.Fatalf("bytes len=%d", len(bytes))
	}
	recovered, err := GovernanceReplayTokenFromBytes(bytes)
	if err != nil {
		t.Fatalf("from bytes: %v", err)
	}
	if recovered != token {
		t.Fatalf("roundtrip mismatch: got=%+v want=%+v", recovered, token)
	}
}

func TestGovernanceReplayTokenFromBytesRejectsWrongLen(t *testing.T) {
	_, err := GovernanceReplayTokenFromBytes(make([]byte, 10))
	if err == nil || !strings.Contains(err.Error(), "expected 26 bytes") {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestGovernanceReplayTokenOverflowSafe(t *testing.T) {
	token := IssueGovernanceReplayToken(1, 1, ^uint64(0)-10, ^uint64(0))
	if err := token.Validate(1, ^uint64(0)-5, 1); err != nil {
		t.Fatalf("validate before saturated expiry: %v", err)
	}
	err := token.Validate(1, ^uint64(0), 1)
	if err == nil || !strings.Contains(err.Error(), "expired: expiry=18446744073709551615") {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestGovernanceReplayTokenNonceZeroAllowed(t *testing.T) {
	token := IssueGovernanceReplayToken(7, 0, 100, 25)
	if err := token.Validate(7, 110, 0); err != nil {
		t.Fatalf("nonce zero should remain valid: %v", err)
	}
}
