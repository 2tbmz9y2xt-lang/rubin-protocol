package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

const (
	txctxGovernanceErrActivationBelowTransition = "ACTIVATION_HEIGHT_BELOW_TRANSITION_HEIGHT"
	txctxGovernanceErrArtifactHashMismatch      = "ARTIFACT_HASH_MISMATCH"
	txctxGovernanceErrDuplicateAllowedSuiteID   = "DUPLICATE_ALLOWED_SUITE_ID"
	txctxGovernanceErrDuplicateChecklist        = "DUPLICATE_DEPENDENCY_CHECKLIST"
	txctxGovernanceErrDuplicateProfileExtID     = "DUPLICATE_PROFILE_EXT_ID"
	txctxGovernanceErrEmptyAllowedSuiteIDs      = "EMPTY_ALLOWED_SUITE_IDS"
	txctxGovernanceErrInvalidChecklist          = "INVALID_DEPENDENCY_CHECKLIST"
	txctxGovernanceErrMempoolGateRequired       = "MEMPOOL_TXCTX_CONFIRMATION_REQUIRED"
	txctxGovernanceErrMissingChecklist          = "MISSING_DEPENDENCY_CHECKLIST"
)

func runTxctxGovernanceVector(req Request, profiles []CoreExtProfileJSON) Response {
	diag := map[string]any{
		"profile_count":         len(profiles),
		"txctx_profile_count":   txctxEnabledProfileCount(profiles),
		"artifact_hash_checked": strings.TrimSpace(req.ExpectedArtifactHash) != "",
	}
	if derived, ok := deriveTxctxTransitionHeight(profiles); ok {
		diag["derived_transition_height"] = derived
	}
	if req.TransitionHeight != nil {
		diag["transition_height"] = *req.TransitionHeight
	}
	if err := validateArtifactHash(req.ArtifactHex, req.ExpectedArtifactHash); err != nil {
		return Response{Ok: false, Err: err.Error(), Diagnostics: diag}
	}
	if err := validateTxctxGovernanceProfiles(
		profiles,
		req.TransitionHeight,
		req.DependencyChecklists,
		req.MempoolTxctxConfirmed,
	); err != nil {
		return Response{Ok: false, Err: err.Error(), Diagnostics: diag}
	}
	return Response{Ok: true, Diagnostics: diag}
}

func validateArtifactHash(artifactHex string, expectedHashHex string) error {
	if strings.TrimSpace(expectedHashHex) == "" {
		return nil
	}
	artifactHex = normalizeGovernanceHex(artifactHex)
	if artifactHex == "" {
		return fmt.Errorf("bad artifact_hex")
	}
	artifactBytes, err := hex.DecodeString(artifactHex)
	if err != nil {
		return fmt.Errorf("bad artifact_hex")
	}
	expectedHashHex = normalizeGovernanceHex(expectedHashHex)
	expectedHash, err := hex.DecodeString(expectedHashHex)
	if err != nil || len(expectedHash) != sha256.Size {
		return fmt.Errorf("bad expected_artifact_hash_hex")
	}
	actualHash := sha256.Sum256(artifactBytes)
	if !equalBytes(actualHash[:], expectedHash) {
		return fmt.Errorf(txctxGovernanceErrArtifactHashMismatch)
	}
	return nil
}

func validateTxctxGovernanceProfiles(
	profiles []CoreExtProfileJSON,
	transitionHeight *uint64,
	checklists []TxctxDependencyChecklistJSON,
	mempoolConfirmed *bool,
) error {
	seenExtIDs := make(map[uint16]struct{}, len(profiles))
	requiredChecklistExtIDs := make(map[uint16]struct{}, len(profiles))
	checklistsByExtID := make(map[uint16]TxctxDependencyChecklistJSON, len(checklists))
	for _, checklist := range checklists {
		extID, ok := parseChecklistExtID(checklist.ProfileExtID)
		if !ok {
			return fmt.Errorf(txctxGovernanceErrInvalidChecklist)
		}
		if _, exists := checklistsByExtID[extID]; exists {
			return fmt.Errorf(txctxGovernanceErrDuplicateChecklist)
		}
		checklistsByExtID[extID] = checklist
	}
	for _, profile := range profiles {
		if _, exists := seenExtIDs[profile.ExtID]; exists {
			return fmt.Errorf(txctxGovernanceErrDuplicateProfileExtID)
		}
		seenExtIDs[profile.ExtID] = struct{}{}
		if len(profile.AllowedSuiteIDs) == 0 {
			return fmt.Errorf(txctxGovernanceErrEmptyAllowedSuiteIDs)
		}
		if hasDuplicateSuiteID(profile.AllowedSuiteIDs) {
			return fmt.Errorf(txctxGovernanceErrDuplicateAllowedSuiteID)
		}
		if profile.TxContextEnabled != 0 && profile.TxContextEnabled != 1 {
			return fmt.Errorf(txctxGovernanceErrInvalidChecklist)
		}
		if profile.TxContextEnabled == 0 {
			continue
		}
		requiredChecklistExtIDs[profile.ExtID] = struct{}{}
		if transitionHeight != nil && profile.ActivationHeight < *transitionHeight {
			return fmt.Errorf(txctxGovernanceErrActivationBelowTransition)
		}
		checklist, ok := checklistsByExtID[profile.ExtID]
		if !ok {
			return fmt.Errorf(txctxGovernanceErrMissingChecklist)
		}
		if err := validateDependencyChecklist(checklist, profile, mempoolConfirmed); err != nil {
			return err
		}
	}
	if len(checklistsByExtID) != len(requiredChecklistExtIDs) {
		return fmt.Errorf(txctxGovernanceErrInvalidChecklist)
	}
	for extID := range checklistsByExtID {
		if _, ok := requiredChecklistExtIDs[extID]; !ok {
			return fmt.Errorf(txctxGovernanceErrInvalidChecklist)
		}
	}
	return nil
}

func validateDependencyChecklist(
	checklist TxctxDependencyChecklistJSON,
	profile CoreExtProfileJSON,
	mempoolConfirmed *bool,
) error {
	if strings.TrimSpace(checklist.SpecDocument) == "" ||
		len(checklist.SighashTypesRequired) == 0 ||
		strings.TrimSpace(checklist.VerifierSideEffects) == "" ||
		strings.TrimSpace(checklist.Reviewer) == "" {
		return fmt.Errorf(txctxGovernanceErrInvalidChecklist)
	}
	if !strings.EqualFold(strings.TrimSpace(checklist.VerifierSideEffects), "none") {
		return fmt.Errorf(txctxGovernanceErrInvalidChecklist)
	}
	if checklist.MaxExtPayloadBytes < 0 || profile.MaxExtPayloadBytes < 0 {
		return fmt.Errorf(txctxGovernanceErrInvalidChecklist)
	}
	if checklist.MaxExtPayloadBytes != profile.MaxExtPayloadBytes {
		return fmt.Errorf(txctxGovernanceErrInvalidChecklist)
	}
	if profile.MaxExtPayloadBytes > 256 && (mempoolConfirmed == nil || !*mempoolConfirmed) {
		return fmt.Errorf(txctxGovernanceErrMempoolGateRequired)
	}
	return nil
}

func normalizeGovernanceHex(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(strings.TrimPrefix(raw, "0x"), "0X")
	return strings.ToLower(raw)
}

func equalBytes(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func parseChecklistExtID(raw string) (uint16, bool) {
	raw = strings.TrimSpace(raw)
	if len(raw) != 6 || !strings.HasPrefix(raw, "0x") {
		return 0, false
	}
	hexRaw := raw[2:]
	for _, ch := range hexRaw {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return 0, false
		}
	}
	value, err := strconv.ParseUint(hexRaw, 16, 16)
	if err != nil {
		return 0, false
	}
	return uint16(value), true
}

func hasDuplicateSuiteID(ids []uint8) bool {
	seen := make(map[uint8]struct{}, len(ids))
	for _, suiteID := range ids {
		if _, exists := seen[suiteID]; exists {
			return true
		}
		seen[suiteID] = struct{}{}
	}
	return false
}

func deriveTxctxTransitionHeight(profiles []CoreExtProfileJSON) (uint64, bool) {
	var min uint64
	first := true
	for _, profile := range profiles {
		if profile.TxContextEnabled == 0 {
			continue
		}
		if first || profile.ActivationHeight < min {
			min = profile.ActivationHeight
			first = false
		}
	}
	if first {
		return 0, false
	}
	return min, true
}

func txctxEnabledProfileCount(profiles []CoreExtProfileJSON) int {
	count := 0
	for _, profile := range profiles {
		if profile.TxContextEnabled != 0 {
			count++
		}
	}
	return count
}
