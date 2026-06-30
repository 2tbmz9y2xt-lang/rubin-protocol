package consensus

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

const (
	liveBindingPolicyVersion                        = 1
	liveBindingPolicyErrStem                        = "live_binding_policy"
	liveBindingPolicyRuntimeOpenSSLDigest32         = "openssl_digest32_v1"
	CoreExtBindingNameVerifySigExtOpenSSLDigest32V1 = "verify_sig_ext_openssl_digest32_v1"
)

// Derived runtime copy of conformance/fixtures/protocol/live_binding_policy_v1.json.
// Go embed cannot read a parent-path artifact directly, so tests keep this
// JSON-equivalent to the canonical protocol fixture.
//
//go:embed live_binding_policy_v1_embedded.json
var embeddedLiveBindingPolicyV1 []byte

type liveBindingPolicyManifest struct {
	Version uint64                   `json:"version"`
	Entries []liveBindingPolicyEntry `json:"entries"`
}

type liveBindingPolicyManifestJSON struct {
	Version *uint64                       `json:"version"`
	Entries *[]liveBindingPolicyEntryJSON `json:"entries"`
}

type liveBindingPolicyEntry struct {
	AlgName         string `json:"alg_name"`
	PubkeyLen       int    `json:"pubkey_len"`
	SigLen          int    `json:"sig_len"`
	RuntimeBinding  string `json:"runtime_binding"`
	OpenSSLAlg      string `json:"openssl_alg"`
	LiveBindingName string `json:"live_binding_name"`
}

type liveBindingPolicyEntryJSON struct {
	AlgName         *string `json:"alg_name"`
	PubkeyLen       *int    `json:"pubkey_len"`
	SigLen          *int    `json:"sig_len"`
	RuntimeBinding  *string `json:"runtime_binding"`
	OpenSSLAlg      *string `json:"openssl_alg"`
	LiveBindingName *string `json:"live_binding_name"`
}

var (
	defaultLiveBindingPolicyOnce   sync.Once
	defaultLiveBindingPolicyCached *liveBindingPolicyManifest
	defaultLiveBindingPolicyErr    error
)

func liveBindingPolicyError(format string, args ...any) error {
	return fmt.Errorf(liveBindingPolicyErrStem+": "+format, args...)
}

type liveBindingPolicyRuntimeEntryNotFoundError struct {
	algName   string
	pubkeyLen int
	sigLen    int
}

func (e liveBindingPolicyRuntimeEntryNotFoundError) Error() string {
	return fmt.Sprintf(
		"%s: runtime tuple not found alg=%q pubkey_len=%d sig_len=%d",
		liveBindingPolicyErrStem,
		e.algName,
		e.pubkeyLen,
		e.sigLen,
	)
}

type liveBindingPolicyBindingNameEntryNotFoundError struct {
	binding string
}

func (e liveBindingPolicyBindingNameEntryNotFoundError) Error() string {
	return fmt.Sprintf(
		"%s: live_binding_name not found %q",
		liveBindingPolicyErrStem,
		e.binding,
	)
}

func liveBindingPolicyRuntimeTupleKey(algName string, pubkeyLen int, sigLen int) string {
	return fmt.Sprintf("%s|%d|%d", algName, pubkeyLen, sigLen)
}

type liveBindingPolicyJSONScope struct {
	object       bool
	keys         map[string]struct{}
	expectingKey bool
}

func rejectDuplicateLiveBindingPolicyJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	stack := make([]liveBindingPolicyJSONScope, 0, 8)

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if err := handleLiveBindingPolicyJSONToken(&stack, token); err != nil {
			return err
		}
	}

	if len(stack) != 0 {
		return fmt.Errorf("incomplete JSON value")
	}
	return nil
}

func handleLiveBindingPolicyJSONToken(stack *[]liveBindingPolicyJSONScope, token json.Token) error {
	switch v := token.(type) {
	case json.Delim:
		return handleLiveBindingPolicyJSONDelim(stack, v)
	case string:
		return handleLiveBindingPolicyJSONString(stack, v)
	default:
		markLiveBindingPolicyJSONValueComplete(*stack)
		return nil
	}
}

func handleLiveBindingPolicyJSONDelim(stack *[]liveBindingPolicyJSONScope, delim json.Delim) error {
	switch delim {
	case '{':
		*stack = append(*stack, liveBindingPolicyJSONScope{
			object:       true,
			keys:         make(map[string]struct{}),
			expectingKey: true,
		})
	case '[':
		*stack = append(*stack, liveBindingPolicyJSONScope{})
	case '}':
		return closeLiveBindingPolicyJSONScope(stack, true)
	case ']':
		return closeLiveBindingPolicyJSONScope(stack, false)
	}
	return nil
}

func closeLiveBindingPolicyJSONScope(stack *[]liveBindingPolicyJSONScope, object bool) error {
	if len(*stack) == 0 || (*stack)[len(*stack)-1].object != object {
		if object {
			return fmt.Errorf("unexpected json object close")
		}
		return fmt.Errorf("unexpected json array close")
	}
	*stack = (*stack)[:len(*stack)-1]
	markLiveBindingPolicyJSONValueComplete(*stack)
	return nil
}

func handleLiveBindingPolicyJSONString(stack *[]liveBindingPolicyJSONScope, value string) error {
	if len(*stack) > 0 && (*stack)[len(*stack)-1].object && (*stack)[len(*stack)-1].expectingKey {
		scope := &(*stack)[len(*stack)-1]
		if _, ok := scope.keys[value]; ok {
			return fmt.Errorf("duplicate JSON key %q", value)
		}
		scope.keys[value] = struct{}{}
		scope.expectingKey = false
		return nil
	}
	markLiveBindingPolicyJSONValueComplete(*stack)
	return nil
}

func markLiveBindingPolicyJSONValueComplete(stack []liveBindingPolicyJSONScope) {
	if len(stack) == 0 {
		return
	}
	top := &stack[len(stack)-1]
	if top.object && !top.expectingKey {
		top.expectingKey = true
	}
}

func decodeSingleLiveBindingPolicyJSONValue(data []byte, dest any) error {
	if err := rejectDuplicateLiveBindingPolicyJSONKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dest); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON tokens")
		}
		return err
	}
	return nil
}

func (manifest liveBindingPolicyManifestJSON) materialize() (*liveBindingPolicyManifest, error) {
	if manifest.Version == nil {
		return nil, liveBindingPolicyError("version missing")
	}
	if manifest.Entries == nil || len(*manifest.Entries) == 0 {
		return nil, liveBindingPolicyError("entries missing")
	}
	entries := make([]liveBindingPolicyEntry, len(*manifest.Entries))
	for i, rawEntry := range *manifest.Entries {
		entry, err := rawEntry.materialize(i)
		if err != nil {
			return nil, err
		}
		entries[i] = entry
	}
	return &liveBindingPolicyManifest{
		Version: *manifest.Version,
		Entries: entries,
	}, nil
}

func (entry liveBindingPolicyEntryJSON) materialize(index int) (liveBindingPolicyEntry, error) {
	var (
		out liveBindingPolicyEntry
		err error
	)
	if out.AlgName, err = requiredLiveBindingPolicyEntryString(index, "alg_name", entry.AlgName); err != nil {
		return liveBindingPolicyEntry{}, err
	}
	if out.PubkeyLen, err = requiredLiveBindingPolicyEntryInt(index, "pubkey_len", entry.PubkeyLen); err != nil {
		return liveBindingPolicyEntry{}, err
	}
	if out.SigLen, err = requiredLiveBindingPolicyEntryInt(index, "sig_len", entry.SigLen); err != nil {
		return liveBindingPolicyEntry{}, err
	}
	if out.RuntimeBinding, err = requiredLiveBindingPolicyEntryString(index, "runtime_binding", entry.RuntimeBinding); err != nil {
		return liveBindingPolicyEntry{}, err
	}
	if out.OpenSSLAlg, err = requiredLiveBindingPolicyEntryString(index, "openssl_alg", entry.OpenSSLAlg); err != nil {
		return liveBindingPolicyEntry{}, err
	}
	if out.LiveBindingName, err = requiredLiveBindingPolicyEntryString(index, "live_binding_name", entry.LiveBindingName); err != nil {
		return liveBindingPolicyEntry{}, err
	}
	return out, nil
}

func requiredLiveBindingPolicyEntryString(index int, name string, value *string) (string, error) {
	if value == nil || *value == "" {
		return "", liveBindingPolicyError("entries[%d]: %s missing", index, name)
	}
	return *value, nil
}

func requiredLiveBindingPolicyEntryInt(index int, name string, value *int) (int, error) {
	if value == nil {
		return 0, liveBindingPolicyError("entries[%d]: %s missing", index, name)
	}
	return *value, nil
}

func loadLiveBindingPolicyFromJSON(raw []byte) (*liveBindingPolicyManifest, error) {
	var manifestJSON liveBindingPolicyManifestJSON
	if err := decodeSingleLiveBindingPolicyJSONValue(raw, &manifestJSON); err != nil {
		return nil, liveBindingPolicyError("parse embedded artifact: %w", err)
	}
	manifest, err := manifestJSON.materialize()
	if err != nil {
		return nil, err
	}
	if manifest.Version != liveBindingPolicyVersion {
		return nil, liveBindingPolicyError(
			"unsupported version %d (want %d)",
			manifest.Version,
			liveBindingPolicyVersion,
		)
	}
	if len(manifest.Entries) == 0 {
		return nil, liveBindingPolicyError("entries missing")
	}
	seenRuntimeTuples := make(map[string]struct{}, len(manifest.Entries))
	seenLiveBindings := make(map[string]struct{}, len(manifest.Entries))
	for i, entry := range manifest.Entries {
		if err := entry.validate(i, seenRuntimeTuples, seenLiveBindings); err != nil {
			return nil, err
		}
	}
	return manifest, nil
}

func (entry liveBindingPolicyEntry) validate(
	index int,
	seenRuntimeTuples map[string]struct{},
	seenLiveBindings map[string]struct{},
) error {
	if entry.AlgName == "" {
		return liveBindingPolicyError("entries[%d]: alg_name missing", index)
	}
	if entry.PubkeyLen <= 0 {
		return liveBindingPolicyError("entries[%d]: pubkey_len must be > 0", index)
	}
	if entry.SigLen <= 0 {
		return liveBindingPolicyError("entries[%d]: sig_len must be > 0", index)
	}
	if entry.RuntimeBinding == "" {
		return liveBindingPolicyError("entries[%d]: runtime_binding missing", index)
	}
	if entry.OpenSSLAlg == "" {
		return liveBindingPolicyError("entries[%d]: openssl_alg missing", index)
	}
	if entry.LiveBindingName == "" {
		return liveBindingPolicyError("entries[%d]: live_binding_name missing", index)
	}
	if _, ok := seenLiveBindings[entry.LiveBindingName]; ok {
		return liveBindingPolicyError(
			"entries[%d]: duplicate live_binding_name %q",
			index,
			entry.LiveBindingName,
		)
	}
	runtimeTupleKey := liveBindingPolicyRuntimeTupleKey(entry.AlgName, entry.PubkeyLen, entry.SigLen)
	if _, ok := seenRuntimeTuples[runtimeTupleKey]; ok {
		return liveBindingPolicyError(
			"entries[%d]: duplicate runtime tuple alg=%q pubkey_len=%d sig_len=%d",
			index,
			entry.AlgName,
			entry.PubkeyLen,
			entry.SigLen,
		)
	}
	switch entry.RuntimeBinding {
	case liveBindingPolicyRuntimeOpenSSLDigest32:
		if entry.AlgName != "ML-DSA-87" {
			return liveBindingPolicyError(
				"entries[%d]: runtime_binding %q requires alg_name %q",
				index,
				entry.RuntimeBinding,
				"ML-DSA-87",
			)
		}
		if entry.OpenSSLAlg != "ML-DSA-87" {
			return liveBindingPolicyError(
				"entries[%d]: runtime_binding %q requires openssl_alg %q",
				index,
				entry.RuntimeBinding,
				"ML-DSA-87",
			)
		}
		if entry.PubkeyLen != ML_DSA_87_PUBKEY_BYTES {
			return liveBindingPolicyError(
				"entries[%d]: runtime_binding %q requires pubkey_len %d",
				index,
				entry.RuntimeBinding,
				ML_DSA_87_PUBKEY_BYTES,
			)
		}
		if entry.SigLen != ML_DSA_87_SIG_BYTES {
			return liveBindingPolicyError(
				"entries[%d]: runtime_binding %q requires sig_len %d",
				index,
				entry.RuntimeBinding,
				ML_DSA_87_SIG_BYTES,
			)
		}
		if entry.LiveBindingName != CoreExtBindingNameVerifySigExtOpenSSLDigest32V1 {
			return liveBindingPolicyError(
				"entries[%d]: runtime_binding %q requires live_binding_name %q",
				index,
				entry.RuntimeBinding,
				CoreExtBindingNameVerifySigExtOpenSSLDigest32V1,
			)
		}
	default:
		return liveBindingPolicyError(
			"entries[%d]: unsupported runtime_binding %q",
			index,
			entry.RuntimeBinding,
		)
	}
	seenRuntimeTuples[runtimeTupleKey] = struct{}{}
	seenLiveBindings[entry.LiveBindingName] = struct{}{}
	return nil
}

func defaultLiveBindingPolicy() (*liveBindingPolicyManifest, error) {
	defaultLiveBindingPolicyOnce.Do(func() {
		defaultLiveBindingPolicyCached, defaultLiveBindingPolicyErr = loadLiveBindingPolicyFromJSON(embeddedLiveBindingPolicyV1)
	})
	return defaultLiveBindingPolicyCached, defaultLiveBindingPolicyErr
}

func liveBindingPolicyRuntimeEntry(
	algName string,
	pubkeyLen int,
	sigLen int,
) (liveBindingPolicyEntry, error) {
	manifest, err := defaultLiveBindingPolicy()
	if err != nil {
		return liveBindingPolicyEntry{}, err
	}
	for i := range manifest.Entries {
		entry := &manifest.Entries[i]
		if entry.AlgName == algName &&
			entry.PubkeyLen == pubkeyLen &&
			entry.SigLen == sigLen {
			return *entry, nil
		}
	}
	return liveBindingPolicyEntry{}, liveBindingPolicyRuntimeEntryNotFoundError{
		algName:   algName,
		pubkeyLen: pubkeyLen,
		sigLen:    sigLen,
	}
}

func liveBindingPolicyBindingNameEntry(binding string) (liveBindingPolicyEntry, error) {
	manifest, err := defaultLiveBindingPolicy()
	if err != nil {
		return liveBindingPolicyEntry{}, err
	}
	for i := range manifest.Entries {
		entry := &manifest.Entries[i]
		if entry.LiveBindingName == binding {
			return *entry, nil
		}
	}
	return liveBindingPolicyEntry{}, liveBindingPolicyBindingNameEntryNotFoundError{
		binding: binding,
	}
}
