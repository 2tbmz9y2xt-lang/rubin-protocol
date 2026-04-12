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
	liveBindingPolicyVersion                = 1
	liveBindingPolicyErrStem                = "live_binding_policy"
	liveBindingPolicyRuntimeOpenSSLDigest32 = "openssl_digest32_v1"
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
	AlgName                string `json:"alg_name"`
	PubkeyLen              int    `json:"pubkey_len"`
	SigLen                 int    `json:"sig_len"`
	RuntimeBinding         string `json:"runtime_binding"`
	OpenSSLAlg             string `json:"openssl_alg"`
	CoreExtLiveBindingName string `json:"core_ext_live_binding_name"`
}

type liveBindingPolicyEntryJSON struct {
	AlgName                *string `json:"alg_name"`
	PubkeyLen              *int    `json:"pubkey_len"`
	SigLen                 *int    `json:"sig_len"`
	RuntimeBinding         *string `json:"runtime_binding"`
	OpenSSLAlg             *string `json:"openssl_alg"`
	CoreExtLiveBindingName *string `json:"core_ext_live_binding_name"`
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

type liveBindingPolicyCoreExtEntryNotFoundError struct {
	binding string
}

func (e liveBindingPolicyCoreExtEntryNotFoundError) Error() string {
	return fmt.Sprintf(
		"%s: core_ext_live_binding_name not found %q",
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
	markValueComplete := func() {
		if len(stack) == 0 {
			return
		}
		top := &stack[len(stack)-1]
		if top.object && !top.expectingKey {
			top.expectingKey = true
		}
	}

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch v := token.(type) {
		case json.Delim:
			switch v {
			case '{':
				stack = append(stack, liveBindingPolicyJSONScope{
					object:       true,
					keys:         make(map[string]struct{}),
					expectingKey: true,
				})
			case '[':
				stack = append(stack, liveBindingPolicyJSONScope{})
			case '}':
				if len(stack) == 0 || !stack[len(stack)-1].object {
					return fmt.Errorf("unexpected json object close")
				}
				stack = stack[:len(stack)-1]
				markValueComplete()
			case ']':
				if len(stack) == 0 || stack[len(stack)-1].object {
					return fmt.Errorf("unexpected json array close")
				}
				stack = stack[:len(stack)-1]
				markValueComplete()
			}
		case string:
			if len(stack) > 0 && stack[len(stack)-1].object && stack[len(stack)-1].expectingKey {
				scope := &stack[len(stack)-1]
				if _, ok := scope.keys[v]; ok {
					return fmt.Errorf("duplicate JSON key %q", v)
				}
				scope.keys[v] = struct{}{}
				scope.expectingKey = false
				continue
			}
			markValueComplete()
		default:
			markValueComplete()
		}
	}

	if len(stack) != 0 {
		return fmt.Errorf("incomplete JSON value")
	}
	return nil
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
	if entry.AlgName == nil || *entry.AlgName == "" {
		return liveBindingPolicyEntry{}, liveBindingPolicyError("entries[%d]: alg_name missing", index)
	}
	if entry.PubkeyLen == nil {
		return liveBindingPolicyEntry{}, liveBindingPolicyError("entries[%d]: pubkey_len missing", index)
	}
	if entry.SigLen == nil {
		return liveBindingPolicyEntry{}, liveBindingPolicyError("entries[%d]: sig_len missing", index)
	}
	if entry.RuntimeBinding == nil {
		return liveBindingPolicyEntry{}, liveBindingPolicyError("entries[%d]: runtime_binding missing", index)
	}
	if entry.OpenSSLAlg == nil || *entry.OpenSSLAlg == "" {
		return liveBindingPolicyEntry{}, liveBindingPolicyError("entries[%d]: openssl_alg missing", index)
	}
	if entry.CoreExtLiveBindingName == nil || *entry.CoreExtLiveBindingName == "" {
		return liveBindingPolicyEntry{}, liveBindingPolicyError("entries[%d]: core_ext_live_binding_name missing", index)
	}
	return liveBindingPolicyEntry{
		AlgName:                *entry.AlgName,
		PubkeyLen:              *entry.PubkeyLen,
		SigLen:                 *entry.SigLen,
		RuntimeBinding:         *entry.RuntimeBinding,
		OpenSSLAlg:             *entry.OpenSSLAlg,
		CoreExtLiveBindingName: *entry.CoreExtLiveBindingName,
	}, nil
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
	seenCoreExtBindings := make(map[string]struct{}, len(manifest.Entries))
	for i, entry := range manifest.Entries {
		if err := entry.validate(i, seenRuntimeTuples, seenCoreExtBindings); err != nil {
			return nil, err
		}
	}
	return manifest, nil
}

func (entry liveBindingPolicyEntry) validate(
	index int,
	seenRuntimeTuples map[string]struct{},
	seenCoreExtBindings map[string]struct{},
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
	if entry.OpenSSLAlg == "" {
		return liveBindingPolicyError("entries[%d]: openssl_alg missing", index)
	}
	if entry.CoreExtLiveBindingName == "" {
		return liveBindingPolicyError("entries[%d]: core_ext_live_binding_name missing", index)
	}
	if _, ok := seenCoreExtBindings[entry.CoreExtLiveBindingName]; ok {
		return liveBindingPolicyError(
			"entries[%d]: duplicate core_ext_live_binding_name %q",
			index,
			entry.CoreExtLiveBindingName,
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
		if entry.CoreExtLiveBindingName != CoreExtBindingNameVerifySigExtOpenSSLDigest32V1 {
			return liveBindingPolicyError(
				"entries[%d]: runtime_binding %q requires core_ext_live_binding_name %q",
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
	seenCoreExtBindings[entry.CoreExtLiveBindingName] = struct{}{}
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

func liveBindingPolicyCoreExtEntry(binding string) (liveBindingPolicyEntry, error) {
	manifest, err := defaultLiveBindingPolicy()
	if err != nil {
		return liveBindingPolicyEntry{}, err
	}
	for i := range manifest.Entries {
		entry := &manifest.Entries[i]
		if entry.CoreExtLiveBindingName == binding {
			return *entry, nil
		}
	}
	return liveBindingPolicyEntry{}, liveBindingPolicyCoreExtEntryNotFoundError{
		binding: binding,
	}
}
