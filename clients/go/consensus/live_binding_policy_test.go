package consensus

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func liveBindingPolicyRepoPath(parts ...string) string {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	segments := append([]string{filepath.Dir(currentFile), "..", "..", ".."}, parts...)
	return filepath.Clean(filepath.Join(segments...))
}

func TestEmbeddedLiveBindingPolicyMatchesCanonicalFixture(t *testing.T) {
	path := liveBindingPolicyRepoPath(
		"conformance",
		"fixtures",
		"protocol",
		"live_binding_policy_v1.json",
	)
	if path == "" {
		t.Fatal("runtime.Caller failed")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	if !bytes.Equal(raw, embeddedLiveBindingPolicyV1) {
		t.Fatal("embedded live binding policy drifted from canonical fixture")
	}
}

func TestLoadLiveBindingPolicyAcceptsEmbeddedManifest(t *testing.T) {
	manifest, err := loadLiveBindingPolicyFromJSON(embeddedLiveBindingPolicyV1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if manifest.Version != liveBindingPolicyVersion {
		t.Fatalf("version=%d, want %d", manifest.Version, liveBindingPolicyVersion)
	}
	if len(manifest.Entries) != 1 {
		t.Fatalf("entries=%d, want 1", len(manifest.Entries))
	}
	entry := manifest.Entries[0]
	if entry.AlgName != "ML-DSA-87" {
		t.Fatalf("alg_name=%q, want %q", entry.AlgName, "ML-DSA-87")
	}
	if entry.CoreExtLiveBindingName != CoreExtBindingNameVerifySigExtOpenSSLDigest32V1 {
		t.Fatalf("core_ext_live_binding_name=%q, want %q", entry.CoreExtLiveBindingName, CoreExtBindingNameVerifySigExtOpenSSLDigest32V1)
	}
}

func TestLoadLiveBindingPolicyRejectsUnsupportedVersion(t *testing.T) {
	_, err := loadLiveBindingPolicyFromJSON([]byte(`{
		"version": 2,
		"entries": [{
			"alg_name": "ML-DSA-87",
			"pubkey_len": 2592,
			"sig_len": 4627,
			"runtime_binding": "openssl_digest32_v1",
			"openssl_alg": "ML-DSA-87",
			"core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
		}]
	}`))
	if err == nil {
		t.Fatal("expected unsupported version rejection")
	}
	if got, want := err.Error(), "live_binding_policy: unsupported version 2 (want 1)"; got != want {
		t.Fatalf("err=%q, want %q", got, want)
	}
}

func TestLoadLiveBindingPolicyRejectsDuplicateCoreExtBindingName(t *testing.T) {
	_, err := loadLiveBindingPolicyFromJSON([]byte(`{
		"version": 1,
		"entries": [
			{
				"alg_name": "ML-DSA-87",
				"pubkey_len": 2592,
				"sig_len": 4627,
				"runtime_binding": "openssl_digest32_v1",
				"openssl_alg": "ML-DSA-87",
				"core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
			},
			{
				"alg_name": "ML-DSA-87",
				"pubkey_len": 2592,
				"sig_len": 4627,
				"runtime_binding": "openssl_digest32_v1",
				"openssl_alg": "ML-DSA-87",
				"core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
			}
		]
	}`))
	if err == nil {
		t.Fatal("expected duplicate core_ext binding rejection")
	}
	if got, want := err.Error(), `live_binding_policy: entries[1]: duplicate core_ext_live_binding_name "verify_sig_ext_openssl_digest32_v1"`; got != want {
		t.Fatalf("err=%q, want %q", got, want)
	}
}

func TestLoadLiveBindingPolicyRejectsDuplicateRuntimeTuple(t *testing.T) {
	_, err := loadLiveBindingPolicyFromJSON([]byte(`{
		"version": 1,
		"entries": [
			{
				"alg_name": "ML-DSA-87",
				"pubkey_len": 2592,
				"sig_len": 4627,
				"runtime_binding": "openssl_digest32_v1",
				"openssl_alg": "ML-DSA-87",
				"core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
			},
			{
				"alg_name": "ML-DSA-87",
				"pubkey_len": 2592,
				"sig_len": 4627,
				"runtime_binding": "openssl_digest32_v1",
				"openssl_alg": "ML-DSA-87",
				"core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1_alt"
			}
		]
	}`))
	if err == nil {
		t.Fatal("expected duplicate runtime tuple rejection")
	}
	if got, want := err.Error(), `live_binding_policy: entries[1]: duplicate runtime tuple alg="ML-DSA-87" pubkey_len=2592 sig_len=4627`; got != want {
		t.Fatalf("err=%q, want %q", got, want)
	}
}

func TestLoadLiveBindingPolicyRejectsMissingEntries(t *testing.T) {
	_, err := loadLiveBindingPolicyFromJSON([]byte(`{
		"version": 1,
		"entries": []
	}`))
	if err == nil {
		t.Fatal("expected entries missing rejection")
	}
	if got, want := err.Error(), "live_binding_policy: entries missing"; got != want {
		t.Fatalf("err=%q, want %q", got, want)
	}
}

func TestLoadLiveBindingPolicyRejectsMissingRequiredFields(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: `version`,
			raw: `{
				"entries": [{
					"alg_name": "ML-DSA-87",
					"pubkey_len": 2592,
					"sig_len": 4627,
					"runtime_binding": "openssl_digest32_v1",
					"openssl_alg": "ML-DSA-87",
					"core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
				}]
			}`,
			want: "live_binding_policy: version missing",
		},
		{
			name: `entry_pubkey_len`,
			raw: `{
				"version": 1,
				"entries": [{
					"alg_name": "ML-DSA-87",
					"sig_len": 4627,
					"runtime_binding": "openssl_digest32_v1",
					"openssl_alg": "ML-DSA-87",
					"core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
				}]
			}`,
			want: "live_binding_policy: entries[0]: pubkey_len missing",
		},
		{
			name: `entry_runtime_binding`,
			raw: `{
				"version": 1,
				"entries": [{
					"alg_name": "ML-DSA-87",
					"pubkey_len": 2592,
					"sig_len": 4627,
					"openssl_alg": "ML-DSA-87",
					"core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
				}]
			}`,
			want: "live_binding_policy: entries[0]: runtime_binding missing",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadLiveBindingPolicyFromJSON([]byte(tc.raw))
			if err == nil {
				t.Fatal("expected rejection")
			}
			if got := err.Error(); got != tc.want {
				t.Fatalf("err=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestLoadLiveBindingPolicyRejectsDuplicateJSONKeys(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "top_level_version",
			raw: `{
				"version": 1,
				"version": 2,
				"entries": [{
					"alg_name": "ML-DSA-87",
					"pubkey_len": 2592,
					"sig_len": 4627,
					"runtime_binding": "openssl_digest32_v1",
					"openssl_alg": "ML-DSA-87",
					"core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
				}]
			}`,
			want: `live_binding_policy: parse embedded artifact: duplicate JSON key "version"`,
		},
		{
			name: "entry_alg_name",
			raw: `{
				"version": 1,
				"entries": [{
					"alg_name": "ML-DSA-87",
					"alg_name": "FAKE",
					"pubkey_len": 2592,
					"sig_len": 4627,
					"runtime_binding": "openssl_digest32_v1",
					"openssl_alg": "ML-DSA-87",
					"core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
				}]
			}`,
			want: `live_binding_policy: parse embedded artifact: duplicate JSON key "alg_name"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadLiveBindingPolicyFromJSON([]byte(tc.raw))
			if err == nil {
				t.Fatal("expected rejection")
			}
			if got := err.Error(); got != tc.want {
				t.Fatalf("err=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestLoadLiveBindingPolicyRejectsFieldAndCanonicalMismatches(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "alg_name_missing",
			raw: `{
				"version": 1,
				"entries": [{
					"alg_name": "",
					"pubkey_len": 2592,
					"sig_len": 4627,
					"runtime_binding": "openssl_digest32_v1",
					"openssl_alg": "ML-DSA-87",
					"core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
				}]
			}`,
			want: "live_binding_policy: entries[0]: alg_name missing",
		},
		{
			name: "pubkey_len_zero",
			raw: `{
				"version": 1,
				"entries": [{
					"alg_name": "ML-DSA-87",
					"pubkey_len": 0,
					"sig_len": 4627,
					"runtime_binding": "openssl_digest32_v1",
					"openssl_alg": "ML-DSA-87",
					"core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
				}]
			}`,
			want: "live_binding_policy: entries[0]: pubkey_len must be > 0",
		},
		{
			name: "sig_len_zero",
			raw: `{
				"version": 1,
				"entries": [{
					"alg_name": "ML-DSA-87",
					"pubkey_len": 2592,
					"sig_len": 0,
					"runtime_binding": "openssl_digest32_v1",
					"openssl_alg": "ML-DSA-87",
					"core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
				}]
			}`,
			want: "live_binding_policy: entries[0]: sig_len must be > 0",
		},
		{
			name: "openssl_alg_missing",
			raw: `{
				"version": 1,
				"entries": [{
					"alg_name": "ML-DSA-87",
					"pubkey_len": 2592,
					"sig_len": 4627,
					"runtime_binding": "openssl_digest32_v1",
					"openssl_alg": "",
					"core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
				}]
			}`,
			want: "live_binding_policy: entries[0]: openssl_alg missing",
		},
		{
			name: "core_ext_binding_missing",
			raw: `{
				"version": 1,
				"entries": [{
					"alg_name": "ML-DSA-87",
					"pubkey_len": 2592,
					"sig_len": 4627,
					"runtime_binding": "openssl_digest32_v1",
					"openssl_alg": "ML-DSA-87",
					"core_ext_live_binding_name": ""
				}]
			}`,
			want: "live_binding_policy: entries[0]: core_ext_live_binding_name missing",
		},
		{
			name: "alg_name_mismatch",
			raw: `{
				"version": 1,
				"entries": [{
					"alg_name": "ML-DSA-65",
					"pubkey_len": 2592,
					"sig_len": 4627,
					"runtime_binding": "openssl_digest32_v1",
					"openssl_alg": "ML-DSA-87",
					"core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
				}]
			}`,
			want: `live_binding_policy: entries[0]: runtime_binding "openssl_digest32_v1" requires alg_name "ML-DSA-87"`,
		},
		{
			name: "openssl_alg_mismatch",
			raw: `{
				"version": 1,
				"entries": [{
					"alg_name": "ML-DSA-87",
					"pubkey_len": 2592,
					"sig_len": 4627,
					"runtime_binding": "openssl_digest32_v1",
					"openssl_alg": "ML-DSA-65",
					"core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
				}]
			}`,
			want: `live_binding_policy: entries[0]: runtime_binding "openssl_digest32_v1" requires openssl_alg "ML-DSA-87"`,
		},
		{
			name: "pubkey_len_mismatch",
			raw: `{
				"version": 1,
				"entries": [{
					"alg_name": "ML-DSA-87",
					"pubkey_len": 2591,
					"sig_len": 4627,
					"runtime_binding": "openssl_digest32_v1",
					"openssl_alg": "ML-DSA-87",
					"core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
				}]
			}`,
			want: `live_binding_policy: entries[0]: runtime_binding "openssl_digest32_v1" requires pubkey_len 2592`,
		},
		{
			name: "sig_len_mismatch",
			raw: `{
				"version": 1,
				"entries": [{
					"alg_name": "ML-DSA-87",
					"pubkey_len": 2592,
					"sig_len": 4626,
					"runtime_binding": "openssl_digest32_v1",
					"openssl_alg": "ML-DSA-87",
					"core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
				}]
			}`,
			want: `live_binding_policy: entries[0]: runtime_binding "openssl_digest32_v1" requires sig_len 4627`,
		},
		{
			name: "core_ext_binding_mismatch",
			raw: `{
				"version": 1,
				"entries": [{
					"alg_name": "ML-DSA-87",
					"pubkey_len": 2592,
					"sig_len": 4627,
					"runtime_binding": "openssl_digest32_v1",
					"openssl_alg": "ML-DSA-87",
					"core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1_alt"
				}]
			}`,
			want: `live_binding_policy: entries[0]: runtime_binding "openssl_digest32_v1" requires core_ext_live_binding_name "verify_sig_ext_openssl_digest32_v1"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadLiveBindingPolicyFromJSON([]byte(tc.raw))
			if err == nil {
				t.Fatal("expected rejection")
			}
			if got := err.Error(); got != tc.want {
				t.Fatalf("err=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestLiveBindingPolicyLookupHelpers(t *testing.T) {
	runtimeEntry, err := liveBindingPolicyRuntimeEntry("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)
	if err != nil {
		t.Fatalf("liveBindingPolicyRuntimeEntry(valid): %v", err)
	}
	if runtimeEntry.OpenSSLAlg != "ML-DSA-87" {
		t.Fatalf("openssl_alg=%q, want %q", runtimeEntry.OpenSSLAlg, "ML-DSA-87")
	}
	runtimeEntry.OpenSSLAlg = "MUTATED"
	runtimeEntryAgain, err := liveBindingPolicyRuntimeEntry("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)
	if err != nil {
		t.Fatalf("liveBindingPolicyRuntimeEntry(reload): %v", err)
	}
	if runtimeEntryAgain.OpenSSLAlg != "ML-DSA-87" {
		t.Fatalf("lookup must return copy, got openssl_alg=%q", runtimeEntryAgain.OpenSSLAlg)
	}
	runtimeMiss, err := liveBindingPolicyRuntimeEntry("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES-1)
	if err == nil {
		t.Fatal("expected runtime miss rejection")
	}
	if got, want := err.Error(), `live_binding_policy: runtime tuple not found alg="ML-DSA-87" pubkey_len=2592 sig_len=4626`; got != want {
		t.Fatalf("runtime miss err=%q, want %q (entry=%+v)", got, want, runtimeMiss)
	}

	coreExtEntry, err := liveBindingPolicyCoreExtEntry(CoreExtBindingNameVerifySigExtOpenSSLDigest32V1)
	if err != nil {
		t.Fatalf("liveBindingPolicyCoreExtEntry(valid): %v", err)
	}
	if coreExtEntry.RuntimeBinding != liveBindingPolicyRuntimeOpenSSLDigest32 {
		t.Fatalf("runtime_binding=%q, want %q", coreExtEntry.RuntimeBinding, liveBindingPolicyRuntimeOpenSSLDigest32)
	}
	coreExtEntry.RuntimeBinding = "MUTATED"
	coreExtEntryAgain, err := liveBindingPolicyCoreExtEntry(CoreExtBindingNameVerifySigExtOpenSSLDigest32V1)
	if err != nil {
		t.Fatalf("liveBindingPolicyCoreExtEntry(reload): %v", err)
	}
	if coreExtEntryAgain.RuntimeBinding != liveBindingPolicyRuntimeOpenSSLDigest32 {
		t.Fatalf("lookup must return copy, got runtime_binding=%q", coreExtEntryAgain.RuntimeBinding)
	}
	coreExtMiss, err := liveBindingPolicyCoreExtEntry("verify_sig_ext_unknown")
	if err == nil {
		t.Fatal("expected core_ext miss rejection")
	}
	if got, want := err.Error(), `live_binding_policy: core_ext_live_binding_name not found "verify_sig_ext_unknown"`; got != want {
		t.Fatalf("core_ext miss err=%q, want %q (entry=%+v)", got, want, coreExtMiss)
	}
}

func TestLoadLiveBindingPolicyRejectsMalformedAndTrailingJSON(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "syntax_error_after_array_open",
			raw:  `{"version":[}`,
			want: `live_binding_policy: parse embedded artifact: invalid character '}' looking for beginning of value`,
		},
		{
			name: "incomplete_json_value",
			raw:  `{"version": 1,`,
			want: `live_binding_policy: parse embedded artifact: incomplete JSON value`,
		},
		{
			name: "unknown_field",
			raw: `{
				"version": 1,
				"entries": [{
					"alg_name": "ML-DSA-87",
					"pubkey_len": 2592,
					"sig_len": 4627,
					"runtime_binding": "openssl_digest32_v1",
					"openssl_alg": "ML-DSA-87",
					"core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
				}],
				"bogus": 7
			}`,
			want: `live_binding_policy: parse embedded artifact: json: unknown field "bogus"`,
		},
		{
			name: "trailing_tokens",
			raw: `{
				"version": 1,
				"entries": [{
					"alg_name": "ML-DSA-87",
					"pubkey_len": 2592,
					"sig_len": 4627,
					"runtime_binding": "openssl_digest32_v1",
					"openssl_alg": "ML-DSA-87",
					"core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
				}]
			} 42`,
			want: `live_binding_policy: parse embedded artifact: trailing JSON tokens`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadLiveBindingPolicyFromJSON([]byte(tc.raw))
			if err == nil {
				t.Fatal("expected rejection")
			}
			if got := err.Error(); got != tc.want {
				t.Fatalf("err=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestLoadLiveBindingPolicyRejectsUnsupportedRuntimeBinding(t *testing.T) {
	_, err := loadLiveBindingPolicyFromJSON([]byte(`{
		"version": 1,
		"entries": [{
			"alg_name": "ML-DSA-87",
			"pubkey_len": 2592,
			"sig_len": 4627,
			"runtime_binding": "unsupported_runtime_v1",
			"openssl_alg": "ML-DSA-87",
			"core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
		}]
	}`))
	if err == nil {
		t.Fatal("expected unsupported runtime binding rejection")
	}
	if got, want := err.Error(), `live_binding_policy: entries[0]: unsupported runtime_binding "unsupported_runtime_v1"`; got != want {
		t.Fatalf("err=%q, want %q", got, want)
	}
}
