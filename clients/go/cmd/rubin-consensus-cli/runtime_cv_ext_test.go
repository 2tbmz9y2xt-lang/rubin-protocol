package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestCVExtConformanceVectors loads CV-EXT.json and verifies each vector
// through the Go CLI runtime, checking ok/err expectations.
func TestCVExtConformanceVectors(t *testing.T) {
	fixturesDir := filepath.Join("..", "..", "..", "..", "conformance", "fixtures")
	path := filepath.Join(fixturesDir, "CV-EXT.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("conformance/fixtures/CV-EXT.json not found (run from repo root)")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read CV-EXT.json: %v", err)
	}

	var fixture struct {
		Gate    string `json:"gate"`
		Vectors []struct {
			ID              string                 `json:"id"`
			Family          string                 `json:"family"`
			Op              string                 `json:"op"`
			CovenantDataHex string                 `json:"covenant_data_hex"`
			Height          uint64                 `json:"height"`
			SuiteID         *uint8                 `json:"suite_id,omitempty"`
			CoreExtProfiles []CoreExtProfileJSON   `json:"core_ext_profiles,omitempty"`
			ExpectOK        bool                   `json:"expect_ok"`
			ExpectErr       string                 `json:"expect_err,omitempty"`
			Extra           map[string]interface{} `json:"-"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("parse CV-EXT.json: %v", err)
	}
	if fixture.Gate != "CV-EXT" {
		t.Fatalf("unexpected gate: %s", fixture.Gate)
	}

	for _, v := range fixture.Vectors {
		t.Run(fmt.Sprintf("%s/%s", v.Family, v.ID), func(t *testing.T) {
			// Build request envelope
			req := map[string]interface{}{
				"op":                v.Op,
				"covenant_data_hex": v.CovenantDataHex,
			}
			if v.Height > 0 {
				req["height"] = v.Height
			}
			if v.SuiteID != nil {
				req["suite_id"] = *v.SuiteID
			}
			if len(v.CoreExtProfiles) > 0 {
				req["core_ext_profiles"] = v.CoreExtProfiles
			}

			reqBytes, err := json.Marshal(req)
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}

			// Capture stdout
			oldStdin := os.Stdin
			oldStdout := os.Stdout

			stdinR, stdinW, _ := os.Pipe()
			stdoutR, stdoutW, _ := os.Pipe()

			os.Stdin = stdinR
			os.Stdout = stdoutW

			go func() {
				stdinW.Write(reqBytes)
				stdinW.Close()
			}()

			done := make(chan struct{})
			var outBuf bytes.Buffer
			go func() {
				defer close(done)
				buf := make([]byte, 4096)
				for {
					n, err := stdoutR.Read(buf)
					if n > 0 {
						outBuf.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}()

			runFromStdin()

			stdoutW.Close()
			<-done

			os.Stdin = oldStdin
			os.Stdout = oldStdout

			var resp Response
			if err := json.Unmarshal(outBuf.Bytes(), &resp); err != nil {
				t.Fatalf("parse response: %v (raw: %s)", err, outBuf.String())
			}

			if resp.Ok != v.ExpectOK {
				t.Errorf("ok mismatch: got=%v want=%v (err=%s)", resp.Ok, v.ExpectOK, resp.Err)
			}
			if !v.ExpectOK && v.ExpectErr != "" && resp.Err != v.ExpectErr {
				t.Errorf("err mismatch: got=%q want=%q", resp.Err, v.ExpectErr)
			}
		})
	}
}
