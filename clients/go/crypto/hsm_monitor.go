// Package crypto: HSM health monitor and failover state machine.
// Implements the protocol defined in operational/RUBIN_HSM_FAILOVER_v1.0.md
//
//go:build wolfcrypt_dylib

package crypto

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// HSMState represents the three operating states of the node with respect to HSM.
type HSMState int32

const (
	HSMStateNormal   HSMState = 0 // HSM reachable, signing works
	HSMStateReadOnly HSMState = 1 // HSM unreachable, signing disabled, verification OK
	HSMStateFailed   HSMState = 2 // timeout exceeded, node must shut down
)

func (s HSMState) String() string {
	switch s {
	case HSMStateNormal:
		return "NORMAL"
	case HSMStateReadOnly:
		return "READ_ONLY"
	case HSMStateFailed:
		return "FAILED"
	default:
		return "UNKNOWN"
	}
}

// HSMConfig holds tunables loaded from env (see RUBIN_HSM_* vars).
type HSMConfig struct {
	HealthInterval  time.Duration // RUBIN_HSM_HEALTH_INTERVAL (default 10s)
	FailThreshold   int           // RUBIN_HSM_FAIL_THRESHOLD (default 3)
	FailoverTimeout time.Duration // RUBIN_HSM_FAILOVER_TIMEOUT (default 300s, 0=∞)
	AlertWebhook    string        // RUBIN_HSM_ALERT_WEBHOOK (optional)
}

// HSMConfigFromEnv reads config from environment variables with safe defaults.
func HSMConfigFromEnv() HSMConfig {
	cfg := HSMConfig{
		HealthInterval:  10 * time.Second,
		FailThreshold:   3,
		FailoverTimeout: 300 * time.Second,
	}
	if v := os.Getenv("RUBIN_HSM_HEALTH_INTERVAL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.HealthInterval = time.Duration(n) * time.Second
		}
	}
	if v := os.Getenv("RUBIN_HSM_FAIL_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.FailThreshold = n
		}
	}
	if v := os.Getenv("RUBIN_HSM_FAILOVER_TIMEOUT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.FailoverTimeout = time.Duration(n) * time.Second
		}
	}
	cfg.AlertWebhook = os.Getenv("RUBIN_HSM_ALERT_WEBHOOK")
	return cfg
}

// HealthCheckFn is the function called to verify HSM reachability.
// In production: attempt a no-op PKCS#11 call or dummy keywrap.
// In tests: inject a mock.
type HealthCheckFn func() error

// HSMMonitor runs the health check loop and drives the state machine.
type HSMMonitor struct {
	cfg         HSMConfig
	check       HealthCheckFn
	state       atomic.Int32
	failCount   int
	readOnlySince time.Time
	mu          sync.Mutex
	onFailed    func() // called when entering FAILED (trigger graceful shutdown)
	logger      *slog.Logger
}

// NewHSMMonitor creates an HSMMonitor. onFailed is called once when the node
// transitions to FAILED state — use it to trigger graceful shutdown.
func NewHSMMonitor(cfg HSMConfig, check HealthCheckFn, onFailed func()) *HSMMonitor {
	m := &HSMMonitor{
		cfg:      cfg,
		check:    check,
		onFailed: onFailed,
		logger:   slog.Default(),
	}
	m.state.Store(int32(HSMStateNormal))
	return m
}

// State returns the current HSM state (safe for concurrent reads).
func (m *HSMMonitor) State() HSMState {
	return HSMState(m.state.Load())
}

// CanSign returns true only when HSM is in NORMAL state.
func (m *HSMMonitor) CanSign() bool {
	return m.State() == HSMStateNormal
}

// Run starts the health check loop. Blocks until ctx is cancelled.
func (m *HSMMonitor) Run(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.HealthInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.tick()
		}
	}
}

func (m *HSMMonitor) tick() {
	err := m.check()
	m.mu.Lock()
	defer m.mu.Unlock()

	current := HSMState(m.state.Load())

	if err == nil {
		// HSM healthy
		if current != HSMStateNormal {
			m.logger.Info("hsm recovered", "from", current.String(), "to", "NORMAL")
			m.logStructured("hsm_state_change", current, HSMStateNormal, 0, "")
		}
		m.failCount = 0
		m.state.Store(int32(HSMStateNormal))
		return
	}

	m.failCount++
	m.logger.Warn("hsm health check failed",
		"fail_count", m.failCount,
		"threshold", m.cfg.FailThreshold,
		"error", err.Error(),
	)

	if current == HSMStateNormal && m.failCount >= m.cfg.FailThreshold {
		m.readOnlySince = time.Now()
		m.state.Store(int32(HSMStateReadOnly))
		m.logger.Warn("HSM unreachable — entering READ_ONLY mode. Signing disabled.",
			"fail_count", m.failCount,
		)
		m.logStructured("hsm_state_change", HSMStateNormal, HSMStateReadOnly, m.failCount, err.Error())
		m.sendAlert(HSMStateReadOnly, m.failCount)
		return
	}

	if current == HSMStateReadOnly && m.cfg.FailoverTimeout > 0 {
		if time.Since(m.readOnlySince) >= m.cfg.FailoverTimeout {
			m.state.Store(int32(HSMStateFailed))
			m.logger.Error("HSM timeout exceeded — node entering FAILED state. Shutting down.",
				"timeout", m.cfg.FailoverTimeout.String(),
			)
			m.logStructured("hsm_state_change", HSMStateReadOnly, HSMStateFailed, m.failCount, err.Error())
			m.sendAlert(HSMStateFailed, m.failCount)
			if m.onFailed != nil {
				go m.onFailed()
			}
		}
	}
}

type hsmEvent struct {
	TS        string `json:"ts"`
	Level     string `json:"level"`
	Event     string `json:"event"`
	From      string `json:"from"`
	To        string `json:"to"`
	FailCount int    `json:"fail_count"`
	Reason    string `json:"reason,omitempty"`
}

func (m *HSMMonitor) logStructured(event string, from, to HSMState, fc int, reason string) {
	ev := hsmEvent{
		TS:        time.Now().UTC().Format(time.RFC3339),
		Level:     levelFor(to),
		Event:     event,
		From:      from.String(),
		To:        to.String(),
		FailCount: fc,
		Reason:    reason,
	}
	b, _ := json.Marshal(ev)
	fmt.Println(string(b)) // structured log to stdout for log aggregator
}

func levelFor(s HSMState) string {
	switch s {
	case HSMStateFailed:
		return "ERROR"
	case HSMStateReadOnly:
		return "WARN"
	default:
		return "INFO"
	}
}

type alertPayload struct {
	Event     string `json:"event"`
	State     string `json:"state"`
	Timestamp string `json:"timestamp"`
	FailCount int    `json:"fail_count"`
}

func (m *HSMMonitor) sendAlert(state HSMState, fc int) {
	if m.cfg.AlertWebhook == "" {
		return
	}
	payload := alertPayload{
		Event:     "hsm_failover",
		State:     state.String(),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		FailCount: fc,
	}
	b, _ := json.Marshal(payload)
	go func() {
		resp, err := http.Post(m.cfg.AlertWebhook, "application/json", bytes.NewReader(b))
		if err != nil {
			m.logger.Warn("hsm alert webhook failed", "error", err.Error())
			return
		}
		resp.Body.Close()
	}()
}
