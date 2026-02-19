# RUBIN HSM Failover Protocol v1.0

Status: OPERATIONAL (non-consensus)
Scope: Sequencers and validators using an HSM for private key custody

## Problem

FIPS 140-3 requires private keys to be stored inside the HSM boundary. If HSM access is lost, a node MUST NOT:
- fail silently (silent failure) - dangerous for the network
- fall back to an in-memory key - violates the FIPS boundary
- keep signing without the HSM - violates key custody policy

## Three node states

```
NORMAL          - HSM reachable, signing enabled
READ_ONLY       - HSM unreachable, verification enabled, signing disabled
FAILED          - HSM unreachable for > MAX_HSM_FAILOVER_WAIT, node stops
```

Transitions:

```
NORMAL → READ_ONLY   : HSM health check fails (3 consecutive)
READ_ONLY → NORMAL   : HSM health check passes (1 success)
READ_ONLY → FAILED   : timeout MAX_HSM_FAILOVER_WAIT exceeded
FAILED → NORMAL      : manual restart only, with `--hsm-override`
```

## Configuration

In `rubin-node.env`:

```env
# HSM health check interval (seconds)
RUBIN_HSM_HEALTH_INTERVAL=10

# Consecutive failures before switching to READ_ONLY
RUBIN_HSM_FAIL_THRESHOLD=3

# Maximum time in READ_ONLY before FAILED (seconds). 0 = infinite (not recommended)
RUBIN_HSM_FAILOVER_TIMEOUT=300

# Alert webhook (optional) - invoked on READ_ONLY and FAILED transitions
RUBIN_HSM_ALERT_WEBHOOK=https://ops.example.com/alerts/hsm
```

## KEK storage and keywrap flow

The private key exists in memory only in wrapped (encrypted) form. Unwrapping/decryption happens only inside the HSM boundary. Flow:

```
1. Node starts
2. Requests KEK via PKCS#11: C_WrapKey / C_GetAttributeValue
3. HSM returns a wrapped key blob
4. Node stores the wrapped blob in memory (plaintext never enters process memory)
5. When signing is needed:
   a. Send digest to the HSM: C_SignInit + C_Sign
   b. HSM signs internally and returns the signature
   c. Plaintext key never leaves the HSM
6. HSM health check every RUBIN_HSM_HEALTH_INTERVAL seconds:
   a. PKCS#11 C_GetSlotInfo or a dummy C_Sign
   b. Failure → counter++
   c. counter >= FAIL_THRESHOLD → READ_ONLY
```

`rubin_wc_aes_keywrap` / `rubin_wc_aes_keyunwrap` are used for:
- **Offline backup**: export an encrypted key blob to cold storage before HSM replacement
- **HSM-to-HSM migration**: move a key between two HSMs via an encrypted blob
- **Test/dev**: replace PKCS#11 in environments without a physical HSM

## Failover sequence

### Scenario: HSM stops responding

```
T=0s   NORMAL - normal operation
T=10s  health check #1 - FAIL - fail_count=1
T=20s  health check #2 - FAIL - fail_count=2
T=30s  health check #3 - FAIL - fail_count=3 >= FAIL_THRESHOLD
       → SWITCH TO READ_ONLY
       → ALERT operator (webhook + stderr)
       → Log: \"HSM unreachable, entering READ_ONLY mode\"
       → All incoming Sign requests → HTTP 503 / error \"HSM unavailable\"
       → Verification continues to work

T=30s-330s   READ_ONLY - operators respond
T=330s  RUBIN_HSM_FAILOVER_TIMEOUT=300 elapsed
        → SWITCH TO FAILED
        → Log: \"HSM timeout exceeded, node shutting down\"
        → ALERT (repeat)
        → Graceful shutdown (finish in-flight requests, close connections)

Operator:
1. Check primary HSM or standby
2. Switch to standby HSM (change PKCS#11 slot in config)
3. Restart node: systemctl restart rubin-node
```

### Scenario: planned HSM replacement

```
1. Operator export (before replacement):
   rubin-node keymgr export-wrapped --out /secure/backup/key_$(date +%Y%m%d).bin
   # internally: rubin_wc_aes_keywrap(kek_from_hsm, sk_from_hsm, ...)

2. Install the new HSM and import KEK

3. Import into the new HSM:
   rubin-node keymgr import-wrapped --in /secure/backup/key_YYYYMMDD.bin
   # internally: rubin_wc_aes_keyunwrap(new_kek, wrapped_blob, ...)

4. Verify: rubin-node keymgr verify-pubkey
   # checks that the pubkey matches the expected key_id

5. Restart the node
```

## What to log (required)

Every HSM state transition MUST be written to structured logs:

```json
{
  "ts": "2026-02-18T12:00:00Z",
  "level": "WARN",
  "event": "hsm_state_change",
  "from": "NORMAL",
  "to": "READ_ONLY",
  "fail_count": 3,
  "hsm_slot": "0",
  "reason": "C_Sign timeout after 5000ms"
}
```

## Alert format (webhook)

POST JSON:

```json
{
  "event": "hsm_failover",
  "state": "READ_ONLY",
  "node_id": "...",
  "timestamp": "...",
  "hsm_slot": "0",
  "fail_count": 3
}
```

## Relationship to keywrap PoC

`rubin_wc_aes_keywrap` / `rubin_wc_aes_keyunwrap` are implemented in the shim as:
- a PKCS#11 replacement for dev/test environments without an HSM
- an offline backup/restore helper
- a base for keymgr pipeline integration tests

In production, PKCS#11 C_WrapKey/C_UnwrapKey are called directly on the HSM; shim functions are not used for online operations.
