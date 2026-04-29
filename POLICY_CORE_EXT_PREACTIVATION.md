# Policy: CORE_EXT pre-activation guardrails

**Status:** NON-CONSENSUS / policy-only safety guardrail
**Date:** 2026-04-28
**Revision:** post-review rc3
**Applies to:** wallets, RPC, mempool, relay, mining templates
**Canonical precedence:** `RUBIN_L1_CANONICAL.md` remains the only source of consensus validity.

## 0. Merge Strategy

This file intentionally keeps the existing repository filename:

```text
rubin-protocol/POLICY_CORE_EXT_PREACTIVATION.md
```

Do not add a parallel file named `POLICY_CORE_EXT_PREACTIVATION_ENFORCEMENT.md`.
Any future split requires a separate controller-approved governance change with its own traceability anchor;
this document does not authorize a sibling enforcement file.

This document is an expanded replacement for the existing policy file, not a sibling document.

## 0.1 Governance and Traceability Anchors

This policy preserves the existing governance traceability surface. Existing anchors to retain in the repository record:

```text
COUNCIL_CORE_EXT_FRAMEWORK_20260315
COUNCIL_NATIVE_ROTATION_ARCH_20260315
Q-IMPL-CORE-EXT-COST-01
EXT_BASE_COST = 64
rubin-spec-private/spec/RUBIN_CORE_EXT_EXTENSION_FRAMEWORK.md
rubin-core-ext-lab/RUBIN_CORE_EXT_EXTENSION_FRAMEWORK.md
RUBIN_L1_CANONICAL.md §23.2.2
RUBIN_L1_CANONICAL.md §12.5
RUBIN_L1_CANONICAL.md §14
CANONICAL §23.2.2
CANONICAL §12.5
CANONICAL §14
RUBIN_NATIVE_CRYPTO_ROTATION_SPEC_v1.md
```

The `EXT_BASE_COST = 64` item is a traceability anchor from the existing repository state. This file does not redefine consensus cost accounting or activation semantics.

Scope boundary:

```text
CORE_EXT is not a native-crypto replacement track.
Native cryptographic suite rotation is a separate governance path.
Native suite lifecycle is governed by RUBIN_NATIVE_CRYPTO_ROTATION_SPEC_v1.md.
CORE_EXT profiles authorize non-native extension behavior only when ACTIVE.
```

## 1. Risk Statement

Before an intended `CORE_EXT` profile is `ACTIVE`, consensus treats spends of that `CORE_EXT(ext_id)` as anyone-can-spend with respect to witness semantics.

Therefore, policy must prevent accidental creation and relay of pre-activation `CORE_EXT` funds.

## 2. Decision

Production policy is fail-closed.

```text
PolicyRejectCoreExtPreActivation = true
```

As a policy requirement, this default applies to implementations of:

- wallet construction;
- RPC transaction creation;
- mempool admission;
- relay forwarding;
- miner template inclusion.

## 2.1 Current Implementation Status

This policy replacement does not claim new implementation coverage. It records policy requirements for
wallet, RPC, mempool, relay, miner, unsafe-override, and telemetry surfaces when those surfaces implement
CORE_EXT pre-activation handling.

The currently documented implemented guardrail remains **miner template filtering**:

- By default, `Miner` excludes any transaction that creates a `CORE_EXT` output or spends a `CORE_EXT` UTXO.
- This is policy-only and does not change consensus validity.

Wallet construction, transaction-construction RPC, mempool admission, relay forwarding, unsafe override,
and telemetry behavior require separate implementation evidence before this repository can claim them as
implemented.

## 3. Wallet Policy

This section is a forward policy requirement for wallet implementations. This document does not claim
that wallet construction for CORE_EXT pre-activation handling is implemented; see §2.1.

Wallets MUST NOT create `CORE_EXT` outputs unless all are true:

1. The target `ext_id` profile is known.
2. The profile is `ACTIVE` at the intended spend height.
3. The wallet has the profile byte layout.
4. The wallet can construct valid post-activation witness semantics.
5. The transaction passes local policy simulation.

If any condition is false, wallet construction MUST fail.

## 4. RPC Policy

This section is a forward policy requirement for transaction-construction RPC implementations. This document
does not claim that such RPC rejection is implemented; the error name and response shape below are target
policy guidance, not present-runtime evidence.

Transaction-construction RPCs MUST reject requests that create a pre-activation `CORE_EXT` output.

The error SHOULD be:

```text
RPC_ERR_CORE_EXT_PREACTIVATION_FORBIDDEN
```

The response SHOULD include:

```json
{
  "ext_id": "0x....",
  "profile_state": "INACTIVE",
  "policy": "PolicyRejectCoreExtPreActivation"
}
```

## 5. Mempool and Relay Policy

This section is a forward policy requirement for mempool and relay implementations. This document does not
claim new mempool or relay implementation coverage; see §2.1.

Reject as non-standard if a transaction:

1. Creates a `CORE_EXT` output for an inactive profile.
2. Spends a `CORE_EXT` output for an inactive profile.
3. Uses an unknown `ext_id` without an active deployment profile.

Relay MUST NOT forward such transactions.

## 6. Miner Template Policy

This is the currently documented implemented guardrail identified in §2.1.

Miners MUST exclude pre-activation `CORE_EXT` creates/spends from policy-compliant templates.

This does not change consensus validity. It prevents accidental block inclusion by honest miners.

## 7. Unsafe Test Override

This section applies only if a future implementation exposes a test-only override. This document does not
claim such an override exists.

A node MAY expose a test-only override:

```text
UnsafeAllowCoreExtPreActivation = true
```

Requirements:

1. Disabled by default.
2. Forbidden in release profile.
3. Startup warning required.
4. Structured log event required.
5. Prometheus/telemetry flag required.
6. CLI help MUST label it unsafe.
7. CI release profile MUST fail if enabled.

Structured warning event:

```json
{
  "class": "node",
  "event": "node.unsafe_core_ext_preactivation_enabled",
  "level": "WARN",
  "consensus_impact": false,
  "fund_safety_risk": true
}
```

## 8. Activation Boundary

At height `h`, a `CORE_EXT` profile is active only if:

```text
h >= activation_height
```

Version-bit signaling is telemetry only and MUST NOT affect admission.

## 9. Telemetry

This section records target policy telemetry names. This document does not claim that these metrics are
currently emitted.

Nodes SHOULD expose:

```text
core_ext_preactivation_reject_total
core_ext_preactivation_miner_exclude_total
core_ext_profile_active_total
core_ext_profile_inactive_total
core_ext_unknown_ext_id_total
core_ext_unsafe_override_enabled
```

## 10. Review Triggers

Review this policy when:

1. A real `CORE_EXT` profile is proposed.
2. A deployment descriptor is byte-anchored.
3. Wallet support for that profile is implemented.
4. Conformance vectors for that profile exist.
5. Governance approves activation.
