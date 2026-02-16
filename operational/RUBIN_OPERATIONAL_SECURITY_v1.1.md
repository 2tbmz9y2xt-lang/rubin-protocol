# RUBIN Operational Security v1.1 (non-consensus)

Status: NON-CONSENSUS  
Date: 2026-02-16  
Audience: controller + operators

Purpose: define operational taxonomy and minimum hygiene requirements referenced by other operational and chain-instance documents.

## 1. Status taxonomy

### 1.1 Document/network status labels

Use these labels for *non-consensus* lifecycle tracking only:

- `DEVELOPMENT (NON-CONSENSUS)`: engineering iteration; may break compatibility; not release-eligible.
- `DRAFT (NON-CONSENSUS)`: integration-ready draft; explicit non-production status.
- `TEMPLATE (NON-CONSENSUS)`: schema/template only; not a claim about any chain instance.

These labels do not change consensus rules.

## 2. Publication hygiene

1. INBOX.md, inbox/, and other local process artifacts MUST NOT be committed.
2. Any artifact intended for public GitHub visibility SHOULD be marked `web-visible` (see `operational/WEB_VISIBLE_POLICY.md`).
