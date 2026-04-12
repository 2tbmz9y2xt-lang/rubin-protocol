'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { jsonrepair } = require('jsonrepair');

const DIFF_CAP = 128000;
const TOTAL_FILE_BUDGET = 100000;
const DEP_BUDGET = 20000;
const PARITY_BUDGET = 60000;
const PER_FILE_CAP = 30000;
const DEP_SCAN_FILE_CAP = 120000;
const USER_PROMPT_CAP = 300000;
const SEPARATOR = '\n\n---\n\n';
const TRUSTED_AUTHORS = new Set(['github-actions[bot]']);

const PARITY_MAP = [
  ['clients/go/consensus/wire_read.go', 'clients/rust/crates/rubin-consensus/src/wire_read.rs'],
  ['clients/go/consensus/tx_helpers.go', 'clients/rust/crates/rubin-consensus/src/tx_helpers.rs'],
  ['clients/go/consensus/block_parse.go', 'clients/rust/crates/rubin-consensus/src/block.rs'],
  ['clients/go/consensus/constants.go', 'clients/rust/crates/rubin-consensus/src/constants.rs'],
  ['clients/go/consensus/connect_block_inmem.go', 'clients/rust/crates/rubin-consensus/src/connect_block_inmem.rs'],
  ['clients/go/consensus/suite_registry.go', 'clients/rust/crates/rubin-consensus/src/suite_registry.rs'],
  ['clients/go/consensus/sighash.go', 'clients/rust/crates/rubin-consensus/src/sighash.rs'],
  ['clients/go/consensus/core_ext.go', 'clients/rust/crates/rubin-consensus/src/core_ext.rs'],
  ['clients/go/consensus/fork_choice.go', 'clients/rust/crates/rubin-consensus/src/fork_choice.rs'],
  ['clients/go/consensus/spend_verify.go', 'clients/rust/crates/rubin-consensus/src/spend_verify.rs'],
  ['clients/go/consensus/pow.go', 'clients/rust/crates/rubin-consensus/src/pow.rs'],
  ['clients/go/consensus/merkle.go', 'clients/rust/crates/rubin-consensus/src/merkle.rs'],
  ['clients/go/consensus/subsidy.go', 'clients/rust/crates/rubin-consensus/src/subsidy.rs'],
  ['clients/go/consensus/utxo_basic.go', 'clients/rust/crates/rubin-consensus/src/utxo_basic.rs'],
  ['clients/go/consensus/block_basic.go', 'clients/rust/crates/rubin-consensus/src/block_basic.rs'],
  ['clients/go/consensus/rotation_descriptor.go', 'clients/rust/crates/rubin-consensus/src/suite_registry.rs'],
  ['clients/go/consensus/rotation_production.go', 'clients/rust/crates/rubin-consensus/src/suite_registry.rs'],
  ['clients/go/consensus/featurebits.go', 'clients/rust/crates/rubin-consensus/src/featurebits.rs'],
  ['clients/go/consensus/flagday.go', 'clients/rust/crates/rubin-consensus/src/flagday.rs'],
  ['clients/go/consensus/htlc.go', 'clients/rust/crates/rubin-consensus/src/htlc.rs'],
  ['clients/go/consensus/vault.go', 'clients/rust/crates/rubin-consensus/src/vault.rs'],
  ['clients/go/consensus/tx_parse.go', 'clients/rust/crates/rubin-consensus/src/tx.rs'],
  ['clients/go/consensus/tx_marshal.go', 'clients/rust/crates/rubin-consensus/src/tx.rs'],
  ['clients/go/consensus/hash.go', 'clients/rust/crates/rubin-consensus/src/hash.rs'],
  ['clients/go/consensus/compact_relay.go', 'clients/rust/crates/rubin-consensus/src/compact_relay.rs'],
  ['clients/go/consensus/da_verify_parallel.go', 'clients/rust/crates/rubin-consensus/src/da_verify_parallel.rs'],
  ['clients/go/consensus/verify_sig_openssl.go', 'clients/rust/crates/rubin-consensus/src/verify_sig_openssl.rs'],
  ['clients/go/consensus/covenant_genesis.go', 'clients/rust/crates/rubin-consensus/src/covenant_genesis.rs'],
  ['clients/go/consensus/txcontext.go', 'clients/rust/crates/rubin-consensus/src/txcontext.rs'],
  ['clients/go/consensus/tx_dep_graph.go', 'clients/rust/crates/rubin-consensus/src/tx_dep_graph.rs'],
  ['clients/go/consensus/core_ext_binding.go', 'clients/rust/crates/rubin-consensus/src/core_ext.rs'],
  ['clients/go/consensus/stealth.go', 'clients/rust/crates/rubin-consensus/src/stealth.rs'],
  ['clients/go/consensus/utxo_snapshot.go', 'clients/rust/crates/rubin-consensus/src/utxo_snapshot.rs'],
  ['clients/go/consensus/compactsize.go', 'clients/rust/crates/rubin-consensus/src/compactsize.rs'],
  ['clients/go/consensus/errors.go', 'clients/rust/crates/rubin-consensus/src/error.rs'],
  ['clients/go/node/config.go', 'clients/rust/crates/rubin-node/src/genesis.rs'],
  ['clients/go/node/config.go', 'clients/rust/crates/rubin-consensus/src/suite_registry.rs'],
  ['clients/rust/crates/rubin-node/src/genesis.rs', 'clients/go/consensus/rotation_production.go'],
  ['clients/go/node/chainstate.go', 'clients/rust/crates/rubin-node/src/chainstate.rs'],
  ['clients/go/node/sync.go', 'clients/rust/crates/rubin-node/src/sync.rs'],
  ['clients/go/node/undo.go', 'clients/rust/crates/rubin-node/src/undo.rs'],
  ['clients/go/node/blockstore.go', 'clients/rust/crates/rubin-node/src/blockstore.rs'],
  ['clients/go/node/miner.go', 'clients/rust/crates/rubin-node/src/miner.rs'],
  ['clients/go/node/mempool.go', 'clients/rust/crates/rubin-node/src/txpool.rs'],
  ['clients/go/node/sync_reorg.go', 'clients/rust/crates/rubin-node/src/sync_reorg.rs'],
  ['clients/go/node/sync_disconnect.go', 'clients/rust/crates/rubin-node/src/sync_disconnect.rs'],
  ['clients/go/node/chainstate_recovery.go', 'clients/rust/crates/rubin-node/src/chainstate.rs'],
  ['clients/go/node/blockstore_p2p.go', 'clients/rust/crates/rubin-node/src/blockstore.rs'],
  ['clients/go/node/sync_mempool.go', 'clients/rust/crates/rubin-node/src/txpool.rs'],
  ['clients/go/node/policy_core_ext.go', 'clients/rust/crates/rubin-node/src/txpool.rs'],
  ['clients/go/node/policy_core_ext.go', 'clients/rust/crates/rubin-node/src/miner.rs'],
  ['clients/go/node/policy_da_anchor.go', 'clients/rust/crates/rubin-node/src/txpool.rs'],
  ['clients/go/node/policy_da_anchor.go', 'clients/rust/crates/rubin-node/src/miner.rs'],
  ['clients/rust/crates/rubin-node/src/main.rs', 'clients/go/cmd/rubin-node/main.go'],
  ['clients/go/cmd/rubin-node/main.go', 'clients/rust/crates/rubin-node/src/genesis.rs'],
  ['clients/go/cmd/rubin-node/http_rpc.go', 'clients/rust/crates/rubin-node/src/devnet_rpc.rs'],
  ['clients/go/node/p2p/rust_interop_test.go', 'clients/rust/crates/rubin-node/src/interop/mod.rs'],
  ['clients/go/node/mine_address.go', 'clients/rust/crates/rubin-node/src/coinbase.rs'],
  ['clients/go/node/safeio.go', 'clients/rust/crates/rubin-node/src/io_utils.rs'],
  ['clients/go/node/peer_manager.go', 'clients/rust/crates/rubin-node/src/p2p_runtime.rs'],
  ['clients/go/node/p2p/service.go', 'clients/rust/crates/rubin-node/src/p2p_service.rs'],
  ['clients/go/node/p2p/wire.go', 'clients/rust/crates/rubin-node/src/p2p_service.rs'],
  ['clients/go/node/p2p/handlers_tx.go', 'clients/rust/crates/rubin-node/src/tx_relay.rs'],
  ['clients/go/node/p2p/seen.go', 'clients/rust/crates/rubin-node/src/tx_seen.rs'],
  ['clients/go/node/p2p/handlers_block.go', 'clients/rust/crates/rubin-node/src/p2p_service.rs'],
  ['clients/go/node/p2p/handlers_inventory.go', 'clients/rust/crates/rubin-node/src/p2p_runtime.rs'],
  ['clients/go/node/p2p/handshake.go', 'clients/rust/crates/rubin-node/src/p2p_service.rs'],
  ['clients/go/node/p2p/reconnect.go', 'clients/rust/crates/rubin-node/src/p2p_runtime.rs'],
  ['clients/go/node/p2p/peer_runtime.go', 'clients/rust/crates/rubin-node/src/p2p_runtime.rs'],
  ['clients/go/node/p2p/service_peer_lifecycle.go', 'clients/rust/crates/rubin-node/src/p2p_service.rs'],
  ['clients/go/node/p2p/service_listener.go', 'clients/rust/crates/rubin-node/src/p2p_service.rs'],
  ['clients/go/node/p2p/service_sync.go', 'clients/rust/crates/rubin-node/src/sync.rs'],
  ['clients/go/node/p2p/service_inventory.go', 'clients/rust/crates/rubin-node/src/p2p_runtime.rs'],
  ['clients/go/node/p2p/addr_manager.go', 'clients/rust/crates/rubin-node/src/p2p_runtime.rs'],
  ['clients/go/node/p2p/addr_discovery.go', 'clients/rust/crates/rubin-node/src/p2p_runtime.rs'],
  ['clients/go/node/p2p/handlers_addr.go', 'clients/rust/crates/rubin-node/src/p2p_runtime.rs'],
  ['clients/go/node/p2p/orphan_pool.go', 'clients/rust/crates/rubin-node/src/relay_pool.rs'],
  ['clients/go/node/p2p/mempool.go', 'clients/rust/crates/rubin-node/src/txpool.rs'],
  ['clients/go/node/p2p/tx_metadata.go', 'clients/rust/crates/rubin-node/src/txpool.rs'],
];

function fromJSONEnv(name, fallbackValue) {
  const raw = process.env[name];
  if (!raw) {
    return fallbackValue;
  }
  try {
    return JSON.parse(raw);
  } catch {
    return fallbackValue;
  }
}

function isReviewRelevantFile(file) {
  return file.endsWith('.go')
    || file.endsWith('.rs')
    || file.endsWith('.lean')
    || file.startsWith('.github/workflows/')
    || file === '.github/security-acknowledged.json'
    || file.startsWith('scripts/security/')
    || /^tools\/.*\.(py|sh|json)$/.test(file);
}

function readChangedFileWithMetadata(repoRoot, repoRootReal, file, maxBytes = null) {
  const fullPath = path.resolve(repoRoot, file);
  const rel = path.relative(repoRoot, fullPath);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    return null;
  }
  try {
    const st = fs.lstatSync(fullPath);
    if (st.isSymbolicLink() || !st.isFile()) {
      return null;
    }
    const realPath = fs.realpathSync(fullPath);
    if (!(realPath === repoRootReal || realPath.startsWith(`${repoRootReal}${path.sep}`))) {
      return null;
    }
    if (!Number.isFinite(maxBytes) || maxBytes <= 0 || st.size <= maxBytes) {
      return { content: fs.readFileSync(realPath, 'utf8'), truncated: false };
    }
    const fd = fs.openSync(realPath, 'r');
    try {
      const buffer = Buffer.alloc(maxBytes);
      const bytesRead = fs.readSync(fd, buffer, 0, maxBytes, 0);
      return { content: buffer.subarray(0, bytesRead).toString('utf8'), truncated: true };
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return null;
  }
}

function readChangedFile(repoRoot, repoRootReal, file, maxBytes = null) {
  return readChangedFileWithMetadata(repoRoot, repoRootReal, file, maxBytes)?.content ?? null;
}

function buildChangedFilePayload(changedFiles, repoRoot, repoRootReal) {
  const entries = [];
  let usedBytes = 0;
  for (const file of changedFiles) {
    const header = `FILE: ${file}\n`;
    const frameSize = header.length + (entries.length > 0 ? SEPARATOR.length : 0);
    if (usedBytes + frameSize + 200 > TOTAL_FILE_BUDGET) {
      continue;
    }
    const remainingBudget = TOTAL_FILE_BUDGET - usedBytes - frameSize;
    const contentBudget = Math.min(PER_FILE_CAP, remainingBudget);
    const content = readChangedFile(repoRoot, repoRootReal, file, contentBudget);
    if (!content) {
      continue;
    }
    const entry = header + content.slice(0, contentBudget);
    entries.push(entry);
    usedBytes += entry.length + (entries.length > 1 ? SEPARATOR.length : 0);
  }
  return entries.join(SEPARATOR);
}

function buildDependencyContext(changedFiles, changedFilesSet, repoRoot, repoRootReal) {
  const depEntries = [];
  let depUsed = 0;
  const depTruncationNotesSeen = new Set();
  let dependencyContextIncomplete = false;

  for (const file of changedFiles) {
    if (!file.endsWith('.rs')) {
      continue;
    }
    const contentInfo = readChangedFileWithMetadata(repoRoot, repoRootReal, file, DEP_SCAN_FILE_CAP);
    if (!contentInfo) {
      continue;
    }
    const content = contentInfo.content;
    if (contentInfo.truncated) {
      dependencyContextIncomplete = true;
    }

    const srcMatch = file.match(/^(.*\/src)\//);
    if (!srcMatch) {
      continue;
    }
    const crateRoot = srcMatch[1];

    const fileLines = content.split('\n');
    const useStatements = [];
    let inUse = false;
    let useAccum = '';
    for (const ln of fileLines) {
      if (/^\s*use\s+crate::/.test(ln) && !ln.includes(';')) {
        inUse = true;
        useAccum = ln;
      } else if (inUse) {
        useAccum += ' ' + ln.trim();
        if (ln.includes(';')) {
          useStatements.push(useAccum);
          inUse = false;
          useAccum = '';
        }
      } else if (/^\s*use\s+crate::/.test(ln) && ln.includes(';')) {
        useStatements.push(ln);
      }
    }

    const isRustIdent = (s) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(s);
    const modImports = new Map();
    for (const stmt of useStatements) {
      const m = stmt.match(/use\s+crate::([^;]+);/);
      if (!m) {
        continue;
      }
      let raw = m[1].replace(/\s+/g, '');
      raw = raw.replace(/::\{self(?:,\s*)?\}/, '');
      const braceIdx = raw.indexOf('{');
      if (braceIdx !== -1) {
        const modPath = raw.slice(0, braceIdx).replace(/:+$/, '');
        const items = raw.slice(braceIdx + 1, raw.lastIndexOf('}')).split(',').map((s) => s.trim()).filter(Boolean);
        if (!modImports.has(modPath)) {
          modImports.set(modPath, new Set());
        }
        for (const item of items) {
          if (isRustIdent(item)) {
            modImports.get(modPath).add(item);
          }
        }
      } else {
        const parts = raw.split('::');
        const symbol = parts.pop();
        const modPath = parts.join('::');
        if (!isRustIdent(symbol)) {
          continue;
        }
        if (!modImports.has(modPath)) {
          modImports.set(modPath, new Set());
        }
        modImports.get(modPath).add(symbol);
      }
    }

    for (const [modPath, symbols] of modImports) {
      const parts = modPath.split('::');
      let modFile = null;
      const candidates = [
        path.join(repoRoot, crateRoot, ...parts) + '.rs',
        path.join(repoRoot, crateRoot, ...parts, 'mod.rs'),
      ];
      if (parts.length > 1) {
        candidates.push(path.join(repoRoot, crateRoot, ...parts.slice(0, -1)) + '.rs');
      }
      for (const cand of candidates) {
        try {
          if (fs.statSync(cand).isFile()) {
            modFile = cand;
            break;
          }
        } catch {}
      }
      if (!modFile) {
        continue;
      }
      const modRel = path.relative(repoRoot, modFile);
      if (!modRel || path.isAbsolute(modRel) || modRel.startsWith('..')) {
        continue;
      }
      if (changedFilesSet.has(modRel)) {
        continue;
      }

      const modContentInfo = readChangedFileWithMetadata(repoRoot, repoRootReal, modRel, DEP_SCAN_FILE_CAP);
      if (!modContentInfo) {
        continue;
      }
      const modContent = modContentInfo.content;
      if (modContentInfo.truncated && !depTruncationNotesSeen.has(modRel)) {
        dependencyContextIncomplete = true;
        const truncationEntry = `### ${modRel}\n[TRUNCATED TO ${DEP_SCAN_FILE_CAP} BYTES FOR DEPENDENCY SCAN; later public items may be omitted]\n`;
        if (depUsed + truncationEntry.length <= DEP_BUDGET) {
          depEntries.push(truncationEntry);
          depUsed += truncationEntry.length;
          depTruncationNotesSeen.add(modRel);
        }
      }

      for (const sym of symbols) {
        if (depUsed >= DEP_BUDGET) {
          break;
        }
        const sigRe = new RegExp(
          '((?:^[ \\t]*///[^\\n]*\\n)*)'
          + '(?:^[ \\t]*#\\[[^\\]]*\\]\\s*\\n)*'
          + '^[ \\t]*pub(?:\\([^)]*\\))?\\s+(?:fn|struct|enum|const|type|trait)\\s+'
          + sym + '\\b[^\\n]*',
          'gm',
        );
        const hit = sigRe.exec(modContent);
        if (!hit) {
          continue;
        }
        const docLines = (hit[1] || '').split('\n')
          .filter((l) => l.trim().startsWith('///'))
          .map((l) => l.trim())
          .join('\n');
        const sigLine = hit[0].replace(hit[1] || '', '').split('\n')[0].trim();
        if (!sigLine) {
          continue;
        }
        const entry = `### ${sym} (${modRel})\n${docLines ? `${docLines}\n` : ''}${sigLine}\n`;
        if (depUsed + entry.length > DEP_BUDGET) {
          continue;
        }
        depEntries.push(entry);
        depUsed += entry.length;
      }
    }
  }

  if (depEntries.length === 0 && !dependencyContextIncomplete) {
    return '';
  }
  const incompleteNote = dependencyContextIncomplete
    ? `[DEPENDENCY CONTEXT INCOMPLETE: at least one Rust file exceeded ${DEP_SCAN_FILE_CAP} bytes during dependency extraction, so later imports or public items may be omitted]\n\n`
    : '';
  return '\n\n---\nDEPENDENCY CONTRACTS (doc-comments and signatures of functions imported by changed files):\n\n'
    + incompleteNote
    + depEntries.join('\n');
}

function buildParityContext(changedFiles, changedFilesSet, repoRoot, repoRootReal) {
  const parityIntro = '\n\n---\nPARITY CONTEXT (counterpart files from the other client):\n\n';
  const parityEntries = [];
  let parityUsed = 0;
  const parityCounterpartsSeen = new Set();

  for (const file of changedFiles) {
    if (parityUsed >= PARITY_BUDGET) {
      break;
    }
    for (const [pathA, pathB] of PARITY_MAP) {
      let counterpart = null;
      if (file === pathA && !changedFilesSet.has(pathB)) {
        counterpart = pathB;
      } else if (file === pathB && !changedFilesSet.has(pathA)) {
        counterpart = pathA;
      }
      if (!counterpart || parityCounterpartsSeen.has(counterpart)) {
        continue;
      }
      const header = `PARITY FILE: ${counterpart} (counterpart of changed ${file})\n`;
      const separatorOverhead = parityEntries.length > 0 ? SEPARATOR.length : 0;
      const introOverhead = parityEntries.length === 0 ? parityIntro.length : 0;
      const cap = Math.min(
        PARITY_BUDGET - parityUsed - separatorOverhead - introOverhead - header.length,
        PER_FILE_CAP,
      );
      if (cap < 200) {
        continue;
      }
      const content = readChangedFile(repoRoot, repoRootReal, counterpart, cap);
      if (!content) {
        continue;
      }
      const entry = header + content.slice(0, cap);
      parityCounterpartsSeen.add(counterpart);
      parityEntries.push(entry);
      parityUsed += separatorOverhead + introOverhead + entry.length;
    }
  }

  if (parityEntries.length === 0) {
    return '';
  }
  return parityIntro + parityEntries.join(SEPARATOR);
}

function buildSystemPrompt(modelId, antiHallucinationRules) {
  return [
    'You are a strict protocol security reviewer for the RUBIN blockchain protocol.',
    '',
    'PROTOCOL CONTEXT:',
    '- Bitcoin-like UTXO chain with dual reference clients (Go + Rust) and Lean4 formal verification',
    '- Cryptography: ML-DSA-87 (FIPS 204) as native signature scheme, post-quantum',
    '- Covenant-typed system: P2PK, HTLC, anchor, DA-commit, CORE_EXT, vault, multisig',
    '- Soft-fork deployment mechanism for protocol upgrades',
    '- Canonical chain: RUBIN_L1_CANONICAL.md -> fixtures -> Go -> Rust -> conformance tests',
    '',
    'SEVERITY CLASSIFICATION:',
    'CRITICAL: double-spend, inflation bug, signature bypass, fork-choice error, proven consensus divergence',
    'HIGH: nonce reuse, weak entropy, PQ parameter misuse, missing signature validation',
    'MEDIUM: integer overflow/underflow, slice bounds, unchecked casts, panic in consensus path',
    'LOW: incorrect state transitions, undo record integrity, non-canonical serialization',
    'INFO: spec/code/fixture drift, missing test coverage',
    'PERF: unbounded allocations, O(n^2) in hot paths',
    '',
    'ANTI-HALLUCINATION RULES:',
    '- CODE CITATION RULE: Every finding MUST cite file:line and quote the exact problematic code.',
    '- Never claim divergence without showing the ACTUAL differing code from both clients.',
    '- Never reference files not provided in context.',
    '- If PARITY CONTEXT shows matching implementations, do NOT report divergence.',
    '- If unsure, mark severity as INFO with "NEEDS VERIFICATION".',
    '- DEDUPLICATION: a "PREVIOUSLY REPORTED" section may appear in the user message. Do NOT re-report findings already in that list — they are already tracked by an earlier review.',
    ...antiHallucinationRules,
    '',
    'OUTPUT FORMAT (JSON only):',
    '```',
    '{',
    `  "model": "${modelId}",`,
    '  "verdict": "PASS|WARN|BLOCK",',
    '  "findings": [{"severity":"...","file":"...","line":N,"title":"...","details":"...","suggestion":"..."}]',
    '}',
    '```',
  ].join('\n');
}

async function fetchPreviousFindings(github, context, modelDisplayName, core) {
  let previousFindings = '';
  try {
    const allReviews = await github.paginate(
      github.rest.pulls.listReviews,
      {
        owner: context.repo.owner,
        repo: context.repo.repo,
        pull_number: context.issue.number,
      },
    );
    const allIssueComments = await github.paginate(
      github.rest.issues.listComments,
      {
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: context.issue.number,
        per_page: 100,
      },
    );
    const allComments = [
      ...allReviews.map((r) => ({ body: r.body, user: r.user, date: r.submitted_at || '' })),
      ...allIssueComments.map((c) => ({ body: c.body, user: c.user, date: c.created_at || '' })),
    ].sort((a, b) => a.date.localeCompare(b.date));

    const modelMarker = `_Model: ${modelDisplayName}_`;
    const reviewComments = allComments
      .filter((c) => c.body
        && TRUSTED_AUTHORS.has(c.user?.login ?? '')
        && c.body.includes('Security Review:')
        && c.body.includes(modelMarker))
      .slice(-3);

    if (reviewComments.length > 0) {
      const titles = [];
      for (const c of reviewComments) {
        const jsonMatch = c.body.match(/```json\n([\s\S]*?)```/);
        if (!jsonMatch) {
          continue;
        }
        try {
          const parsed = JSON.parse(jsonMatch[1]);
          for (const f of (parsed.findings || [])) {
            const sev = String(f.severity || '').replace(/[^A-Z]/g, '').slice(0, 10);
            const title = String(f.title || '').replace(/[\r\n]+/g, ' ').replace(/[^\x20-\x7E]/g, '').slice(0, 120);
            const file = String(f.file || '').replace(/[^\x20-\x7E]/g, '').slice(0, 200);
            if (sev && title) {
              titles.push(`[${sev}] ${title}${file ? ` (in ${file})` : ''}`);
            }
          }
        } catch {}
      }
      if (titles.length > 0) {
        previousFindings = '\n\nPREVIOUSLY REPORTED (do NOT re-report these — they are already tracked):\n'
          + [...new Set(titles)].join('\n');
      }
    }
  } catch (err) {
    core.warning(`Could not fetch previous reviews: ${err.message}`);
  }
  return previousFindings;
}

module.exports = async function runSecurityReview({ github, context, core }) {
  const usesGitHubModels = fromJSONEnv('REVIEW_USES_GITHUB_MODELS', false);
  const apiUrl = fromJSONEnv('REVIEW_API_URL', '');
  const modelId = fromJSONEnv('REVIEW_MODEL_ID', '');
  const modelDisplayName = fromJSONEnv('REVIEW_MODEL_DISPLAY_NAME', '');
  const maxTokens = fromJSONEnv('REVIEW_MAX_TOKENS', 0);
  const needsJsonMode = fromJSONEnv('REVIEW_NEEDS_JSON_MODE', false);
  const antiHallucinationRulesInput = fromJSONEnv('REVIEW_ANTI_HALLUCINATION_RULES', '[]');
  const baseSha = process.env.REVIEW_BASE_SHA || '';
  const headSha = process.env.REVIEW_HEAD_SHA || '';

  const requiredEnvironmentContract = [
    ['apiUrl', apiUrl],
    ['modelId', modelId],
    ['modelDisplayName', modelDisplayName],
    ['baseSha', baseSha],
    ['headSha', headSha],
  ];
  const missingEnvironmentKeys = requiredEnvironmentContract
    .filter(([, value]) => !value)
    .map(([key]) => key);

  if (missingEnvironmentKeys.length > 0) {
    const environmentDiagnostics = requiredEnvironmentContract
      .map(([key, value]) => `${key}=${value ? `present(len=${String(value).length})` : 'missing/empty'}`)
      .join(', ');
    core.setFailed(
      `Missing required security-review environment contract: ${missingEnvironmentKeys.join(', ')}. ${environmentDiagnostics}`,
    );
    return;
  }

  const diffRaw = fs.readFileSync('pr-diff.txt', 'utf8');
  const diffTruncationNote = `\n\n[TRUNCATED — diff exceeded ${DIFF_CAP} bytes; tail omitted]`;
  const diff = diffRaw.length > DIFF_CAP
    ? diffRaw.slice(0, Math.max(0, DIFF_CAP - diffTruncationNote.length)) + diffTruncationNote
    : diffRaw;

  const repoRoot = process.cwd();
  const repoRootReal = fs.realpathSync(repoRoot);
  const changedFiles = execFileSync(
    'git',
    ['diff', '--diff-filter=ACMR', '--name-only', '-z', baseSha, headSha],
    { encoding: 'utf8', maxBuffer: 20 * 1024 * 1024 },
  ).split('\0').filter(Boolean).filter(isReviewRelevantFile);
  const changedFilesSet = new Set(changedFiles);

  let antiHallucinationRules = [];
  try {
    const parsedAntiHallucinationRules = Array.isArray(antiHallucinationRulesInput)
      ? antiHallucinationRulesInput
      : typeof antiHallucinationRulesInput === 'string'
        ? JSON.parse(antiHallucinationRulesInput)
        : [];
    antiHallucinationRules = Array.isArray(parsedAntiHallucinationRules)
      ? parsedAntiHallucinationRules
      : [];
  } catch (parseErr) {
    core.warning(`Failed to parse anti_hallucination_rules input as JSON: ${parseErr.message}. Continuing with empty rules — model-specific guardrails are NOT applied.`);
  }

  const changedFilePayload = buildChangedFilePayload(changedFiles, repoRoot, repoRootReal);
  const dependencyContext = buildDependencyContext(changedFiles, changedFilesSet, repoRoot, repoRootReal);
  const parityContext = buildParityContext(changedFiles, changedFilesSet, repoRoot, repoRootReal);
  const previousFindings = await fetchPreviousFindings(github, context, modelDisplayName, core);
  const systemPrompt = buildSystemPrompt(modelId, antiHallucinationRules);

  const userPromptRaw = [
    'Review this PR diff for security issues:\n',
    diff,
    changedFilePayload,
    dependencyContext,
    parityContext,
    previousFindings,
  ].join('\n');
  const userPromptTruncationNote = `\n\n[TRUNCATED — user prompt exceeded ${USER_PROMPT_CAP} bytes; later sections may be missing, do not treat omissions as "unchanged"]`;
  const userPrompt = userPromptRaw.length > USER_PROMPT_CAP
    ? userPromptRaw.slice(0, Math.max(0, USER_PROMPT_CAP - userPromptTruncationNote.length)) + userPromptTruncationNote
    : userPromptRaw;

  const apiKey = usesGitHubModels ? process.env.GITHUB_TOKEN : process.env.API_KEY;
  const headers = usesGitHubModels
    ? { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' }
    : {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': `https://github.com/${context.repo.owner}/${context.repo.repo}`,
        'X-Title': 'RUBIN Protocol Security Review',
      };

  const requestBody = {
    model: modelId,
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userPrompt },
    ],
    temperature: 0.2,
    top_p: 0.9,
  };
  if (modelId.toLowerCase().startsWith('qwen/')) {
    requestBody.reasoning = { max_tokens: 50000 };
  }
  if (maxTokens > 0) {
    requestBody.max_tokens = maxTokens;
  }
  if (needsJsonMode) {
    requestBody.response_format = { type: 'json_object' };
  }

  const response = await fetch(apiUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    const errText = await response.text();
    core.setFailed(`API error ${response.status}: ${errText.slice(0, 500)}`);
    return;
  }

  const responseText = await response.text();
  let data;
  try {
    data = JSON.parse(responseText);
  } catch (jsonErr) {
    core.setFailed(`Provider returned 2xx but non-JSON body: ${jsonErr.message}. Body preview: ${responseText.slice(0, 500)}`);
    return;
  }
  const rawContent = data.choices?.[0]?.message?.content || '';
  if (!rawContent) {
    core.setFailed('Empty response from model');
    return;
  }

  let result = rawContent.replace(/<think>[\s\S]*?<\/think>/g, '').trim();
  const jsonMatch = result.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (jsonMatch) {
    result = jsonMatch[1].trim();
  } else {
    const firstBrace = result.indexOf('{');
    const lastBrace = result.lastIndexOf('}');
    if (firstBrace !== -1 && lastBrace > firstBrace) {
      result = result.slice(firstBrace, lastBrace + 1).trim();
    }
  }

  try {
    JSON.parse(result);
  } catch (e) {
    core.warning(`Malformed JSON: ${e.message}. Attempting jsonrepair...`);
    try {
      result = jsonrepair(result);
      JSON.parse(result);
    } catch (e2) {
      fs.writeFileSync('raw-review-output.txt', rawContent);
      core.setFailed(`jsonrepair failed: ${e2.message}`);
      return;
    }
  }

  fs.writeFileSync('review-output.json', result);
  core.setOutput('review_file', 'review-output.json');
};
