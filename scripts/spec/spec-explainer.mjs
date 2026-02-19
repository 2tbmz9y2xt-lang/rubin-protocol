#!/usr/bin/env node
/**
 * Produce a lightweight explainer for spec-diff.json without external LLM deps.
 *
 * Input:  analysis/spec/spec-diff.json
 * Output: analysis/spec/spec-explainer.json
 */
import fs from 'node:fs'
import path from 'node:path'

const repoRoot = process.cwd()
const diffPath = path.join(repoRoot, 'analysis', 'spec', 'spec-diff.json')
const outPath = path.join(repoRoot, 'analysis', 'spec', 'spec-explainer.json')

if (!fs.existsSync(diffPath)) {
  console.error('spec:explain: missing analysis/spec/spec-diff.json; run spec:diff first')
  process.exit(1)
}

const diffData = JSON.parse(fs.readFileSync(diffPath, 'utf8'))
const diff = String(diffData.diff || '')
const updated = new Date().toISOString().replace('T', ' ').slice(0, 19)

function explain(d) {
  const lower = d.toLowerCase()
  const findings = []

  const hasConsensus = /\b(consensus|block_err_|tx_err_|must|normative)\b/i.test(d)
  const touchesWeight = /\bweight\b|max_block_weight|verify_cost/i.test(lower)
  const touchesWitness = /\bwitness\b|max_witness/i.test(lower)
  const touchesAnchor = /\banchor\b|max_anchor/i.test(lower)
  const touchesDeploy = /version_bits|deployment|locked_in|active|failed/i.test(lower)
  const touchesHtlc = /\bhtlc\b/i.test(lower)

  if (diff.includes('No changes')) {
    return [
      {
        area: 'No-op',
        impact: 'docs',
        summary: 'No changes in canonical spec relative to HEAD.',
        action: 'No action required.',
        risk: 'low',
      },
    ]
  }

  if (touchesWeight || touchesWitness) {
    findings.push({
      area: 'L1 weight/TPS',
      impact: 'consensus',
      summary: 'Weight and/or witness rules were touched; TPS and DoS thresholds may change.',
      action: 'Run the conformance bundle and recompute derived metrics.',
      risk: 'medium',
    })
  }
  if (touchesAnchor) {
    findings.push({
      area: 'ANCHOR limits',
      impact: 'consensus',
      summary: 'ANCHOR limits/semantics were touched.',
      action: 'Re-check per-block limits, relay policy, and the light-client anchorproof protocol.',
      risk: 'medium',
    })
  }
  if (touchesDeploy) {
    findings.push({
      area: 'VERSION_BITS',
      impact: 'consensus',
      summary: 'Deployment/activation logic was touched (VERSION_BITS).',
      action: 'Verify deployment tables for devnet/testnet/mainnet and cross-client interpretation.',
      risk: 'medium',
    })
  }
  if (touchesHtlc) {
    findings.push({
      area: 'HTLC',
      impact: hasConsensus ? 'consensus' : 'docs',
      summary: 'HTLC rules/descriptions were touched.',
      action: 'Check error codes and conformance CV-HTLC/CV-HTLC-ANCHOR.',
      risk: 'low',
    })
  }

  if (findings.length === 0) {
    findings.push({
      area: 'Docs/format',
      impact: hasConsensus ? 'consensus' : 'docs',
      summary: 'Diff did not touch typical key areas (weight/witness/anchor/deploy/htlc).',
      action: 'Review the diff manually for terminology and references.',
      risk: 'low',
    })
  }
  return findings
}

const findings = explain(diff)
const output = {
  updated,
  note: 'Heuristic explainer (offline).',
  findings,
}

fs.mkdirSync(path.dirname(outPath), { recursive: true })
fs.writeFileSync(outPath, JSON.stringify(output, null, 2), 'utf8')
console.log(`[${updated}] spec-explainer.json saved -> ${outPath} (${findings.length} findings)`)
