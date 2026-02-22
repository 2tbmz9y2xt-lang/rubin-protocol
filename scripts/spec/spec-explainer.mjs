#!/usr/bin/env node
/**
 * Produce an offline heuristic explainer for analysis/spec/spec-diff.json.
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

const input = JSON.parse(fs.readFileSync(diffPath, 'utf8'))
const diff = String(input.diff || '')
const changedFiles = Array.isArray(input.changed_files) ? input.changed_files : []
const updated = new Date().toISOString().replace('T', ' ').slice(0, 19)

function classify(text) {
  const lower = text.toLowerCase()
  const findings = []

  const touchesConsensus =
    /\b(must|normative|consensus|block_err_|tx_err_|sighash|pow|utxo|covenant)\b/i.test(text)
  const touchesWeight = /weight|max_block_weight|witness_discount/i.test(lower)
  const touchesP2P = /compact|shortid|relay|mempool|orphan|cmpctblock/i.test(lower)
  const touchesDA = /\bda_|payload|chunk|commit\b/i.test(lower)
  const touchesEconomics = /subsidy|max_supply|coinbase|fee/i.test(lower)

  if (text.includes('No spec changes')) {
    return [
      {
        area: 'No-op',
        impact: 'docs',
        summary: 'No spec changes detected.',
        action: 'No action required.',
        risk: 'low',
      },
    ]
  }

  if (touchesConsensus) {
    findings.push({
      area: 'Consensus semantics',
      impact: 'consensus',
      summary: 'Normative consensus sections were changed.',
      action: 'Run cross-client conformance and parity checks before merge.',
      risk: 'high',
    })
  }
  if (touchesWeight) {
    findings.push({
      area: 'Weight / throughput',
      impact: 'consensus',
      summary: 'Weight or witness accounting related text changed.',
      action: 'Recompute TPS/weight examples and confirm code constants.',
      risk: 'medium',
    })
  }
  if (touchesDA || touchesP2P) {
    findings.push({
      area: 'DA / relay',
      impact: touchesConsensus ? 'consensus+p2p' : 'p2p',
      summary: 'DA payload or compact relay behavior changed.',
      action: 'Re-run CV-COMPACT and verify block/data commitment consistency.',
      risk: 'medium',
    })
  }
  if (touchesEconomics) {
    findings.push({
      area: 'Economics',
      impact: 'consensus',
      summary: 'Subsidy/coinbase/economic parameters changed.',
      action: 'Re-validate emission tables and coinbase constraints.',
      risk: 'medium',
    })
  }
  if (findings.length === 0) {
    findings.push({
      area: 'Documentation',
      impact: 'docs',
      summary: 'No critical keyword clusters detected; likely wording/structure updates.',
      action: 'Perform quick manual review for references and numbering.',
      risk: 'low',
    })
  }

  return findings
}

const output = {
  updated,
  changed_files: changedFiles,
  note: 'Heuristic offline explainer.',
  findings: classify(diff),
}

fs.mkdirSync(path.dirname(outPath), { recursive: true })
fs.writeFileSync(outPath, JSON.stringify(output, null, 2), 'utf8')
console.log(`[${updated}] spec-explainer saved -> ${outPath} (${output.findings.length} finding(s))`)
