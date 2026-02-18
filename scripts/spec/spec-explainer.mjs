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

  if (diff.includes('Нет изменений')) {
    return [
      {
        area: 'No-op',
        impact: 'docs',
        summary: 'Изменений в каноникале относительно HEAD нет.',
        action: 'Ничего делать не нужно.',
        risk: 'low',
      },
    ]
  }

  if (touchesWeight || touchesWitness) {
    findings.push({
      area: 'L1 weight/TPS',
      impact: 'consensus',
      summary: 'Изменены/затронуты правила веса или witness. Это может менять TPS и DoS-порог.',
      action: 'Прогнать conformance bundle и пересчитать производные метрики.',
      risk: 'medium',
    })
  }
  if (touchesAnchor) {
    findings.push({
      area: 'ANCHOR limits',
      impact: 'consensus',
      summary: 'Затронуты ANCHOR-ограничения/семантика.',
      action: 'Сверить per-block лимиты, relay-политику и light-client anchorproof протокол.',
      risk: 'medium',
    })
  }
  if (touchesDeploy) {
    findings.push({
      area: 'VERSION_BITS',
      impact: 'consensus',
      summary: 'Затронуты deployment/активации (VERSION_BITS).',
      action: 'Проверить deployment таблицы для devnet/testnet/mainnet и cross-client интерпретацию.',
      risk: 'medium',
    })
  }
  if (touchesHtlc) {
    findings.push({
      area: 'HTLC',
      impact: hasConsensus ? 'consensus' : 'docs',
      summary: 'Затронуты HTLC правила/описания.',
      action: 'Проверить error codes и conformance CV-HTLC/CV-HTLC-ANCHOR.',
      risk: 'low',
    })
  }

  if (findings.length === 0) {
    findings.push({
      area: 'Docs/format',
      impact: hasConsensus ? 'consensus' : 'docs',
      summary: 'Diff не зацепил типовые ключевые области (weight/witness/anchor/deploy/htlc).',
      action: 'Просмотреть diff вручную на предмет терминологии и ссылок.',
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

