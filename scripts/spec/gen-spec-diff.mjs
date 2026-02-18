#!/usr/bin/env node
/**
 * Generate git diff for canonical spec and write to analysis/spec/spec-diff.json.
 *
 * Input:  git diff -- spec/RUBIN_L1_CANONICAL_v1.1.md
 * Output: analysis/spec/spec-diff.json
 */
import fs from 'node:fs'
import path from 'node:path'
import { execSync } from 'node:child_process'

const repoRoot = process.cwd()
const target = path.join(repoRoot, 'analysis', 'spec', 'spec-diff.json')
const updated = new Date().toISOString().replace('T', ' ').slice(0, 19)

let diff = ''
try {
  diff = execSync('git diff --unified=3 -- spec/RUBIN_L1_CANONICAL_v1.1.md', {
    cwd: repoRoot,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim()
  if (!diff) diff = 'Нет изменений в каноникале относительно текущего HEAD.'
} catch (e) {
  diff = `Не удалось получить diff: ${e.message}`
}

fs.mkdirSync(path.dirname(target), { recursive: true })
fs.writeFileSync(target, JSON.stringify({ updated, diff }, null, 2), 'utf8')
console.log(`[${updated}] spec-diff.json saved -> ${target}`)

