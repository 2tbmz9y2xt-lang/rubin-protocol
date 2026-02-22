#!/usr/bin/env node
/**
 * Generate git diff for ./spec and write to analysis/spec/spec-diff.json.
 *
 * Input:  git diff -- spec/
 * Output: analysis/spec/spec-diff.json
 */
import fs from 'node:fs'
import path from 'node:path'
import { execSync } from 'node:child_process'

const repoRoot = process.cwd()
const outPath = path.join(repoRoot, 'analysis', 'spec', 'spec-diff.json')
const updated = new Date().toISOString().replace('T', ' ').slice(0, 19)

let diff = ''
let changedFiles = []

try {
  diff = execSync('git diff --unified=3 -- spec/', {
    cwd: repoRoot,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim()
  changedFiles = execSync('git diff --name-only -- spec/', {
    cwd: repoRoot,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  })
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean)
  if (!diff) diff = 'No spec changes relative to current HEAD.'
} catch (e) {
  diff = `Failed to collect diff: ${e.message}`
}

fs.mkdirSync(path.dirname(outPath), { recursive: true })
fs.writeFileSync(
  outPath,
  JSON.stringify({ updated, changed_files: changedFiles, diff }, null, 2),
  'utf8',
)
console.log(`[${updated}] spec-diff saved -> ${outPath}`)
