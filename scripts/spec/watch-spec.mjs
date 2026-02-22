#!/usr/bin/env node
/**
 * Watch ./spec for markdown changes and run spec pipeline.
 */
import fs from 'node:fs'
import path from 'node:path'
import { execSync } from 'node:child_process'

const repoRoot = process.cwd()
const specDir = path.join(repoRoot, 'spec')

if (!fs.existsSync(specDir)) {
  console.error(`spec:watch: missing directory: ${specDir}`)
  process.exit(1)
}

let queued = false
function run(reason) {
  if (queued) return
  queued = true
  setTimeout(() => {
    queued = false
    const ts = new Date().toISOString().replace('T', ' ').slice(0, 19)
    try {
      execSync('npm run -s spec:all', { stdio: 'inherit', cwd: repoRoot })
      console.log(`[${ts}] spec pipeline done (${reason})`)
    } catch (e) {
      console.error(`[${ts}] spec pipeline failed (${reason}): ${e.message}`)
    }
  }, 250)
}

run('initial')
fs.watch(specDir, { persistent: true }, (_event, filename) => {
  if (!filename || !filename.endsWith('.md')) return
  run(`change:${filename}`)
})
