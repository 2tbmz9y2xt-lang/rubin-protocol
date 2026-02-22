#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import { repoRoot, run } from './_lib.mjs'

const argSet = new Set(process.argv.slice(2))
const allowDirty = argSet.has('--allow-dirty')
const allowMain = argSet.has('--allow-main') || (process.env.CI && argSet.has('--ci-allow-main'))
const allowDetached = argSet.has('--allow-detached') || Boolean(process.env.CI)
const allowLocalMainAhead = argSet.has('--allow-local-main-ahead') || Boolean(process.env.CI)

const failures = []

function exists(rel) {
  return fs.existsSync(path.join(repoRoot, '.git', rel))
}

function maybeRun(cmd) {
  try {
    return run(cmd)
  } catch {
    return ''
  }
}

if (exists('rebase-merge') || exists('rebase-apply')) {
  failures.push('git rebase in progress')
}
if (exists('MERGE_HEAD')) {
  failures.push('git merge in progress')
}

const branch = maybeRun('git rev-parse --abbrev-ref HEAD')
if (branch === 'HEAD' && !allowDetached) {
  failures.push('detached HEAD is not allowed (use --allow-detached to override)')
}
if (branch === 'main' && !allowMain) {
  failures.push('direct work on main is blocked (create a codex/* branch)')
}

const dirty = maybeRun('git status --porcelain')
if (dirty && !allowDirty) {
  failures.push('working tree is dirty (use --allow-dirty to override)')
}

const hasOriginMain = maybeRun('git show-ref --verify refs/remotes/origin/main')
if (hasOriginMain && !allowLocalMainAhead) {
  const aheadRaw = maybeRun('git rev-list --count origin/main..main')
  const ahead = Number(aheadRaw || 0)
  if (Number.isFinite(ahead) && ahead > 0) {
    failures.push(`local main is ahead of origin/main by ${ahead} commit(s)`) 
  }
}

if (failures.length > 0) {
  console.error(`branch guard failed (${failures.length}):`)
  for (const f of failures) console.error(` - ${f}`)
  process.exit(1)
}

console.log(`branch guard: OK (branch=${branch || 'unknown'})`)
