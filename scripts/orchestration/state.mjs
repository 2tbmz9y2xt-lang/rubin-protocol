#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import {
  ensureDirFor,
  fileSha256,
  nowIso,
  repoRoot,
  resolveStatePath,
} from './_lib.mjs'

const canonicalPath = path.join(repoRoot, 'spec', 'RUBIN_L1_CANONICAL.md')
const compactPath = path.join(repoRoot, 'spec', 'RUBIN_COMPACT_BLOCKS.md')
const networkPath = path.join(repoRoot, 'spec', 'RUBIN_NETWORK_PARAMS.md')

function readState(statePath) {
  if (!fs.existsSync(statePath)) return null
  return JSON.parse(fs.readFileSync(statePath, 'utf8'))
}

function writeState(statePath, state) {
  ensureDirFor(statePath)
  fs.writeFileSync(statePath, `${JSON.stringify(state, null, 2)}\n`, 'utf8')
}

function requiredString(v) {
  return typeof v === 'string' && v.trim() !== ''
}

function validateStateObject(obj) {
  const errors = []
  if (!obj || typeof obj !== 'object') errors.push('state must be an object')
  if (obj?.version !== 1) errors.push('version must be 1')
  const status = obj?.status
  if (!['IN_PROGRESS', 'BLOCKED', 'DONE', 'SKIPPED'].includes(status)) {
    errors.push('status must be one of IN_PROGRESS/BLOCKED/DONE/SKIPPED')
  }
  if (!requiredString(obj?.active_phase)) errors.push('active_phase must be non-empty string')
  if (!requiredString(obj?.active_task_id)) errors.push('active_task_id must be non-empty string')
  if (!requiredString(obj?.next_step)) errors.push('next_step must be non-empty string')
  if (typeof obj?.last_merged_pr !== 'string') errors.push('last_merged_pr must be string')
  const spec = obj?.spec_hashes
  const hashRx = /^[a-f0-9]{64}$/
  if (!spec || typeof spec !== 'object') {
    errors.push('spec_hashes must be object')
  } else {
    for (const k of ['canonical_sha256', 'compact_sha256', 'network_sha256']) {
      if (!hashRx.test(String(spec[k] || ''))) errors.push(`spec_hashes.${k} must be 64 hex chars`)
    }
  }
  if (!requiredString(obj?.updated_at)) errors.push('updated_at must be non-empty string')
  return errors
}

function currentSpecHashes() {
  return {
    canonical_sha256: fileSha256(canonicalPath),
    compact_sha256: fileSha256(compactPath),
    network_sha256: fileSha256(networkPath),
  }
}

function defaultState() {
  return {
    version: 1,
    status: 'IN_PROGRESS',
    active_phase: 'S0',
    active_task_id: 'Q-C001',
    next_step: 'Continue roadmap execution from highest-priority open task.',
    last_merged_pr: '',
    spec_hashes: currentSpecHashes(),
    updated_at: nowIso(),
  }
}

function parseArgs(args) {
  const out = {}
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i]
    if (!a.startsWith('--')) continue
    const key = a.slice(2)
    const val = args[i + 1]
    out[key] = val
    i += 1
  }
  return out
}

function usage() {
  console.log('Usage:')
  console.log('  node scripts/orchestration/state.mjs init')
  console.log('  node scripts/orchestration/state.mjs validate')
  console.log('  node scripts/orchestration/state.mjs show')
  console.log(
    '  node scripts/orchestration/state.mjs set --status IN_PROGRESS --phase C1 --task Q-R001 --next-step "..." --last-pr 123',
  )
}

function main() {
  const cmd = process.argv[2]
  const opts = parseArgs(process.argv.slice(3))
  const statePath = resolveStatePath()

  if (!cmd) {
    usage()
    process.exit(1)
  }

  if (cmd === 'init') {
    if (fs.existsSync(statePath)) {
      console.log(`state exists: ${statePath}`)
      process.exit(0)
    }
    const state = defaultState()
    writeState(statePath, state)
    console.log(`state initialized: ${statePath}`)
    process.exit(0)
  }

  if (cmd === 'show') {
    const state = readState(statePath)
    if (!state) {
      console.error(`state missing: ${statePath}`)
      process.exit(1)
    }
    console.log(JSON.stringify(state, null, 2))
    process.exit(0)
  }

  if (cmd === 'validate') {
    const state = readState(statePath)
    if (!state) {
      console.error(`state missing: ${statePath}`)
      process.exit(1)
    }
    const errors = validateStateObject(state)
    if (errors.length > 0) {
      console.error(`state invalid (${errors.length}):`)
      for (const e of errors) console.error(` - ${e}`)
      process.exit(1)
    }
    console.log(`state valid: ${statePath}`)
    process.exit(0)
  }

  if (cmd === 'set') {
    const state = readState(statePath) || defaultState()
    if (opts.status) state.status = opts.status
    if (opts.phase) state.active_phase = opts.phase
    if (opts.task) state.active_task_id = opts.task
    if (opts['next-step']) state.next_step = opts['next-step']
    if (opts['last-pr']) state.last_merged_pr = String(opts['last-pr']).startsWith('#')
      ? String(opts['last-pr'])
      : `#${opts['last-pr']}`
    state.spec_hashes = currentSpecHashes()
    state.updated_at = nowIso()

    const errors = validateStateObject(state)
    if (errors.length > 0) {
      console.error(`refusing to write invalid state (${errors.length}):`)
      for (const e of errors) console.error(` - ${e}`)
      process.exit(1)
    }
    writeState(statePath, state)
    console.log(`state updated: ${statePath}`)
    process.exit(0)
  }

  usage()
  process.exit(1)
}

main()
