#!/usr/bin/env node
import { runStreaming } from './_lib.mjs'

const args = new Set(process.argv.slice(2))
const fast = args.has('--fast')
const allowDirty = args.has('--allow-dirty')
const allowMain = args.has('--allow-main')
const skipSpecAll = args.has('--skip-spec-all')
const skipGo = args.has('--skip-go')
const skipRust = args.has('--skip-rust')
const skipConformance = args.has('--skip-conformance')
const allowLocalMainAhead = args.has('--allow-local-main-ahead')

const steps = []

function addStep(name, cmd) {
  steps.push({ name, cmd })
}

const guardFlags = []
if (allowDirty) guardFlags.push('--allow-dirty')
if (allowMain) guardFlags.push('--allow-main')
if (allowLocalMainAhead) guardFlags.push('--allow-local-main-ahead')
if (process.env.CI) {
  guardFlags.push('--ci-allow-main', '--allow-detached', '--allow-local-main-ahead')
}

addStep('Branch guard', `node scripts/orchestration/guard-branch.mjs ${guardFlags.join(' ')}`.trim())
addStep('Spec drift check', 'node scripts/orchestration/check-spec-drift.mjs')
addStep('State init', 'node scripts/orchestration/state.mjs init')
addStep('State validate', 'node scripts/orchestration/state.mjs validate')

if (!fast) {
  if (!skipGo) addStep('Go tests', '( cd clients/go && go test ./... )')
  if (!skipRust) addStep('Rust tests', '( cd clients/rust && cargo test --workspace )')
  if (!skipConformance) addStep('Conformance bundle', 'python3 conformance/runner/run_cv_bundle.py')
  if (!skipSpecAll) addStep('Spec tooling', 'npm run spec:all')
}

for (let i = 0; i < steps.length; i += 1) {
  const step = steps[i]
  console.log(`[${i + 1}/${steps.length}] ${step.name}`)
  runStreaming(step.cmd)
}

console.log('preflight: OK')
