#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { execSync } from 'node:child_process'

export const repoRoot = process.cwd()

export function run(cmd, opts = {}) {
  return execSync(cmd, {
    cwd: repoRoot,
    stdio: ['ignore', 'pipe', 'pipe'],
    encoding: 'utf8',
    ...opts,
  }).trim()
}

export function runStreaming(cmd, opts = {}) {
  execSync(cmd, {
    cwd: repoRoot,
    stdio: 'inherit',
    ...opts,
  })
}

export function normalizeNumberText(v) {
  return String(v || '').replace(/[^0-9]/g, '')
}

export function fileSha256(filePath) {
  const data = fs.readFileSync(filePath)
  return crypto.createHash('sha256').update(data).digest('hex')
}

export function resolveInboxDir() {
  const fromEnv = process.env.RUBIN_INBOX_DIR
  if (fromEnv && fromEnv.trim() !== '') return path.resolve(fromEnv)
  // Default for current workstation layout: /Users/gpt/Documents/rubin-protocol -> ../inbox
  return path.resolve(repoRoot, '..', 'inbox')
}

export function resolveStatePath() {
  const fromEnv = process.env.RUBIN_STATE_PATH
  if (fromEnv && fromEnv.trim() !== '') return path.resolve(fromEnv)
  return path.join(resolveInboxDir(), 'STATE.json')
}

export function ensureDirFor(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true })
}

export function nowIso() {
  return new Date().toISOString()
}
