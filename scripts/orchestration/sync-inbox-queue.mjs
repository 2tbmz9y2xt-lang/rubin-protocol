#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import { nowIso, resolveInboxDir } from './_lib.mjs'

function parseArgs(args) {
  const out = {}
  for (let i = 0; i < args.length; i += 1) {
    const key = args[i]
    if (!key.startsWith('--')) continue
    const name = key.slice(2)
    const next = args[i + 1]
    if (!next || next.startsWith('--')) {
      out[name] = true
      continue
    }
    out[name] = next
    i += 1
  }
  return out
}

function read(filePath) {
  return fs.readFileSync(filePath, 'utf8')
}

function write(filePath, data) {
  fs.writeFileSync(filePath, data, 'utf8')
}

function formatRow(cells) {
  return `| ${cells.join(' | ')} |`
}

function nextInboxId(inboxContent) {
  const nums = [...inboxContent.matchAll(/\|\s*I-(\d+)\s*\|/g)].map((m) => Number(m[1]))
  const max = nums.length > 0 ? Math.max(...nums) : 0
  return `I-${String(max + 1).padStart(3, '0')}`
}

function updateQueue(queueText, taskId, status, report) {
  const lines = queueText.split('\n')
  const rowRx = new RegExp(`^\\|\\s*${taskId.replace(/[.*+?^${}()|[\\]\\]/g, '\\$&')}\\s*\\|`)

  let found = false
  for (let i = 0; i < lines.length; i += 1) {
    if (!rowRx.test(lines[i])) continue
    const parts = lines[i].split('|').slice(1, -1).map((x) => x.trim())
    if (parts.length < 5) {
      throw new Error(`queue row malformed for ${taskId}`)
    }
    parts[1] = status
    if (report) parts[4] = report
    lines[i] = formatRow(parts)
    found = true
    break
  }

  if (!found) {
    throw new Error(`task not found in QUEUE: ${taskId}`)
  }

  return lines.join('\n')
}

function insertInboxRow(inboxText, row) {
  const lines = inboxText.split('\n')
  const activeIdx = lines.findIndex((l) => l.trim() === '## Активные')
  if (activeIdx === -1) {
    lines.push('')
    lines.push('## Активные')
    lines.push('')
    lines.push('| ID | Date | From | Status | Subject | Link |')
    lines.push('|---|---|---|---|---|---|')
    lines.push(row)
    return lines.join('\n')
  }

  let headerIdx = -1
  for (let i = activeIdx + 1; i < lines.length; i += 1) {
    if (lines[i].startsWith('| ID | Date | From | Status | Subject | Link |')) {
      headerIdx = i
      break
    }
    if (lines[i].startsWith('## ') && i > activeIdx + 1) break
  }

  if (headerIdx === -1) {
    lines.splice(activeIdx + 1, 0, '', '| ID | Date | From | Status | Subject | Link |', '|---|---|---|---|---|---|', row)
    return lines.join('\n')
  }

  const separatorIdx = headerIdx + 1
  lines.splice(separatorIdx + 1, 0, row)
  return lines.join('\n')
}

function todayDate() {
  return nowIso().slice(0, 10)
}

function main() {
  const opts = parseArgs(process.argv.slice(2))
  const taskId = String(opts['task-id'] || '').trim()
  const status = String(opts.status || '').trim()
  const subject = String(opts.subject || '').trim()

  if (!taskId) {
    console.error('missing --task-id')
    process.exit(1)
  }
  if (!status) {
    console.error('missing --status')
    process.exit(1)
  }
  if (!subject) {
    console.error('missing --subject')
    process.exit(1)
  }

  const validStatuses = new Set(['OPEN', 'CLAIMED', 'DONE', 'BLOCKED'])
  if (!validStatuses.has(status)) {
    console.error('status must be OPEN/CLAIMED/DONE/BLOCKED')
    process.exit(1)
  }

  const inboxDir = resolveInboxDir()
  const queuePath = path.resolve(String(opts.queue || path.join(inboxDir, 'QUEUE.md')))
  const inboxPath = path.resolve(String(opts.inbox || path.join(inboxDir, 'INBOX.md')))

  if (!fs.existsSync(queuePath)) {
    console.error(`QUEUE not found: ${queuePath}`)
    process.exit(1)
  }
  if (!fs.existsSync(inboxPath)) {
    console.error(`INBOX not found: ${inboxPath}`)
    process.exit(1)
  }

  const report = String(opts.report || '').trim()
  const from = String(opts.from || 'Codex').trim()
  const inboxStatus = String(opts['inbox-status'] || (status === 'DONE' ? 'DONE' : 'NEW')).trim()
  const link = report || `queue: ${taskId}`
  const date = String(opts.date || todayDate())

  const queueText = read(queuePath)
  const updatedQueue = updateQueue(queueText, taskId, status, report)
  write(queuePath, updatedQueue)

  const inboxText = read(inboxPath)
  const id = nextInboxId(inboxText)
  const row = formatRow([id, date, from, inboxStatus, subject, link])
  const updatedInbox = insertInboxRow(inboxText, row)
  write(inboxPath, updatedInbox)

  console.log(`queue updated: ${queuePath} (${taskId} -> ${status})`)
  console.log(`inbox row added: ${id} @ ${inboxPath}`)
}

main()
