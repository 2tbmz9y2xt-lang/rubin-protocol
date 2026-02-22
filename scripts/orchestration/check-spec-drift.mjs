#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import { normalizeNumberText, repoRoot } from './_lib.mjs'

const canonicalPath = path.join(repoRoot, 'spec', 'RUBIN_L1_CANONICAL.md')
const compactPath = path.join(repoRoot, 'spec', 'RUBIN_COMPACT_BLOCKS.md')
const networkPath = path.join(repoRoot, 'spec', 'RUBIN_NETWORK_PARAMS.md')

const files = {
  canonical: canonicalPath,
  compact: compactPath,
  network: networkPath,
}

function readFile(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`missing file: ${filePath}`)
  }
  return fs.readFileSync(filePath, 'utf8')
}

function escRx(value) {
  return String(value).replace(/[.*+?^${}()|[\\]\\]/g, '\\$&')
}

function toNumber(value) {
  const firstNumericToken = String(value).match(/[0-9][0-9_,]*/)
  if (!firstNumericToken) return null
  const normalized = normalizeNumberText(firstNumericToken[0])
  if (!normalized) return null
  const num = Number(normalized)
  return Number.isFinite(num) ? num : null
}

function parseCanonicalConstants(md) {
  const out = {}
  const rx = /^- `([A-Z0-9_]+)\s*=\s*([^`]+)`/gm
  for (const m of md.matchAll(rx)) {
    out[m[1]] = m[2].trim()
  }
  return out
}

function tableValue(md, key) {
  const rx = new RegExp(`\\|\\s*\\x60${escRx(key)}\\x60\\s*\\|\\s*([^|]+?)\\s*\\|`, 'm')
  const m = md.match(rx)
  return m ? m[1].trim() : null
}

function sectionMap(md) {
  const map = new Set()
  const rx = /^#{2,6}\s+([0-9]+(?:\.[0-9]+)*)\b/gm
  for (const m of md.matchAll(rx)) {
    map.add(m[1])
  }
  return map
}

function hasSection(targetSections, sec) {
  if (targetSections.has(sec)) return true
  if (!sec.includes('.')) {
    for (const s of targetSections) {
      if (s === sec || s.startsWith(`${sec}.`)) return true
    }
  }
  return false
}

function collectExternalRefs(fileLabel, md) {
  const refs = []
  const rx = /\b(RUBIN_[A-Z0-9_]+\.md)\s*§\s*([0-9]+(?:\.[0-9]+)*)/g
  for (const m of md.matchAll(rx)) {
    refs.push({ from: fileLabel, targetFile: m[1], section: m[2] })
  }
  return refs
}

function main() {
  const canonical = readFile(canonicalPath)
  const compact = readFile(compactPath)
  const network = readFile(networkPath)

  const errors = []
  const warnings = []

  const canonicalConsts = parseCanonicalConstants(canonical)

  const constantChecks = [
    {
      name: 'TARGET_BLOCK_INTERVAL',
      canonical: canonicalConsts.TARGET_BLOCK_INTERVAL,
      compact: tableValue(compact, 'TARGET_BLOCK_INTERVAL'),
      network: tableValue(network, 'TARGET_BLOCK_INTERVAL'),
    },
    {
      name: 'MAX_BLOCK_WEIGHT',
      canonical: canonicalConsts.MAX_BLOCK_WEIGHT,
      compact: tableValue(compact, 'MAX_BLOCK_WEIGHT'),
      network: tableValue(network, 'MAX_BLOCK_WEIGHT'),
    },
    {
      name: 'MAX_BLOCK_BYTES',
      canonical: null,
      compact: tableValue(compact, 'MAX_BLOCK_BYTES'),
      network: tableValue(network, 'MAX_BLOCK_BYTES'),
    },
    {
      name: 'MAX_DA_BYTES_PER_BLOCK',
      canonical: canonicalConsts.MAX_DA_BYTES_PER_BLOCK,
      compact: tableValue(compact, 'MAX_DA_BYTES_PER_BLOCK'),
      network: tableValue(network, 'MAX_DA_BYTES_PER_BLOCK'),
    },
    {
      name: 'WINDOW_SIZE',
      canonical: canonicalConsts.WINDOW_SIZE,
      compact: tableValue(compact, 'WINDOW_SIZE'),
      network: tableValue(network, 'WINDOW_SIZE'),
    },
    {
      name: 'MIN_DA_RETENTION_BLOCKS',
      canonical: null,
      compact: tableValue(compact, 'MIN_DA_RETENTION_BLOCKS'),
      network: tableValue(network, 'MIN_DA_RETENTION_BLOCKS'),
    },
    {
      name: 'MAX_RELAY_MSG_BYTES',
      canonical: canonicalConsts.MAX_RELAY_MSG_BYTES,
      compact: tableValue(compact, 'MAX_RELAY_MSG_BYTES'),
      network: tableValue(network, 'Max relay message') || tableValue(network, 'MAX_RELAY_MSG_BYTES'),
    },
    {
      name: 'CHUNK_BYTES',
      canonical: canonicalConsts.CHUNK_BYTES,
      compact: null,
      network: tableValue(network, 'Chunk size'),
    },
    {
      name: 'MAX_DA_MANIFEST_BYTES_PER_TX',
      canonical: canonicalConsts.MAX_DA_MANIFEST_BYTES_PER_TX,
      compact: null,
      network: tableValue(network, 'Max DA manifest bytes per tx'),
    },
  ]

  for (const c of constantChecks) {
    const values = [
      ['canonical', c.canonical],
      ['compact', c.compact],
      ['network', c.network],
    ].filter(([, v]) => v !== null && v !== undefined)

    for (const [src, raw] of values) {
      if (raw === null || raw === undefined || String(raw).trim() === '') {
        errors.push(`${c.name}: missing value in ${src}`)
      }
    }

    const numbers = values
      .map(([src, raw]) => [src, toNumber(raw)])
      .filter(([, n]) => n !== null)

    if (numbers.length >= 2) {
      const expected = numbers[0][1]
      for (let i = 1; i < numbers.length; i += 1) {
        const [src, n] = numbers[i]
        if (n !== expected) {
          errors.push(
            `${c.name}: mismatch (${numbers[0][0]}=${numbers[0][1]} vs ${src}=${n})`,
          )
        }
      }
    }

    if (values.length === 0) {
      warnings.push(`${c.name}: no sources found for drift check`) // unreachable in current map
    }
  }

  const docs = {
    canonical: canonical,
    compact: compact,
    network: network,
  }
  const sections = {
    canonical: sectionMap(canonical),
    compact: sectionMap(compact),
    network: sectionMap(network),
  }

  const aliases = {
    'RUBIN_L1_CANONICAL.md': 'canonical',
    'RUBIN_COMPACT_BLOCKS.md': 'compact',
    'RUBIN_NETWORK_PARAMS.md': 'network',
  }

  for (const [label, md] of Object.entries(docs)) {
    const refs = collectExternalRefs(label, md)
    for (const ref of refs) {
      const alias = aliases[ref.targetFile]
      if (!alias) {
        warnings.push(`unknown target in section reference: ${ref.targetFile} (from ${ref.from})`)
        continue
      }
      if (!hasSection(sections[alias], ref.section)) {
        errors.push(
          `broken section reference: ${ref.from} -> ${ref.targetFile} §${ref.section}`,
        )
      }
    }
  }

  if (warnings.length > 0) {
    console.log(`WARNINGS (${warnings.length}):`)
    for (const w of warnings) console.log(` - ${w}`)
  }

  if (errors.length > 0) {
    console.error(`SPEC DRIFT CHECK FAILED (${errors.length})`)
    for (const e of errors) console.error(` - ${e}`)
    process.exit(1)
  }

  console.log('spec drift check: OK')
}

main()
