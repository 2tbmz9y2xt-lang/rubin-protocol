#!/usr/bin/env node
/**
 * Convert all spec/*.md files to HTML.
 *
 * Input:  spec/*.md
 * Output: analysis/spec/html/*.html
 */
import fs from 'node:fs'
import path from 'node:path'
import { marked } from 'marked'

const repoRoot = process.cwd()
const srcDir = path.join(repoRoot, 'spec')
const outDir = path.join(repoRoot, 'analysis', 'spec', 'html')

if (!fs.existsSync(srcDir)) {
  console.error(`spec:html: missing directory: ${srcDir}`)
  process.exit(1)
}

const files = fs
  .readdirSync(srcDir)
  .filter((f) => f.endsWith('.md'))
  .sort((a, b) => a.localeCompare(b))

if (files.length === 0) {
  console.error('spec:html: no markdown files found in ./spec')
  process.exit(1)
}

fs.mkdirSync(outDir, { recursive: true })

function render(title, body) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 1024px; margin: 32px auto; padding: 0 18px; line-height: 1.6; color: #0f172a; background:#fff; }
    code { background: #f1f5f9; padding: 2px 5px; border-radius: 4px; }
    pre { background: #0b0d14; color: #f4f6fb; padding: 12px; border-radius: 8px; overflow-x: auto; }
    table { border-collapse: collapse; width: 100%; margin: 12px 0; }
    th, td { border: 1px solid #e2e8f0; padding: 6px 8px; }
    th { background: #f8fafc; }
    tr:nth-child(even) { background: #f8fafc; }
    a { color: #0ea5e9; }
  </style>
</head>
<body>
${body}
</body>
</html>`
}

const generated = []
for (const file of files) {
  const src = path.join(srcDir, file)
  const md = fs.readFileSync(src, 'utf8')
  const htmlBody = marked.parse(md)
  const name = file.replace(/\.md$/, '')
  const dst = path.join(outDir, `${name}.html`)
  fs.writeFileSync(dst, render(name, htmlBody), 'utf8')
  generated.push(dst)
}

console.log(`spec:html: generated ${generated.length} file(s)`)
for (const f of generated) console.log(` - ${f}`)
