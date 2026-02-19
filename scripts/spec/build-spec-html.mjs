#!/usr/bin/env node
/**
 * Convert canonical spec Markdown -> HTML.
 *
 * Input:  spec/RUBIN_L1_CANONICAL_v1.1.md
 * Output: analysis/spec/RUBIN_L1_CANONICAL_v1.1.html
 *
 * This is tooling-only; output is ignored by git.
 */
import fs from "node:fs";
import path from "node:path";
import { marked } from "marked";

const repoRoot = process.cwd();
const src = path.join(repoRoot, "spec", "RUBIN_L1_CANONICAL_v1.1.md");
const dstDir = path.join(repoRoot, "analysis", "spec");
const dst = path.join(dstDir, "RUBIN_L1_CANONICAL_v1.1.html");

if (!fs.existsSync(src)) {
  console.error(`spec:html: missing input: ${src}`);
  process.exit(1);
}

const md = fs.readFileSync(src, "utf8");
const htmlBody = marked.parse(md);
const template = `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <title>RUBIN L1 CANONICAL v1.1</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 1000px; margin: 32px auto; padding: 0 18px; line-height: 1.6; color: #0f172a; background:#ffffff; }
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
${htmlBody}
</body>
</html>`;

fs.mkdirSync(dstDir, { recursive: true });
fs.writeFileSync(dst, template, "utf8");
console.log(`Spec HTML saved -> ${dst}`);
