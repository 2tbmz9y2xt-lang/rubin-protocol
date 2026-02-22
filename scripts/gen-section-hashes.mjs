#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const specPath = path.join(root, "spec", "RUBIN_L1_CANONICAL.md");
const outPath = path.join(root, "spec", "SECTION_HASHES.json");
const spec = fs.readFileSync(specPath, "utf8").replace(/\r\n/g, "\n");

const sectionHeadings = {
  transaction_identifiers: "## 8. Transaction Identifiers (TXID / WTXID)",
  weight_accounting: "## 9. Weight Accounting (Normative)",
  sighash_v1: "## 12. Sighash v1 (Normative)",
  consensus_error_codes: "## 13. Consensus Error Codes (Normative)",
  difficulty_update: "## 15. Difficulty Update (Normative)",
  value_conservation: "## 20. Value Conservation (Normative)",
};

function extractSection(md, heading) {
  const lines = md.split("\n");
  const start = lines.findIndex((line) => line.trim() === heading);
  if (start === -1) {
    return null;
  }
  const level = heading.match(/^#+/)[0].length;
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i += 1) {
    const m = lines[i].match(/^(#+)\s/);
    if (!m) {
      continue;
    }
    if (m[1].length <= level) {
      end = i;
      break;
    }
  }
  return lines.slice(start, end).join("\n").trim() + "\n";
}

const hashes = {};
for (const [key, heading] of Object.entries(sectionHeadings)) {
  const section = extractSection(spec, heading);
  if (!section) {
    console.error(`Section not found: ${heading}`);
    process.exit(1);
  }
  hashes[key] = crypto.createHash("sha256").update(section).digest("hex");
  console.log(`${key}: ${hashes[key]}`);
}

const doc = {
  schema_version: 1,
  hash_algorithm: "sha256",
  source_file: "spec/RUBIN_L1_CANONICAL.md",
  canonicalization:
    "LF normalization; extract markdown from exact section heading to next heading of same/higher level; trim; append trailing LF",
  section_headings: sectionHeadings,
  sections: hashes,
};

fs.writeFileSync(outPath, JSON.stringify(doc, null, 2) + "\n", "utf8");
console.log(`Updated ${outPath}`);
