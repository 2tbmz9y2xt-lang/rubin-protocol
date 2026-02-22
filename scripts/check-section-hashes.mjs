#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const specPath = path.join(root, "spec", "RUBIN_L1_CANONICAL.md");
const hashesPath = path.join(root, "spec", "SECTION_HASHES.json");

const spec = fs.readFileSync(specPath, "utf8").replace(/\r\n/g, "\n");
const expectedDoc = JSON.parse(fs.readFileSync(hashesPath, "utf8"));

let expected = expectedDoc;
if (expectedDoc && typeof expectedDoc === "object" && expectedDoc.sections) {
  expected = expectedDoc.sections;
  if (expectedDoc.hash_algorithm && expectedDoc.hash_algorithm !== "sha256") {
    console.error(`FAIL [meta] unsupported hash_algorithm: ${expectedDoc.hash_algorithm}`);
    process.exit(1);
  }
}

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

let failed = 0;
for (const [key, heading] of Object.entries(sectionHeadings)) {
  const section = extractSection(spec, heading);
  if (!section) {
    console.error(`FAIL [${key}] missing section: ${heading}`);
    failed += 1;
    continue;
  }
  const actual = crypto.createHash("sha256").update(section).digest("hex");
  if (actual !== expected[key]) {
    console.error(`FAIL [${key}] hash mismatch`);
    console.error(`  expected: ${expected[key]}`);
    console.error(`  actual:   ${actual}`);
    failed += 1;
  } else {
    console.log(`OK   [${key}]`);
  }
}

if (failed > 0) {
  console.error(`FAILED: ${failed}/${Object.keys(sectionHeadings).length} section hashes mismatch`);
  process.exit(1);
}

console.log(`OK: all ${Object.keys(sectionHeadings).length} section hashes match`);
