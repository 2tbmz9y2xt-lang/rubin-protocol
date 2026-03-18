#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outPath = path.join(root, "spec", "SECTION_HASHES.json");
const defaultSourceFile = "spec/RUBIN_L1_CANONICAL.md";
const sectionSources = {
  replay_domain_checks: "spec/RUBIN_CONSENSUS_STATE_MACHINE.md",
  utxo_state_model: "spec/RUBIN_CONSENSUS_STATE_MACHINE.md",
};
const allowedSourceFiles = [defaultSourceFile, ...new Set(Object.values(sectionSources))];

const sectionHeadings = {
  transaction_wire: "## 5. Transaction Wire",
  transaction_identifiers: "## 8. Transaction Identifiers (TXID / WTXID)",
  weight_accounting: "## 9. Weight Accounting (Normative)",
  witness_commitment: "### 10.4.1 Witness Commitment (Coinbase Anchor)",
  sighash_v1: "## 12. Sighash v1 (Normative)",
  consensus_error_codes: "## 13. Consensus Error Codes (Normative)",
  covenant_registry: "## 14. Covenant Type Registry (Normative)",
  difficulty_update: "## 15. Difficulty Update (Normative)",
  transaction_structural_rules: "## 16. Transaction Structural Rules (Normative)",
  replay_domain_checks: "## 1. Replay-Domain Checks (Normative)",
  utxo_state_model: "## 2. UTXO State Model (Normative)",
  value_conservation: "## 20. Value Conservation (Normative)",
  da_set_integrity: "## 21. DA Set Integrity (Normative)",
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
const sources = new Map();
for (const [key, heading] of Object.entries(sectionHeadings)) {
  const srcRel = sectionSources[key] || defaultSourceFile;
  if (!sources.has(srcRel)) {
    const srcPath = path.join(root, srcRel);
    sources.set(srcRel, fs.readFileSync(srcPath, "utf8").replace(/\r\n/g, "\n"));
  }
  const section = extractSection(sources.get(srcRel), heading);
  if (!section) {
    console.error(`Section not found: ${heading} (${srcRel})`);
    process.exit(1);
  }
  hashes[key] = crypto.createHash("sha3-256").update(section).digest("hex");
  console.log(`${key}: ${hashes[key]}`);
}

const doc = {
  schema_version: 2,
  hash_algorithm: "sha3-256",
  source_file: defaultSourceFile,
  canonicalization:
    "LF normalization; extract markdown from exact section heading to next heading of same/higher level; trim; append trailing LF",
  allowed_source_files: allowedSourceFiles,
  section_sources: sectionSources,
  section_headings: sectionHeadings,
  sections: hashes,
};

fs.writeFileSync(outPath, JSON.stringify(doc, null, 2) + "\n", "utf8");
console.log(`Updated ${outPath}`);
