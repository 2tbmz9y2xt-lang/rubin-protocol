#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const argv = process.argv.slice(2);

function argValue(flag) {
  const idx = argv.indexOf(flag);
  if (idx === -1 || idx + 1 >= argv.length) {
    return "";
  }
  return argv[idx + 1];
}

function unique(values) {
  const out = [];
  const seen = new Set();
  for (const value of values) {
    if (!value) {
      continue;
    }
    const normalized = path.resolve(value);
    if (seen.has(normalized)) {
      continue;
    }
    seen.add(normalized);
    out.push(normalized);
  }
  return out;
}

function resolveSpecRoot(repoRoot) {
  const cli = argValue("--spec-root");
  const env = process.env.RUBIN_SPEC_ROOT || "";
  const candidates = unique([
    cli,
    env,
    path.join(repoRoot, "spec"),
    path.resolve(repoRoot, "..", "rubin-spec-private", "spec"),
    path.resolve(repoRoot, "..", "rubin-spec", "spec"),
  ]);

  for (const candidate of candidates) {
    const canonical = path.join(candidate, "RUBIN_L1_CANONICAL.md");
    const hashes = path.join(candidate, "SECTION_HASHES.json");
    if (fs.existsSync(canonical) && fs.existsSync(hashes)) {
      return { specRoot: candidate, specPath: canonical, hashesPath: hashes, candidates };
    }
  }
  return { specRoot: "", specPath: "", hashesPath: "", candidates };
}

const resolved = resolveSpecRoot(root);
if (!resolved.specPath || !resolved.hashesPath) {
  console.error("FAIL [spec-root] cannot locate RUBIN_L1_CANONICAL.md + SECTION_HASHES.json");
  console.error(`Tried: ${resolved.candidates.join(", ")}`);
  process.exit(2);
}

const specPath = resolved.specPath;
const hashesPath = resolved.hashesPath;

const spec = fs.readFileSync(specPath, "utf8").replace(/\r\n/g, "\n");
const expectedDoc = JSON.parse(fs.readFileSync(hashesPath, "utf8"));

let expected = expectedDoc;
let hashAlgorithm = "sha256";
if (expectedDoc && typeof expectedDoc === "object" && expectedDoc.sections) {
  expected = expectedDoc.sections;
  if (expectedDoc.hash_algorithm) {
    hashAlgorithm = String(expectedDoc.hash_algorithm).toLowerCase();
  }
  if (!["sha256", "sha3-256"].includes(hashAlgorithm)) {
    console.error(`FAIL [meta] unsupported hash_algorithm: ${hashAlgorithm}`);
    process.exit(1);
  }
}

const fallbackSectionHeadings = {
  transaction_wire: "## 5. Transaction Wire",
  transaction_identifiers: "## 8. Transaction Identifiers (TXID / WTXID)",
  weight_accounting: "## 9. Weight Accounting (Normative)",
  witness_commitment: "### 10.4.1 Witness Commitment (Coinbase Anchor)",
  sighash_v1: "## 12. Sighash v1 (Normative)",
  consensus_error_codes: "## 13. Consensus Error Codes (Normative)",
  covenant_registry: "## 14. Covenant Type Registry (Normative)",
  difficulty_update: "## 15. Difficulty Update (Normative)",
  transaction_structural_rules: "## 16. Transaction Structural Rules (Normative)",
  replay_domain_checks: "## 17. Replay-Domain Checks (Normative)",
  utxo_state_model: "## 18. UTXO State Model (Normative)",
  value_conservation: "## 20. Value Conservation (Normative)",
  da_set_integrity: "## 21. DA Set Integrity (Normative)",
};
const sectionHeadings = expectedDoc.section_headings || fallbackSectionHeadings;

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
  const actual = crypto.createHash(hashAlgorithm).update(section).digest("hex");
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

console.log(`OK: all ${Object.keys(sectionHeadings).length} section hashes match (${resolved.specRoot})`);
