#!/usr/bin/env node
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
    if (fs.existsSync(canonical)) {
      return { specRoot: candidate, specPath: canonical, candidates };
    }
  }
  return { specRoot: "", specPath: "", candidates };
}

const resolved = resolveSpecRoot(root);
if (!resolved.specPath) {
  console.error("FAIL [spec-root] cannot locate RUBIN_L1_CANONICAL.md");
  console.error(`Tried: ${resolved.candidates.join(", ")}`);
  process.exit(2);
}
const spec = fs.readFileSync(resolved.specPath, "utf8");

const invariants = [
  { id: "CONST_TARGET_INTERVAL", re: /TARGET_BLOCK_INTERVAL\s*=\s*120/, desc: "TARGET_BLOCK_INTERVAL = 120" },
  { id: "CONST_WINDOW_SIZE", re: /WINDOW_SIZE\s*=\s*10_080/, desc: "WINDOW_SIZE = 10_080" },
  { id: "CONST_MAX_BLOCK_WEIGHT", re: /MAX_BLOCK_WEIGHT\s*=\s*68_000_000/, desc: "MAX_BLOCK_WEIGHT = 68_000_000" },
  { id: "CONST_MAX_DA_BLOCK", re: /MAX_DA_BYTES_PER_BLOCK\s*=\s*32_000_000/, desc: "MAX_DA_BYTES_PER_BLOCK = 32_000_000" },
  { id: "CONST_RELAY_MSG", re: /MAX_RELAY_MSG_BYTES\s*=\s*96_000_000/, desc: "MAX_RELAY_MSG_BYTES = 96_000_000" },
  { id: "CONST_VAULT_KEYS", re: /MAX_VAULT_KEYS\s*=\s*12/, desc: "MAX_VAULT_KEYS = 12" },
  { id: "CONST_MULTISIG_KEYS", re: /MAX_MULTISIG_KEYS\s*=\s*12/, desc: "MAX_MULTISIG_KEYS = 12" },
  { id: "CONST_VAULT_WHITELIST", re: /MAX_VAULT_WHITELIST_ENTRIES\s*=\s*1_?024/, desc: "MAX_VAULT_WHITELIST_ENTRIES = 1024" },
  { id: "CONST_POW_LIMIT", re: /POW_LIMIT_DEVNET\s*=\s*0x[0-9a-fA-F]+/, desc: "POW_LIMIT profile constant defined" },
  { id: "REG_VAULT", re: /0x0101` `CORE_VAULT/, desc: "registry: CORE_VAULT = 0x0101" },
  { id: "REG_DA_COMMIT", re: /0x0103` `CORE_DA_COMMIT/, desc: "registry: CORE_DA_COMMIT = 0x0103" },
  { id: "REG_MULTISIG", re: /0x0104` `CORE_MULTISIG/, desc: "registry: CORE_MULTISIG = 0x0104" },
  { id: "REG_0102_UNASSIGNED", re: /0x0102.*unassigned/, desc: "registry: 0x0102 is unassigned" },
  { id: "RULE_CLAMP_POW_LIMIT", re: /min\(target_old \* 4,\s*POW_LIMIT\)/, desc: "retarget clamp uses POW_LIMIT" },
  { id: "RULE_TARGET_RANGE", re: /1 <= target <= POW_LIMIT/, desc: "target range bound present" },
  { id: "RULE_320_BIT", re: /320-bit/, desc: "320-bit arithmetic requirement present" },
  { id: "CURSOR_MODEL", re: /WitnessItems are consumed by inputs using a cursor model/, desc: "cursor model section present" },
  { id: "CURSOR_WITNESS_SLOTS", re: /witness_slots\(e\)/, desc: "witness_slots(e) rule present" },
  { id: "OUTPUT_DESCRIPTOR_SECTION", re: /### 18\.3 OutputDescriptorBytes \(Normative\)/, desc: "OutputDescriptorBytes section present" },
  { id: "OUTPUT_VALUE_EXCLUDED", re: /`output\.value` is intentionally excluded/, desc: "OutputDescriptor excludes value" },
  { id: "DA_COMMIT_ERR", re: /BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID/, desc: "DA payload commit error code present" },
  { id: "VALIDATION_ORDER_SECTION", re: /## 25\. Block Validation Order \(Normative\)/, desc: "validation order section present" },
];

let failed = 0;
for (const inv of invariants) {
  if (!inv.re.test(spec)) {
    console.error(`FAIL [${inv.id}] ${inv.desc}`);
    failed += 1;
  }
}

if (failed > 0) {
  console.error(`FAILED: ${failed}/${invariants.length} invariants missing`);
  process.exit(1);
}

console.log(`OK: ${invariants.length} invariants (${resolved.specRoot})`);
