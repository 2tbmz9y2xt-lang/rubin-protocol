#!/usr/bin/env node
/**
 * Watch canonical spec and re-run spec pipeline on change.
 *
 * Watches: spec/RUBIN_L1_CANONICAL_v1.1.md
 * Runs:    npm run spec:all
 */
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";

const repoRoot = process.cwd();
const src = path.join(repoRoot, "spec", "RUBIN_L1_CANONICAL_v1.1.md");

if (!fs.existsSync(src)) {
  console.error(`spec:watch: missing input: ${src}`);
  process.exit(1);
}

let queued = false;
function run(reason) {
  if (queued) return;
  queued = true;
  setTimeout(() => {
    queued = false;
    const ts = new Date().toISOString().replace("T", " ").slice(0, 19);
    try {
      execSync("npm run -s spec:all", { stdio: "inherit", cwd: repoRoot });
      console.log(`[${ts}] spec pipeline done (${reason})`);
    } catch (e) {
      console.error(`[${ts}] spec pipeline failed (${reason}):`, e.message);
    }
  }, 250);
}

run("initial");
fs.watch(src, { persistent: true }, () => run("change"));
