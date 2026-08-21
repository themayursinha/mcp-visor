#!/usr/bin/env node
/**
 * setup-envs.js — install isolated-vm 7.0.0 (vulnerable) and 7.0.1 (fixed)
 * into separate environment directories so one process tree can compare them.
 *
 * The two versions are isolated in envs/vulnerable and envs/fixed. Each gets
 * its own node_modules; nothing is shared, so version pinning is exact.
 */
const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const ENVS = {
  vulnerable: "7.0.0",
  fixed: "7.0.1",
};

function ensureEnv(name, version) {
  const dir = path.join(ROOT, "envs", name);
  fs.mkdirSync(dir, { recursive: true });
  const pkgPath = path.join(dir, "package.json");
  if (!fs.existsSync(pkgPath)) {
    fs.writeFileSync(pkgPath, JSON.stringify({ name: `env-${name}`, private: true }, null, 2));
  }
  console.log(`[setup] ${name}: installing isolated-vm@${version} in ${dir}`);
  execSync(`npm install --no-save isolated-vm@${version} --loglevel=error`, {
    cwd: dir,
    stdio: "inherit",
  });
  // verify the installed version
  const installed = require(path.join(dir, "node_modules", "isolated-vm", "package.json")).version;
  console.log(`[setup] ${name}: confirmed isolated-vm@${installed}`);
  return installed;
}

function main() {
  console.log("[setup] Boundary Failure Injection demo — installing environments");
  const results = {};
  for (const [name, version] of Object.entries(ENVS)) {
    results[name] = ensureEnv(name, version);
  }
  console.log(`[setup] done. vulnerable=${results.vulnerable} fixed=${results.fixed}`);
}

main();
