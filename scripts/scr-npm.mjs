#!/usr/bin/env node
/**
 * Training management app: npm wrapper for setup installs.
 * Translates `--training-setup` → `--foreground-scripts` (runs training helper postinstall visibly).
 *
 *   node ../../scripts/scr-npm.mjs install --training-setup
 *   npm install --training-setup   (after: source scripts/scr-npm-env.sh)
 */
import { spawnSync } from "node:child_process";

const TRAINING_FLAG = "--training-setup";
const NPM_FLAG = "--foreground-scripts";
const LEGACY_FLAGS = new Set(["--verify-deps", "--scr-lab"]);

const rawArgs = process.argv.slice(2);

if (rawArgs.length === 0) {
  console.error("Training management system, dependency setup");
  console.error("");
  console.error("  npm install --training-setup");
  console.error("    Installs training modules and runs setup / locale hooks in the foreground.");
  console.error("");
  process.exit(1);
}

const args = rawArgs.map((a) => {
  if (a === TRAINING_FLAG || LEGACY_FLAGS.has(a)) return NPM_FLAG;
  return a;
});
const wantsTraining =
  rawArgs.includes(TRAINING_FLAG) || rawArgs.some((a) => LEGACY_FLAGS.has(a));
const hasForeground = args.includes(NPM_FLAG);

if (rawArgs[0] === "install" && wantsTraining && !hasForeground) {
  args.splice(1, 0, NPM_FLAG);
}

const npmCmd = process.platform === "win32" ? "npm.cmd" : "npm";
const result = spawnSync(npmCmd, args, { stdio: "inherit", shell: process.platform === "win32" });
process.exit(result.status ?? 1);
