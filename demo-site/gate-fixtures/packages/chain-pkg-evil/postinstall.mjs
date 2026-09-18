// Synthetic BENIGN fixture hook - NOT-approved path.
// Would write a harmless marker file IF executed. The gate must BLOCK this package
// BEFORE this hook runs, so this marker must NEVER appear in the blocked case.
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const marker = join(root, "MARKER_EVIL.txt");
mkdirSync(root, { recursive: true });
writeFileSync(marker, "chain-pkg-evil postinstall ran (should NEVER appear)\n", "utf8");
console.log("[chain-pkg-evil] marker written (this is the BLOCKED path - should not happen)");
