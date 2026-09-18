// Synthetic BENIGN fixture hook - APPROVED path.
// Writes a harmless marker file so a test can prove this hook ran.
// This is a benign local test fixture, NOT lab code.
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const marker = join(root, "MARKER_GOOD.txt");
mkdirSync(root, { recursive: true });
writeFileSync(marker, "chain-pkg-good postinstall ran (APPROVED path)\n", "utf8");
console.log("[chain-pkg-good] benign marker written:", marker);
