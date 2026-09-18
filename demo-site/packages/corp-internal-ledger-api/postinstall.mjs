/**
 * Trusted internal package (ATK2 control case).
 *
 * Asks the same protection gate as the attacker twin before finishing the install, so the
 * control shows the gate ALLOWING the trusted internal release, not merely an install that
 * never asked.
 */
import { fetchProtectionCheck } from "../_lab/protection-check.mjs";

const PACKAGE = "corp-internal-ledger-api";
const PACKAGE_VERSION = "1.4.2";

const protection = await fetchProtectionCheck(PACKAGE, PACKAGE_VERSION);

if (protection.blocked) {
  console.error(`[supply-chain-security] Install refused: ${protection.reason}`);
  process.exit(1);
}

const decision = protection.engine?.action || "not checked";
console.log(`[${PACKAGE}] v${PACKAGE_VERSION}: internal registry install OK (gate: ${decision}).`);
