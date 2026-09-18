// Real-render regression tests for the unknown/HOLD risk-rendering guard.
// Usage: node tests/run-tests.mjs   (exit 0 = all green, 1 = failures)
//
// Bundles tests/_render-entry.jsx with esbuild (JSX transform), imports the
// result, and asserts on the ACTUAL react-dom/server HTML for each scenario.
import { build } from "esbuild";
import { pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
const outfile = path.join(here, ".build", "entry.mjs");

await build({
  entryPoints: [path.join(here, "_render-entry.jsx")],
  outfile,
  bundle: true,
  format: "esm",
  platform: "node",
  jsx: "automatic",
  loader: { ".js": "jsx" },
  external: ["react", "react-dom", "react-dom/server", "react/jsx-runtime"],
  define: { "import.meta.env": "{}" },
  logLevel: "error",
});

const mod = await import(pathToFileURL(outfile).href);
const scenarios = mod.scenarios;

// Strict 0%: "40%" / "60%" / "100%" must NOT count as "0%".
const R0 = /(?:^|[^\d.])0%(?![\d])/;
const R62 = /(?:^|[^\d.])62%(?![\d])/;
const UNKNOWN = /unavailable|cannot evaluate|-|hold|held/i;
const ZERO_NUM = />0<|>0</;

// Per-scenario expectations: exact, not inferred from names.
const EXPECT = {
  "null+hold: ScanPipeline":        { unknown: true },
  "null+hold: ScanVerdictHero":     { unknown: true },
  "null+hold: ScanLayerCards":      { unknown: true },
  "null+hold: DefenseCompareTable": { unknown: true },
  "null+hold: SbomInsightsPanel":   { unknown: true },
  "null+hold: SocketInsightsPanel": { unknown: true },
  "null+hold: AiDecisionCard":      { unknown: true },
  "null+hold: DefenseComparisonPanel": { unknown: true },
  "null+hold: GaugeScore":          { unknown: true },

  "NaN: ScanPipeline":        { unknown: true },
  "null+hold: ScanPipeline (layers)": { unknown: true },
  "NaN: ScanPipeline (layers)":       { unknown: true },
  "NaN: ScanVerdictHero":     { unknown: true },
  "undefined: GaugeScore":    { unknown: true },
  "NaN: AiDecisionCard":      { unknown: true },
  "undefined: SbomInsightsPanel": { unknown: true },

  "zero: ScanVerdictHero":     { zero: true },
  "zero: ScanPipeline":        { zero: true },
  "zero: GaugeScore":          { zero: true },
  "zero: AiDecisionCard":      { zero: true },
  "zero: DefenseCompareTable": { zero: true },
  "zero: SbomInsightsPanel":   { zero: true },

  "block+null: ScanVerdictHero":     { block: true },
  "block+null: ScanPipeline":        { block: true },
  "block+null: AiDecisionCard":      { block: true },
  "block+null: DefenseCompareTable": { block: true },

  "normal: ScanVerdictHero":     { normal: true },
  "normal: ScanPipeline":        { normal: true },
  "normal: GaugeScore":          { normal: true },
  "normal: DefenseCompareTable": { normal: true },
};

let pass = 0;
const failures = [];

for (const [name, fn] of Object.entries(scenarios)) {
  const html = fn();
  const exp = EXPECT[name] || {};
  const errs = [];

  if (typeof html !== "string" || html.includes("__RENDER_ERROR__")) {
    errs.push("component threw during render: " + String(html).slice(0, 300));
  }

  if (exp.unknown) {
    if (R0.test(html)) errs.push('unknown score rendered as "0%" (safe-looking)');
    if (/\bdec-allow\b/.test(html)) errs.push("unknown state got the green allow class (dec-allow)");
    if (/\ballow\b/i.test(html)) errs.push('unknown state says "allow"');
    if (/\bsafe\b/i.test(html)) errs.push('unknown state says "safe"');
    if (!UNKNOWN.test(html)) errs.push("no explicit unknown/cannot-evaluate marker rendered");
  }
  if (exp.zero) {
    if (!R0.test(html) && !ZERO_NUM.test(html)) errs.push("genuine numeric 0 was not rendered as a number");
    if (/unavailable|cannot evaluate/i.test(html)) errs.push("genuine numeric 0 was treated as unknown");
  }
  if (exp.block) {
    if (R0.test(html)) errs.push('unknown score rendered as "0%"');
    if (!/\bblock\b/i.test(html)) errs.push("known BLOCK was not rendered as BLOCK");
    if (/UNAVAILABLE/i.test(html)) errs.push("known BLOCK was downgraded to UNAVAILABLE");
  }
  if (exp.normal) {
    if (!R62.test(html) && !/>62</.test(html)) errs.push('expected "62"');
    if (/unavailable|cannot evaluate/i.test(html)) errs.push("normal numeric score rendered as unknown");
  }

  if (errs.length) {
    failures.push({ name, errs, html });
  } else {
    pass++;
  }
}

const names = Object.keys(scenarios);
console.log(names.map((n) => (failures.find((f) => f.name === n) ? `FAIL  ${n}` : `ok    ${n}`)).join("\n"));
console.log(`\n${pass}/${names.length} scenarios passed`);

if (failures.length) {
  console.log("\n--- failing detail ---");
  for (const f of failures) {
    console.log(`\n[${f.name}]  ${f.errs.join(" | ")}`);
    console.log("  markup: " + f.html.slice(0, 400));
  }
  process.exit(1);
}
