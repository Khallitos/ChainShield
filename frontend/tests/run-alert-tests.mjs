// Real-render tests for the alert-text guard (complements tests/run-tests.mjs, which stays
// untouched). Usage: node tests/run-alert-tests.mjs   (exit 0 = all green)
//
// Bundles tests/_alert-entry.jsx with esbuild, renders with react-dom/server,
// and asserts the ACTUAL HTML for each alert scenario:
//   - no unbacked CVE string can render (CVE claim without a source is relabelled)
//   - unknown risk scores are never defaulted to a number (0.15 / 0)
//   - engine/notification details preserve unknown risk end-to-end
//   - no fabricated attack-campaign names render
//   - demo data carries an explicit demo/illustrative label
import { build } from "esbuild";
import { pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
const outfile = path.join(here, ".build", "alert-entry.mjs");

await build({
  entryPoints: [path.join(here, "_alert-entry.jsx")],
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

const CVE = /\bCVE\b/i;
const UNKNOWN = /UNKNOWN/;

const EXPECT = {
  // 1) unbacked CVE must be relabelled, raw CVE text gone
  "cve: unbacked CVE alert relabelled": { noCve: true, relabel: true },
  // 2) sourced CVE id is preserved, still visible
  "cve: sourced CVE alert preserved": { hasCve: true, notRelabel: true },
  // 3) unknown risk → no number; known → passthrough
  "risk: unknown not defaulted to 0.15": { noDefaultedRisk: true },
  "risk: known scores preserved": { knownRisk: true },
  // 4) engine details unknown preservation
  "engine: unknown risk_score preserved": { engineUnknown: true },
  "engine: known risk_score preserved": { engineKnown: true },
  // 5) no fabricated campaign names
  "campaigns: no fabricated names (no demo)": { noCampaigns: true },
  // 6) demo label
  "demo: data labelled as demo/illustrative": { demoLabel: true },
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

  if (exp.noCve) {
    if (CVE.test(html)) errs.push("an unbacked CVE string rendered");
    if (/Critical CVE vulnerability/.test(html)) errs.push('raw fabricated title "Critical CVE vulnerability" rendered');
    if (/CVE-2024-1234/.test(html)) errs.push("fabricated CVE id rendered");
    if (!/unverified/i.test(html)) errs.push("unbacked alert was not labelled unverified");
  }
  if (exp.relabel && !/Unverified heuristic signal/.test(html)) {
    errs.push("alert not relabelled as unverified heuristic");
  }
  if (exp.hasCve) {
    if (!/CVE-2023-0001/.test(html)) errs.push("source-backed CVE id was dropped");
  }
  if (exp.notRelabel && /Unverified heuristic signal/.test(html)) {
    errs.push("source-backed alert was wrongly relabelled");
  }
  if (exp.noDefaultedRisk) {
    // exactly three outputs, all UNKNOWN (null, undefined, NaN), none may be a number
    const outs = (html.match(/data-risk="?"?>([\s\S]*?)<\/div>/g) || []);
    const vals = [...html.matchAll(/UNKNOWN|v:[0-9.]+/g)].map((m) => m[0]);
    if (vals.some((v) => v !== "UNKNOWN")) errs.push("unknown risk defaulted to a number: " + vals.join(","));
    if (vals.filter((v) => v === "UNKNOWN").length !== 3) errs.push("expected 3 unknown markers, saw " + JSON.stringify(vals));
    if (/0\.15/.test(html)) errs.push("unknown risk became 0.15");
  }
  if (exp.knownRisk) {
    if (!/v:0\.62/.test(html) || !/v:0\.15/.test(html) || !/v:0\b/.test(html)) {
      errs.push("known risk (0.62/0.15/0) not preserved: " + html.replace(/\s+/g, " ").slice(0, 200));
    }
  }
  if (exp.engineUnknown) {
    if (!UNKNOWN.test(html)) errs.push("unknown risk_score coerced to a number in engine details");
    if (/v:0|>0</.test(html)) errs.push("unknown engine score became 0");
  }
  if (exp.engineKnown && !/v:0\.7/.test(html)) errs.push("known engine risk_score not preserved");
  if (exp.noCampaigns) {
    if (/GemStuffor/.test(html)) errs.push("fabricated campaign name 'GemStuffor' rendered");
    if (/Red Hat Cloud Services Package Compromise/.test(html)) errs.push("fabricated campaign name rendered");
  }
  if (exp.demoLabel) {
    if (!/demo|illustrative/i.test(html)) errs.push("demo data not labelled (demo/illustrative)");
    if (/GemStuffor/.test(html)) errs.push("fabricated campaign name rendered in demo mode");
  }

  if (errs.length) failures.push({ name, errs, html });
  else pass++;
}

const names = Object.keys(scenarios);
console.log(names.map((n) => (failures.find((f) => f.name === n) ? `FAIL  ${n}` : `ok    ${n}`)).join("\n"));
console.log(`\n${pass}/${names.length} alert scenarios passed`);

if (failures.length) {
  console.log("\n--- failing detail ---");
  for (const f of failures) {
    console.log(`\n[${f.name}]  ${f.errs.join(" | ")}`);
    console.log("  markup: " + f.html.slice(0, 500));
  }
  process.exit(1);
}