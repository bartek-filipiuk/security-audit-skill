// Run: node --test scripts/*.test.mjs
// Export (roadmap R11): remediation.json + finding files -> SARIF 2.1.0, Linear CSV, Jira CSV.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { csvCell, findingLocation, loadExport, render, toSarif, TOOL } from "./export.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const script = join(here, "export.mjs");

const finding = ({ id, severity = "HIGH", file, title = `${id} title`, impact = `A signed-in user can read another organization's data through ${id}.`, fix = "Scope the query to the session's organization.", remediation = "" }) =>
  `---\nid: ${id}\ncategory: ${id.replace(/-\d+$/, "")}\nseverity: ${severity}\nstatus: verified\nsource_agent: auditor-auth\nproof: static\nprerequisite_count: 0\nrejection_reason: ""\n${remediation}---\n\n## Title\n${title}\n\n## Evidence\n- **File**: ${file}\n- **Code**:\n\`\`\`\nconst x = 1;\n\`\`\`\n\n## Impact\n${impact}\n\n## Regression Test\nstatic: no runner.\n\n## Chained With\n- none\n\n## Recommendation\n${fix}\n\n## Test Coverage\nuntested\n`;

// An audit directory whose remediation.json is written by audit-state.mjs itself, so the test reads the
// real contract and not a hand-written copy of it.
function auditDir() {
  const root = mkdtempSync(join(tmpdir(), "sa-export-"));
  const dir = join(root, ".security-audit");
  mkdirSync(join(dir, "findings"), { recursive: true });
  mkdirSync(join(dir, "non-issues"));
  const files = {
    "auth-101": finding({ id: "auth-101", file: "`src/app/(app)/invoices/actions.ts:10`" }),
    "rate-limit-114": finding({ id: "rate-limit-114", severity: "MEDIUM", file: "`src/app/api/assistant/billing/route.ts:16-18`", title: '=cost "abuse", with quotes', fix: "1. Allowlist the model.\n2. Cap maxTokens and maxSteps." }),
    "exposure-304": finding({ id: "exposure-304", file: "`.env` in commit 3ec2d73, removed in e9915ab", impact: "Anyone with a clone holds a live key (see `src/lib/stripe.ts:3`)." }),
    "config-308": finding({ id: "config-308", severity: "LOW", file: "`next.config.ts:3`" }),
    "auth-120": finding({ id: "auth-120", file: "`src/a.ts:4`", remediation: 'remediation:\n  status: fixed\n  fix_evidence: ["src/a.ts:4"]\n  verification: "scoped"\n' }),
    "auth-121": finding({ id: "auth-121", severity: "LOW", file: "`src/b.ts:9`", remediation: 'remediation:\n  status: wont_fix\n  verification: "accepted: internal tool"\n' }),
  };
  for (const [id, text] of Object.entries(files)) writeFileSync(join(dir, "findings", `${id}.md`), text);
  const r = spawnSync(process.execPath, [join(here, "audit-state.mjs"), "--dir", dir, "--final", "--write"], { encoding: "utf8" });
  assert.ok(existsSync(join(dir, "remediation.json")), `audit-state wrote remediation.json:\n${r.stdout}${r.stderr}`);
  return dir;
}

// RFC 4180 reader, only for the tests.
function parseCsv(text) {
  const rows = [];
  let row = [], cell = "", q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"' && text[i + 1] === '"') { cell += '"'; i++; } else if (c === '"') q = false; else cell += c;
    } else if (c === '"') q = true;
    else if (c === ",") { row.push(cell); cell = ""; }
    else if (c === "\r" && text[i + 1] === "\n") { row.push(cell); rows.push(row); row = []; cell = ""; i++; }
    else cell += c;
  }
  assert.equal(q, false, "no unterminated quote");
  if (cell || row.length) { row.push(cell); rows.push(row); }
  return rows;
}

// Structural checks of SARIF 2.1.0 that GitHub code scanning relies on (no schema download).
function assertSarif(doc) {
  assert.equal(doc.version, "2.1.0");
  assert.match(doc.$schema, /sarif-2\.1\.0/);
  assert.ok(Array.isArray(doc.runs) && doc.runs.length === 1);
  const run = doc.runs[0];
  const driver = run.tool?.driver;
  assert.equal(typeof driver?.name, "string");
  assert.equal(typeof driver.version, "string");
  assert.ok(Array.isArray(driver.rules));
  const ruleIds = driver.rules.map((r) => r.id);
  assert.equal(new Set(ruleIds).size, ruleIds.length, "rule ids are unique");
  for (const rule of driver.rules) {
    assert.ok(rule.id && rule.shortDescription?.text && rule.fullDescription?.text && rule.help?.text, `rule ${rule.id} has texts`);
    assert.ok(["error", "warning", "note", "none"].includes(rule.defaultConfiguration.level));
    const sev = Number(rule.properties["security-severity"]);
    assert.ok(sev >= 0 && sev <= 10, "security-severity is a number from 0 to 10");
    assert.ok(rule.properties.tags.includes("security"));
  }
  assert.ok(Array.isArray(run.results));
  for (const r of run.results) {
    assert.equal(driver.rules[r.ruleIndex].id, r.ruleId, "ruleIndex points at the rule");
    assert.ok(["error", "warning", "note", "none"].includes(r.level));
    assert.ok(typeof r.message?.text === "string" && r.message.text.length > 0);
    for (const l of r.locations ?? []) {
      const p = l.physicalLocation;
      assert.ok(p.artifactLocation.uri && !p.artifactLocation.uri.startsWith("/"), "uri is relative to the project root");
      assert.ok(!/^[a-z]+:/i.test(p.artifactLocation.uri), "uri has no scheme");
      assert.ok(run.originalUriBaseIds[p.artifactLocation.uriBaseId], "uriBaseId is declared");
      if (p.region) {
        assert.ok(Number.isInteger(p.region.startLine) && p.region.startLine >= 1);
        assert.ok(Number.isInteger(p.region.endLine) && p.region.endLine >= p.region.startLine);
      }
    }
  }
  assert.doesNotThrow(() => JSON.parse(JSON.stringify(doc)));
}

test("location: Evidence File line with a line, a range, a history-only file, and the fallback", () => {
  assert.deepEqual(findingLocation("- **File**: `src/app/(app)/invoices/actions.ts:10`"), { file: "src/app/(app)/invoices/actions.ts", start: 10, end: 10 });
  assert.deepEqual(findingLocation("- **File**: `src/x.ts:16-18`"), { file: "src/x.ts", start: 16, end: 18 });
  assert.deepEqual(findingLocation("- **File**: `./src/x.ts:6,13`"), { file: "src/x.ts", start: 6, end: 6 });
  assert.deepEqual(findingLocation("- **File**: `.env` in commit 3ec2d73, removed in e9915ab"), { file: ".env", start: null, end: null });
  assert.deepEqual(findingLocation("- **File**: src/p/[slug]/page.tsx:7"), { file: "src/p/[slug]/page.tsx", start: 7, end: 7 });
  assert.deepEqual(findingLocation("## Evidence\nSee `src/lib/auth.ts:28` and `src/y.ts:2`."), { file: "src/lib/auth.ts", start: 28, end: 28 });
  assert.equal(findingLocation("## Evidence\nnothing cited"), null);
});

test("loadExport joins remediation.json with the finding files and skips fixed and wont_fix by default", () => {
  const dir = auditDir();
  const { items, warnings } = loadExport(dir);
  assert.deepEqual(items.map((f) => f.id).sort(), ["auth-101", "config-308", "exposure-304", "rate-limit-114"]);
  assert.deepEqual(warnings, []);
  const rl = items.find((f) => f.id === "rate-limit-114");
  assert.deepEqual(rl.location, { file: "src/app/api/assistant/billing/route.ts", start: 16, end: 18 });
  assert.match(rl.fix, /Allowlist the model\.\n2\. Cap maxTokens/);
  assert.match(rl.impact, /signed-in user/);
  const all = loadExport(dir, { all: true }).items;
  assert.equal(all.length, 6);
  assert.equal(all.find((f) => f.id === "auth-120").status, "fixed");
});

test("SARIF 2.1.0: driver, one rule per finding with the fix as help, levels from severity, file and line", () => {
  const data = loadExport(auditDir());
  const doc = JSON.parse(render("sarif", data));
  assertSarif(doc);
  const run = doc.runs[0];
  assert.equal(run.tool.driver.name, TOOL.name);
  assert.equal(run.tool.driver.version, TOOL.version);
  assert.equal(run.results.length, 4);
  const res = (id) => run.results.find((r) => r.ruleId === id);
  const rule = (id) => run.tool.driver.rules.find((r) => r.id === id);
  assert.equal(res("auth-101").level, "error");
  assert.equal(res("rate-limit-114").level, "warning");
  assert.equal(res("config-308").level, "note");
  assert.equal(rule("auth-101").properties["security-severity"], "8.0");
  assert.deepEqual(rule("rate-limit-114").properties.tags, ["security", "rate-limit"]);
  assert.match(rule("rate-limit-114").help.text, /^Fix: 1\. Allowlist the model/);
  assert.match(rule("rate-limit-114").help.markdown, /\*\*Fix\*\*/);
  assert.deepEqual(res("rate-limit-114").locations[0].physicalLocation, {
    artifactLocation: { uri: "src/app/api/assistant/billing/route.ts", uriBaseId: "%SRCROOT%" },
    region: { startLine: 16, endLine: 18 },
  });
  assert.equal(res("auth-101").locations[0].physicalLocation.artifactLocation.uri, "src/app/(app)/invoices/actions.ts");
  const env = res("exposure-304").locations[0].physicalLocation;
  assert.equal(env.artifactLocation.uri, ".env");
  assert.equal(env.region, undefined, "a history-only file has no region");
  assert.match(res("auth-101").message.text, /^auth-101 title\. A signed-in user/);
  assert.equal(res("auth-101").properties.remediation_status, "open");
});

test("SARIF without findings is still a valid empty run", () => {
  const doc = toSarif({ meta: {}, items: [] });
  assertSarif(doc);
  assert.deepEqual(doc.runs[0].results, []);
});

test("Linear and Jira CSV: one row per finding, file:line in title and description, severity, fix steps", () => {
  const data = loadExport(auditDir());
  const linear = parseCsv(render("linear", data));
  assert.deepEqual(linear[0], ["Title", "Description", "Priority", "Labels"]);
  assert.equal(linear.length, 1 + 4);
  const row = linear.find((r) => r[0].includes("rate-limit-114") || r[1].includes("Finding rate-limit-114"));
  assert.match(row[0], /^\[MEDIUM\] =cost "abuse", with quotes \(src\/app\/api\/assistant\/billing\/route\.ts:16-18\)$/);
  assert.match(row[1], /Location: src\/app\/api\/assistant\/billing\/route\.ts:16-18/);
  assert.match(row[1], /Fix:\n1\. Allowlist the model\.\n2\. Cap maxTokens and maxSteps\./);
  assert.match(row[1], /\.security-audit\/findings\/rate-limit-114\.md/);
  assert.equal(row[2], "Medium");
  assert.equal(row[3], "security, rate-limit");
  const urgent = parseCsv(render("linear", { meta: {}, items: [{ ...data.items[0], severity: "CRITICAL" }] }));
  assert.equal(urgent[1][2], "Urgent");

  const jira = parseCsv(render("jira", data));
  assert.deepEqual(jira[0], ["Summary", "Description", "Issue Type", "Priority", "Labels", "Labels"]);
  assert.equal(jira.length, 1 + 4);
  for (const r of jira.slice(1)) {
    assert.equal(r.length, 6);
    assert.equal(r[2], "Bug");
    assert.ok(["Highest", "High", "Medium", "Low"].includes(r[3]));
    assert.equal(r[4], "security");
    assert.ok(!/\s/.test(r[5]), "a Jira label has no spaces");
  }
  const env = jira.find((r) => r[1].includes("Finding exposure-304"));
  assert.match(env[1], /Location: \.env\n/);
});

test("CSV cells: quotes doubled, formula prefixes neutralised", () => {
  assert.equal(csvCell('a "b"'), '"a ""b"""');
  assert.equal(csvCell("=HYPERLINK(1)"), `"'=HYPERLINK(1)"`);
  assert.equal(csvCell("+1"), `"'+1"`);
  assert.equal(csvCell("-1"), `"'-1"`);
  assert.equal(csvCell("@x"), `"'@x"`);
  assert.equal(csvCell("[HIGH] x"), '"[HIGH] x"');
  assert.equal(csvCell(undefined), '""');
});

test("a finding file missing from findings/ is exported without a location and reported", () => {
  const dir = auditDir();
  const rem = JSON.parse(readFileSync(join(dir, "remediation.json"), "utf8"));
  rem.findings.push({ id: "auth-999", category: "auth", severity: "HIGH", title: "gone", proof: "static", remediation_status: "open" });
  writeFileSync(join(dir, "remediation.json"), JSON.stringify(rem));
  const data = loadExport(dir);
  assert.deepEqual(data.warnings, ["auth-999: no findings/auth-999.md, exported without location, impact or fix"]);
  const doc = toSarif(data);
  assertSarif(doc);
  assert.equal(doc.runs[0].results.find((r) => r.ruleId === "auth-999").locations, undefined);
});

test("CLI: one command writes the file into .security-audit/export/, --out - prints, bad input exits non-zero", () => {
  const dir = auditDir();
  const cli = (...a) => spawnSync(process.execPath, [script, ...a], { encoding: "utf8" });
  for (const [format, name] of [["sarif", "security-audit.sarif"], ["linear", "linear.csv"], ["jira", "jira.csv"]]) {
    const r = cli("--format", format, "--dir", dir);
    assert.equal(r.status, 0, r.stderr);
    assert.ok(existsSync(join(dir, "export", name)), `${name} written`);
    assert.match(r.stdout, /4 findings/);
  }
  assertSarif(JSON.parse(readFileSync(join(dir, "export", "security-audit.sarif"), "utf8")));
  const out = cli("--format", "sarif", "--dir", dir, "--out", "-", "--all");
  assert.equal(JSON.parse(out.stdout).runs[0].results.length, 6);
  assert.equal(cli("--format", "pdf", "--dir", dir).status, 2);
  assert.equal(cli("--dir", dir).status, 2);
  const empty = mkdtempSync(join(tmpdir(), "sa-export-none-"));
  const missing = cli("--format", "jira", "--dir", empty);
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /remediation\.json/);
});
