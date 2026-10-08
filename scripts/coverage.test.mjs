// Run: node --test scripts/
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { CATEGORIES } from "./audit-state.mjs";
import { AUDIT_CLASSES, CLASSES, coverageModel, notAssessedRows, renderCoverageMd, validateLedger } from "./coverage.mjs";
import { writeCarried } from "./incremental.mjs";
import { renderReportMd } from "./report-md.mjs";

const here = dirname(fileURLToPath(import.meta.url));

// A ledger row; a key set to undefined is left out, as it would be in the JSON file.
const row = (o) => JSON.parse(JSON.stringify({ class: "auth", target: "src/app/api/export/route.ts", handler: "GET /api/export", status: "checked", auditor: "auditor-auth", evidence: ["auth-101"], ...o }));
const ledger = (...entries) => ({ schema_version: "1.0", entries });

function auditDir({ ledgers = {}, findings = [], nonIssues = [], entryPoints, notAssessed, summary } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "sa-cov-"));
  for (const d of ["findings", "non-issues", "tools", "coverage"]) mkdirSync(join(dir, d));
  for (const [name, doc] of Object.entries(ledgers)) writeFileSync(join(dir, "coverage", `${name}.json`), typeof doc === "string" ? doc : JSON.stringify(doc));
  for (const id of findings) writeFileSync(join(dir, "findings", `${id}.md`), `---\nid: ${id}\ncategory: auth\nseverity: HIGH\nstatus: raw\n---\n\n## Title\nt\n`);
  for (const id of nonIssues) writeFileSync(join(dir, "non-issues", `${id}.md`), `---\nid: ${id}\ncategory: auth\nsource_agent: auditor-auth\n---\n\n## Area Examined\na\n`);
  if (entryPoints) writeFileSync(join(dir, "tools", "entry-points.json"), JSON.stringify(entryPoints));
  if (notAssessed) writeFileSync(join(dir, "not-assessed.md"), notAssessed);
  if (summary) writeFileSync(join(dir, "tools", "summary.json"), JSON.stringify(summary));
  return dir;
}

const cli = (dir, ...args) => spawnSync(process.execPath, [join(here, "coverage.mjs"), "--dir", dir, ...args], { encoding: "utf8" });

test("schema classes are the canonical finding categories (minus chain) plus all", () => {
  assert.deepEqual(CLASSES, [...CATEGORIES.filter((c) => c !== "chain"), "all"]);
  assert.equal(AUDIT_CLASSES.length, 12);
});

test("a valid ledger passes: checked with evidence, not_applicable and not_assessed with a reason", () => {
  const doc = ledger(
    row(),
    row({ class: "upload", target: "*", handler: undefined, status: "not_applicable", evidence: undefined, reason: "no upload handling", auditor: "auditor-upload" }),
    row({ class: "concurrency", status: "not_assessed", evidence: undefined, reason: "needs a running database", check: "double-submit on export" }),
    row({ class: "dependency", target: "*", handler: undefined, evidence: ["pnpm-lock.yaml:246", "non-dependency-301"], auditor: "auditor-infra" }),
  );
  assert.deepEqual(validateLedger(doc, { ids: new Set(["auth-101", "non-dependency-301"]) }), []);
});

test("invalid ledgers fail with clear messages", () => {
  const errs = (doc, opts) => validateLedger(doc, opts).join("\n");
  const { class: _c, ...noClass } = row();
  assert.match(errs(ledger(noClass)), /^ledger\.entries\[0\]: missing required field "class"$/m);
  assert.match(errs(ledger(row({ status: "done" }))), /ledger\.entries\[0\]\.status: "done" is not one of: checked, not_applicable, not_assessed/);
  assert.match(errs(ledger(row({ class: "xss" }))), /ledger\.entries\[0\]\.class: "xss" is not one of: auth, injection, .*, all/);
  assert.match(errs(ledger(row({ evidence: undefined }))), /entries\[0\]: missing required field "evidence" \(required when status is "checked"\)/);
  assert.match(errs(ledger(row({ status: "not_assessed", evidence: undefined }))), /missing required field "reason" \(required when status is "not_applicable" or "not_assessed"\)/);
  assert.match(errs(ledger(row({ evidence: [] }))), /entries\[0\]\.evidence: needs at least 1 item/);
  assert.match(errs(ledger(row({ evidence: ["looked at it"] }))), /evidence\[0\]: "looked at it" is invalid \(a finding or non-issue id/);
  assert.match(errs(ledger(row({ auditor: "me" }))), /entries\[0\]\.auditor: "me" is invalid/);
  assert.match(errs(ledger(row({ target: "/abs/path.ts" }))), /entries\[0\]\.target: "\/abs\/path\.ts" is invalid/);
  assert.match(errs(ledger(row({ verdict: "ok" }))), /entries\[0\]: unknown field "verdict"/);
  assert.match(errs({ entries: [] }), /^ledger: missing required field "schema_version"$/m);
  assert.match(errs({ schema_version: "2.0", entries: {} }), /schema_version: must be "1.0"[\s\S]*entries: expected array, got object/);
  assert.match(errs(ledger(row({ class: "all" }))), /class "all" is only for gaps/);
  assert.match(errs(ledger(row({ evidence: ["auth-199"] })), { ids: new Set(["auth-101"]) }), /"auth-199" names no finding or non-issue file/);
});

test("the CLI validates every ledger file, names the file, exits 1, and --write refuses", () => {
  const dir = auditDir({ findings: ["auth-101"], ledgers: { auth: ledger(row()), broken: "{ not json", infra: ledger(row({ status: "maybe" })) } });
  const r = cli(dir, "--write");
  assert.equal(r.status, 1);
  assert.match(r.stdout, /coverage: 3 ledger file\(s\)/);
  assert.match(r.stdout, /coverage\/broken\.json: not valid JSON/);
  assert.match(r.stdout, /coverage\/infra\.json: ledger\.entries\[0\]\.status: "maybe" is not one of/);
  assert.match(r.stdout, /coverage\.json NOT written/);

  const ok = auditDir({ findings: ["auth-101"], ledgers: { auth: ledger(row()), infra: ledger(row({ class: "config", target: "*", handler: undefined, evidence: ["next.config.ts:3"], auditor: "auditor-infra" })) } });
  const w = cli(ok, "--write", "--summary");
  assert.equal(w.status, 0, w.stdout);
  const merged = JSON.parse(readFileSync(join(ok, "coverage.json"), "utf8"));
  assert.equal(merged.entries.length, 2);
  assert.deepEqual(validateLedger(merged), [], "the merged file validates against the same schema");
  assert.match(w.stdout, /classes not recorded: injection, rate-limit, exposure, upload, dependency/);
});

test("rendering: coverage table per class, entry points, not-applicable list and every gap", () => {
  const dir = auditDir({
    findings: ["auth-101"],
    entryPoints: [
      { kind: "route-handler", name: "GET", route: "/api/export", file: "src/app/api/export/route.ts", line: 4 },
      { kind: "server-action", name: "getInvoice", route: "", file: "src/app/(app)/invoices/actions.ts", line: 9 },
    ],
    ledgers: {
      "auditor-auth": ledger(row(), row({ class: "concurrency", status: "not_assessed", evidence: undefined, reason: "needs a running database", check: "double-submit" })),
      "auditor-upload": ledger({ class: "upload", target: "*", status: "not_applicable", auditor: "auditor-upload", reason: "no upload handling in the code" }),
    },
    notAssessed: "| Category | Check | Why not assessed |\n|---|---|---|\n| code | semgrep rule scan | NOT RUN: not installed (prepass) |\n",
    summary: { deps: { status: "NOT RUN: install osv-scanner or docker", rows: [] }, secrets: { status: "local: 0 hits", rows: [] } },
  });
  const md = renderCoverageMd(dir);
  assert.match(md, /^## Coverage$/m);
  assert.match(md, /^\| auth \(§2\.1\) \| 1 \(1\) \| 0 \| 0 \| auditor-auth \|$/m);
  assert.match(md, /^\| concurrency \(§2\.9\) \| 0 \(0\) \| 0 \| 1 \| auditor-auth \|$/m);
  assert.match(md, /^\| injection \(§2\.2\) \| not looked at \| 0 \| 0 \| – \|$/m);
  assert.match(md, /Entry points: 1 of 2 from the pre-pass have a coverage row; 1 have none/);
  assert.match(md, /^- upload \(§2\.6\) · whole project: no upload handling in the code \(auditor-upload\)$/m);

  const gaps = md.slice(md.indexOf("## Not Assessed (coverage gaps)"));
  assert.match(gaps, /Nobody checked these\. They are unknown, not safe\./);
  assert.match(gaps, /^\| concurrency \| src\/app\/api\/export\/route\.ts \(GET \/api\/export\) \| double-submit \| needs a running database \| auditor-auth \|$/m);
  assert.match(gaps, /^\| injection \| – \| whole class \| no auditor recorded this class: not looked at \| coverage\.mjs \|$/m);
  assert.ok(!/^\| upload \| – \| whole class/m.test(gaps), "a not_applicable class is accounted for");
  assert.match(gaps, /entry points with no coverage row \| no auditor recorded checking them: src\/app\/\(app\)\/invoices\/actions\.ts:9 server-action getInvoice/);
  assert.match(gaps, /^\| dependency \| – \| Dependencies scan \| NOT RUN: install osv-scanner or docker \| prepass \|$/m);
  assert.match(gaps, /^\| code \| – \| semgrep rule scan \| NOT RUN: not installed \(prepass\) \| not-assessed\.md \|$/m);
  assert.ok(!/Secrets scan/.test(gaps), "a scan that ran is not a gap");
});

test("every not_assessed row reaches report.md and report-html's rows, even with an invalid ledger", () => {
  const reasons = Array.from({ length: 5 }, (_, i) => `reason number ${i}`);
  const dir = auditDir({
    ledgers: {
      a: ledger(...reasons.slice(0, 3).map((reason, i) => ({ class: AUDIT_CLASSES[i], target: `src/f${i}.ts`, status: "not_assessed", auditor: "auditor-a", reason }))),
      b: ledger(...reasons.slice(3).map((reason, i) => ({ class: "logging", target: "*", status: "not_assessed", auditor: "auditor-b", reason, check: `c${i}`, bogus: true }))),
    },
  });
  writeFileSync(join(dir, "summary.md"), "# Security Audit Report\n");
  const report = renderReportMd(dir);
  const section = report.slice(report.indexOf("## Not Assessed (coverage gaps)"), report.indexOf("## Documentation vs Reality"));
  for (const r of reasons) assert.ok(section.includes(r), `missing from report.md: ${r}`);
  assert.ok(report.indexOf("## Coverage") < report.indexOf("## Not Assessed"), "Coverage comes before Not Assessed");
  const rows = notAssessedRows(dir);
  for (const r of reasons) assert.ok(rows.some((g) => g.why === r), `missing from report-html rows: ${r}`);
});

test("without a ledger the report says coverage is unknown; with nothing recorded at all the html rows are null", () => {
  const legacy = auditDir({ notAssessed: "| Category | Check | Why not assessed |\n|---|---|---|\n| all | everything outside scope \"auth\" | out of scope |\n" });
  const md = renderCoverageMd(legacy);
  assert.match(md, /No coverage ledger was recorded/);
  assert.match(md, /^\| all \| – \| coverage ledger \| no coverage ledger was recorded/m);
  assert.match(md, /^\| all \| – \| everything outside scope "auth" \| out of scope \| not-assessed\.md \|$/m);
  assert.equal(coverageModel(legacy).recorded, false);
  assert.equal(notAssessedRows(auditDir()), null);
});

test("--since carries ledger rows only for untouched targets whose cited findings were carried", () => {
  const prev = auditDir({
    findings: ["auth-101", "auth-102"],
    ledgers: { "auditor-auth": ledger(
      row({ target: "src/a.ts", evidence: ["auth-101"] }),
      row({ target: "src/b.ts", evidence: ["auth-102"] }),
      row({ target: "src/changed.ts", evidence: ["src/changed.ts:3"] }),
      row({ target: "src/c.ts", evidence: ["src/changed.ts:9"] }),
      row({ class: "upload", target: "*", status: "not_applicable", evidence: undefined, handler: undefined, reason: "no uploads" }),
    ) },
  });
  const out = mkdtempSync(join(tmpdir(), "sa-cov-out-"));
  const plan = { carry: [{ kind: "finding", name: "auth-101.md", text: "---\nid: auth-101\n---\n" }], affected: ["src/changed.ts"], reaudit: [] };
  writeCarried(prev, out, plan, { commit: "0123456789abcdef0123456789abcdef01234567", run: "2026-10-01T00-00-00" });
  const carried = JSON.parse(readFileSync(join(out, "coverage", "carried.json"), "utf8"));
  assert.deepEqual(carried.entries.map((e) => e.target), ["src/a.ts", "*"]);
  assert.ok(carried.entries.every((e) => e.carried_from === "0123456789abcdef0123456789abcdef01234567"));
  assert.deepEqual(validateLedger(carried, { ids: new Set(["auth-101"]) }), []);
});
