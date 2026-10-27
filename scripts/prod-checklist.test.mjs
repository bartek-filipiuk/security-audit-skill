// Run: node --test scripts/*.test.mjs
// Production checklist (roadmap R14): deployment checks built from the Not Assessed rows.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { notAssessedRows } from "./coverage.mjs";
import { ITEMS, productionChecklist, renderProdChecklistMd } from "./prod-checklist.mjs";
import { renderReport } from "./report-html.mjs";
import { renderReportMd } from "./report-md.mjs";

const BASELINE = ITEMS.filter((it) => it.baseline).map((it) => it.title);

function auditDir({ ledgers = {}, notAssessed, summary } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "sa-prod-"));
  for (const d of ["findings", "non-issues", "tools", "coverage"]) mkdirSync(join(dir, d));
  for (const [name, entries] of Object.entries(ledgers)) writeFileSync(join(dir, "coverage", `${name}.json`), JSON.stringify({ schema_version: "1.0", entries }));
  if (notAssessed) writeFileSync(join(dir, "not-assessed.md"), notAssessed);
  if (summary) writeFileSync(join(dir, "tools", "summary.json"), JSON.stringify(summary));
  writeFileSync(join(dir, "summary.md"), "# Security Audit Report\n");
  return dir;
}

const gap = (o) => ({ status: "not_assessed", auditor: "auditor-infra", target: "*", ...o });

function sampleDir() {
  return auditDir({
    ledgers: {
      "auditor-infra": [
        gap({ class: "config", check: "security headers in production", reason: "set by the reverse proxy, not in the repository" }),
        gap({ class: "concurrency", target: "src/jobs/export.ts", check: "double-submit", reason: "needs a running database" }),
        { class: "auth", target: "src/login.ts", status: "checked", auditor: "auditor-auth", evidence: ["src/login.ts:4"] },
      ],
    },
    notAssessed: "| Category | Check | Why not assessed |\n|---|---|---|\n| all | database backups | outside the repository |\n",
    summary: { deps: { status: "NOT RUN: install osv-scanner or docker", rows: [] }, secrets: { status: "local: 0 hits", rows: [] } },
  });
}

test("matching Not Assessed rows flag their items and name the row", () => {
  const c = productionChecklist(notAssessedRows(sampleDir()));
  const byId = Object.fromEntries(c.items.map((it) => [it.id, it]));
  assert.ok(byId.headers.flagged && byId.backups.flagged && byId.deps.flagged);
  assert.equal(byId.headers.rows[0].check, "security headers in production");
  assert.equal(byId.deps.rows[0].check, "Dependencies scan", "a specific row is listed before the whole-class one");
  assert.equal(byId.deps.rows.at(-1).check, "whole class");
  assert.equal(byId.backups.rows[0].by, "not-assessed.md");
  assert.ok(!byId.cookies, "a non-baseline item no row matches is left out");
  assert.deepEqual(c.items.slice(0, c.flagged).map((it) => it.flagged), Array(c.flagged).fill(true), "flagged items come first");
  // whole classes nobody recorded (rate-limit, logging...) flag their items too
  assert.ok(byId.limits.flagged && byId.logging.flagged);
  assert.match(byId.limits.rows.map((r) => r.check).join(), /whole class/);

  const md = renderProdChecklistMd(notAssessedRows(sampleDir()));
  assert.match(md, /^## Production checklist$/m);
  assert.match(md, /^- \[ \] \*\*Security headers\*\* · from this audit$/m);
  assert.match(md, /^ {2}- Not assessed: config · security headers in production \(set by the reverse proxy, not in the repository\)$/m);
  assert.match(md, /^ {2}- Not assessed: all · database backups \(outside the repository\)$/m);
  assert.match(md, /^ {2}- How to check: `curl -sI https:\/\/<your-host>\/`/m);
  assert.match(md, /^\d+ other Not Assessed row\(s\) are code checks/m, "unmatched rows are counted, not listed");
  assert.doesNotMatch(md, /double-submit|injection · whole class/);
});

test("baseline items are always listed, marked baseline when nothing matched", () => {
  const md = renderProdChecklistMd([]);
  for (const t of BASELINE) assert.match(md, new RegExp(`^- \\[ \\] \\*\\*${t}\\*\\* · baseline$`, "m"));
  assert.doesNotMatch(md, /from this audit$/m);
  assert.doesNotMatch(md, /Session cookie flags/);
  assert.doesNotMatch(md, /Nothing about coverage was recorded/);
  const c = productionChecklist([{ class: "config", target: "", check: "session cookie flags", why: "set at deploy time", by: "not-assessed.md" }]);
  assert.equal(c.items[0].id, "cookies");
  assert.equal(c.items.length, BASELINE.length + 1);
});

test("bookkeeping rows (missing ledger, uncovered entry points) flag nothing", () => {
  const rows = [
    { class: "all", target: "", check: "coverage ledger", why: "no coverage ledger was recorded", by: "coverage.mjs" },
    { class: "all", target: "2 entry point(s)", check: "entry points with no coverage row", why: "src/api/backup.ts:3 route-handler POST /api/backup", by: "coverage.mjs" },
  ];
  const c = productionChecklist(rows);
  assert.equal(c.flagged, 0);
  assert.equal(c.unmatched, 0);
});

test("with nothing recorded about coverage the baseline list renders with a note", () => {
  const dir = auditDir();
  assert.equal(notAssessedRows(dir), null);
  const md = renderProdChecklistMd(null);
  assert.match(md, /Nothing about coverage was recorded for this audit/);
  for (const t of BASELINE) assert.ok(md.includes(`**${t}** · baseline`), t);
  const report = renderReportMd(dir);
  assert.match(report, /^## Production checklist$/m);
  assert.match(renderReport(dir), /<h2 id="prod">Production checklist<\/h2>[\s\S]*Nothing about coverage was recorded/);
});

test("report.md places the section right after Not Assessed", () => {
  const report = renderReportMd(sampleDir());
  const na = report.indexOf("## Not Assessed (coverage gaps)");
  const prod = report.indexOf("## Production checklist");
  assert.ok(na > 0 && prod > na, "after Not Assessed");
  assert.ok(prod < report.indexOf("## Documentation vs Reality"), "before Documentation vs Reality");
});

test("report.html renders the section after Not assessed and escapes row text", () => {
  const dir = auditDir({
    ledgers: { "auditor-infra": [gap({ class: "config", check: "CSP <script>alert(1)</script> header", reason: "proxy \"edge\" & cdn" })] },
  });
  const html = renderReport(dir);
  assert.ok(html.indexOf('id="gaps"') < html.indexOf('<h2 id="prod">'), "after Not assessed");
  assert.match(html, /<a href="#prod">Production checklist <b>\d+<\/b><\/a>/);
  const section = html.slice(html.indexOf('<h2 id="prod">'), html.indexOf("</ul>", html.indexOf('<h2 id="prod">')));
  assert.match(section, /<strong>Security headers<\/strong> <span class="chip chip-warn">From this audit<\/span>/);
  assert.match(section, /Not assessed: config · CSP &lt;script&gt;alert\(1\)&lt;\/script&gt; header \(proxy &quot;edge&quot; &amp; cdn\)/);
  assert.doesNotMatch(section, /<script>/);
  assert.match(section, /<strong>Backups and a tested restore<\/strong> <span class="chip chip-muted">Baseline<\/span>/);
  assert.match(section, /How to check: <code>curl -sI https:\/\/&lt;your-host&gt;\/<\/code>/);
});

test("every how-to is defensive and uses placeholder hosts only", () => {
  for (const it of ITEMS) {
    assert.ok(it.how.length > 40, it.id);
    for (const host of it.how.match(/https?:\/\/[^\s`/]+/g) ?? []) assert.match(host, /<your-host>|example\.(com|org|net)$/, `${it.id}: ${host}`);
    assert.doesNotMatch(it.how, /\b(exploit|payload|nmap|sqlmap|hydra|bypass)\b/i, it.id);
  }
});
