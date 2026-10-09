// Run: node --test scripts/*.test.mjs
// Audit diff (roadmap R12): new, fixed, regressed and unchanged findings against the previous run in history/.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { classify, diffAudit, historyRuns, matchFindings, normTitle, renderDiffMd, sameTitle } from "./diff.mjs";
import { renderReportMd } from "./report-md.mjs";
import { renderReport } from "./report-html.mjs";

const here = dirname(fileURLToPath(import.meta.url));

const finding = ({ id, severity = "HIGH", status = "verified", file, title, remediation = "" }) =>
  `---\nid: ${id}\ncategory: ${id.replace(/-\d+$/, "")}\nseverity: ${severity}\nstatus: ${status}\nsource_agent: auditor-auth\nproof: static\nprerequisite_count: 0\nrejection_reason: "${status === "rejected" ? "best_practice" : ""}"\n${remediation}---\n\n## Title\n${title}\n\n## Evidence\n- **File**: \`${file}\`\n- **Code**:\n\`\`\`\nconst x = 1;\n\`\`\`\n\n## Impact\nA signed-in user can read another organization's records.\n\n## Recommendation\nScope the query.\n`;
const FIXED = 'remediation:\n  status: fixed\n  fix_evidence: ["src/x.ts:1"]\n  verification: "scoped"\n';

// Writes one run (findings + report.md + tools/summary.json) into `dir`.
function writeRun(dir, findings, { report = true, scope = null, commit = "abc1234" } = {}) {
  mkdirSync(join(dir, "findings"), { recursive: true });
  mkdirSync(join(dir, "non-issues"), { recursive: true });
  mkdirSync(join(dir, "tools"), { recursive: true });
  for (const f of findings) writeFileSync(join(dir, "findings", `${f.id}.md`), finding(f));
  writeFileSync(join(dir, "tools", "summary.json"), JSON.stringify({ commit, scope: scope && { label: scope, entries: 3, total: 40 }, deps: { status: "ran", rows: [] }, secrets: { status: "ran", rows: [] } }));
  if (report) writeFileSync(join(dir, "report.md"), "# Security Audit Report\n");
}

const auditRoot = () => join(mkdtempSync(join(tmpdir(), "sa-diff-")), ".security-audit");

const PREVIOUS = [
  { id: "auth-101", file: "src/a.ts:10-12", title: "Invoice read without organization scope" },
  { id: "auth-107", file: "src/a.ts:200", title: "Admin role check missing on export" },
  { id: "injection-102", severity: "MEDIUM", file: "src/q.ts:40", title: "Raw SQL built from the search term" },
  { id: "exposure-103", file: "src/e.ts:5", title: "Stack traces returned to anonymous callers" },
  { id: "auth-104", file: "src/b.ts:20", title: "Webhook accepted without signature check", remediation: FIXED },
  { id: "config-105", severity: "LOW", file: "next.config.ts:3", title: "No Content-Security-Policy header" },
  { id: "logging-106", severity: "MEDIUM", file: "src/old/log.ts:9", title: "Session token written to logs" },
  { id: "auth-109", status: "rejected", file: "src/z.ts:1", title: "Rejected candidate" },
];
const CURRENT = [
  // same place, lines moved by one and a reworded title: unchanged
  { id: "auth-201", file: "src/a.ts:11", title: "Invoices readable across organizations (no org scope)" },
  // moved 40 lines down, same title, severity raised: unchanged + severity change
  { id: "injection-205", file: "src/q.ts:80", title: "Raw SQL built from the search term at `src/q.ts:80`" },
  // was marked fixed, back again: regressed
  { id: "auth-210", file: "src/b.ts:21", title: "Webhook accepted without a signature check" },
  // still present but marked fixed by --verify-fixes: fixed
  { id: "config-301", severity: "LOW", file: "next.config.ts:3", title: "No Content-Security-Policy header", remediation: FIXED },
  // file moved, same title: unchanged
  { id: "logging-230", severity: "MEDIUM", file: "src/new/log.ts:9", title: "Session token written to logs" },
  // nothing like it before: new (title with markup, to check escaping)
  { id: "rate-limit-220", severity: "MEDIUM", file: "src/r.ts:7", title: "Unbounded <b>login</b> attempts" },
  // rejected: not a finding, never counted
  { id: "auth-299", status: "rejected", file: "src/a.ts:200", title: "Admin role check missing on export" },
];

function secondRun() {
  const dir = auditRoot();
  writeRun(join(dir, "history", "2026-10-01T09-00-00"), PREVIOUS);
  writeRun(dir, CURRENT, { commit: "def5678" });
  return dir;
}

const ids = (list) => list.map((f) => f.id).sort();

test("first run: no history, no diff and no section in either report", () => {
  const dir = auditRoot();
  writeRun(dir, CURRENT);
  assert.equal(diffAudit(dir), null);
  assert.equal(renderDiffMd(null), "");
  assert.doesNotMatch(renderReportMd(dir), /Since Last Audit/i);
  assert.doesNotMatch(renderReport(dir), /id="since"|Since last audit/i);
});

test("an unfinished previous run (no report.md) is not a baseline", () => {
  const dir = auditRoot();
  writeRun(join(dir, "history", "2026-10-01T09-00-00"), PREVIOUS, { report: false });
  writeRun(dir, CURRENT);
  assert.deepEqual(historyRuns(dir), []);
  assert.equal(diffAudit(dir), null);
});

test("second run: new, fixed, regressed, unchanged, moved lines and severity changes", () => {
  const d = diffAudit(secondRun());
  assert.equal(d.previous.run, "2026-10-01T09-00-00");
  assert.equal(d.previous.commit, "abc1234");
  assert.deepEqual(ids(d.new), ["rate-limit-220"]);
  assert.deepEqual(ids(d.regressed), ["auth-210"]);
  assert.equal(d.regressed[0].was.id, "auth-104");
  assert.match(d.regressed[0].how, /marked fixed in run 2026-10-01T09-00-00/);
  assert.deepEqual(ids(d.fixed), ["auth-107", "config-105", "exposure-103"]);
  assert.equal(d.fixed.find((f) => f.id === "config-105").how, "marked fixed");
  assert.equal(d.fixed.find((f) => f.id === "config-105").now.id, "config-301");
  assert.equal(d.fixed.find((f) => f.id === "exposure-103").how, "no longer reported");
  assert.deepEqual(ids(d.unchanged), ["auth-201", "injection-205", "logging-230"]);
  assert.equal(d.unchanged.find((f) => f.id === "auth-201").was.id, "auth-101");
  assert.equal(d.unchanged.find((f) => f.id === "logging-230").was.id, "logging-106");
  assert.deepEqual(d.severity_changed.map((f) => [f.id, f.from, f.to]), [["injection-205", "MEDIUM", "HIGH"]]);
  assert.deepEqual(d.not_rechecked, []);
});

test("report.md renders the Since Last Audit section with counts and lists", () => {
  const md = renderReportMd(secondRun());
  const sec = md.match(/## Since Last Audit\n([\s\S]*?)\n## Findings/)?.[1];
  assert.ok(sec, "section sits before Findings");
  assert.match(sec, /run 2026-10-01T09-00-00, commit abc1234\): 1 new, 3 fixed, 1 regressed, 3 unchanged, 1 severity change\./);
  assert.match(sec, /\*\*New\*\*\n\n- rate-limit-220 \(MEDIUM, rate-limit\): Unbounded <b>login<\/b> attempts \(src\/r\.ts:7\)/);
  assert.match(sec, /\*\*Regressed\*\*\n\n- auth-210 \(HIGH, auth\): .*; was auth-104, marked fixed in run 2026-10-01T09-00-00/);
  assert.match(sec, /- exposure-103 \(HIGH, exposure\): .*; no longer reported/);
  assert.match(sec, /- config-105 \(LOW, config\): .*; marked fixed as config-301/);
  assert.match(sec, /injection-205: MEDIUM → HIGH/);
  assert.match(sec, /\*\*Unchanged\*\*: auth-201, injection-205, logging-230\./);
});

test("report.html renders the Since last audit section, escaped, with a nav entry", () => {
  const html = renderReport(secondRun());
  assert.match(html, /<h2 id="since">Since last audit<\/h2>/);
  assert.match(html, /href="#since">Since last audit <b>2<\/b>/);
  assert.match(html, /<h3>New · 1<\/h3>/);
  assert.match(html, /<h3>Regressed · 1<\/h3>/);
  assert.match(html, /<h3>Fixed · 3<\/h3>/);
  assert.match(html, /Unbounded &lt;b&gt;login&lt;\/b&gt; attempts/);
  assert.doesNotMatch(html, /Unbounded <b>login/);
});

test("a finding gone from the previous full run and back now is regressed (older history)", () => {
  const dir = auditRoot();
  writeRun(join(dir, "history", "2026-09-01T09-00-00"), [{ id: "crypto-108", file: "src/c.ts:3", title: "Password hashed with MD5" }]);
  writeRun(join(dir, "history", "2026-10-01T09-00-00"), [{ id: "auth-101", file: "src/a.ts:10", title: "Invoice read without organization scope" }]);
  writeRun(dir, [
    { id: "crypto-140", file: "src/c.ts:4", title: "Password hashed with MD5" },
    { id: "auth-201", file: "src/a.ts:10", title: "Invoice read without organization scope" },
  ]);
  const d = diffAudit(dir);
  assert.equal(d.previous.run, "2026-10-01T09-00-00");
  assert.deepEqual(ids(d.regressed), ["crypto-140"]);
  assert.match(d.regressed[0].how, /last reported in run 2026-09-01T09-00-00, gone from run 2026-10-01T09-00-00/);
  assert.deepEqual(ids(d.new), []);
});

test("partial previous run: older history is not used to call a finding regressed", () => {
  const dir = auditRoot();
  writeRun(join(dir, "history", "2026-09-01T09-00-00"), [{ id: "crypto-108", file: "src/c.ts:3", title: "Password hashed with MD5" }]);
  writeRun(join(dir, "history", "2026-10-01T09-00-00"), [], { scope: "auth" });
  writeRun(dir, [{ id: "crypto-140", file: "src/c.ts:3", title: "Password hashed with MD5" }]);
  const d = diffAudit(dir);
  assert.deepEqual(ids(d.new), ["crypto-140"]);
  assert.deepEqual(d.regressed, []);
  assert.match(renderDiffMd(d), /previous audit was partial \(scope "auth"\)/);
});

test("partial current run: absent findings are not re-checked, not fixed", () => {
  const dir = auditRoot();
  writeRun(join(dir, "history", "2026-10-01T09-00-00"), PREVIOUS);
  writeRun(dir, CURRENT, { scope: "payments" });
  const d = diffAudit(dir);
  assert.deepEqual(ids(d.not_rechecked), ["auth-107", "exposure-103"]);
  assert.deepEqual(ids(d.fixed), ["config-105"]);
  assert.match(renderDiffMd(d), /Not re-checked \(outside this audit's scope\)/);
});

test("history order: newest run first, collision suffixes sorted numerically", () => {
  const dir = auditRoot();
  for (const n of ["2026-10-01T09-00-00", "2026-10-01T09-00-00-2", "2026-10-01T09-00-00-10", "2026-09-30T23-59-59"]) writeRun(join(dir, "history", n), []);
  assert.deepEqual(historyRuns(dir).map((r) => r.name), ["2026-10-01T09-00-00-10", "2026-10-01T09-00-00-2", "2026-10-01T09-00-00", "2026-09-30T23-59-59"]);
});

test("matching: line window, title fallback, category must agree, each finding used once", () => {
  const f = (id, category, file, start, title, end = start) => ({ id, category, file, start, end, title, severity: "HIGH", fixed: false });
  const prev = [f("p1", "auth", "a.ts", 10, "Missing org scope on invoices"), f("p2", "auth", "a.ts", 14, "Missing org scope on invoices")];
  const cur = [f("c1", "auth", "a.ts", 13, "Missing org scope on invoices"), f("c2", "injection", "a.ts", 10, "Missing org scope on invoices")];
  const m = matchFindings(cur, prev);
  assert.deepEqual(m.pairs.map(([c, p]) => [c.id, p.id]), [["c1", "p2"]], "nearest wins; another category never matches");
  assert.deepEqual(m.newOnes.map((x) => x.id), ["c2"]);
  assert.deepEqual(m.gone.map((x) => x.id), ["p1"]);
  // outside the window and a different title: no match
  assert.equal(matchFindings([f("c", "auth", "a.ts", 50, "Admin export lacks role check")], [f("p", "auth", "a.ts", 10, "Missing org scope")]).pairs.length, 0);
});

test("titles: case, punctuation, numbers and file:line tokens are ignored", () => {
  assert.equal(normTitle("IDOR in `src/a.ts:12` (route 2)!"), "idor in route");
  assert.ok(sameTitle("Raw SQL built from the search term", "raw SQL built from the search-term at src/q.ts:80"));
  assert.ok(!sameTitle("Raw SQL built from the search term", "Session token written to logs"));
  assert.ok(!sameTitle("", ""));
});

test("classify is pure: a previous fixed finding absent now stays fixed (not listed)", () => {
  const prev = { name: "r1", scope: null, findings: [{ id: "a-1", category: "auth", file: "a.ts", start: 1, end: 1, title: "x y z", severity: "LOW", fixed: true }] };
  const d = classify([], [prev]);
  assert.equal(d.still_fixed, 1);
  assert.deepEqual([d.new, d.fixed, d.regressed, d.unchanged].map((l) => l.length), [0, 0, 0, 0]);
});

test("CLI prints the section, or says it is the first run", () => {
  const first = auditRoot();
  writeRun(first, CURRENT);
  const r1 = spawnSync(process.execPath, [join(here, "diff.mjs"), "--dir", first], { encoding: "utf8" });
  assert.equal(r1.status, 0);
  assert.match(r1.stdout, /first run/);
  const r2 = spawnSync(process.execPath, [join(here, "diff.mjs"), "--dir", secondRun(), "--json"], { encoding: "utf8" });
  assert.equal(r2.status, 0);
  assert.deepEqual(ids(JSON.parse(r2.stdout).new), ["rate-limit-220"]);
});

test("report-md CLI writes report.md with the section on a second run", () => {
  const dir = secondRun();
  const r = spawnSync(process.execPath, [join(here, "report-md.mjs"), "--dir", dir], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.match(readFileSync(join(dir, "report.md"), "utf8"), /## Since Last Audit/);
});
