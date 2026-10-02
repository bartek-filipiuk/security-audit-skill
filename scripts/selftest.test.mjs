// Run: node --test scripts/
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { buildRemediation, loadAudit, parseFrontmatter, validate } from "./audit-state.mjs";
import { inScope, rankHotspots, scanEntryPoints, scanScope, walk } from "./surface.mjs";
import { score } from "../benchmark/score.mjs";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
const { files } = walk(join(repo, "benchmark", "app"));
const key = JSON.parse((await import("node:fs")).readFileSync(join(repo, "benchmark", "answer-key.json"), "utf8"));

test("entry points cover the framework conventions the old Express-only table missed", () => {
  const eps = scanEntryPoints(files);
  const has = (kind, name, file) => eps.some((e) => e.kind === kind && e.name === name && (!file || e.file.endsWith(file)));
  assert.ok(has("server-action", "getInvoice", "invoices/actions.ts"));
  assert.equal(eps.find((e) => e.name === "getInvoice").guard, "");
  assert.ok(has("trpc", "projectRouter.update"));
  assert.equal(eps.find((e) => e.name === "projectRouter.update").guard, "orgProcedure");
  assert.ok(has("http-route", "GET") && eps.some((e) => e.route === "/api/public/invoices"));
  assert.ok(has("route-handler", "GET", "api/admin/stats/route.ts"));
  assert.ok(has("webhook", "POST", "webhooks/stripe/route.ts"));
  assert.ok(has("job", "overdue-digest") && has("ai-tool", "searchInvoices"));
  assert.match(eps.find((e) => e.kind === "middleware").guard, /\/admin\/:path\*/);
  assert.ok(eps.some((e) => e.kind === "route-handler" && e.name === "POST" && e.route === "/api/auth/[...all]"));
  assert.ok(eps.some((e) => e.kind === "page" && e.route === "/invoices/[id]"));
});

test("scope scan flags the unscoped Drizzle statements and none of the scoped decoys", () => {
  const { sites, tables } = scanScope(files);
  const cand = sites.filter((s) => s.status !== "scoped");
  const flagged = (file, table, status = "UNSCOPED") => cand.some((s) => s.file.endsWith(file) && s.table === table && s.status === status);
  assert.ok(flagged("invoices/actions.ts", "invoices"));
  assert.ok(flagged("invoices/actions.ts", "invoiceLines", "PARENT-ONLY"));
  assert.ok(flagged("routers/project.ts", "projects"));
  assert.ok(flagged("p/[slug]/page.tsx", "projects"));
  for (const decoy of ["projects/actions.ts", "routers/invoice.ts", "documents/[id]/download/route.ts", "queries/dashboard.ts"]) {
    assert.ok(!cand.some((s) => s.file.endsWith(decoy)), `decoy flagged: ${decoy}`);
  }
  assert.deepEqual(tables.find((t) => t.var === "invoiceLines").via, ["invoiceId -> invoices"]);
  assert.ok(!sites.some((s) => s.file.endsWith(".test.ts")));
});

function auditDir(findings, nonIssues = {}) {
  const dir = mkdtempSync(join(tmpdir(), "sa-test-"));
  mkdirSync(join(dir, "findings"));
  mkdirSync(join(dir, "non-issues"));
  for (const [name, text] of Object.entries(findings)) writeFileSync(join(dir, "findings", `${name}.md`), text);
  for (const [name, text] of Object.entries(nonIssues)) writeFileSync(join(dir, "non-issues", `${name}.md`), text);
  return dir;
}

const verifiedHigh = `---
id: auth-001
category: auth
severity: HIGH
status: verified
proof: dynamic
remediation:
  status: fixed
  fix_evidence:
    - "src/app/(app)/invoices/actions.ts:11"
  public_safe: true
---

## Title
getInvoice server action reads any organization's invoice

## Evidence
- **File**: \`src/app/(app)/invoices/actions.ts:11\`

## Exploit Steps
1. Sign in as a member of org B.
2. Call the getInvoice action with an invoice id from org A.

## Proof
$ node .security-audit/poc/auth-001.mjs
status 200, invoice number INV-0042 from org A
`;

test("audit-state accepts a well-formed finding and rejects drift", () => {
  const dir = auditDir({
    "auth-001": verifiedHigh,
    "injection-001": `---\nid: injection-001\ncategory: injection\nseverity: HIGH\nstatus: fixed\n---\n## Title\nx\n`,
    "exposure-001": `---\nid: exposure-001\ncategory: "2.4 Data Exposure"\nseverity: MEDIUM\nstatus: verified\nremediation:\n  status: open\n  public_safe: true\n---\n## Title\ny\n## Evidence\n\`a.ts:1\`\n## Exploit Steps\n1. do it\n`,
    "auth-002": `---\nid: auth-002\ncategory: auth\nseverity: HIGH\nstatus: rejected\nrejection_reason: duplicate_of_auth-999\n---\n`,
    "auth-003": `---\nid: auth-003\ncategory: auth\nseverity: LOW\nstatus: rejected\nrejection_reason: best_practice — fine as is\n---\n`,
    "auth-004": `---\nid: auth-004\ncategory: auth\nseverity: CRITICAL\nstatus: raw\n---\n`,
  });
  const audit = loadAudit(dir);
  const errors = validate(audit, { final: true });
  const about = (id) => errors.filter((e) => e.includes(`/${id}.md`));
  assert.deepEqual(about("auth-001"), []);
  assert.deepEqual(about("auth-003"), []);
  assert.ok(about("injection-001").some((e) => e.includes("legacy")));
  assert.ok(about("exposure-001").some((e) => e.includes("category")));
  assert.ok(about("exposure-001").some((e) => e.includes("public_safe")));
  assert.ok(about("auth-002").some((e) => e.includes("unknown finding")));
  assert.ok(about("auth-004").some((e) => e.includes("still raw")));

  const doc = buildRemediation(audit, null, { project: "x", source: "baseline-from-audit", commit: "abc1234" });
  const entry = doc.findings.find((f) => f.id === "auth-001");
  assert.equal(entry.remediation_status, "fixed");
  assert.equal(entry.public_safe, true);
  assert.deepEqual(entry.fix_evidence, ["src/app/(app)/invoices/actions.ts:11"]);
  assert.equal(doc.findings.find((f) => f.id === "exposure-001").public_safe, false);
  assert.equal(doc.summary.cleared.rejected, 2);
});

test("frontmatter parser handles comments, flow arrays and block scalars", () => {
  const { data, errors } = parseFrontmatter(`---\nid: a-001 # trailing\nlist: ["x:1", "y:2"]\nnote: |\n---\nbody`);
  assert.equal(data.id, "a-001");
  assert.deepEqual(data.list, ["x:1", "y:2"]);
  assert.ok(errors.some((e) => e.includes("block scalars")));
});

test("benchmark scoring separates found, dropped, decoy hits and unmatched", () => {
  const dir = auditDir({
    "auth-001": verifiedHigh,
    "auth-002": `---\nid: auth-002\ncategory: auth\nseverity: HIGH\nstatus: verified\nproof: static\n---\n## Title\nprojects/actions.ts deleteProject lacks ownership check\n\`src/app/(app)/projects/actions.ts:40\`\n`,
    "crypto-001": `---\nid: crypto-001\ncategory: crypto\nseverity: CRITICAL\nstatus: rejected\nrejection_reason: no_evidence\n---\n## Title\nStripe webhook signature not verified\n\`src/app/api/webhooks/stripe/route.ts:6\`\n`,
    "config-009": `---\nid: config-009\ncategory: config\nseverity: LOW\nstatus: verified\n---\n## Title\nMissing CSP header\n\`next.config.ts:3\`\n`,
  });
  const r = score(loadAudit(dir).findings, key);
  const by = Object.fromEntries(r.seeded.map((s) => [s.id, s.result]));
  assert.equal(by.B01, "found");
  assert.equal(by.B08, "dropped_by_verifier");
  assert.equal(by.B02, "missed");
  assert.equal(r.decoy_fp, 1);
  assert.deepEqual(r.unmatched.map((u) => u.id), ["config-009"]);
});

test("hotspot ranking puts the seeded code-level bugs near the top", () => {
  const hot = rankHotspots(files, scanEntryPoints(files), scanScope(files));
  const code = key.seeded.filter((b) => !b.detect.startsWith("tool:"));
  const within = (n) => code.filter((b) => hot.slice(0, n).some((h) => b.files.some((f) => h.file.endsWith(f) || h.reasons.some((r) => r.includes(f)))));
  const top10 = within(10).length;
  const top20 = within(20).length;
  console.log(`hotspots: ${top10}/${code.length} seeded bugs in top 10, ${top20}/${code.length} in top 20`);
  assert.ok(top10 >= 9, `only ${top10} seeded bugs in the top 10`);
  assert.ok(top20 >= 13, `only ${top20} seeded bugs in the top 20`);
  for (const decoy of ["projects/actions.ts", "routers/invoice.ts", "services/rates.ts", "lib/analytics.ts"]) {
    assert.ok(!hot.slice(0, 10).some((h) => h.file.endsWith(decoy)), `decoy in the top 10: ${decoy}`);
  }
  assert.ok(!hot.some((h) => h.file.endsWith("api/trpc/[trpc]/route.ts") && h.reasons.includes("no auth check in the handler")));
});

test("report.html escapes everything that comes from findings", async () => {
  const { renderReport } = await import("./report-html.mjs");
  const dir = auditDir(
    {
      "injection-001": `---\nid: injection-001\ncategory: injection\nseverity: HIGH\nstatus: verified\nproof: static\n---\n## Title\n<script>alert(1)</script> in \`<img src=x onerror=alert(2)>\`\n## Evidence\n- **File**: \`src/a.ts:1\`\n\`\`\`\n</code></pre><script>alert(3)</script>\n\`\`\`\n## Exploit Steps\n1. "><svg onload=alert(4)>\n`,
    },
    { "non-auth-001": `---\nid: non-auth-001\ncategory: auth\n---\n## Area Examined\n<iframe src=//evil>\n## Why Not Vulnerable\nok\n## Evidence\n\`b.ts:2\`\n` },
  );
  const html = renderReport(dir);
  assert.ok(!/<script>alert|<img src=x|<svg onload|<iframe/.test(html), "unescaped markup from a finding");
  assert.ok(html.includes("&lt;script&gt;alert(1)&lt;/script&gt;"));
  assert.match(html, /Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-/);
  assert.equal((html.match(/<script>/g) ?? []).length, 1, "only the report's own print script");
});

test("--scope selects areas, paths and the top N, and rejects unknown names", () => {
  const hot = rankHotspots(files, scanEntryPoints(files), scanScope(files));
  const sel = (spec) => hot.filter(inScope(spec, hot.filter((h) => h.score > 0))).map((h) => h.file);
  assert.ok(sel("auth").includes("src/lib/auth.ts") && sel("auth").includes("src/proxy.ts"));
  assert.ok(!sel("auth").some((f) => f.includes("webhooks/stripe")));
  assert.equal(sel("top5").length, 5);
  assert.ok(sel("src/server/trpc").every((f) => f.startsWith("src/server/trpc/")));
  assert.ok(sel("payments,webhooks").includes("src/app/api/webhooks/stripe/route.ts"));
  assert.throws(() => inScope("bogus", []), /unknown scope/);
});

test("CLI scripts run when invoked through a symlinked skill directory", async () => {
  const { spawnSync } = await import("node:child_process");
  const { symlinkSync } = await import("node:fs");
  const link = join(mkdtempSync(join(tmpdir(), "sa-link-")), "skill");
  symlinkSync(repo, link);
  const dir = auditDir({ "auth-001": verifiedHigh });
  const r = spawnSync(process.execPath, [join(link, "scripts", "audit-state.mjs"), "--dir", dir], { encoding: "utf8" });
  assert.match(r.stdout, /audit-state: 1 findings/);
  const h = spawnSync(process.execPath, [join(link, "scripts", "report-html.mjs"), "--dir", dir], { encoding: "utf8" });
  assert.match(h.stdout, /report.html written/);
});

test("briefs carry only the auditor's checklist sections and the project's languages", async () => {
  const { patternsFor, writeBriefs } = await import("./briefs.mjs");
  const dir = auditDir({});
  writeBriefs(dir, { auth: ["2.1", "2.11"] }, ["js"]);
  const brief = (await import("node:fs")).readFileSync(join(dir, "briefs", "auth.md"), "utf8");
  assert.match(brief, /## 2\.1 Authentication/);
  assert.match(brief, /## 2\.11 Business Logic/);
  assert.ok(!/## 2\.10 /.test(brief), "2.1 must not pull in 2.10");
  assert.ok(brief.includes("| Drizzle |") && !brief.includes("| PHP |") && !brief.includes("PHP-Specific"));
  assert.ok(patternsFor(["php"]).includes("PHP-Specific") && !patternsFor(["php"]).includes("| JS/TS |"));
});

test("report.md is assembled from summary.md and the finding files", async () => {
  const { renderReportMd } = await import("./report-md.mjs");
  const dir = auditDir(
    { "auth-001": verifiedHigh, "auth-002": `---\nid: auth-002\ncategory: auth\nseverity: LOW\nstatus: rejected\nrejection_reason: best_practice — fine\n---\n## Title\nx\n` },
    { "non-auth-001": `---\nid: non-auth-001\ncategory: auth\n---\n## Area Examined\nLogin rate limit\n## Evidence\n\`src/a.ts:9\`\n` },
  );
  writeFileSync(join(dir, "summary.md"), "# Security Audit Report\n\n## Executive Summary\n- Top 3 risks: auth-001 (dynamic)\n");
  const md = renderReportMd(dir);
  assert.match(md, /^# Security Audit Report/);
  assert.match(md, /### \[F1\] getInvoice server action reads any organization's invoice/);
  assert.match(md, /\*\*Proof\*\*: dynamic/);
  assert.match(md, /\| 1 \| non-auth-001 \| Login rate limit \| src\/a\.ts:9 \|/);
  assert.match(md, /\| auth-002 \| best_practice — fine \|/);
});

test("prepass --new-run archives the previous run and workspace-check sees later writes", async () => {
  const { spawnSync } = await import("node:child_process");
  const { workspaceCheck } = await import("./workspace-check.mjs");
  const fsm = await import("node:fs");
  const proj = mkdtempSync(join(tmpdir(), "sa-proj-"));
  writeFileSync(join(proj, "server.js"), 'app.get("/api/health", (req, res) => res.send("ok"));\n');
  const audit = join(proj, ".security-audit");
  mkdirSync(join(audit, "findings"), { recursive: true });
  writeFileSync(join(audit, "findings", "auth-001.md"), verifiedHigh);
  writeFileSync(join(audit, "report.md"), "# old\n");
  const r = spawnSync(process.execPath, [join(repo, "scripts", "prepass.mjs"), "--root", proj, "--no-docker", "--new-run"], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /previous run archived/);
  const hist = fsm.readdirSync(join(audit, "history"));
  assert.equal(hist.length, 1);
  assert.ok(fsm.existsSync(join(audit, "history", hist[0], "findings", "auth-001.md")));
  assert.deepEqual(fsm.readdirSync(join(audit, "findings")), []);
  assert.ok(fsm.existsSync(join(audit, "prepass.md")));
  await new Promise((res) => setTimeout(res, 20));
  writeFileSync(join(proj, "generated.html"), "<p>written by a test run</p>");
  const ws = workspaceCheck(audit);
  assert.ok(ws.ok);
  assert.deepEqual(ws.changed, ["generated.html"]);
});
