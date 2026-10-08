// Run: node --test scripts/
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { detectStack, resolveStack } from "./stack.mjs";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
const fixture = (name) => join(repo, "scripts", "fixtures", "stack", name);
const prepass = (root, ...extra) =>
  spawnSync(process.execPath, [join(repo, "scripts", "prepass.mjs"), "--root", root, "--out", join(root, ".security-audit"), "--no-docker", ...extra], { encoding: "utf8" });
const copy = (name) => {
  const dir = join(mkdtempSync(join(tmpdir(), "sa-stack-")), name);
  cpSync(fixture(name), dir, { recursive: true });
  return dir;
};

test("Ledgerly is detected as the dedicated JS/TS profile with its frameworks", () => {
  const s = detectStack(join(repo, "benchmark", "app"));
  assert.deepEqual(s.applied, ["js"]);
  assert.equal(s.warning, "");
  const p = s.profiles[0];
  assert.equal(p.dedicated, true);
  for (const fw of ["Next.js", "tRPC", "Hono", "Drizzle", "Better-Auth", "AI SDK", "pg-boss"]) assert.ok(p.frameworks.includes(fw), fw);
  assert.ok(p.covers.some((c) => c.includes("Drizzle tenant-scope scan")));
  assert.ok(p.gaps.some((g) => g.includes("ORMs other than Drizzle")));
});

test("a Laravel app is PHP with no dedicated profile; its vite package.json is not a second stack", () => {
  const s = detectStack(fixture("laravel"));
  assert.deepEqual(s.applied, ["php"]);
  assert.deepEqual(s.detected[0].frameworks, ["Laravel"]);
  assert.ok(s.detected[0].notes.some((n) => n.includes("frontend build tooling")));
  const p = s.profiles[0];
  assert.equal(p.dedicated, false);
  assert.ok(p.gaps.some((g) => g.includes("Laravel and Symfony routes")));
  assert.ok(!p.covers.some((c) => c.includes("Drupal")), "Drupal routing only claimed for Drupal");
});

test("Django (requirements.txt + manage.py) and FastAPI (pyproject.toml) are Python", () => {
  const dj = detectStack(fixture("django"));
  assert.deepEqual(dj.applied, ["python"]);
  assert.deepEqual(dj.detected[0].frameworks, ["Django"]);
  const fa = detectStack(fixture("fastapi"));
  assert.deepEqual(fa.applied, ["python"]);
  assert.deepEqual(fa.detected[0].frameworks, ["FastAPI", "SQLAlchemy"]);
  assert.equal(fa.profiles[0].dedicated, false);
  assert.ok(fa.profiles[0].gaps.some((g) => g.includes("bandit and pip-audit")));
});

test("monorepo: every stack gets its own profile, in the package directories, and unsupported frameworks are named", () => {
  const s = detectStack(fixture("monorepo"));
  assert.deepEqual(s.applied, ["js", "python"]);
  const js = s.detected.find((d) => d.id === "js");
  assert.deepEqual(js.dirs, ["apps/web"], "the workspace root without a framework is not a stack location");
  assert.deepEqual(s.detected.find((d) => d.id === "python").dirs, ["services/api"]);
  assert.ok(s.profiles[0].gaps[0].includes("Prisma"));
});

test("--stack forces a profile, warns on a conflict and lists what it leaves out", () => {
  const conflict = detectStack(fixture("laravel"), { force: "django" });
  assert.deepEqual(conflict.applied, ["python"]);
  assert.match(conflict.warning, /overrides detection: the code looks like PHP \(Laravel\)/);
  assert.ok(conflict.profiles[0].gaps.some((g) => g.includes("PHP (Laravel): detected but not profiled")));
  const agree = detectStack(fixture("laravel"), { force: "php" });
  assert.equal(agree.warning, "");
  assert.equal(agree.forced, "php");
  const partial = detectStack(fixture("monorepo"), { force: "nextjs" });
  assert.deepEqual(partial.applied, ["js"]);
  assert.match(partial.warning, /also detected: Python \(FastAPI\) in services\/api/);
  assert.throws(() => resolveStack("cobol"), /unknown stack/);
  assert.equal(resolveStack("Laravel"), "php");
});

test("prepass writes the profile to prepass.md and summary.json, and the reports show it", async () => {
  const proj = copy("laravel");
  const r = prepass(proj);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /profile php \(general checklist\)/);
  const audit = join(proj, ".security-audit");
  const md = readFileSync(join(audit, "prepass.md"), "utf8");
  assert.match(md, /## Stack and Profile/);
  assert.match(md, /\*\*Profile: PHP \(Laravel\): no dedicated profile, the general checklist applies \(profile planned as R05\)\.\*\*/);
  assert.match(md, /- Does not cover: Laravel and Symfony routes/);
  const sum = JSON.parse(readFileSync(join(audit, "tools", "summary.json"), "utf8"));
  assert.deepEqual(sum.stack.applied, ["php"]);
  assert.equal(sum.stack.forced, null);

  writeFileSync(join(audit, "summary.md"), "# Security Audit Report\n");
  const { renderReportMd } = await import("./report-md.mjs");
  const rep = renderReportMd(audit);
  assert.match(rep, /## Stack and Profile/);
  assert.match(rep, /Does not cover: Laravel and Symfony routes/);
  const { renderReport } = await import("./report-html.mjs");
  const html = renderReport(audit);
  assert.match(html, /Profile: PHP \(Laravel\): no dedicated profile, the general checklist applies/);
  assert.match(html, /Does not cover: Laravel and Symfony routes/);
});

test("prepass --stack: conflict warning in the output and the files, forced language in the briefs, bad name exits 2", async () => {
  const proj = copy("fastapi");
  const r = prepass(proj, "--stack", "laravel");
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /WARNING: --stack laravel overrides detection/);
  const audit = join(proj, ".security-audit");
  assert.match(readFileSync(join(audit, "prepass.md"), "utf8"), /\*\*Warning:\*\* --stack laravel overrides detection/);
  const sum = JSON.parse(readFileSync(join(audit, "tools", "summary.json"), "utf8"));
  assert.equal(sum.stack.forced, "php");
  const { forcedLanguage } = await import("./briefs.mjs");
  assert.equal(forcedLanguage(audit), "php");
  const { renderReport } = await import("./report-html.mjs");
  assert.match(renderReport(audit), /Forced with --stack/);

  const bad = prepass(proj, "--stack", "cobol");
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /unknown stack "cobol"/);
  assert.equal(prepass(proj, "--stack").status, 2);
});

test("old audits without a stack record render without the section", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sa-nostack-"));
  for (const d of ["findings", "non-issues", "tools"]) mkdirSync(join(dir, d));
  writeFileSync(join(dir, "tools", "summary.json"), JSON.stringify({ project: "x", commit: "", deps: { status: "ok", rows: [] }, secrets: { status: "ok", rows: [] } }));
  const { renderReportMd } = await import("./report-md.mjs");
  const { renderReport } = await import("./report-html.mjs");
  assert.ok(!renderReportMd(dir).includes("Stack and Profile"));
  assert.ok(!renderReport(dir).includes("Profile:"));
});
