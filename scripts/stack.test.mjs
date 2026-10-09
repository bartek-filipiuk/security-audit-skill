// Run: node --test scripts/*.test.mjs
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

test("a Laravel app gets the dedicated PHP profile (R05); its vite package.json is not a second stack", () => {
  const s = detectStack(fixture("laravel"));
  assert.deepEqual(s.applied, ["php"]);
  assert.deepEqual(s.detected[0].frameworks, ["Laravel"]);
  assert.ok(s.detected[0].notes.some((n) => n.includes("frontend build tooling")));
  const p = s.profiles[0];
  assert.equal(p.dedicated, true);
  assert.ok(p.covers.some((c) => c.startsWith("Laravel routes/*.php entry points")));
  assert.ok(p.gaps.some((g) => g.includes("Psalm taint analysis is not run")));
  assert.ok(!p.covers.some((c) => /^(Drupal|Symfony) /.test(c)), "routing only claimed for the detected frameworks");
  const plain = detectStack(fixture("django"), { force: "php" }).profiles[0];
  assert.equal(plain.dedicated, false, "PHP without Laravel, Symfony or Drupal stays on the general checklist");
});

test("Django (requirements.txt + manage.py) and FastAPI (pyproject.toml) are Python", () => {
  const dj = detectStack(fixture("django"));
  assert.deepEqual(dj.applied, ["python"]);
  assert.deepEqual(dj.detected[0].frameworks, ["Django"]);
  const fa = detectStack(fixture("fastapi"));
  assert.deepEqual(fa.applied, ["python"]);
  assert.deepEqual(fa.detected[0].frameworks, ["FastAPI", "SQLAlchemy"]);
  assert.equal(fa.profiles[0].dedicated, true, "dedicated Python profile (R06)");
  assert.ok(fa.profiles[0].covers.some((c) => c.startsWith("FastAPI @app/@router entry points")));
  assert.ok(!fa.profiles[0].covers.some((c) => c.startsWith("Django urls.py")), "Django routing only claimed for Django");
  assert.ok(fa.profiles[0].covers.some((c) => c.includes("pip-audit") && c.includes("bandit") === false));
  assert.ok(fa.profiles[0].covers.some((c) => c.startsWith("bandit through the rule-scanner runner")));
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
  assert.match(r.stdout, /profile php(?! \(general checklist\))/);
  const audit = join(proj, ".security-audit");
  const md = readFileSync(join(audit, "prepass.md"), "utf8");
  assert.match(md, /## Stack and Profile/);
  assert.match(md, /\*\*Profile: PHP \(Laravel\): dedicated profile\.\*\*/);
  assert.match(md, /- Does not cover: no Eloquent or Doctrine tenant-scope scan/);
  const sum = JSON.parse(readFileSync(join(audit, "tools", "summary.json"), "utf8"));
  assert.deepEqual(sum.stack.applied, ["php"]);
  assert.equal(sum.stack.forced, null);

  writeFileSync(join(audit, "summary.md"), "# Security Audit Report\n");
  const { renderReportMd } = await import("./report-md.mjs");
  const rep = renderReportMd(audit);
  assert.match(rep, /## Stack and Profile/);
  assert.match(rep, /Does not cover: no Eloquent or Doctrine tenant-scope scan/);
  const { renderReport } = await import("./report-html.mjs");
  const html = renderReport(audit);
  assert.match(html, /Profile: PHP \(Laravel\): dedicated profile/);
  assert.match(html, /Does not cover: no Eloquent or Doctrine tenant-scope scan/);
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

test("one detector: framework profiles, briefs languages and semgrep rulesets all come from stack.mjs", async () => {
  const { detectLanguages } = await import("./briefs.mjs");
  const { inventory, rulesetStack } = await import("./tools.mjs");
  const app = (name) => join(repo, "benchmark", name, "app");
  const cases = [
    [join(repo, "benchmark", "app"), [], "js"],
    [app("supabase-notes"), ["supabase", "firebase"], "js,supabase,firebase"],
    [app("php-tickets"), ["laravel", "symfony", "drupal"], "php,laravel,symfony,drupal"],
    [app("py-clinic"), ["django", "fastapi", "flask"], "python,django,fastapi,flask"],
  ];
  for (const [root, fps, briefs] of cases) {
    const s = detectStack(root);
    assert.deepEqual(s.framework_profiles, fps, root);
    assert.equal(detectLanguages(root).join(","), briefs, root);
  }
  // The Drupal module has no composer.json within reach of the manifest walk: its files put Drupal on the PHP stack.
  const php = detectStack(app("php-tickets"));
  assert.deepEqual(php.detected[0].frameworks, ["Laravel", "Symfony", "Drupal"]);
  assert.equal(php.profiles[0].dedicated, true);
  assert.ok(php.profiles[0].covers.some((c) => c.startsWith("Drupal *.routing.yml")));
  const py = app("py-clinic");
  const tags = rulesetStack(inventory(py), detectStack(py));
  for (const t of ["python", "django", "fastapi", "flask"]) assert.ok(tags.includes(t), t);
  assert.ok(rulesetStack(inventory(join(repo, "benchmark", "app"))).includes("react"), "React from the stack's libraries");
});
