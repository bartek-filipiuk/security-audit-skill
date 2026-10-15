// Run: node --test scripts/*.test.mjs
// CI example (roadmap R15): ci-scope.mjs, ci-summary.mjs and the example workflow's structure.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { FALLBACK, safeDir, scopeDirs, scopeValue } from "./ci-scope.mjs";
import { MARKER, plainTitle, summarize, verdictOf } from "./ci-summary.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const scopeScript = join(here, "ci-scope.mjs");
const summaryScript = join(here, "ci-summary.mjs");
const workflow = join(here, "..", "examples", "github-actions", "security-audit.yml");

// ---- ci-scope ---------------------------------------------------------------------------------------------

const gitEnv = { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.com", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.com", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" };
const git = (cwd, ...args) => execFileSync("git", args, { cwd, env: gitEnv, encoding: "utf8" });
const put = (root, path, text = "x\n") => { mkdirSync(dirname(join(root, path)), { recursive: true }); writeFileSync(join(root, path), text); };

// A repository with a `main` branch and a `feature` branch checked out; `change(root)` edits the feature branch.
function repo(change) {
  const root = mkdtempSync(join(tmpdir(), "sa-ciscope-"));
  git(root, "init", "-q", "-b", "main");
  put(root, "src/old/moved.ts", "export const moved = 1;\n");
  put(root, "src/lib/keep.ts");
  put(root, "README.md");
  git(root, "add", "-A");
  git(root, "commit", "-qm", "base");
  git(root, "checkout", "-qb", "feature");
  change(root);
  git(root, "add", "-A");
  git(root, "commit", "-qm", "change", "--allow-empty");
  return root;
}

const runScope = (root, args = ["--base", "main"], env = {}) =>
  spawnSync(process.execPath, [scopeScript, ...args], { cwd: root, encoding: "utf8", env: { ...gitEnv, ...env } });

test("ci-scope: safeDir cuts a path at its first unsafe segment", () => {
  assert.equal(safeDir("src/app/api"), "src/app/api");
  assert.equal(safeDir("src/my dir/x"), "src");
  assert.equal(safeDir("src/$(id)/x"), "src");
  assert.equal(safeDir("src/a;b"), "src");
  assert.equal(safeDir("-rf/x"), "");
  assert.equal(safeDir("src/../etc"), "src");
  assert.equal(safeDir("zażółć/x"), "");
});

test("ci-scope: dirnames, root files and .security-audit dropped, children folded into a changed parent", () => {
  assert.deepEqual(scopeDirs(["README.md", ".security-audit/report.md", ".security-audit/findings/a.md", "src/a/b.ts", "src/a/c/d.ts", "lib/x.ts", "lib/x2.ts"]), ["lib", "src/a"]);
  assert.deepEqual(scopeValue(["src/a/b.ts", "lib/x.ts"]).value, "lib/,src/a/");
});

test("ci-scope: more than --max directories or no directory falls back to top20 with a reason", () => {
  const many = Array.from({ length: 21 }, (_, i) => `pkg${i}/index.ts`);
  const r = scopeValue(many);
  assert.equal(r.value, FALLBACK);
  assert.match(r.note, /21 changed directories/);
  assert.equal(scopeValue(many.slice(0, 20)).value.split(",").length, 20);
  assert.equal(scopeValue(many, { max: 30 }).value.split(",").length, 21);
  const none = scopeValue(["package.json", "README.md"]);
  assert.equal(none.value, FALLBACK);
  assert.match(none.note, /only root files/);
});

test("ci-scope CLI: renames count at their new path, deletions are left out, odd names are cut", () => {
  const root = repo((r) => {
    mkdirSync(join(r, "src/new"));
    git(r, "mv", "src/old/moved.ts", "src/new/moved.ts");
    git(r, "rm", "-q", "src/lib/keep.ts");
    put(r, "app/my dir/page.ts");
    put(r, "app2/we$ird;name/x.ts");
    put(r, "docs/a\"b/c.md");
  });
  const out = join(mkdtempSync(join(tmpdir(), "sa-ghout-")), "out");
  const r = runScope(root, ["--base", "main"], { GITHUB_OUTPUT: out });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout.trim(), "app/,app2/,docs/,src/new/");
  assert.match(r.stdout.trim(), /^[A-Za-z0-9_./,-]+$/);
  assert.equal(readFileSync(out, "utf8"), "scope=app/,app2/,docs/,src/new/\n");
});

test("ci-scope CLI: a branch that changed only root files gives top20 and says why on stderr", () => {
  const root = repo((r) => put(r, "package.json", "{}\n"));
  const r = runScope(root);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout.trim(), "top20");
  assert.match(r.stderr, /falling back to top20/);
  const empty = runScope(repo(() => {}));
  assert.equal(empty.stdout.trim(), "top20");
});

test("ci-scope CLI: more than 20 directories gives top20", () => {
  const root = repo((r) => { for (let i = 0; i < 25; i++) put(r, `mod${i}/x.ts`); });
  const r = runScope(root);
  assert.equal(r.stdout.trim(), "top20");
  assert.match(r.stderr, /25 changed directories/);
});

test("ci-scope CLI: a missing or option-like base is an error (exit 2)", () => {
  const root = repo((r) => put(r, "src/x.ts"));
  assert.equal(runScope(root, []).status, 2);
  assert.equal(runScope(root, ["--base", "--output=/tmp/x"]).status, 2);
  const bad = runScope(root, ["--base", "no-such-branch"]);
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /fetch-depth 0/);
});

// ---- ci-summary -------------------------------------------------------------------------------------------

const finding = ({ id, severity, title, remediation = "" }) =>
  `---\nid: ${id}\ncategory: ${id.replace(/-\d+$/, "")}\nseverity: ${severity}\nstatus: verified\nsource_agent: auditor-auth\nproof: static\nprerequisite_count: 0\nrejection_reason: ""\n${remediation}---\n\n## Title\n${title}\n\n## Evidence\n- **File**: \`src/a.ts:3\`\n- **Code**:\n\`\`\`\nconst x = 1;\n\`\`\`\n\n## Impact\nA signed-in user can read another organization's data.\n\n## Regression Test\nstatic: no runner.\n\n## Chained With\n- none\n\n## Recommendation\nScope the query.\n\n## Test Coverage\nuntested\n`;
const FIXED = 'remediation:\n  status: fixed\n  fix_evidence: ["src/a.ts:3"]\n  verification: "scoped"\n';

// Same pattern as export.test.mjs: remediation.json is written by audit-state.mjs itself.
function auditDir(files) {
  const root = mkdtempSync(join(tmpdir(), "sa-cisum-"));
  const dir = join(root, ".security-audit");
  mkdirSync(join(dir, "findings"), { recursive: true });
  mkdirSync(join(dir, "non-issues"));
  for (const f of files) writeFileSync(join(dir, "findings", `${f.id}.md`), finding(f));
  const r = spawnSync(process.execPath, [join(here, "audit-state.mjs"), "--dir", dir, "--final", "--write"], { encoding: "utf8" });
  assert.ok(existsSync(join(dir, "remediation.json")), `audit-state wrote remediation.json:\n${r.stdout}${r.stderr}`);
  return dir;
}

const env = { GITHUB_SERVER_URL: "https://github.com", GITHUB_REPOSITORY: "acme/ledgerly", GITHUB_RUN_ID: "42", PR_NUMBER: "7" };
const runSummary = (dir, args = [], extraEnv = {}) => {
  const out = join(mkdtempSync(join(tmpdir(), "sa-cibody-")), "body.md");
  const r = spawnSync(process.execPath, [summaryScript, "--dir", dir, "--out", out, ...args], { encoding: "utf8", env: { ...process.env, ...env, ...extraEnv } });
  return { ...r, out, body: existsSync(out) ? readFileSync(out, "utf8") : "" };
};

test("ci-summary: exit 1 when an unresolved finding is at or above --fail-on, counts in the body", () => {
  const dir = auditDir([
    { id: "auth-101", severity: "HIGH", title: "Invoice export reads other organizations" },
    { id: "config-308", severity: "LOW", title: "Verbose errors" },
    { id: "auth-120", severity: "CRITICAL", title: "Fixed already", remediation: FIXED },
  ]);
  const r = runSummary(dir);
  assert.equal(r.status, 1, r.stderr);
  assert.ok(r.body.startsWith(MARKER), "the comment starts with the marker");
  assert.match(r.body, /\| CRITICAL \| 0 \|/, "a fixed finding is not counted");
  assert.match(r.body, /\| HIGH \| 1 \|/);
  assert.match(r.body, /\| LOW \| 1 \|/);
  assert.match(r.body, /\| Total \| 2 \|/);
  assert.match(r.body, /https:\/\/github\.com\/acme\/ledgerly\/actions\/runs\/42/);
  assert.match(r.body, /security\/code-scanning\?query=pr%3A7%20tool%3Asecurity-audit/);
  assert.doesNotMatch(r.body, /Invoice export/, "no titles without --titles");
  assert.equal(runSummary(dir, ["--fail-on", "CRITICAL"]).status, 0);
  assert.equal(runSummary(dir, ["--fail-on", "none"]).status, 0);
  assert.equal(runSummary(dir, ["--fail-on", "LOW"]).status, 1);
  assert.equal(runSummary(dir, ["--fail-on", "SEVERE"]).status, 2, "an unknown threshold is a usage error");
});

test("ci-summary: exit 0 when nothing reaches the threshold; GITHUB_OUTPUT and the step summary are written", () => {
  const dir = auditDir([{ id: "config-308", severity: "MEDIUM", title: "Missing header" }]);
  const gh = mkdtempSync(join(tmpdir(), "sa-ghenv-"));
  const r = runSummary(dir, [], { GITHUB_OUTPUT: join(gh, "out"), GITHUB_STEP_SUMMARY: join(gh, "summary"), SECURITY_AUDIT_SCOPE: "src/app/,lib/" });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.body, /No unresolved finding at or above/);
  assert.match(r.body, /Scope: `src\/app\/,lib\/`/);
  const out = readFileSync(join(gh, "out"), "utf8");
  assert.match(out, /^verdict=pass$/m);
  assert.match(out, /^medium=1$/m);
  assert.match(out, new RegExp(`^body=${r.out.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "m"));
  assert.equal(readFileSync(join(gh, "summary"), "utf8"), r.body);
});

test("ci-summary: exit 2 and an 'incomplete' body when remediation.json is missing", () => {
  const dir = join(mkdtempSync(join(tmpdir(), "sa-cinone-")), ".security-audit");
  mkdirSync(dir);
  const gh = mkdtempSync(join(tmpdir(), "sa-ghenv-"));
  const r = runSummary(dir, [], { GITHUB_OUTPUT: join(gh, "out") });
  assert.equal(r.status, 2);
  assert.ok(r.body.startsWith(MARKER));
  assert.match(r.body, /did not finish/);
  assert.doesNotMatch(r.body, /\| HIGH \|/, "no counts that could read as a clean result");
  assert.match(readFileSync(join(gh, "out"), "utf8"), /^verdict=incomplete$/m);
});

test("ci-summary: --titles lists titles as plain text, without Markdown or HTML from the audited code", () => {
  const dir = auditDir([{ id: "auth-101", severity: "HIGH", title: "Org scope <img src=x> [link](https://example.com) `code`" }]);
  const r = runSummary(dir, ["--titles"]);
  assert.equal(r.status, 1);
  assert.match(r.body, /- HIGH: Org scope img src=x linkhttps:\/\/example\.com code/);
  assert.doesNotMatch(r.body.split("\n").filter((l) => l.startsWith("- ")).join("\n"), /[<>[\]`]/);
  assert.equal(plainTitle("a\nb"), "a b");
  assert.equal(verdictOf({ CRITICAL: 0, HIGH: 0, MEDIUM: 3, LOW: 0 }, "HIGH"), "pass");
  assert.equal(summarize(dir, { env: {} }).code, 1);
});

// ---- example workflow -------------------------------------------------------------------------------------

const yml = readFileSync(workflow, "utf8");
const lines = yml.split("\n");
const active = lines.filter((l) => !/^\s*#/.test(l));

// The body of every `run:` block (block scalar or one line), comments included.
function runBlocks(text) {
  const all = text.split("\n");
  const blocks = [];
  for (let i = 0; i < all.length; i++) {
    const m = all[i].match(/^(\s*)(?:- )?run:\s*(.*)$/);
    if (!m || /^\s*#/.test(all[i])) continue;
    if (!/^[|>]/.test(m[2])) { blocks.push(m[2]); continue; }
    const indent = m[1].length;
    const body = [];
    for (i++; i < all.length && (all[i].trim() === "" || all[i].match(/^\s*/)[0].length > indent); i++) body.push(all[i]);
    i--;
    blocks.push(body.join("\n"));
  }
  return blocks;
}

test("workflow: lives under examples/, never under .github/workflows", () => {
  assert.ok(existsSync(workflow));
  assert.ok(!existsSync(join(here, "..", ".github", "workflows", "security-audit.yml")));
});

test("workflow: every `uses:` is pinned to a full commit SHA or a flagged <pin-sha> placeholder", () => {
  const uses = lines.map((l) => l.match(/^\s*#?\s*(?:- )?uses:\s*(\S+)/)?.[1]).filter(Boolean);
  assert.ok(uses.length >= 4, "the workflow uses actions");
  const placeholders = [];
  for (const u of uses) {
    const ref = u.split("@")[1] ?? "";
    if (ref === "<pin-sha>") { placeholders.push(u); continue; }
    assert.match(ref, /^[0-9a-f]{40}$/, `${u} is pinned to a 40-hex commit SHA`);
  }
  for (const l of active) if (/uses:/.test(l)) assert.doesNotMatch(l, /<pin-sha>/, "a placeholder only in a commented-out step");
  const skillRef = yml.match(/SKILL_REF:\s*"([^"]*)"/)?.[1];
  assert.ok(skillRef === "<pin-sha>" || /^[0-9a-f]{40}$/.test(skillRef), "the skill is pinned by commit SHA or a placeholder");
  if (skillRef === "<pin-sha>") placeholders.push("SKILL_REF (the skill's commit)");
  if (placeholders.length) console.log(`# to pin before use: ${placeholders.join(", ")}`);
});

test("workflow: pull_request only, least privilege, concurrency, timeout, full history", () => {
  assert.doesNotMatch(active.join("\n"), /pull_request_target/);
  assert.match(yml, /^on:\n\s+pull_request:\n\s+types: \[opened, synchronize, reopened, ready_for_review\]/m);
  assert.match(yml, /^permissions: \{\}$/m, "no default permissions at the top level");
  assert.match(yml, /^\s+permissions:\n\s+contents: read/m);
  assert.doesNotMatch(active.join("\n"), /(contents|actions|id-token):\s*write/);
  assert.match(yml, /^concurrency:\n\s+group: security-audit-\$\{\{ github\.event\.pull_request\.number \}\}\n\s+cancel-in-progress: true/m);
  assert.match(yml, /timeout-minutes: \d+/);
  assert.match(yml, /fetch-depth: 0/);
  assert.match(yml, /persist-credentials: false/);
  assert.match(yml, /head\.repo\.full_name == github\.repository/);
  assert.match(yml, /dependabot\[bot\]/);
});

test("workflow: no expression inside run: scripts, the scope reaches them through env only", () => {
  const blocks = runBlocks(yml);
  assert.ok(blocks.length >= 5, `found ${blocks.length} run blocks`);
  for (const b of blocks) {
    assert.doesNotMatch(b, /\$\{\{/, `no \${{ }} in a run script:\n${b}`);
    assert.doesNotMatch(b, /github\.event\.pull_request\.(title|body)|head_ref/);
  }
  assert.match(yml, /SECURITY_AUDIT_SCOPE: \$\{\{ steps\.scope\.outputs\.scope \}\}/);
  assert.match(yml, /BASE_REF: \$\{\{ github\.base_ref \}\}/);
  assert.match(yml, /prompt: "\/security-audit --scope \$\{\{ steps\.scope\.outputs\.scope \}\}"/);
  assert.match(yml, /--setting-sources user,project/);
  assert.match(yml, /CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS/);
  assert.doesNotMatch(active.join("\n"), /--max-turns/);
  assert.doesNotMatch(active.join("\n"), /\.claude\/skills.*\$GITHUB_WORKSPACE|github\.workspace.*\.claude\/skills/, "the skill is installed outside the checkout");
});

test("workflow: parses as YAML (python3 + PyYAML when available)", (t) => {
  const py = spawnSync("python3", ["-c", "import sys, json, yaml; d = yaml.safe_load(open(sys.argv[1])); print(json.dumps(d, default=str))", workflow], { encoding: "utf8" });
  if (py.error || py.status !== 0 && /No module named|not found/.test(py.stderr ?? "")) {
    t.skip("python3 with PyYAML is not available: YAML parse skipped");
    return;
  }
  assert.equal(py.status, 0, py.stderr);
  const doc = JSON.parse(py.stdout);
  const on = doc.on ?? doc.true; // YAML 1.1 reads the bare key `on` as true
  assert.deepEqual(Object.keys(on), ["pull_request"]);
  const job = doc.jobs.audit;
  assert.equal(job["timeout-minutes"], 90);
  assert.deepEqual(doc.permissions, {});
  assert.equal(job.permissions.contents, "read");
  const steps = job.steps;
  const checkout = steps.find((s) => String(s.uses).startsWith("actions/checkout@"));
  assert.equal(checkout.with["fetch-depth"], 0);
  const audit = steps.find((s) => String(s.uses).startsWith("anthropics/claude-code-action@"));
  assert.deepEqual(Object.keys(audit.with).sort(), ["anthropic_api_key", "claude_args", "github_token", "prompt", "settings"]);
  assert.deepEqual(JSON.parse(audit.with.settings), { env: { CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS: "0" } });
  const upload = steps.find((s) => String(s.uses).startsWith("github/codeql-action/upload-sarif@"));
  assert.equal(upload.with.category, "security-audit");
  for (const s of steps.filter((s) => s.run)) assert.doesNotMatch(s.run, /\$\{\{/, `step "${s.name}" has no expression in run`);
});
