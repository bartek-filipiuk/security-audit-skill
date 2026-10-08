// Run: node --test scripts/*.test.mjs
// Every scanner here is mocked: an injected runner or a fake binary that prints a fixture.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { toolFreeEnv } from "./test-helpers.mjs";
import {
  dedupe, IMAGES, inventory, MAX_ROWS, mergeNotAssessed, parseHadolint, parseSarif, parseSemgrep,
  parseTrivy, renderTools, rulesetStack, runTools, semgrepConfigs,
} from "./tools.mjs";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");

function project(files) {
  const dir = mkdtempSync(join(tmpdir(), "sa-tools-"));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  return dir;
}

const infraProject = () => project({
  "package.json": JSON.stringify({ name: "demo", dependencies: { next: "15", react: "19", express: "5" } }),
  "src/app/page.tsx": "export default function Page() { return null; }\n",
  "server.js": "module.exports = {};\n",
  ".github/workflows/ci.yml": "on: push\njobs: {}\n",
  "Dockerfile": "FROM node:20\n",
  "docker/worker.Dockerfile": "FROM node:20\n",
  "docker-compose.yml": "services: {}\n",
  "infra/main.tf": "terraform {}\n",
  "node_modules/dep/Dockerfile": "FROM scratch\n",
  ".security-audit/tools/Dockerfile": "FROM scratch\n",
});

const semgrepOut = (root) => JSON.stringify({
  results: [
    { check_id: "js.express.xss", path: "/src/server.js", start: { line: 3 }, extra: { severity: "WARNING", message: "User input\nreaches `res.send`" } },
    { check_id: "js.express.xss", path: "./server.js", start: { line: 3 }, extra: { severity: "ERROR", message: "User input reaches `res.send`" } },
    { check_id: "ts.next.open-redirect", path: `${root}/src/app/page.tsx`, start: { line: 1 }, extra: { severity: "INFO", message: "redirect" } },
    { check_id: "x.audit-dir", path: ".security-audit/tests/a.ts", start: { line: 1 }, extra: { severity: "ERROR", message: "own file" } },
  ],
  errors: [],
});
const zizmorOut = JSON.stringify({ runs: [{ results: [{ ruleId: "template-injection", level: "error", message: { text: "code injection via template expansion" }, locations: [{ physicalLocation: { artifactLocation: { uri: ".github/workflows/ci.yml" }, region: { startLine: 9 } } }] }] }] });
const hadolintOut = JSON.stringify([{ code: "DL3007", file: "/src/Dockerfile", line: 1, level: "warning", message: "Using latest is prone to errors" }]);
const trivyOut = JSON.stringify({ Results: [{ Target: "Dockerfile", Misconfigurations: [
  { ID: "DS002", Title: "Image user should not be 'root'", Severity: "HIGH", Status: "FAIL", CauseMetadata: { StartLine: 1 } },
  { ID: "DS026", Title: "No HEALTHCHECK", Severity: "LOW", Status: "PASS" },
] }] });

test("inventory finds workflows, Dockerfiles and IaC outside skipped directories; stack picks semgrep rulesets", () => {
  const root = infraProject();
  const inv = inventory(root);
  assert.deepEqual(inv.workflows, [".github/workflows/ci.yml"]);
  assert.deepEqual(inv.dockerfiles, ["Dockerfile", "docker/worker.Dockerfile"]);
  assert.deepEqual(inv.iac, ["docker-compose.yml", "infra/main.tf"]);
  const stack = rulesetStack(inv);
  for (const s of ["express", "js", "nextjs", "react", "ts"]) assert.ok(stack.includes(s), s);
  assert.deepEqual(semgrepConfigs(stack), ["p/expressjs", "p/javascript", "p/nextjs", "p/react", "p/typescript"]);
  const py = project({ "requirements.txt": "Django==5.0\nrequests\n", "app/views.py": "x = 1\n", "manage.py": "\n" });
  assert.deepEqual(semgrepConfigs(rulesetStack(inventory(py))), ["p/django", "p/python"]);
  // The rulesets come from stack.mjs: a result passed in is used as is, not detected again.
  assert.deepEqual(rulesetStack({ langs: { python: 1 } }, { detected: [{ id: "python", frameworks: ["FastAPI"] }] }), ["fastapi", "python"]);
  assert.deepEqual(semgrepConfigs([]), []);
});

test("on Ledgerly every tool applies (R08 seeds a workflow, Dockerfile and compose file) and none runs without a binary or docker", () => {
  const root = join(repo, "benchmark", "app");
  const inv = inventory(root);
  const stack = rulesetStack(inv);
  assert.ok(stack.includes("nextjs") && stack.includes("ts"));
  const calls = [];
  const res = runTools({ root, inv, stack, runner: { installed: () => false, run: (...a) => calls.push(a), dockerOk: false } });
  assert.deepEqual(calls, [], "nothing is executed when no tool is available");
  const by = Object.fromEntries(res.map((r) => [r.tool, r]));
  assert.equal(by.semgrep.state, "not-run");
  assert.match(by.semgrep.status, /^NOT RUN: semgrep not installed and docker unavailable; to enable: `pipx install semgrep`/);
  assert.deepEqual(inv.workflows, [".github/workflows/ci.yml", ".github/workflows/preview.yml"]);
  assert.deepEqual(inv.dockerfiles, ["Dockerfile"]);
  assert.deepEqual(inv.iac, ["docker-compose.yml"]);
  for (const t of ["zizmor", "hadolint", "trivy"]) assert.match(by[t].status, new RegExp(`^NOT RUN: ${t} not installed and docker unavailable`), t);
});

test("parsers normalize paths, severities and notes; dedupe keeps the most severe copy", () => {
  const root = "/work/demo";
  const sem = parseSemgrep(semgrepOut(root), root);
  assert.deepEqual(sem.map((r) => `${r.file}:${r.line}`), ["server.js:3", "server.js:3", "src/app/page.tsx:1", ".security-audit/tests/a.ts:1"]);
  assert.equal(sem[0].note, "User input reaches 'res.send'");
  const d = dedupe(sem.slice(0, 3));
  assert.equal(d.length, 2);
  assert.deepEqual([d[0].file, d[0].severity], ["server.js", "high"]);
  assert.deepEqual(parseSarif(zizmorOut, root)[0], { file: ".github/workflows/ci.yml", line: 9, rule: "template-injection", severity: "high", note: "code injection via template expansion" });
  assert.deepEqual(parseHadolint(hadolintOut, root)[0], { file: "Dockerfile", line: 1, rule: "DL3007", severity: "medium", note: "Using latest is prone to errors" });
  assert.deepEqual(parseTrivy(trivyOut, root).map((r) => r.rule), ["DS002"], "passed checks are not candidates");
  assert.throws(() => parseSemgrep("semgrep: error", root));
  assert.throws(() => parseHadolint("{}", root));
});

test("runTools: native first, then docker pinned by digest, else NOT RUN; FAILED on unparsable output", () => {
  const root = infraProject();
  const inv = inventory(root);
  const stack = rulesetStack(inv);
  const calls = [];
  const written = {};
  const runner = {
    installed: (cmd) => cmd === "semgrep" || cmd === "zizmor",
    dockerOk: true,
    run: (cmd, argv) => {
      calls.push([cmd, argv]);
      if (cmd === "semgrep") return { status: 0, stdout: semgrepOut(root) };
      if (cmd === "zizmor") return { status: 14, stdout: "", stderr: "fatal: no audit was performed\n" };
      if (argv.includes(IMAGES.hadolint)) return { status: 0, stdout: hadolintOut };
      return { status: 0, stdout: trivyOut };
    },
  };
  const res = runTools({ root, inv, stack, runner, write: (n, t) => { written[n] = t; } });
  const by = Object.fromEntries(res.map((r) => [r.tool, r]));

  const [, semArgs] = calls.find(([c]) => c === "semgrep");
  for (const a of ["--json", "--metrics=off", "p/nextjs", ".security-audit"]) assert.ok(semArgs.includes(a), a);
  assert.equal(by.semgrep.status, "semgrep: 2 candidates (p/expressjs, p/javascript, p/nextjs, p/react, p/typescript)");
  assert.ok(!by.semgrep.rows.some((r) => r.file.startsWith(".security-audit/")));

  assert.equal(by.zizmor.state, "failed");
  assert.equal(by.zizmor.status, "FAILED (zizmor): fatal: no audit was performed");

  const [, hadArgs] = calls.find(([c, a]) => c === "docker" && a.includes(IMAGES.hadolint));
  assert.ok(hadArgs.includes(`${root}:/src:ro`));
  assert.ok(hadArgs.includes("/src/Dockerfile") && hadArgs.includes("/src/docker/worker.Dockerfile"));
  assert.equal(by.hadolint.via, "hadolint (docker)");
  assert.equal(by.trivy.total, 1);
  assert.deepEqual(Object.keys(written).sort(), ["hadolint.json", "semgrep.json", "trivy.json"]);

  const off = runTools({ root, inv, stack, runner: { installed: () => false, run: () => assert.fail("must not run"), dockerOk: false, dockerDisabled: true } });
  assert.equal(off.find((r) => r.tool === "bandit").status, "skipped: no Python source outside tests");
  assert.ok(off.filter((r) => r.tool !== "bandit").every((r) => r.state === "not-run"));
  assert.match(off[0].status, /docker disabled by --no-docker/);
});

test("candidates are capped per tool and the total is kept", () => {
  const root = "/w";
  const results = Array.from({ length: MAX_ROWS + 5 }, (_, i) => ({ check_id: "r", path: `a${i}.js`, start: { line: 1 }, extra: { severity: "INFO", message: "m|n" } }));
  const res = runTools({
    root, inv: { langs: { js: 1 }, manifests: [], workflows: [], dockerfiles: [], iac: [] }, stack: ["js"], only: ["semgrep"],
    runner: { installed: () => true, run: () => ({ status: 0, stdout: JSON.stringify({ results }) }) },
  });
  assert.equal(res[0].rows.length, MAX_ROWS);
  assert.equal(res[0].total, MAX_ROWS + 5);
  const md = renderTools(res, (h, rows) => [h.join("|"), ...rows.map((r) => r.join("|"))].join("\n"));
  assert.match(md, /\(\+5 more in tools\/tool-candidates\.json\)/);
});

test("not-assessed rows: added for NOT RUN/FAILED, replaced on re-run, other rows kept", () => {
  const notRun = [{ tool: "semgrep", category: "code", check: "semgrep rule scan (p/javascript)", state: "not-run", status: "NOT RUN: x | y" }, { tool: "zizmor", category: "ci/cd", check: "c", state: "skipped", status: "skipped: no workflows" }];
  const first = mergeNotAssessed("", notRun);
  assert.equal(first, "| Category | Check | Why not assessed |\n|---|---|---|\n| code | semgrep rule scan (p/javascript) | NOT RUN: x \\| y (prepass) |\n");
  const agent = `${first}| auth | login rate limit | no tests |\n`;
  assert.equal(mergeNotAssessed(agent, notRun).match(/semgrep/g).length, 1, "idempotent");
  const ran = mergeNotAssessed(agent, [{ ...notRun[0], state: "ran", status: "semgrep: 0 candidates" }]);
  assert.ok(!ran.includes("semgrep") && ran.includes("login rate limit"));
  assert.equal(mergeNotAssessed("", [notRun[1]]), "");
});

test("docker images are pinned by digest", () => {
  for (const [tool, image] of Object.entries(IMAGES)) assert.match(image, /^[\w./-]+:[\w.-]+@sha256:[0-9a-f]{64}$/, tool);
});

test("prepass end to end: fake scanners become candidates, missing ones NOT RUN, existing sections unchanged", () => {
  const root = infraProject();
  const fix = mkdtempSync(join(tmpdir(), "sa-fix-"));
  writeFileSync(join(fix, "semgrep.json"), semgrepOut(root));
  writeFileSync(join(fix, "hadolint.json"), hadolintOut);
  // PATH holds only these fakes and git, so the fake prints its fixture through node, not cat.
  const fake = (file) => `[ "$1" = "--version" ] && { echo 1.0; exit 0; }\nexec "${process.execPath}" -e 'process.stdout.write(require("fs").readFileSync(process.argv[1]))' "${join(fix, file)}"`;
  const prepass = (env) => spawnSync(process.execPath, [join(repo, "scripts", "prepass.mjs"), "--root", root, "--no-docker", "--new-run"], { encoding: "utf8", env });

  let r = prepass(toolFreeEnv());
  assert.equal(r.status, 0, r.stderr);
  const audit = join(root, ".security-audit");
  let md = readFileSync(join(audit, "prepass.md"), "utf8");
  for (const t of ["semgrep", "zizmor", "hadolint", "trivy"]) assert.match(md, new RegExp(`^- ${t}: NOT RUN: ${t} not installed and docker disabled by --no-docker`, "m"));
  for (const s of ["## Hotspots (start here)", "## Entry Points", "## Dependency Advisories", "## Secret Scan (values redacted)"]) assert.ok(md.includes(s), s);
  assert.equal(readFileSync(join(audit, "not-assessed.md"), "utf8").match(/\(prepass\) \|/g).length, 4);

  r = prepass(toolFreeEnv({ semgrep: fake("semgrep.json"), hadolint: fake("hadolint.json") }));
  assert.equal(r.status, 0, r.stderr);
  md = readFileSync(join(audit, "prepass.md"), "utf8");
  assert.match(md, /^- semgrep: semgrep: 2 candidates/m);
  assert.match(md, /\| high \| server\.js:3 \| js\.express\.xss \| User input reaches 'res\.send' \|/);
  assert.match(md, /\| medium \| Dockerfile:1 \| DL3007 \|/);
  assert.match(md, /^- trivy: NOT RUN/m);
  const na = readFileSync(join(audit, "not-assessed.md"), "utf8");
  assert.ok(!na.includes("semgrep") && !na.includes("hadolint") && na.includes("zizmor") && na.includes("trivy"));
  assert.ok(existsSync(join(audit, "tools", "semgrep.json")) && !existsSync(join(audit, "tools", "trivy.json")));
  const summary = JSON.parse(readFileSync(join(audit, "tools", "summary.json"), "utf8"));
  assert.equal(summary.tools.semgrep.candidates, 2);
  const cands = JSON.parse(readFileSync(join(audit, "tools", "tool-candidates.json"), "utf8"));
  assert.equal(cands.find((c) => c.tool === "hadolint").candidates[0].rule, "DL3007");
});
