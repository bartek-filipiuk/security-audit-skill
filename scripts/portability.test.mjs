// Run: node --test scripts/*.test.mjs
// R26: the deterministic layer of the skill does not depend on Claude Code. The scripts run from a skill
// directory outside ~/.claude, with no scanner, docker or package manager on PATH and HOME pointed at an
// empty directory, through the whole Phase 0 → Phase 5 sequence documented in SKILL.md.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { toolFreeEnv } from "./test-helpers.mjs";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");

const finding = `---
id: auth-001
category: auth
severity: MEDIUM
status: verified
source_agent: auditor-auth
---

## Title
Health endpoint returns internal state without a session

## Evidence
- **File**: \`app/main.py:7\`

## Impact
Anyone who can reach the service reads the health payload without signing in.
`;

const ledger = {
  schema_version: "1.0",
  entries: [
    { class: "auth", target: "app/main.py", handler: "GET /health", status: "checked", auditor: "coordinator", evidence: ["auth-001"] },
    { class: "upload", target: "*", status: "not_applicable", auditor: "coordinator", reason: "no file upload handling in the code" },
  ],
};

test("the script pipeline runs from a skill directory outside ~/.claude with an empty HOME", () => {
  // The skill as another agent installs it: a symlink under a non-.claude path (e.g. ~/.agents/skills).
  const skill = join(mkdtempSync(join(tmpdir(), "sa-agents-")), "skills", "security-audit");
  mkdirSync(dirname(skill), { recursive: true });
  symlinkSync(repo, skill);
  const home = mkdtempSync(join(tmpdir(), "sa-home-"));
  const env = { ...toolFreeEnv(), HOME: home, USERPROFILE: home };
  const proj = mkdtempSync(join(tmpdir(), "sa-port-"));
  cpSync(join(repo, "scripts", "fixtures", "stack", "fastapi"), proj, { recursive: true });

  const run = (script, ...args) => {
    const r = spawnSync(process.execPath, [join(skill, "scripts", script), ...args], { cwd: proj, encoding: "utf8", env });
    assert.equal(r.status, 0, `${script} ${args.join(" ")} exited ${r.status}\n${r.stdout}\n${r.stderr}`);
    return r.stdout;
  };
  const audit = join(proj, ".security-audit");

  // Phase 0 and the Phase 2 briefs.
  run("prepass.mjs", "--new-run", "--no-docker");
  assert.ok(existsSync(join(audit, "prepass.md")));
  run("briefs.mjs");
  assert.ok(readdirSync(join(audit, "briefs")).some((f) => f.endsWith(".md")));

  // What the agents would write, in the documented formats (references/finding-format.md).
  writeFileSync(join(audit, "findings", "auth-001.md"), finding);
  writeFileSync(join(audit, "coverage", "coordinator.json"), JSON.stringify(ledger, null, 2));
  writeFileSync(join(audit, "summary.md"), "# Security Audit Report\n\n## Executive Summary\n\n1 verified finding.\n");

  // Phase 5 script sequence, in the order SKILL.md gives it.
  assert.match(run("audit-state.mjs", "--final", "--write", "--source", "baseline-from-audit"), /remediation\.json written: 1 verified/);
  run("workspace-check.mjs");
  assert.match(run("coverage.mjs", "--write"), /coverage\.json written/);
  run("report-md.mjs");
  run("report-html.mjs");
  for (const f of ["remediation.json", "coverage.json", "report.md", "report.html"]) assert.ok(existsSync(join(audit, f)), `${f} missing`);
  assert.match(readFileSync(join(audit, "report.md"), "utf8"), /auth-001/);
  assert.match(readFileSync(join(audit, "report.html"), "utf8"), /auth-001/);

  // Nothing was written under HOME (so nothing under ~/.claude either).
  assert.deepEqual(readdirSync(home), []);
});

test("no script reads the home directory or a Claude Code path", () => {
  const scripts = readdirSync(join(repo, "scripts")).filter((f) => f.endsWith(".mjs") && !f.endsWith(".test.mjs") && f !== "test-helpers.mjs");
  for (const f of scripts) {
    // Comments may mention ~/.claude (where Claude Code links the skill); code may not.
    const code = readFileSync(join(repo, "scripts", f), "utf8").replace(/^\s*\/\/.*$/gm, "");
    assert.doesNotMatch(code, /homedir\(|process\.env\.HOME|USERPROFILE|\.claude\b/, `${f} depends on the home directory or a Claude path`);
  }
});
