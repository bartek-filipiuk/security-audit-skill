#!/usr/bin/env node
// What changed in the project while the audit ran? Agents may only write inside .security-audit/,
// but the project's own test suite, a stray command or a regression test can touch other files (in one real run
// the project's `npm test` regenerated 50 gitignored pages). Compares against the mark prepass.mjs took at start.
//   node workspace-check.mjs [--dir .security-audit]
// Prints a short report and writes <dir>/tools/workspace-check.json. Informational: exit 0.

import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, readdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SKIP = new Set(["node_modules", ".git", ".next", ".turbo", "dist", "build", "coverage"]);

export function workspaceCheck(dir) {
  const markPath = join(dir, "tools", "workspace-mark.json");
  if (!existsSync(markPath)) return { ok: false, reason: "no workspace mark (prepass.mjs did not run with this audit dir)" };
  const mark = JSON.parse(readFileSync(markPath, "utf8"));
  const root = mark.root;
  const since = Date.parse(mark.at);
  const auditDir = resolve(dir);

  const changed = [];
  (function walk(d) {
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      if (SKIP.has(name) || resolve(p) === auditDir) continue;
      const st = lstatSync(p);
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) walk(p);
      else if (st.mtimeMs > since) changed.push(relative(root, p));
    }
  })(root);

  let statusAdded = [];
  let statusGone = [];
  if (Array.isArray(mark.git_status)) {
    const now = spawnSync("git", ["-C", root, "status", "--porcelain"], { encoding: "utf8" }).stdout.split("\n").filter(Boolean);
    const before = new Set(mark.git_status);
    statusAdded = now.filter((l) => !before.has(l));
    statusGone = mark.git_status.filter((l) => !now.includes(l));
  }
  return { ok: true, since: mark.at, root, changed: changed.sort(), git_status_new: statusAdded, git_status_gone: statusGone };
}

// realpath on both sides: the skill is usually run through a symlink (~/.claude/skills/...).
if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const dir = resolve(args.indexOf("--dir") >= 0 ? args[args.indexOf("--dir") + 1] : ".security-audit");
  const r = workspaceCheck(dir);
  if (existsSync(join(dir, "tools"))) writeFileSync(join(dir, "tools", "workspace-check.json"), JSON.stringify(r, null, 2));
  if (!r.ok) {
    console.log(`workspace-check: skipped, ${r.reason}`);
  } else if (!r.changed.length && !r.git_status_new.length && !r.git_status_gone.length) {
    console.log(`workspace-check: nothing outside the audit dir changed since ${r.since}`);
  } else {
    console.log(`workspace-check: WARNING, the project changed during the audit (since ${r.since})`);
    if (r.git_status_new.length) console.log(`  new git status lines: ${r.git_status_new.slice(0, 10).join(" | ")}`);
    if (r.git_status_gone.length) console.log(`  git status lines gone: ${r.git_status_gone.slice(0, 10).join(" | ")}`);
    if (r.changed.length) console.log(`  ${r.changed.length} files modified (incl. gitignored): ${r.changed.slice(0, 8).join(", ")}${r.changed.length > 8 ? ", …" : ""}`);
    console.log("  Report this to the user: say which phase likely caused it (usually the project's own test run) and whether tracked files changed.");
  }
}
