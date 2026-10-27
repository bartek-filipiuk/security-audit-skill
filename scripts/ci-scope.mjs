#!/usr/bin/env node
// The --scope value for an audit of a pull request (roadmap R15): the directories the branch changed.
//   node ci-scope.mjs --base <ref> [--max 20] [--cwd <repo>]
// Prints the value (for example `src/app/api/,src/lib/`) and, when $GITHUB_OUTPUT is set, appends `scope=<value>`.
// Files are listed with `git diff --name-only -z <base>...HEAD` (what the branch changed since it left the base),
// deleted files left out, renames counted at their new path. Every directory keeps a trailing slash, so the
// pre-pass reads it as a path and not as an area name.
// A directory name is cut at its first segment with a character outside [A-Za-z0-9_.-] (or a leading `-`, or
// `.`/`..`), so the value is always safe to put in a prompt or a command line. Files at the repository root and
// anything under .security-audit/ are left out.
// More than --max directories, or none at all (only root files changed), gives `top20`: the riskiest entry
// points, the same as for a big project's first run. A note on stderr says why.
// No shell: git runs through execFileSync with an argument list, so a file name is never interpreted.

import { execFileSync } from "node:child_process";
import { appendFileSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const FALLBACK = "top20";
const SAFE_SEGMENT = /^[A-Za-z0-9_.-]+$/;

// The safe prefix of a directory path ("" when its first segment is not safe).
export function safeDir(dir) {
  const kept = [];
  for (const seg of dir.split("/")) {
    if (!SAFE_SEGMENT.test(seg) || seg.startsWith("-") || seg === "." || seg === "..") break;
    kept.push(seg);
  }
  return kept.join("/");
}

// Changed file paths -> sorted, de-duplicated directories, children folded into a changed parent.
export function scopeDirs(files) {
  const dirs = new Set();
  for (const f of files) {
    const slash = f.lastIndexOf("/");
    if (slash < 0) continue; // a root file
    const d = safeDir(f.slice(0, slash));
    if (!d || d === ".security-audit" || d.startsWith(".security-audit/")) continue;
    dirs.add(d);
  }
  const sorted = [...dirs].sort();
  return sorted.filter((d) => !sorted.some((p) => p !== d && d.startsWith(p + "/")));
}

export function scopeValue(files, { max = 20 } = {}) {
  const dirs = scopeDirs(files);
  if (!dirs.length) return { value: FALLBACK, dirs, note: "no directory with auditable changes (only root files, or none): falling back to top20" };
  if (dirs.length > max) return { value: FALLBACK, dirs, note: `${dirs.length} changed directories, more than --max ${max}: falling back to top20` };
  return { value: dirs.map((d) => `${d}/`).join(","), dirs, note: "" };
}

export function changedFiles(base, cwd = process.cwd()) {
  if (!base || base.startsWith("-")) throw new Error("--base needs a git ref (for example origin/main)");
  const out = execFileSync("git", ["diff", "--name-only", "-z", "--diff-filter=d", `${base}...HEAD`], { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  return out.split("\0").filter(Boolean);
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const opt = (name, def) => (args.includes(name) ? args[args.indexOf(name) + 1] : def);
  const max = Number(opt("--max", "20"));
  if (!Number.isInteger(max) || max < 1) {
    console.error("ci-scope: --max must be a positive integer");
    process.exit(2);
  }
  let files;
  try {
    files = changedFiles(opt("--base"), opt("--cwd", process.cwd()));
  } catch (e) {
    console.error(`ci-scope: ${e.stderr ? String(e.stderr).trim() : e.message}`);
    console.error("Usage: node ci-scope.mjs --base <ref> [--max 20] (the base needs the full history: checkout with fetch-depth 0)");
    process.exit(2);
  }
  const { value, note } = scopeValue(files, { max });
  if (note) console.error(`ci-scope: ${note}`);
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `scope=${value}\n`);
  console.log(value);
}
