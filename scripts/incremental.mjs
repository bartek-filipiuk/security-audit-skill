// Incremental audit (--since): which entry points must be re-audited, and which findings and
// non-issues of the previous run can be carried over unchanged. Used by prepass.mjs.
// Rule: an item is carried only when none of the files it cites changed and none of them belongs to a
// re-audited target. A target (entry point or access-deciding config file) is re-audited when its file
// changed or imports, directly or transitively, a changed file. When that cannot be decided safely
// (no previous run, previous run was partial, unknown commit, a file that gates every route changed,
// or most of the code changed) the plan says "full" with the reason, and a full audit runs.
// ponytail: imports are resolved by regex (relative paths and tsconfig "paths" aliases), not by the
// TypeScript compiler. A dynamic import with a computed path is invisible; the cited-file rule still
// re-audits any finding that names the changed file.

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, posix } from "node:path";
import { parseFrontmatter } from "./audit-state.mjs";

// Files that decide access or resolution for every route: a change here means a full audit.
const GLOBAL_RE = /(^|\/)(next\.config\.[cm]?[jt]s|tsconfig(\.\w+)?\.json|jsconfig\.json)$/;
// Share of targets above which an incremental run saves too little to be worth the risk.
export const FULL_ABOVE = 0.5;

const git = (root, argv) => spawnSync("git", ["-C", root, ...argv], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });

export function resolveCommit(root, ref) {
  const r = git(root, ["rev-parse", "--verify", "--quiet", `${ref}^{commit}`]);
  return r.status === 0 ? r.stdout.trim() : null;
}

// Files changed between `base` and the working tree (committed, staged, unstaged and untracked),
// relative to `root`.
export function changedSince(root, base) {
  const lines = (r) => r.stdout.split("\n").map((l) => l.trim()).filter(Boolean);
  const diff = git(root, ["diff", "--name-only", "--relative", "--no-renames", base]);
  if (diff.status !== 0) return null;
  const untracked = git(root, ["ls-files", "--others", "--exclude-standard"]);
  return [...new Set([...lines(diff), ...lines(untracked)])].filter((p) => !p.startsWith(".security-audit/")).sort();
}

// tsconfig/jsconfig "paths": { "@/*": ["./src/*"] } -> [["@/", "src/"]]
export function readAliases(root) {
  for (const name of ["tsconfig.json", "jsconfig.json"]) {
    const p = join(root, name);
    if (!existsSync(p)) continue;
    const text = readFileSync(p, "utf8");
    const block = text.match(/"paths"\s*:\s*\{([^}]*)\}/)?.[1] ?? "";
    const base = text.match(/"baseUrl"\s*:\s*"([^"]*)"/)?.[1] ?? ".";
    return [...block.matchAll(/"([^"]+?)\*?"\s*:\s*\[\s*"([^"]+?)\*?"/g)].map(([, from, to]) => [from, posix.normalize(posix.join(base, to)).replace(/^\.\//, "")]);
  }
  return [];
}

const EXTS = ["", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", "/index.ts", "/index.tsx", "/index.js", "/index.jsx"];
const IMPORT_RE = /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+|\brequire\s*\(\s*|\bexport\s*\*\s*from\s*)["'`]([^"'`]+)["'`]/g;

// file -> Set of local files it imports.
export function importGraph(files, aliases = []) {
  const known = new Set(files.map((f) => f.path));
  const resolveSpec = (from, spec) => {
    let base;
    if (spec.startsWith(".")) base = posix.normalize(posix.join(posix.dirname(from), spec));
    else {
      const a = aliases.find(([prefix]) => spec.startsWith(prefix));
      if (!a) return null;
      base = posix.normalize(a[1] + "/" + spec.slice(a[0].length)).replace(/^\.\//, "");
    }
    for (const ext of EXTS) if (known.has(base + ext)) return base + ext;
    // `./x.js` written for a `x.ts` source (TypeScript ESM convention).
    const stripped = base.replace(/\.[cm]?js$/, "");
    for (const ext of EXTS.slice(1)) if (known.has(stripped + ext)) return stripped + ext;
    return null;
  };
  const graph = new Map();
  for (const f of files) {
    const deps = new Set();
    for (const m of f.text.matchAll(IMPORT_RE)) {
      const hit = resolveSpec(f.path, m[1]);
      if (hit && hit !== f.path) deps.add(hit);
    }
    graph.set(f.path, deps);
  }
  return graph;
}

// Changed files plus every file that imports one of them, transitively.
export function affectedFiles(graph, changed) {
  const importers = new Map();
  for (const [file, deps] of graph) for (const d of deps) importers.set(d, [...(importers.get(d) ?? []), file]);
  const out = new Set(changed);
  const queue = [...changed];
  while (queue.length) {
    for (const imp of importers.get(queue.pop()) ?? []) if (!out.has(imp)) { out.add(imp); queue.push(imp); }
  }
  return out;
}

// Project files a finding or non-issue cites (path suffixes are matched against the known files).
export function citedFiles(text, universe) {
  const out = new Set();
  for (const m of text.matchAll(/([\w.()[\]@+-]+(?:\/[\w.()[\]@+-]+)*\.[\w]+)(?::\d+)?/g)) {
    const p = m[1].replace(/^\.\//, "");
    if (p.startsWith(".security-audit/")) continue;
    for (const f of universe) if (f === p || f.endsWith("/" + p)) out.add(f);
  }
  return out;
}

// Reads the previous run from an audit directory (before or after it is archived).
export function loadPreviousRun(dir) {
  if (!dir || !existsSync(dir)) return { ok: false, reason: "no previous audit in .security-audit/" };
  const json = (p) => { try { return JSON.parse(readFileSync(join(dir, p), "utf8")); } catch { return null; } };
  const summary = json("tools/summary.json");
  const read = (sub) => (existsSync(join(dir, sub)) ? readdirSync(join(dir, sub)).filter((n) => n.endsWith(".md")).sort() : []);
  const findings = read("findings");
  const nonIssues = read("non-issues");
  if (!existsSync(join(dir, "report.md"))) return { ok: false, reason: "the previous audit has no report.md (it did not finish)" };
  if (!summary?.commit) return { ok: false, reason: "the previous audit recorded no git commit" };
  if (summary.scope) return { ok: false, reason: `the previous audit was partial (scope "${summary.scope.label}"), so it cannot stand in for the rest of the code` };
  if (!findings.length && !nonIssues.length) return { ok: false, reason: "the previous audit left no findings or non-issues to carry" };
  const mark = json("tools/workspace-mark.json");
  return { ok: true, dir, summary, commit: summary.commit_full || summary.commit, findings, nonIssues, dirtyAtAudit: (mark?.git_status ?? []).map((l) => l.slice(3).replace(/^.* -> /, "")) };
}

// Decide what to re-audit and what to carry. Pure: all inputs are data.
//   targets: ranked hotspots (entry points + config files, each with file/line/kind)
//   items: [{ kind: "finding"|"non-issue", name, text }] from the previous run
export function planIncremental({ targets, entries, files, changed, universe, items, aliases = [] }) {
  const globalHit = changed.filter((p) => GLOBAL_RE.test(p) || entries.some((e) => e.kind === "middleware" && e.file === p));
  const graph = importGraph(files, aliases);
  const affected = affectedFiles(graph, changed);
  const reaudit = targets.filter((t) => affected.has(t.file));
  const base = { changed, affected: [...affected].sort(), reaudit, total: targets.length, carry: [], drop: [] };
  if (globalHit.length) return { ...base, mode: "full", reason: `${globalHit.join(", ")} changed, and it decides access or module resolution for every route` };
  if (targets.length && reaudit.length / targets.length > FULL_ABOVE) {
    return { ...base, mode: "full", reason: `${reaudit.length} of ${targets.length} targets are affected (more than ${Math.round(FULL_ABOVE * 100)}%), so a full audit costs about the same` };
  }
  const touched = new Set([...affected, ...reaudit.map((t) => t.file)]);
  const carry = [];
  const drop = [];
  for (const it of items) {
    const { data } = parseFrontmatter(it.text);
    if (!data) { drop.push({ ...it, why: "unreadable frontmatter" }); continue; }
    if (it.kind === "finding" && data.status === "raw") { drop.push({ ...it, why: "still raw in the previous run" }); continue; }
    const cites = [...citedFiles(it.text, universe)];
    const hit = cites.filter((f) => touched.has(f));
    if (hit.length) drop.push({ ...it, why: `cites ${hit.slice(0, 3).join(", ")}` });
    else carry.push({ ...it, cites });
  }
  return { ...base, mode: "incremental", reason: "", carry, drop };
}

// Adds carried_from / carried_run to the frontmatter. An item carried before keeps both: they name the
// commit and run in which its code was last actually read.
export function markCarried(text, commit, run) {
  if (parseFrontmatter(text).data?.carried_from) return text;
  return text.replace(/^---\r?\n/, `---\ncarried_from: "${commit}"\ncarried_run: "${run}"\n`);
}

// Writes the carried items, recon.md, test-quality.md and the unaffected not-assessed rows into the
// fresh audit directory.
export function writeCarried(prevDir, out, plan, { commit, run }) {
  for (const it of plan.carry) {
    const sub = it.kind === "finding" ? "findings" : "non-issues";
    mkdirSync(join(out, sub), { recursive: true });
    writeFileSync(join(out, sub, it.name), markCarried(it.text, commit, run));
  }
  const banner = (what) => `> Carried over from the audit of commit ${commit.slice(0, 12)} (run ${run}). Re-check only the rows for the targets listed under "Incremental audit" in prepass.md; ${what}\n\n`;
  for (const [name, what] of [["recon.md", "the rest still describes the unchanged code."], ["test-quality.md", "it does not cover findings made in this run."]]) {
    const p = join(prevDir, name);
    if (existsSync(p)) writeFileSync(join(out, name), banner(what) + readFileSync(p, "utf8"));
  }
  const na = join(prevDir, "not-assessed.md");
  if (existsSync(na)) {
    const touched = new Set([...plan.affected, ...plan.reaudit.map((t) => t.file)]);
    const keep = readFileSync(na, "utf8").split("\n").filter((l) => ![...touched].some((f) => l.includes(f)));
    writeFileSync(join(out, "not-assessed.md"), keep.join("\n"));
  }
}

export function loadItems(prev) {
  const read = (sub, kind) => prev[sub === "findings" ? "findings" : "nonIssues"].map((name) => ({ kind, name, text: readFileSync(join(prev.dir, sub, name), "utf8") }));
  return [...read("findings", "finding"), ...read("non-issues", "non-issue")];
}

export const trackedFiles = (root) => {
  const r = git(root, ["ls-files", "--cached", "--others", "--exclude-standard"]);
  return r.status === 0 ? r.stdout.split("\n").filter(Boolean) : [];
};
