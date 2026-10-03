#!/usr/bin/env node
// Deterministic pre-pass for the security-audit skill. Runs before any agent reads code.
//   node prepass.mjs [--root DIR] [--out DIR] [--no-docker] [--scope auth,payments|src/app/api|top20] [--new-run]
// --new-run (Phase 0 of a fresh audit): moves a previous run into <out>/history/<date>/ so the new
// agents cannot anchor on old results, and records the workspace state for workspace-check.mjs.
// Defaults: --root = cwd, --out = <root>/.security-audit
// Writes <out>/prepass.md (read by recon) and raw tool output to <out>/tools/.
// Tools: osv-scanner and gitleaks, native binary first, then their official docker images.
// Secrets are always redacted (gitleaks --redact) so no secret value lands on disk or in agent context.

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join, relative, resolve } from "node:path";
import { inScope, LOCKFILES, rankHotspots, scanEntryPoints, scanScope, walk } from "./surface.mjs";

const args = process.argv.slice(2);
const opt = (name, fallback) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : fallback;
};
const root = resolve(opt("--root", process.cwd()));
const out = resolve(opt("--out", join(root, ".security-audit")));
const toolsDir = join(out, "tools");
const allowDocker = !args.includes("--no-docker");
const scopeSpec = opt("--scope", "");
try {
  if (scopeSpec) inScope(scopeSpec, []);
} catch (err) {
  console.error(`prepass: ${err.message}`);
  process.exit(2);
}
if (args.includes("--new-run")) {
  archivePreviousRun();
  rmSync(join(toolsDir, "workspace-mark.json"), { force: true });
}
mkdirSync(toolsDir, { recursive: true });
for (const d of ["findings", "non-issues", "tests"]) mkdirSync(join(out, d), { recursive: true });

const run = (cmd, argv, opts = {}) =>
  spawnSync(cmd, argv, { encoding: "utf8", maxBuffer: 512 * 1024 * 1024, timeout: 600_000, ...opts });
const installed = (cmd, argv = ["--version"]) => !run(cmd, argv, { timeout: 10_000 }).error;
const dockerOk = allowDocker && run("docker", ["info", "--format", "{{.ServerVersion}}"], { timeout: 15_000 }).status === 0;
const uid = process.getuid ? `${process.getuid()}:${process.getgid()}` : null;
const isGit = run("git", ["-C", root, "rev-parse", "--is-inside-work-tree"]).stdout?.trim() === "true";
// History lives at the repo top level; a monorepo package audit still needs the whole history scanned.
const gitTop = isGit ? run("git", ["-C", root, "rev-parse", "--show-toplevel"]).stdout.trim() : root;
const commit = isGit ? run("git", ["-C", root, "rev-parse", "--short", "HEAD"]).stdout.trim() : "";

// The mark is taken once per run, before any agent (or the project's own tests) can write anything.
const markPath = join(toolsDir, "workspace-mark.json");
if (!existsSync(markPath)) {
  writeFileSync(markPath, JSON.stringify({ at: new Date().toISOString(), root, git_status: gitStatus() }, null, 2));
}

const t0 = Date.now();
const { files, lockfiles: ownLocks } = walk(root);
// Auditing one package of a monorepo: the lockfile lives at the workspace root, above `root`.
let depRoot = root;
let lockfiles = ownLocks;
for (let dir = root; !lockfiles.length && dir !== dirname(dir) && relative(gitTop, dir) !== ".."; dir = dirname(dir)) {
  const found = [...LOCKFILES].filter((n) => existsSync(join(dir, n)));
  if (found.length) { depRoot = dir; lockfiles = found; }
  if (dir === gitTop) break;
}
const entries = scanEntryPoints(files);
const scope = scanScope(files, depRoot === root ? files : walk(depRoot).files);
const ranked = rankHotspots(files, entries, scope);
// Scope narrows what the agents audit; the maps above always cover the whole repo, because
// authorization is decided in shared code (proxy, layouts, DAL helpers, schema).
const pick = scopeSpec ? inScope(scopeSpec, ranked.filter((h) => h.score > 0)) : () => true;
for (const h of ranked) h.inScope = pick(h);
const hotspots = ranked.filter((h) => h.score > 0);
const scoped = scopeSpec ? { label: scopeSpec, entries: ranked.filter((h) => h.inScope), total: ranked.length } : null;
const deps = runDeps();
const secrets = runSecrets();

writeFileSync(join(toolsDir, "entry-points.json"), JSON.stringify(entries, null, 2));
writeFileSync(join(toolsDir, "scope-scan.json"), JSON.stringify(scope, null, 2));
writeFileSync(join(toolsDir, "hotspots.json"), JSON.stringify(hotspots, null, 2));
if (scoped) writeFileSync(join(toolsDir, "scope.json"), JSON.stringify(scoped, null, 2));
else rmSync(join(toolsDir, "scope.json"), { force: true });
writeFileSync(join(toolsDir, "summary.json"), JSON.stringify({
  generated_at: new Date().toISOString(), project: basename(root), commit,
  scope: scoped && { label: scoped.label, entries: scoped.entries.length, total: scoped.total },
  entry_points: entries.length, scope_candidates: scope.sites.filter((s) => s.status !== "scoped").length,
  deps: { status: deps.status, rows: deps.rows }, secrets: { status: secrets.status, rows: secrets.rows },
}, null, 2));
writeFileSync(join(out, "prepass.md"), render());

const unscoped = scope.sites.filter((s) => s.status !== "scoped").length;
console.log(
  `prepass: ${entries.length} entry points, ${hotspots.length} hotspots, ${unscoped} scope candidates, ` +
    `deps: ${deps.status}, secrets: ${secrets.status} (${((Date.now() - t0) / 1000).toFixed(1)}s) -> ${join(out, "prepass.md")}`,
);

// ---------------------------------------------------------------- dependencies

function runDeps() {
  for (const f of ["osv.json", "pnpm-audit.json", "npm-audit.json", "composer-audit.json"]) rmSync(join(toolsDir, f), { force: true });
  if (!lockfiles.length) return { status: "no lockfile found", rows: [] };
  let res;
  let via;
  if (installed("osv-scanner")) {
    via = "osv-scanner";
    res = run("osv-scanner", ["scan", "source", "-r", "--format", "json", depRoot]);
  } else if (dockerOk) {
    via = "osv-scanner (docker)";
    res = run("docker", ["run", "--rm", "-v", `${depRoot}:/src:ro`, "ghcr.io/google/osv-scanner:latest", "scan", "source", "-r", "--format", "json", "/src"]);
  } else {
    return fallbackAudit();
  }
  let data;
  try {
    data = JSON.parse(res.stdout);
  } catch {
    return { status: `FAILED (${via}): ${(res.stderr || res.error?.message || "no output").trim().split("\n").pop()}`, rows: [] };
  }
  writeFileSync(join(toolsDir, "osv.json"), res.stdout);

  const prod = prodPackages();
  const rows = [];
  for (const r of data.results ?? []) {
    const lock = r.source?.path?.replace(/^\/src\/?/, "").replace(depRoot + "/", "") ?? "";
    for (const p of r.packages ?? []) {
      const { name, version, ecosystem } = p.package;
      const vulns = p.vulnerabilities ?? [];
      const cvss = Math.max(0, ...(p.groups ?? []).map((g) => Number.parseFloat(g.max_severity) || 0));
      const fixed = new Set();
      for (const v of vulns)
        for (const a of v.affected ?? [])
          if (a.package?.name === name) for (const rg of a.ranges ?? []) for (const e of rg.events ?? []) if (e.fixed) fixed.add(e.fixed);
      const key = `${name}@${version}`;
      rows.push({
        name, version, ecosystem, lock,
        scope: prod.known ? (prod.set.has(key) ? "prod" : "dev-only") : (prod.direct.get(name) ?? "unknown"),
        cvss: cvss || "",
        ids: (p.groups ?? []).map((g) => g.ids?.find((id) => id.startsWith("CVE-")) ?? g.ids?.[0]).filter(Boolean),
        fixed: [...fixed].slice(0, 4),
      });
    }
  }
  rows.sort((a, b) => (Number(b.cvss) || 0) - (Number(a.cvss) || 0));
  const where = depRoot === root ? "" : ` (lockfile at ${depRoot})`;
  return { status: `${via}: ${rows.length} vulnerable packages${where}`, rows };
}

// Exact prod/dev split needs installed node_modules; without them only direct deps can be classified.
function prodPackages() {
  const set = new Set();
  const collect = (deps) => {
    for (const [name, d] of Object.entries(deps ?? {})) {
      if (d?.version) set.add(`${name}@${d.version}`);
      collect(d?.dependencies);
    }
  };
  const tryList = (cmd, argv) => {
    if (!existsSync(join(depRoot, "node_modules"))) return false;
    const res = run(cmd, argv, { cwd: depRoot, timeout: 120_000 });
    try {
      const parsed = JSON.parse(res.stdout);
      for (const proj of Array.isArray(parsed) ? parsed : [parsed]) collect(proj.dependencies);
      return set.size > 0;
    } catch {
      return false;
    }
  };
  const known =
    (existsSync(join(depRoot, "pnpm-lock.yaml")) && tryList("pnpm", ["list", "-r", "--prod", "--depth", "Infinity", "--json"])) ||
    (existsSync(join(depRoot, "package-lock.json")) && tryList("npm", ["ls", "--omit=dev", "--all", "--json"]));

  const direct = new Map();
  for (const f of lockfiles.filter((l) => /(^|\/)(pnpm-lock\.yaml|package-lock\.json|yarn\.lock|bun\.lock)$/.test(l))) {
    const pkgPath = join(depRoot, dirname(f), "package.json");
    if (!existsSync(pkgPath)) continue;
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
    for (const n of Object.keys(pkg.devDependencies ?? {})) if (!direct.has(n)) direct.set(n, "dev (direct)");
    for (const n of Object.keys(pkg.dependencies ?? {})) direct.set(n, "prod (direct)");
  }
  return { known, set, direct };
}

function fallbackAudit() {
  const tries = [
    ["pnpm-lock.yaml", "pnpm", ["audit", "--json"]],
    ["package-lock.json", "npm", ["audit", "--json"]],
    ["composer.lock", "composer", ["audit", "--locked", "--format=json"]],
  ];
  const done = [];
  for (const [lock, cmd, argv] of tries) {
    if (!existsSync(join(depRoot, lock)) || !installed(cmd)) continue;
    const res = run(cmd, argv, { cwd: depRoot, timeout: 180_000 });
    const file = `${cmd}-audit.json`;
    writeFileSync(join(toolsDir, file), res.stdout || res.stderr || "");
    done.push(`${cmd} audit -> tools/${file}`);
  }
  return {
    status: done.length
      ? `osv-scanner and docker unavailable; fallback ran: ${done.join(", ")} (summarize from the raw file)`
      : "NOT RUN: install osv-scanner or docker",
    rows: [],
  };
}

// ---------------------------------------------------------------- secrets

function runSecrets() {
  const mode = isGit ? "git" : "dir";
  const common = ["--redact", "--no-banner", "--report-format", "json", "--exit-code", "0"];
  let res;
  let via;
  const report = join(toolsDir, "gitleaks.json");
  rmSync(report, { force: true }); // never read a previous run's report as this run's result
  if (installed("gitleaks", ["version"])) {
    via = "gitleaks";
    res = run("gitleaks", [mode, gitTop, ...common, "--report-path", report]);
  } else if (dockerOk) {
    via = "gitleaks (docker)";
    const user = uid ? ["--user", uid] : [];
    res = run("docker", [
      "run", "--rm", ...user, "-v", `${gitTop}:/repo:ro`, "-v", `${toolsDir}:/out`,
      "ghcr.io/gitleaks/gitleaks:latest", mode, "/repo", ...common, "--report-path", "/out/gitleaks.json",
    ]);
  } else {
    return { status: "NOT RUN: install gitleaks or docker (secret and git-history scan missing)", rows: [] };
  }
  let hits;
  try {
    hits = JSON.parse(readFileSync(report, "utf8"));
  } catch {
    return { status: `FAILED (${via}): ${(res.stderr || res.error?.message || "no report").trim().split("\n").pop()}`, rows: [] };
  }
  const rows = hits.map((h) => {
    const file = h.File.replace(/^\/repo\//, "").replace(gitTop + "/", "");
    return {
      rule: h.RuleID,
      file,
      line: h.StartLine,
      commit: h.Commit ? h.Commit.slice(0, 7) : "",
      date: h.Date ? h.Date.slice(0, 10) : "",
      present: existsSync(join(gitTop, file)) ? "yes" : "no (history only)",
    };
  });
  const scope = isGit
    ? `${run("git", ["-C", gitTop, "rev-list", "--all", "--count"]).stdout.trim()} commits of ${gitTop === root ? "this repo" : gitTop}`
    : "working tree only (not a git repo)";
  return { status: `${via}: ${rows.length} hits, ${scope}`, rows };
}

// ---------------------------------------------------------------- report

function render() {
  const esc = (s) => String(s ?? "").replace(/\|/g, "\\|");
  const table = (head, rows) =>
    [`| ${head.join(" | ")} |`, `|${head.map(() => "---").join("|")}|`, ...rows.map((r) => `| ${r.map(esc).join(" | ")} |`)].join("\n");
  const cands = scope.sites.filter((s) => s.status !== "scoped");
  const L = [];
  L.push(`# Pre-pass (deterministic)`);
  L.push("");
  L.push(`Generated ${new Date().toISOString()} by prepass.mjs for \`${basename(root)}\`. Commit: ${commit || "not a git repo"}.`);
  L.push("");
  L.push(`- Entry points: ${entries.length} (framework conventions)`);
  L.push(`- Scope scan: ${scope.tables.length} owner-scoped tables, ${scope.sites.length} query sites, ${cands.length} candidates`);
  L.push(`- Dependencies: ${deps.status}`);
  L.push(`- Secrets: ${secrets.status}`);
  L.push("");
  L.push(`Anything marked NOT RUN or FAILED is a coverage gap: report it under "Not assessed", never as secure.`);
  L.push("");
  if (scoped) {
    L.push(`## Scope: ${scoped.label}`);
    L.push("");
    L.push(`Partial audit: ${scoped.entries.length} of ${scoped.total} targets (entry points and access-deciding config files) are in scope. Auditors read any code they need to trace a flow, but report findings only for these entry points and the sinks they reach. Everything else goes to not-assessed.md as "out of scope". The sections below still cover the whole repo.`);
    L.push("");
    L.push(scoped.entries.length ? table(["Kind", "Name", "Route", "File:line"], scoped.entries.map((e) => [e.kind, e.name, e.route, `${e.file}:${e.line}`])) : "Nothing matched this scope.");
    L.push("");
  }
  L.push(`## Hotspots (start here)`);
  L.push("");
  L.push(`Ranked by signals that real leaks keep coming from: sensitive area (auth/SSO/login, admin, payments, webhooks, files, AI), public-by-design entry kinds, no guard in the handler, unscoped queries, dangerous sinks, risky auth/CORS/env configuration. A ranking, not a verdict: audit these first, then everything else. Full list: tools/hotspots.json.`);
  L.push("");
  L.push(hotspots.length
    ? table(["#", "Score", "Kind", "Where", "Name", "Why"], hotspots.filter((h) => h.inScope).slice(0, 20).map((h, i) => [i + 1, h.score, h.kind, `${h.file}:${h.line}`, h.name, h.reasons.join("; ")]))
    : "No hotspots.");
  L.push("");
  L.push(`## Entry Points`);
  L.push("");
  L.push(`Reachable by framework convention even when no UI calls them (a \`"use server"\` export is a public POST endpoint). "Guard hint" lists guard-like calls found by regex in the handler body: a claim to verify, not proof.`);
  L.push("");
  L.push(table(["#", "Kind", "Name", "Route", "File:line", "Guard hint"], entries.map((e, i) => [i + 1, e.kind, e.name, e.route, `${e.file}:${e.line}`, e.guard || "none found"])));
  L.push("");
  L.push(`## Data Scope Scan (Drizzle)`);
  L.push("");
  if (!scope.tables.length) {
    L.push(`No Drizzle tables with owner/tenant columns found. If the project uses another ORM or raw SQL, the authz auditor must do this check by hand.`);
  } else {
    L.push(`Owner-scoped tables: ${scope.tables.filter((t) => t.owners.length).map((t) => `${t.var}(${t.owners.join(", ")})`).join(", ")}.`);
    const ind = scope.tables.filter((t) => t.via.length);
    if (ind.length) L.push(`Scoped only through a parent row: ${ind.map((t) => `${t.var} [${t.via.join(", ")}]`).join(", ")}.`);
    L.push("");
    const authorOnly = scope.tables.filter((t) => !t.owners.length && t.authors?.length);
    if (authorOnly.length) L.push(`Authorship only (checked on update/delete): ${authorOnly.map((t) => `${t.var}(${t.authors.join(", ")})`).join(", ")}.`);
    L.push("");
    L.push(`UNSCOPED = the statement never references the table's owner column. AUTHOR-UNCHECKED = an update/delete on a table that only records its author, without that column in the statement. PARENT-ONLY = filtered by the parent id, so the parent's ownership must be checked first. Each row is a candidate: the authz auditor resolves it to a finding or to a non-issue that cites where scoping happens (file:line). Intentionally global queries (auth lookups, admin, webhooks keyed by provider id) are expected here.`);
    L.push("");
    L.push(cands.length ? table(["Status", "Verb", "Table", "File:line", "Enclosing"], cands.map((s) => [s.status, s.verb, s.table, `${s.file}:${s.line}`, s.enclosing])) : "All query sites reference an owner column.");
  }
  L.push("");
  L.push(`## Dependency Advisories`);
  L.push("");
  L.push(`Scope: prod / dev-only come from the installed dependency tree; "(direct)" means only package.json was available. A dev-only advisory is a recommendation unless it runs in CI/build on untrusted input or a dev server is exposed.`);
  L.push("");
  L.push(deps.rows.length ? table(["Package", "Version", "Scope", "Max CVSS", "Advisories", "Fixed in", "Lockfile"], deps.rows.map((r) => [r.name, r.version, r.scope, r.cvss, r.ids.slice(0, 6).join(", ") + (r.ids.length > 6 ? ` (+${r.ids.length - 6})` : ""), r.fixed.join(", "), r.lock])) : "No rows.");
  L.push("");
  L.push(`## Secret Scan (values redacted)`);
  L.push("");
  L.push(`A secret that was ever committed is leaked until rotated, even if the file is gone now. Test fixtures and placeholders are common false positives.`);
  L.push("");
  L.push(secrets.rows.length ? table(["Rule", "File:line", "Commit", "Date", "File still present"], secrets.rows.map((r) => [r.rule, `${r.file}:${r.line}`, r.commit, r.date, r.present])) : "No rows.");
  L.push("");
  return L.join("\n");
}

// ---------------------------------------------------------------- run lifecycle

function gitStatus() {
  if (!isGit) return null;
  return run("git", ["-C", root, "status", "--porcelain"]).stdout.split("\n").filter(Boolean);
}

function archivePreviousRun() {
  if (!existsSync(out)) return;
  const items = readdirSync(out).filter((n) => n !== "history");
  const findings = join(out, "findings");
  const hadRun = (existsSync(findings) && readdirSync(findings).length) || existsSync(join(out, "recon.md")) || existsSync(join(out, "report.md"));
  if (!hadRun) return;
  const report = join(out, "report.md");
  const when = (existsSync(report) ? statSync(report).mtime : new Date()).toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const dest = join(out, "history", when);
  mkdirSync(dest, { recursive: true });
  for (const n of items) renameSync(join(out, n), join(dest, n));
  console.log(`prepass: previous run archived to ${dest} (agents must not read history/)`);
}
