// Deterministic tools of the pre-pass beyond dependencies and secrets (roadmap R07):
//   semgrep   rulesets chosen from the detected stack, over the source tree
//   zizmor    GitHub Actions workflows (.github/workflows), offline audits only
//   hadolint  Dockerfiles
//   trivy     `trivy config`: misconfigurations in Dockerfiles, compose, Terraform, Kubernetes, Helm
// Each tool first decides whether it applies (no workflows = skipped, with the reason), then runs
// natively if installed, else through its official docker image pinned by digest, else reports NOT RUN
// with how to enable it. Hits are normalized to candidates (file:line, rule, short note), deduplicated
// and capped; the raw output goes to tools/. A candidate is a lead for an auditor, never a finding.
// The runner is injected so tests never execute a real scanner.

import { lstatSync, readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { SKIP_DIRS } from "./surface.mjs";

// Official images, pinned by the manifest-list digest read from each registry on 2026-10-06 (no pull).
// Update tag and digest together; docker ignores the tag when a digest is given.
export const IMAGES = {
  semgrep: "semgrep/semgrep:1.179.0@sha256:93963d9295a366f59e4850127b1550400ee7b388f04fe144e4a1f6325d96e01b",
  zizmor: "ghcr.io/zizmorcore/zizmor:1.30.1@sha256:a2eb396d886c053073405c7a980f2139ba2248ec172243cfa3841e57196e8101",
  hadolint: "hadolint/hadolint:v2.15.1@sha256:32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d",
  trivy: "aquasec/trivy:0.75.0@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa",
};

export const MAX_ROWS = 40; // per tool in prepass.md; the full list stays in tools/tool-candidates.json

const INSTALL = {
  semgrep: "`pipx install semgrep` or `brew install semgrep`",
  zizmor: "`pipx install zizmor`, `brew install zizmor` or `cargo install --locked zizmor`",
  hadolint: "`brew install hadolint` or the binary from its GitHub releases",
  trivy: "`brew install trivy` or the binary from its GitHub releases",
};

// ---------------------------------------------------------------- inventory and stack

const DOCKERFILE_RE = /^(?:Dockerfile|Containerfile)(?:\..+)?$|\.(?:dockerfile|containerfile)$/i;
const COMPOSE_RE = /^(?:docker-)?compose(?:\.[\w-]+)?\.ya?ml$/i;
const LANG = { js: /\.[cm]?jsx?$/, ts: /\.[cm]?tsx?$/, php: /\.(?:php|module|inc|theme)$/, python: /\.py$/, go: /\.go$/, ruby: /\.rb$/, rust: /\.rs$/, java: /\.(?:java|kt)$/ };
const MANIFESTS = new Set(["package.json", "composer.json", "pyproject.toml", "requirements.txt", "Pipfile", "go.mod", "Gemfile", "Cargo.toml"]);

// One walk over the project for what the tools need: language counts, manifests, workflows, infra files.
export function inventory(root) {
  const inv = { langs: {}, manifests: [], workflows: [], dockerfiles: [], iac: [] };
  (function rec(dir) {
    let names;
    try { names = readdirSync(dir); } catch { return; }
    for (const name of names) {
      if (SKIP_DIRS.has(name)) continue;
      const p = join(dir, name);
      const st = lstatSync(p);
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) { rec(p); continue; }
      const rel = relative(root, p).split(sep).join("/");
      for (const [lang, re] of Object.entries(LANG)) if (re.test(name)) inv.langs[lang] = (inv.langs[lang] ?? 0) + 1;
      if (MANIFESTS.has(name) && st.size < 1_000_000) inv.manifests.push({ path: rel, text: readFileSync(p, "utf8") });
      if (/^\.github\/workflows\/[^/]+\.ya?ml$/.test(rel)) inv.workflows.push(rel);
      if (DOCKERFILE_RE.test(name)) inv.dockerfiles.push(rel);
      if (COMPOSE_RE.test(name) || /\.tf$/.test(name) || name === "Chart.yaml" || /^kustomization\.ya?ml$/.test(name)) inv.iac.push(rel);
    }
  })(root);
  for (const k of ["workflows", "dockerfiles", "iac"]) inv[k].sort();
  return inv;
}

// Minimal stack detection for choosing semgrep rulesets. Hook for R04: when the shared stack detector
// lands, pass its result as `stack` to runTools() and drop this function.
export function detectStack(inv) {
  const stack = new Set(Object.keys(inv.langs).filter((l) => inv.langs[l] > 0));
  for (const m of inv.manifests) {
    if (m.path.endsWith("package.json")) {
      let pkg = {};
      try { pkg = JSON.parse(m.text); } catch {}
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      if (deps.next) stack.add("nextjs");
      if (deps.react) stack.add("react");
      if (deps.express) stack.add("express");
    } else if (/(^|\/)(pyproject\.toml|requirements\.txt|Pipfile)$/.test(m.path)) {
      for (const fw of ["django", "flask", "fastapi"]) if (new RegExp(`(^|[\\s"'\\[])${fw}\\b`, "im").test(m.text)) stack.add(fw);
    }
  }
  return [...stack].sort();
}

// Registry rulesets (checked to exist on semgrep.dev, 2026-10-06). p/secrets is left out: gitleaks covers it.
const RULESETS = {
  js: "p/javascript", ts: "p/typescript", nextjs: "p/nextjs", react: "p/react", express: "p/expressjs",
  php: "p/php", python: "p/python", django: "p/django", flask: "p/flask", fastapi: "p/fastapi",
  go: "p/golang", ruby: "p/ruby", rust: "p/rust", java: "p/java",
};
// Most p/javascript rules match TypeScript too, and p/typescript alone is small, so TS gets both.
export const semgrepConfigs = (stack) => [...new Set(stack.flatMap((s) => (s === "ts" ? ["js", "ts"] : [s])).map((s) => RULESETS[s]).filter(Boolean))].sort();

// ---------------------------------------------------------------- tool specs

const SEVERITY = { critical: 0, error: 1, high: 1, warning: 2, medium: 2, low: 3, note: 4, info: 4, style: 4, none: 4 };
const sev = (s) => {
  const v = String(s ?? "").toLowerCase();
  if (v === "critical") return "critical";
  if (v === "error" || v === "high") return "high";
  if (v === "warning" || v === "medium") return "medium";
  if (v === "low") return "low";
  return "info";
};

// Paths come back relative, absolute under the project, or under the container mount.
export function normPath(p, root) {
  let s = String(p ?? "").replace(/^file:\/\//, "");
  const prefix = root.endsWith("/") ? root : `${root}/`;
  if (s.startsWith(prefix)) s = s.slice(prefix.length);
  return s.replace(/^\/src\//, "").replace(/^\.\//, "");
}

const note = (s) => String(s ?? "").replace(/\s+/g, " ").replace(/`/g, "'").trim().slice(0, 140);

export function parseSemgrep(stdout, root) {
  const data = JSON.parse(stdout);
  if (!Array.isArray(data.results)) throw new Error("no results array");
  return data.results.map((r) => ({
    file: normPath(r.path, root), line: r.start?.line ?? 0, rule: r.check_id, severity: sev(r.extra?.severity), note: note(r.extra?.message),
  }));
}

export function parseSarif(stdout, root) {
  const data = JSON.parse(stdout);
  if (!Array.isArray(data.runs)) throw new Error("no runs array");
  const rows = [];
  for (const run of data.runs) {
    for (const r of run.results ?? []) {
      const loc = r.locations?.[0]?.physicalLocation;
      rows.push({
        file: normPath(loc?.artifactLocation?.uri, root), line: loc?.region?.startLine ?? 0, rule: r.ruleId,
        severity: sev(r.level ?? "warning"), note: note(r.message?.text),
      });
    }
  }
  return rows;
}

export function parseHadolint(stdout, root) {
  const data = JSON.parse(stdout);
  if (!Array.isArray(data)) throw new Error("not an array");
  return data.map((h) => ({ file: normPath(h.file, root), line: h.line ?? 0, rule: h.code, severity: sev(h.level), note: note(h.message) }));
}

export function parseTrivy(stdout, root) {
  const data = JSON.parse(stdout);
  const rows = [];
  for (const res of data.Results ?? []) {
    for (const m of res.Misconfigurations ?? []) {
      if (m.Status && m.Status !== "FAIL") continue;
      rows.push({
        file: normPath(res.Target, root), line: m.CauseMetadata?.StartLine ?? 0, rule: m.ID || m.AVDID,
        severity: sev(m.Severity), note: note(m.Title || m.Message),
      });
    }
  }
  return rows;
}

const EXCLUDE = [".security-audit", "node_modules"];

export const TOOLS = [
  {
    name: "semgrep",
    category: "code",
    check: (ctx) => `semgrep rule scan (${ctx.configs.join(", ")})`,
    applies: (ctx) => (ctx.configs.length ? null : "no language with a semgrep ruleset detected"),
    version: ["--version"],
    // Registry rulesets are fetched at run time; --metrics=off keeps the scan from reporting usage.
    args: (ctx, base) => ["scan", "--json", "--metrics=off", "--disable-version-check", "--quiet",
      ...ctx.configs.flatMap((c) => ["--config", c]), ...EXCLUDE.flatMap((e) => ["--exclude", e]), base],
    native: (ctx) => ["semgrep", TOOLS[0].args(ctx, ".")],
    docker: (ctx) => ["semgrep", ...TOOLS[0].args(ctx, "/src")],
    raw: "semgrep.json",
    parse: parseSemgrep,
  },
  {
    name: "zizmor",
    category: "ci/cd",
    check: () => "GitHub Actions workflow audit (zizmor, offline)",
    applies: (ctx) => (ctx.inv.workflows.length ? null : "no .github/workflows/*.yml"),
    version: ["--version"],
    native: () => ["zizmor", ["--format", "sarif", "--offline", "."]],
    docker: () => ["--format", "sarif", "--offline", "/src"],
    raw: "zizmor.sarif",
    parse: parseSarif,
  },
  {
    name: "hadolint",
    category: "infra",
    check: () => "Dockerfile lint (hadolint)",
    applies: (ctx) => (ctx.inv.dockerfiles.length ? null : "no Dockerfile"),
    version: ["--version"],
    native: (ctx) => ["hadolint", ["--format", "json", "--no-fail", ...ctx.inv.dockerfiles]],
    docker: (ctx) => ["hadolint", "--format", "json", "--no-fail", ...ctx.inv.dockerfiles.map((f) => `/src/${f}`)],
    raw: "hadolint.json",
    parse: parseHadolint,
  },
  {
    name: "trivy",
    category: "infra",
    check: () => "Dockerfile and IaC misconfiguration scan (trivy config)",
    applies: (ctx) => (ctx.inv.dockerfiles.length || ctx.inv.iac.length ? null : "no Dockerfile, compose, Terraform, Helm or Kustomize file"),
    version: ["--version"],
    native: () => ["trivy", ["config", "--format", "json", "--quiet", "--exit-code", "0", ...EXCLUDE.flatMap((e) => ["--skip-dirs", e]), "."]],
    docker: () => ["config", "--format", "json", "--quiet", "--exit-code", "0", "/src"],
    raw: "trivy.json",
    parse: parseTrivy,
  },
];

// ---------------------------------------------------------------- run

// runner: { installed(cmd, argv) -> bool, run(cmd, argv, opts) -> {status, stdout, stderr, error}, dockerOk, dockerDisabled }
// write(name, text): stores raw output under tools/. Returns one result per tool, in TOOLS order.
export function runTools({ root, inv, stack, runner, write = () => {}, only = null }) {
  const ctx = { root, inv, stack, configs: semgrepConfigs(stack) };
  return TOOLS.filter((t) => !only || only.includes(t.name)).map((t) => {
    const base = { tool: t.name, category: t.category, check: t.check(ctx), rows: [], total: 0 };
    const skip = t.applies(ctx);
    if (skip) return { ...base, state: "skipped", status: `skipped: ${skip}` };
    let res;
    let via;
    const [cmd, argv] = t.native(ctx);
    if (runner.installed(cmd, t.version)) {
      via = t.name;
      res = runner.run(cmd, argv, { cwd: root });
    } else if (runner.dockerOk) {
      via = `${t.name} (docker)`;
      res = runner.run("docker", ["run", "--rm", "-v", `${root}:/src:ro`, "-w", "/src", IMAGES[t.name], ...t.docker(ctx)], { cwd: root });
    } else {
      const docker = runner.dockerDisabled ? "docker disabled by --no-docker" : "docker unavailable";
      return { ...base, state: "not-run", status: `NOT RUN: ${t.name} not installed and ${docker}; to enable: ${INSTALL[t.name]}, or a running docker (pulls ${IMAGES[t.name].split("@")[0]}, pinned by digest)` };
    }
    let rows;
    try {
      rows = t.parse(res.stdout, root);
    } catch {
      const why = (res.stderr || res.error?.message || "no parseable output").trim().split("\n").pop();
      return { ...base, state: "failed", status: `FAILED (${via}): ${why}` };
    }
    write(t.raw, res.stdout);
    const all = dedupe(rows.filter((r) => r.file && !EXCLUDE.some((e) => r.file === e || r.file.startsWith(`${e}/`))));
    return { ...base, state: "ran", via, status: `${via}: ${all.length} candidates${t.name === "semgrep" ? ` (${ctx.configs.join(", ")})` : ""}`, rows: all.slice(0, MAX_ROWS), total: all.length, all };
  });
}

// Same file, line and rule once; most severe first, then by place.
export function dedupe(rows) {
  const seen = new Map();
  for (const r of rows) {
    const k = `${r.file}:${r.line}:${r.rule}`;
    if (!seen.has(k) || SEVERITY[r.severity] < SEVERITY[seen.get(k).severity]) seen.set(k, r);
  }
  return [...seen.values()].sort((a, b) => SEVERITY[a.severity] - SEVERITY[b.severity] || a.file.localeCompare(b.file) || a.line - b.line || String(a.rule).localeCompare(String(b.rule)));
}

// ---------------------------------------------------------------- output

export function renderTools(results, table) {
  const L = [];
  L.push(`## Tool Candidates (semgrep, zizmor, hadolint, trivy)`);
  L.push("");
  L.push(`Rule hits from deterministic tools. Each row is a candidate, never a finding: the auditor who owns the file (infra for workflows, Dockerfiles and IaC) reads the code and resolves it to a finding, a non-issue citing the control, or a false positive. Rule severity is the tool's, not the audit's. Full lists: tools/tool-candidates.json.`);
  L.push("");
  for (const r of results) {
    L.push(`### ${r.tool}: ${r.status}`);
    L.push("");
    if (r.state !== "ran") continue;
    if (!r.rows.length) { L.push("No rows."); L.push(""); continue; }
    L.push(table(["Severity", "File:line", "Rule", "Note"], r.rows.map((x) => [x.severity, `${x.file}:${x.line}`, x.rule, x.note])));
    if (r.total > r.rows.length) L.push("", `(+${r.total - r.rows.length} more in tools/tool-candidates.json)`);
    L.push("");
  }
  return L.join("\n");
}

// Rows for not-assessed.md: one per tool that applied but did not produce a result.
export const gapRows = (results) =>
  results.filter((r) => r.state === "not-run" || r.state === "failed").map((r) => `| ${r.category} | ${r.check} | ${r.status.replace(/\|/g, "\\|")} (prepass) |`);

// Replaces this pre-pass's earlier tool rows and keeps everything the agents or a carried run wrote.
export function mergeNotAssessed(text, results) {
  const head = "| Category | Check | Why not assessed |\n|---|---|---|";
  const ours = new Set(TOOLS.map((t) => t.name));
  const lines = (text ?? "").split("\n").filter((l) => !/\(prepass\) \|$/.test(l) || ![...ours].some((n) => l.includes(n)));
  const rows = gapRows(results);
  if (!rows.length) return lines.join("\n");
  const body = lines.join("\n").replace(/\n+$/, "");
  return `${body.includes("| Category |") ? body : body ? `${head}\n${body}` : head}\n${rows.join("\n")}\n`;
}
