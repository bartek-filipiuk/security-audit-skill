#!/usr/bin/env node
// Finding frontmatter is the single source of truth for audit state. This script validates it and
// derives remediation.json from it, so the two can never drift apart.
//   node audit-state.mjs [--dir .security-audit] [--final] [--write] [--source baseline-from-audit|verified-only|fix-applied]
// --final: also fail on findings still `raw` (use after Phase 3).
// --write: (re)generate remediation.json; refuses while there are validation errors.
// --summary: compact counts plus one line per verified finding, so the coordinator need not read the files.
// Exit code 1 when validation fails.

import { existsSync, readFileSync, readdirSync, realpathSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const CATEGORIES = [
  "auth", "injection", "rate-limit", "exposure", "config", "upload", "dependency", "crypto",
  "concurrency", "docs-vs-reality", "business-logic", "logging", "test-gap", "chain",
];
export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
export const STATUSES = ["raw", "verified", "rejected"];
export const REJECTIONS = ["dead_code", "unreachable", "defensive_failure", "best_practice", "no_evidence"];
export const REMEDIATION = ["fixed", "partial", "open", "wont_fix", "cannot_verify"];
export const PROOFS = ["dynamic", "static"];

// Minimal YAML subset: `key: value` lines, one level of nesting, `- item` block lists,
// JSON-style or bare flow arrays.
export function parseFrontmatter(text) {
  const m = text.match(/^---\r?\n([\s\S]*?)\r?\n---[^\S\n]*(?:\r?\n|$)/);
  if (!m) return { data: null, body: text, errors: ["missing frontmatter block"] };
  const data = {};
  const errors = [];
  let parent = null;
  let last = null; // [container, key] of the most recent key, for `- item` lines
  for (const raw of m[1].split(/\r?\n/)) {
    if (!raw.trim() || raw.trim().startsWith("#")) continue;
    const indent = raw.match(/^ */)[0].length;
    const item = raw.trim().match(/^-\s+(.*)$/);
    if (item && last) {
      const [obj, key] = last;
      if (!Array.isArray(obj[key])) obj[key] = [];
      obj[key].push(scalar(stripComment(item[1])));
      if (obj === data) parent = null;
      continue;
    }
    const kv = raw.trim().match(/^([\w-]+):(?:\s+(.*))?$/);
    if (!kv) { errors.push(`unparseable line: ${raw.trim()}`); continue; }
    const key = kv[1];
    const rawVal = stripComment(kv[2] ?? "");
    if (/^[|>][-+]?$/.test(rawVal)) errors.push(`${key}: block scalars are not supported, use a one-line value`);
    if (indent === 0) {
      if (rawVal === "") { data[key] = {}; parent = key; } else { data[key] = scalar(rawVal); parent = null; }
      last = [data, key];
    } else if (parent && typeof data[parent] === "object" && !Array.isArray(data[parent])) {
      data[parent][key] = scalar(rawVal);
      last = [data[parent], key];
    } else {
      errors.push(`unexpected indentation: ${raw.trim()}`);
    }
  }
  return { data, body: text.slice(m[0].length), errors };
}

function stripComment(s) {
  let q = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === "\\") i++; else if (c === q) q = null; continue; }
    if (c === '"' || c === "'") q = c;
    else if (c === "#" && (i === 0 || /\s/.test(s[i - 1]))) return s.slice(0, i).trim();
  }
  return s.trim();
}

function scalar(s) {
  if (s === "") return "";
  if (s.startsWith("[")) {
    try { return JSON.parse(s); } catch {}
    return s.slice(1, -1).split(",").map((x) => x.trim().replace(/^["']|["']$/g, "")).filter(Boolean);
  }
  if (s.startsWith('"')) { try { return JSON.parse(s); } catch { return s.slice(1, -1); } }
  if (s.startsWith("'")) return s.slice(1, -1).replace(/''/g, "'");
  if (s === "true" || s === "false") return s === "true";
  if (/^-?\d+$/.test(s)) return Number(s);
  return s;
}

export const section = (body, name) => {
  const m = body.match(new RegExp(`^##\\s+${name}\\s*\\n([\\s\\S]*?)(?=^##\\s|$(?![\\s\\S]))`, "m"));
  return m ? m[1].trim() : null;
};
export const titleOf = (fm, body) => fm.title || section(body, "Title")?.split("\n")[0] || "";

export function loadAudit(dir) {
  const read = (sub) => {
    const d = join(dir, sub);
    if (!existsSync(d)) return [];
    return readdirSync(d)
      .filter((f) => f.endsWith(".md"))
      .sort()
      .map((f) => {
        const text = readFileSync(join(d, f), "utf8");
        return { file: `${sub}/${f}`, stem: f.replace(/\.md$/, ""), text, ...parseFrontmatter(text) };
      });
  };
  return { findings: read("findings"), nonIssues: read("non-issues") };
}

export function validate({ findings, nonIssues }, { final = false } = {}) {
  const errors = [];
  const ids = new Set(findings.map((f) => f.data?.id));
  const err = (f, msg) => errors.push(`${f.file}: ${msg}`);

  for (const f of findings) {
    f.errors.forEach((e) => err(f, e));
    const fm = f.data;
    if (!fm) continue;
    if (fm.id !== f.stem) err(f, `id "${fm.id}" must equal the file name "${f.stem}"`);
    if (!CATEGORIES.includes(fm.category)) err(f, `category "${fm.category}" not in: ${CATEGORIES.join(", ")}`);
    if (fm.status === "fixed") err(f, `status "fixed" is legacy: keep status "verified" and set remediation.status: fixed`);
    else if (!STATUSES.includes(fm.status)) err(f, `status "${fm.status}" not in: ${STATUSES.join(", ")}`);
    if (fm.status !== "rejected" && !SEVERITIES.includes(fm.severity)) err(f, `severity "${fm.severity}" not in: ${SEVERITIES.join(", ")}`);
    if (final && fm.status === "raw") err(f, "still raw after verification (loop-exit invariant)");

    if (fm.status === "rejected") {
      // The reason code comes first; a short explanation may follow it ("best_practice — ...").
      const code = String(fm.rejection_reason ?? "").match(/^[\w-]+/)?.[0] ?? "";
      const dup = code.match(/^duplicate_of_([\w-]+)$/);
      if (dup && !ids.has(dup[1])) err(f, `rejection_reason points to unknown finding "${dup[1]}"`);
      if (!dup && !REJECTIONS.includes(code)) err(f, `rejection_reason must start with one of: ${REJECTIONS.join(", ")}, duplicate_of_<id> (got "${String(fm.rejection_reason ?? "").slice(0, 60)}")`);
    }

    if (fm.status === "verified") {
      if (!/`?[\w./()[\]@-]+\.\w+:\d+/.test(f.body)) err(f, "verified finding cites no file:line");
      const steps = section(f.body, "Exploit Steps");
      if (!steps || !/^\s*1\.\s*\S/m.test(steps)) err(f, 'verified finding needs "## Exploit Steps" with numbered steps');
      if (["CRITICAL", "HIGH"].includes(fm.severity) && !PROOFS.includes(fm.proof))
        err(f, `${fm.severity} finding needs proof: dynamic | static`);
    }
    if (fm.proof !== undefined && !PROOFS.includes(fm.proof)) err(f, `proof "${fm.proof}" not in: ${PROOFS.join(", ")}`);
    if (fm.proof === "dynamic" && !section(f.body, "Proof")) err(f, 'proof: dynamic needs a "## Proof" section with the command and its output');

    if (fm.remediation !== undefined) {
      const r = fm.remediation;
      if (typeof r !== "object" || Array.isArray(r)) err(f, "remediation must be a nested block");
      else {
        if (fm.status !== "verified" && fm.status !== "fixed") err(f, `remediation block on a ${fm.status} finding (only verified findings are remediated)`);
        if (!REMEDIATION.includes(r.status)) err(f, `remediation.status "${r.status}" not in: ${REMEDIATION.join(", ")}`);
        if (r.status === "fixed" && !(Array.isArray(r.fix_evidence) && r.fix_evidence.length)) err(f, "remediation.status fixed needs fix_evidence: [\"path:line\"]");
        if (r.public_safe === true && r.status !== "fixed") err(f, "public_safe: true is allowed only when remediation.status is fixed");
        if (r.status === "wont_fix" && !r.verification) err(f, "wont_fix needs a one-line rationale in remediation.verification");
      }
    }
  }

  for (const n of nonIssues) {
    n.errors.forEach((e) => err(n, e));
    if (!n.data) continue;
    if (n.data.id !== n.stem) err(n, `id "${n.data.id}" must equal the file name "${n.stem}"`);
    if (!CATEGORIES.includes(n.data.category)) err(n, `category "${n.data.category}" not in: ${CATEGORIES.join(", ")}`);
  }
  return errors;
}

export function summarize({ findings, nonIssues }) {
  const by = (list, key) => list.reduce((m, x) => ((m[key(x)] = (m[key(x)] ?? 0) + 1), m), {});
  const fs = findings.filter((f) => f.data);
  const verified = fs.filter((f) => f.data.status === "verified")
    .sort((a, b) => SEVERITIES.indexOf(a.data.severity) - SEVERITIES.indexOf(b.data.severity) || a.stem.localeCompare(b.stem));
  const rejected = fs.filter((f) => f.data.status === "rejected");
  const L = [
    `status: ${JSON.stringify(by(fs, (f) => f.data.status))} · non-issues: ${nonIssues.length}`,
    `verified by severity: ${JSON.stringify(by(verified, (f) => f.data.severity))} · by category: ${JSON.stringify(by(verified, (f) => f.data.category))}`,
    `rejected by reason: ${JSON.stringify(by(rejected, (f) => String(f.data.rejection_reason ?? "").match(/^[\w-]+/)?.[0]?.replace(/^duplicate_of_.*/, "duplicate") ?? "?"))}`,
    ...verified.map((f) => `  ${f.data.severity.padEnd(8)} ${f.stem.padEnd(22)} ${(f.data.proof ?? "-").padEnd(7)} pre=${f.data.prerequisite_count ?? "?"} ${titleOf(f.data, f.body).slice(0, 110)}`),
  ];
  return L.join("\n");
}

export function buildRemediation({ findings, nonIssues }, prev, { project, source, commit }) {
  const verified = findings.filter((f) => f.data?.status === "verified");
  const entries = verified.map((f) => {
    const fm = f.data;
    const r = typeof fm.remediation === "object" && fm.remediation ? fm.remediation : {};
    const status = r.status || "open";
    const e = {
      id: fm.id,
      category: fm.category,
      severity: fm.severity,
      title: titleOf(fm, f.body),
      proof: fm.proof || "static",
      remediation_status: status,
      fixed_at: r.fixed_at || undefined,
      fix_commit: r.fix_commit || undefined,
      fix_evidence: Array.isArray(r.fix_evidence) ? r.fix_evidence : [],
      verification: r.verification || "",
      regression_test: r.regression_test || undefined,
      public_safe: status === "fixed",
    };
    return JSON.parse(JSON.stringify(e));
  });
  const count = (s) => entries.filter((e) => e.remediation_status === s).length;
  return {
    schema_version: "1.0",
    project,
    audited_commit: prev?.audited_commit || commit || "",
    audit_date: prev?.audit_date || new Date().toISOString().slice(0, 10),
    generated_at: new Date().toISOString(),
    source,
    summary: {
      verified_total: entries.length,
      fixed: count("fixed"), partial: count("partial"), open: count("open"),
      wont_fix: count("wont_fix"), cannot_verify: count("cannot_verify"),
      cleared: { rejected: findings.filter((f) => f.data?.status === "rejected").length, non_issues: nonIssues.length },
    },
    findings: entries,
  };
}

// realpath on both sides: the skill is usually run through a symlink (~/.claude/skills/...).
if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const opt = (n, d) => (args.indexOf(n) >= 0 ? args[args.indexOf(n) + 1] : d);
  const dir = resolve(opt("--dir", ".security-audit"));
  const audit = loadAudit(dir);
  const errors = validate(audit, { final: args.includes("--final") });

  console.log(`audit-state: ${audit.findings.length} findings, ${audit.nonIssues.length} non-issues in ${dir}`);
  if (errors.length) {
    console.log(`${errors.length} problem(s):`);
    for (const e of errors) console.log(`  - ${e}`);
  }
  if (args.includes("--summary")) console.log(summarize(audit));
  if (args.includes("--write")) {
    if (errors.length) {
      console.log("remediation.json NOT written: fix the problems above first.");
    } else {
      const out = join(dir, "remediation.json");
      const source = opt("--source", "baseline-from-audit");
      // A new baseline starts a new audit: keep the previous date/commit only for fix/verify updates.
      const prev = source !== "baseline-from-audit" && existsSync(out) ? JSON.parse(readFileSync(out, "utf8")) : null;
      const prepass = join(dir, "prepass.md");
      const commit = existsSync(prepass) ? readFileSync(prepass, "utf8").match(/Commit: (\w+)/)?.[1] : undefined;
      const doc = buildRemediation(audit, prev, {
        project: basename(dirname(dir)),
        source,
        commit,
      });
      writeFileSync(out, JSON.stringify(doc, null, 2) + "\n");
      const s = doc.summary;
      console.log(`remediation.json written: ${s.verified_total} verified (${s.fixed} fixed, ${s.partial} partial, ${s.open} open, ${s.wont_fix} wont_fix, ${s.cannot_verify} cannot_verify)`);
    }
  }
  process.exit(errors.length ? 1 : 0);
}
