#!/usr/bin/env node
// The pull-request summary of an audit run in CI (roadmap R15). Reads only local files, no network.
//   node ci-summary.mjs [--dir .security-audit] [--out <file>] [--fail-on CRITICAL|HIGH|MEDIUM|LOW|none] [--titles]
// Counts the unresolved findings in remediation.json by severity (fixed and wont_fix left out, as in export.mjs)
// and writes a Markdown body for one sticky PR comment (it starts with MARKER), with a link to the workflow run
// and to code scanning. Finding titles are left out unless --titles: a PR comment on a public repository is
// public, and a title names an unfixed weakness.
// When $GITHUB_OUTPUT is set it appends verdict=pass|fail|incomplete, the counts and body=<path>; when
// $GITHUB_STEP_SUMMARY is set it appends the body.
// Exit 0: nothing unresolved at or above --fail-on (default HIGH). Exit 1: something is. Exit 2: no
// remediation.json, so the audit did not finish: that is not a verdict on the code.

import { appendFileSync, existsSync, mkdirSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadExport } from "./export.mjs";

export const MARKER = "<!-- security-audit-ci -->";
export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export function countBySeverity(items) {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const f of items) counts[SEVERITIES.includes(f.severity) ? f.severity : "MEDIUM"]++;
  return counts;
}

// Index of the threshold in SEVERITIES; -1 for "none" (never fails).
export function threshold(failOn) {
  const s = String(failOn ?? "HIGH").toUpperCase();
  if (s === "NONE") return -1;
  const i = SEVERITIES.indexOf(s);
  if (i < 0) throw new Error(`--fail-on must be one of: ${SEVERITIES.join(", ")}, none`);
  return i;
}

export function verdictOf(counts, failOn) {
  const t = threshold(failOn);
  return SEVERITIES.slice(0, t + 1).some((s) => counts[s] > 0) ? "fail" : "pass";
}

// A title written by the audit of the PR's own code: one line, no Markdown or HTML that could change the comment.
export const plainTitle = (t) => String(t ?? "").replace(/[\r\n]+/g, " ").replace(/[`*_<>[\]()!|#~\\]/g, "").replace(/\s+/g, " ").trim().slice(0, 120);

export function links(env = process.env) {
  const server = env.GITHUB_SERVER_URL || "https://github.com";
  const repo = env.GITHUB_REPOSITORY;
  if (!repo) return {};
  const pr = /^\d+$/.test(env.PR_NUMBER ?? "") ? env.PR_NUMBER : "";
  return {
    run: /^\d+$/.test(env.GITHUB_RUN_ID ?? "") ? `${server}/${repo}/actions/runs/${env.GITHUB_RUN_ID}` : "",
    codeScanning: `${server}/${repo}/security/code-scanning${pr ? `?query=${encodeURIComponent(`pr:${pr} tool:security-audit`)}` : ""}`,
  };
}

export function renderBody({ verdict, counts, items = [], failOn = "HIGH", titles = false, scope = "", env = process.env }) {
  const l = links(env);
  const lines = [MARKER, "## Security audit"];
  if (verdict === "incomplete") {
    lines.push("", "The audit did not finish (no `remediation.json`), so there is no verdict on this change. Check the run log.");
  } else {
    const total = SEVERITIES.reduce((n, s) => n + counts[s], 0);
    const gate = threshold(failOn) < 0 ? "no severity fails the check" : `the check fails at ${SEVERITIES[threshold(failOn)]} or above`;
    lines.push("", verdict === "fail" ? `**Unresolved findings at or above ${SEVERITIES[threshold(failOn)]}.**` : "**No unresolved finding at or above the threshold.**");
    lines.push("", `| Severity | Unresolved |`, `|---|---|`, ...SEVERITIES.map((s) => `| ${s} | ${counts[s]} |`), `| Total | ${total} |`);
    lines.push("", `Threshold: ${gate}.`);
    if (titles && items.length) {
      lines.push("", "Findings:");
      for (const f of items) lines.push(`- ${f.severity}: ${plainTitle(f.title)}`);
    }
  }
  if (scope) lines.push("", `Scope: \`${String(scope).replace(/[^A-Za-z0-9_./,-]/g, "")}\``);
  const refs = [l.run && `[workflow run](${l.run})`, l.codeScanning && `[code scanning](${l.codeScanning})`].filter(Boolean);
  if (refs.length) lines.push("", `Details: ${refs.join(" · ")} (the report itself stays on the runner; it names unfixed weaknesses).`);
  return lines.join("\n") + "\n";
}

// Reads the audit directory; never throws for a missing remediation.json (that is the "incomplete" verdict).
export function summarize(dir, { failOn = "HIGH", titles = false, scope = "", env = process.env } = {}) {
  threshold(failOn);
  if (!existsSync(join(dir, "remediation.json"))) {
    const counts = countBySeverity([]);
    return { verdict: "incomplete", code: 2, counts, body: renderBody({ verdict: "incomplete", counts, failOn, scope, env }) };
  }
  const { items } = loadExport(dir);
  const counts = countBySeverity(items);
  const verdict = verdictOf(counts, failOn);
  return { verdict, code: verdict === "fail" ? 1 : 0, counts, body: renderBody({ verdict, counts, items, failOn, titles, scope, env }) };
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const opt = (name, def) => (args.includes(name) ? args[args.indexOf(name) + 1] : def);
  const dir = resolve(opt("--dir", ".security-audit"));
  const out = resolve(opt("--out", join(dir, "export", "pr-comment.md")));
  let r;
  try {
    r = summarize(dir, { failOn: opt("--fail-on", "HIGH"), titles: args.includes("--titles"), scope: process.env.SECURITY_AUDIT_SCOPE ?? "" });
  } catch (e) {
    console.error(`ci-summary: ${e.message}`);
    process.exit(2);
  }
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, r.body);
  if (process.env.GITHUB_OUTPUT) {
    const kv = { verdict: r.verdict, critical: r.counts.CRITICAL, high: r.counts.HIGH, medium: r.counts.MEDIUM, low: r.counts.LOW, body: out };
    appendFileSync(process.env.GITHUB_OUTPUT, Object.entries(kv).map(([k, v]) => `${k}=${v}\n`).join(""));
  }
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, r.body);
  console.log(`${r.verdict}: ${SEVERITIES.map((s) => `${r.counts[s]} ${s}`).join(", ")} → ${out}`);
  process.exit(r.code);
}
