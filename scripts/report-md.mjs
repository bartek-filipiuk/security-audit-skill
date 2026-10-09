#!/usr/bin/env node
// Assembles .security-audit/report.md from the coordinator's summary.md plus the audit files, so the
// coordinator never has to read every finding into its own context (the expensive part on big projects).
//   node report-md.mjs [--dir .security-audit]
// summary.md (written by the coordinator): title, Project Summary, Executive Summary with Top 3 risks
// and their proof labels, Recommended Actions. Everything else below it is generated from the files.

import { existsSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadAudit, section, titleOf } from "./audit-state.mjs";
import { renderCoverageMd } from "./coverage.mjs";
import { diffAudit, renderDiffMd } from "./diff.mjs";
import { profileHeadline } from "./stack.mjs";

const ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
const FIELDS = ["Evidence", "TRACE", "Impact", "Regression Test", "Chained With", "Recommendation", "Test Coverage"];
const cell = (s) => String(s ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
const firstLoc = (t) => t?.match(/`?([\w./()[\]@-]+\.\w+:\d+[\d,-]*)`?/)?.[1] ?? "";

export function renderReportMd(dir) {
  const { findings, nonIssues } = loadAudit(dir);
  const read = (n) => (existsSync(join(dir, n)) ? readFileSync(join(dir, n), "utf8").trim() : "");
  const summary = read("summary.md") || "# Security Audit Report\n\n(summary.md missing: the coordinator writes Project Summary, Executive Summary and Recommended Actions there.)";
  const verified = findings.filter((f) => f.data?.status === "verified")
    .sort((a, b) => (ORDER[a.data.severity] ?? 9) - (ORDER[b.data.severity] ?? 9) || a.stem.localeCompare(b.stem));
  const rejected = findings.filter((f) => f.data?.status === "rejected");

  const inc = existsSync(join(dir, "tools", "incremental.json")) ? JSON.parse(read("tools/incremental.json")) : null;
  const carriedNote = (fm) => (fm.carried_from ? ` · **Carried over** from the audit of commit ${String(fm.carried_from).slice(0, 12)} (run ${fm.carried_run})` : "");
  const L = [summary, ""];
  const stack = existsSync(join(dir, "tools", "summary.json")) ? JSON.parse(read("tools/summary.json")).stack : null;
  if (stack?.profiles?.length) {
    L.push("## Stack and Profile", "", `Detected: ${stack.detected.length ? stack.detected.join("; ") : "no known manifest"}.${stack.forced ? ` Profile forced with --stack.` : ""}`);
    if (stack.warning) L.push("", `**Warning:** ${stack.warning}`);
    for (const p of stack.profiles) {
      L.push("", `**Profile: ${profileHeadline(p)}.**`, "", `- Covers: ${p.covers.join("; ")}.`, `- Does not cover: ${p.gaps.join("; ")}.`);
    }
    L.push("");
  }
  if (inc?.mode === "incremental") {
    const cf = findings.filter((f) => f.data?.carried_from).length;
    const cn = nonIssues.filter((n) => n.data?.carried_from).length;
    L.push("## Incremental Audit", "", `Re-audited ${inc.targets.length} of ${inc.total} targets whose code changed since commit ${inc.since.slice(0, 12)} (${inc.changed.length} changed files). ${cf} findings and ${cn} non-issues were carried over from the audit of commit ${inc.carried_from.slice(0, 12)} (run ${inc.carried_run}) because none of the files they cite changed; they are marked "Carried over" below.`, "");
  } else if (inc) {
    L.push("## Incremental Audit", "", `An incremental audit was requested, but this is a full audit: ${inc.reason}.`, "");
  }
  const diff = renderDiffMd(diffAudit(dir));
  if (diff) L.push(diff);
  L.push("## Findings", "");
  verified.forEach((f, i) => {
    const fm = f.data;
    L.push(`### [F${i + 1}] ${titleOf(fm, f.body)}`);
    L.push(`- **Id**: ${fm.id} · **Severity**: ${fm.severity} · **Category**: ${fm.category} · **Prerequisites**: ${fm.prerequisite_count ?? 0}${["CRITICAL", "HIGH"].includes(fm.severity) ? ` · **Proof**: ${fm.proof}` : ""}${carriedNote(fm)}`);
    for (const name of FIELDS) {
      const body = section(f.body, name);
      if (body) L.push("", `**${name}**`, "", body);
    }
    L.push("");
  });

  L.push("## Non-Issues (examined and found secure)", "", "| # | Id | Area Examined | Evidence |", "|---|---|---|---|");
  nonIssues.forEach((n, i) => {
    L.push(`| ${i + 1} | ${n.stem}${n.data?.carried_from ? ` (carried from ${String(n.data.carried_from).slice(0, 7)})` : ""} | ${cell((section(n.body, "Area Examined") ?? "").split("\n")[0]).slice(0, 180)} | ${firstLoc(section(n.body, "Evidence") ?? n.body)} |`);
  });

  L.push("", renderCoverageMd(dir));

  const docs = findings.filter((f) => f.data?.category === "docs-vs-reality");
  L.push("## Documentation vs Reality", "");
  L.push(docs.length ? docs.map((f) => `- ${f.stem} (${f.data.status}): ${titleOf(f.data, f.body)}`).join("\n") : "No documentation claims were found incorrect.");
  L.push("");

  const tq = read("test-quality.md");
  const verdict = tq.match(/## Overall Verdict\s*\n([\s\S]*?)(?=\n## |$)/)?.[1]?.trim();
  L.push("## Test Quality Details", "", tq ? `Overall verdict: ${verdict ?? "see test-quality.md"}. Full assessment: test-quality.md.` : "Test-quality assessment missing.", "");

  const ws = existsSync(join(dir, "tools", "workspace-check.json")) ? JSON.parse(read("tools/workspace-check.json")) : null;
  if (ws?.ok && (ws.changed.length || ws.git_status_new.length || ws.git_status_gone.length)) {
    L.push("## Side Effects on the Project", "", `Files changed outside the audit directory while the audit ran (since ${ws.since}): ${ws.changed.length} modified, ${ws.git_status_new.length} new git status lines. Usually the project's own test run. First files: ${ws.changed.slice(0, 10).join(", ")}.`, "");
  }

  L.push("## Filtered Out (rejected by the verifier)", "", "| Id | Reason |", "|---|---|");
  for (const f of rejected) L.push(`| ${f.stem}${f.data.carried_from ? " (carried)" : ""} | ${cell(f.data.rejection_reason).slice(0, 160)} |`);
  return L.join("\n") + "\n";
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const dir = resolve(args.indexOf("--dir") >= 0 ? args[args.indexOf("--dir") + 1] : ".security-audit");
  const md = renderReportMd(dir);
  writeFileSync(join(dir, "report.md"), md);
  console.log(`report.md written: ${md.split("\n").length} lines -> ${join(dir, "report.md")}`);
}
