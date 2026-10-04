#!/usr/bin/env node
// Renders .security-audit/ into one self-contained report.html: what to fix (red), what is verified
// safe (green), what was not assessed (grey), plus hotspots, dependency advisories and secrets.
//   node report-html.mjs [--dir .security-audit] [--out <dir>/report.html]
// Built from the finding files only (no LLM), so it always matches the data. Every string from the
// audit is escaped: findings are written by a model that read untrusted code. A CSP with a
// script hash blocks anything that slips through. The file names unfixed weaknesses: keep it private.
// ponytail: system font stacks, because the file must open offline and stay small.

import { createHash } from "node:crypto";
import { existsSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadAudit, section, titleOf } from "./audit-state.mjs";

const SEVERITY = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const CATEGORY = {
  auth: "Authentication & authorization", injection: "Injection & SSRF", "rate-limit": "Rate limiting & abuse",
  exposure: "Data exposure & secrets", config: "Headers, CORS & configuration", upload: "File upload & storage",
  dependency: "Dependencies", crypto: "Cryptography", concurrency: "Concurrency & races",
  "docs-vs-reality": "Documentation vs reality", "business-logic": "Business logic", logging: "Logging & monitoring",
  "test-gap": "Test gaps", chain: "Chains",
};

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
// The package name reads better than a directory called "app"; fall back to the directory.
function packageName(root) {
  try {
    const name = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).name;
    return typeof name === "string" && name.trim() ? name.replace(/^@[^/]+\//, "") : null;
  } catch {
    return null;
  }
}
const firstLoc = (text) => text?.match(/`?([\w./()[\]@-]+\.\w+:\d+(?:[-,]\d+)*)`?/)?.[1] ?? "";

// Minimal markdown: fenced code, lists, inline code, bold. Input is escaped before any markup is added.
const inline = (t) => esc(t).replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
function md(src) {
  if (!src) return "";
  const out = [];
  let list = null;
  const close = () => { if (list) { out.push(`</${list}>`); list = null; } };
  const parts = src.split(/^```[\w-]*\s*$/m);
  parts.forEach((part, i) => {
    if (i % 2) { close(); out.push(`<pre><code>${esc(part.replace(/^\n|\n$/g, ""))}</code></pre>`); return; }
    for (const line of part.split("\n")) {
      const ol = line.match(/^\s*\d+[.)]\s+(.*)$/);
      const ul = line.match(/^\s*[-*]\s+(.*)$/);
      if (ol || ul) {
        const tag = ol ? "ol" : "ul";
        if (list !== tag) { close(); out.push(`<${tag}>`); list = tag; }
        out.push(`<li>${inline((ol ?? ul)[1])}</li>`);
      } else if (line.trim()) {
        close();
        out.push(`<p>${inline(line.replace(/^#+\s*/, ""))}</p>`);
      }
    }
  });
  close();
  return out.join("\n");
}

function load(dir) {
  const { findings, nonIssues } = loadAudit(dir);
  const json = (p) => (existsSync(join(dir, p)) ? JSON.parse(readFileSync(join(dir, p), "utf8")) : null);
  const summary = json("tools/summary.json");
  const hotspots = json("tools/hotspots.json") ?? [];
  // null = never recorded (audits older than the not-assessed rule), [] = recorded and empty.
  let notAssessed = existsSync(join(dir, "not-assessed.md"))
    ? readFileSync(join(dir, "not-assessed.md"), "utf8").split("\n")
        .filter((l) => /^\|/.test(l) && !/^\|\s*-/.test(l) && !/^\|\s*category\s*\|/i.test(l))
        .map((l) => l.split("|").slice(1, -1).map((c) => c.trim()))
    : null;
  for (const [label, block] of [["Dependencies", summary?.deps], ["Secrets", summary?.secrets]]) {
    if (block && /NOT RUN|FAILED/.test(block.status)) (notAssessed ??= []).push([label.toLowerCase(), `${label} scan`, block.status]);
  }

  const items = findings.filter((f) => f.data).map((f) => {
    const fm = f.data;
    const legacyFixed = fm.status === "fixed";
    const rem = typeof fm.remediation === "object" && fm.remediation ? fm.remediation : {};
    const sec = (n) => section(f.body, n);
    return {
      id: fm.id ?? f.stem, category: fm.category, severity: String(fm.severity ?? "").toUpperCase(),
      status: legacyFixed ? "verified" : fm.status, remediation: legacyFixed ? "fixed" : rem.status || "open",
      fixEvidence: rem.fix_evidence ?? [], proof: fm.proof, rejection: String(fm.rejection_reason ?? ""),
      title: titleOf(fm, f.body) || f.stem, loc: firstLoc(sec("Evidence") ?? f.body),
      evidence: sec("Evidence"), trace: sec("TRACE"), impact: sec("Impact"), proofText: sec("Regression Test"),
      chain: sec("Chained With"), fix: sec("Recommendation"), rejectionNote: sec("Rejection Note"),
      carriedFrom: fm.carried_from ? String(fm.carried_from).slice(0, 12) : "", carriedRun: String(fm.carried_run ?? ""),
    };
  });
  const safe = nonIssues.filter((n) => n.data).map((n) => ({
    category: n.data.category, area: section(n.body, "Area Examined")?.split("\n")[0] ?? n.stem,
    why: section(n.body, "Why Not Vulnerable") ?? "", loc: firstLoc(section(n.body, "Evidence") ?? n.body),
  }));
  const reportPath = join(dir, "report.md");
  return {
    project: summary?.project ?? packageName(dirname(resolve(dir))) ?? basename(dirname(resolve(dir))),
    commit: summary?.commit ?? "",
    date: (existsSync(reportPath) ? statSync(reportPath).mtime : new Date()).toISOString().slice(0, 10),
    scope: summary?.scope ?? null,
    incremental: json("tools/incremental.json"),
    items, safe, notAssessed, hotspots, summary,
  };
}

const sevRank = (s) => (SEVERITY.indexOf(s) + 5) % 5;
const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

function proofChip(f) {
  if (!["CRITICAL", "HIGH"].includes(f.severity)) return "";
  return f.proof === "test"
    ? `<span class="chip chip-proof">Failing test</span>`
    : `<span class="chip chip-static">Code reading only</span>`;
}

function findingRow(f) {
  const status = f.remediation === "partial" ? `<span class="chip chip-warn">Partly fixed</span>`
    : f.remediation === "cannot_verify" ? `<span class="chip chip-muted">Cannot verify</span>` : "";
  const block = (label, body) => (body ? `<section><h4>${label}</h4>${md(body)}</section>` : "");
  return `<details class="row sev-${f.severity.toLowerCase()}" id="${esc(f.id)}">
<summary><span class="sev">${esc(f.severity.toLowerCase())}</span><span class="title">${inline(f.title)}</span>${proofChip(f)}${status}${f.carriedFrom ? `<span class="chip chip-muted">Carried over</span>` : ""}<span class="loc">${esc(f.loc)}</span></summary>
<div class="body">
${block("How to fix", f.fix)}
${block("Evidence", f.evidence)}
${block("Data flow", f.trace)}
${block("Impact", f.impact)}
${block("Regression test", f.proofText)}
${f.chain && !/^none\b/i.test(f.chain.trim()) ? block("Chained with", f.chain) : ""}
<p class="meta">${esc(f.id)} · ${esc(CATEGORY[f.category] ?? f.category)}${f.carriedFrom ? ` · carried over from the audit of commit ${esc(f.carriedFrom)} (run ${esc(f.carriedRun)}); its files did not change` : ""}</p>
</div></details>`;
}

function render(d) {
  const toFix = d.items.filter((f) => f.status === "verified" && !["fixed", "wont_fix"].includes(f.remediation))
    .sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || (b.proof === "test") - (a.proof === "test") || a.id.localeCompare(b.id));
  const fixed = d.items.filter((f) => f.status === "verified" && f.remediation === "fixed");
  const accepted = d.items.filter((f) => f.status === "verified" && f.remediation === "wont_fix");
  const rejected = d.items.filter((f) => f.status === "rejected");
  const raw = d.items.filter((f) => f.status === "raw");
  const count = (s) => toFix.filter((f) => f.severity === s).length;

  const counts = SEVERITY.map((s) => [s, count(s)]).filter(([, n]) => n);
  const verdict = toFix.length
    ? `${plural(toFix.length, "issue")} to fix${counts.length ? ` (${counts.map(([s, n]) => `${n} ${s.toLowerCase()}`).join(", ")})` : ""}.`
    : "Nothing open to fix.";
  const gaps = d.notAssessed ?? [];
  const secondary = [
    `${plural(d.safe.length, "area")} verified safe`,
    fixed.length ? `${fixed.length} fixed` : "",
    d.notAssessed ? `${plural(gaps.length, "check")} not assessed` : "coverage gaps not recorded (older audit format)",
  ].filter(Boolean).join(" · ");

  const bar = [
    ...SEVERITY.map((s) => [s.toLowerCase(), count(s), `${count(s)} ${s.toLowerCase()}`]),
    ["fixed", fixed.length, `${fixed.length} fixed`],
    ["safe", d.safe.length, `${d.safe.length} verified safe`],
    ["gap", gaps.length, `${gaps.length} not assessed`],
  ].filter(([, n]) => n);
  const total = bar.reduce((s, [, n]) => s + n, 0) || 1;

  const bySev = SEVERITY.map((s) => [s, toFix.filter((f) => f.severity === s)]).filter(([, l]) => l.length);
  const safeByCat = Object.entries(d.safe.reduce((m, n) => ((m[n.category] ??= []).push(n), m), {}))
    .sort((a, b) => b[1].length - a[1].length);
  const nav = [
    ["fix", "To fix", toFix.length], ["safe", "Verified safe", d.safe.length], ["gaps", "Not assessed", d.notAssessed ? gaps.length : "–"],
    ...(d.hotspots.length ? [["hotspots", "Hotspots", Math.min(20, d.hotspots.filter((h) => h.inScope !== false).length)]] : []),
    ...(d.summary ? [["deps", "Dependencies", d.summary.deps.rows.length], ["secrets", "Secrets", d.summary.secrets.rows.length]] : []),
    ["filtered", "Filtered out", rejected.length],
  ];

  const script = `addEventListener("beforeprint",()=>document.querySelectorAll("details").forEach((d)=>d.open=true));`;
  const hash = createHash("sha256").update(script).digest("base64");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-${hash}'; img-src data:">
<meta name="robots" content="noindex">
<title>Security audit · ${esc(d.project)}</title>
<style>
:root {
  --paper: #f6f2ea; --paper-2: #efe9dd; --ink: #1d1b18; --ink-2: #5b554b; --rule: #d9d1c1;
  --crit: #a3171d; --high: #cf3a1c; --med: #b7791f; --low: #4f6489; --safe: #1f7a4d; --fixed: #2f6f7e; --gap: #9a9184;
  --tint-crit: #f3dcd8; --tint-safe: #dcebe1; --tint-gap: #e8e3da; --code: #ebe4d6;
  /* Darker steps for severity badges that carry text (>= 4.5:1 with --paper); bars and dots keep the brighter ones. */
  --high-ink: #b8330f; --med-ink: #94590a;
  --display: "Iowan Old Style", "Palatino Linotype", Palatino, "Book Antiqua", Charter, "Bitstream Charter", Georgia, serif;
  --text: "Avenir Next", "Segoe UI Variable Text", "Segoe UI", "Helvetica Neue", Ubuntu, Cantarell, sans-serif;
  --mono: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, "DejaVu Sans Mono", monospace;
  color-scheme: light;
}
@media (prefers-color-scheme: dark) {
  :root {
    --paper: #16140f; --paper-2: #1e1b15; --ink: #ece6d8; --ink-2: #a89f8e;
    --rule: #353025; --crit: #f0695e; --high: #f28c5b; --med: #e0b45a; --low: #8ea5cf; --safe: #5cc28c; --fixed: #6fb6c6; --gap: #8b8377;
    --tint-crit: #3a1d19; --tint-safe: #17301f; --tint-gap: #29251e; --code: #24201a;
    --high-ink: #f28c5b; --med-ink: #e0b45a;
    color-scheme: dark;
  }
}
* { box-sizing: border-box; }
html { background: var(--paper); }
body { margin: 0; color: var(--ink); font: 16px/1.55 var(--text); font-variant-numeric: tabular-nums; -webkit-font-smoothing: antialiased; }
::selection { background: var(--crit); color: var(--paper); }
:focus-visible { outline: 2px solid var(--crit); outline-offset: 3px; border-radius: 4px; }
a { color: inherit; text-underline-offset: 3px; text-decoration-thickness: 1px; }
code, pre { font-family: var(--mono); font-size: 0.86em; }
code { background: var(--code); padding: 0.08em 0.35em; border-radius: 4px; overflow-wrap: anywhere; }
pre { background: var(--code); padding: 0.9rem 1rem; border-radius: 10px; overflow-x: auto; line-height: 1.45; }
pre code { background: none; padding: 0; }
.wrap { max-width: 1180px; margin: 0 auto; padding: 0 clamp(16px, 4vw, 48px); display: grid; grid-template-columns: 200px minmax(0, 1fr); gap: 56px; }
header { grid-column: 1 / -1; padding: 56px 0 28px; border-bottom: 1px solid var(--rule); }
header .meta { color: var(--ink-2); font-size: 0.92rem; margin: 0 0 18px; }
h1 { font: 600 clamp(2.4rem, 5vw, 3.6rem)/1.05 var(--display); letter-spacing: -0.02em; margin: 0 0 22px; }
.verdict { font: 500 clamp(1.4rem, 2.6vw, 1.9rem)/1.25 var(--display); margin: 0 0 6px; max-width: 34ch; }
.secondary { color: var(--ink-2); margin: 0 0 26px; }
.ledger { display: flex; height: 14px; border-radius: 7px; overflow: hidden; background: var(--paper-2); gap: 2px; animation: reveal 900ms cubic-bezier(.2,.7,.1,1) 120ms both; }
.ledger span { flex-grow: var(--n); min-width: 6px; }
@keyframes reveal { from { clip-path: inset(0 100% 0 0); } to { clip-path: inset(0 0 0 0); } }
@media (prefers-reduced-motion: reduce) { .ledger { animation: none; } }
.legend { display: flex; flex-wrap: wrap; gap: 6px 18px; margin: 12px 0 0; padding: 0; list-style: none; font-size: 0.86rem; color: var(--ink-2); }
.legend i { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 7px; vertical-align: 0; }
.c-critical { background: var(--crit); } .c-high { background: var(--high); } .c-medium { background: var(--med); } .c-low { background: var(--low); }
.c-fixed { background: var(--fixed); } .c-safe { background: var(--safe); } .c-gap { background: var(--gap); }
.scope { margin: 18px 0 0; padding: 10px 14px; background: var(--tint-gap); border-radius: 10px; font-size: 0.92rem; }
nav { position: sticky; top: 0; align-self: start; padding-top: 28px; }
nav ol { list-style: none; margin: 0; padding: 0; }
nav a { display: flex; justify-content: space-between; padding: 6px 0; text-decoration: none; color: var(--ink-2); border-bottom: 1px solid transparent; }
nav a:hover { color: var(--ink); border-bottom-color: var(--rule); }
nav b { font-weight: 500; color: var(--ink); }
main { padding: 28px 0 96px; min-width: 0; }
h2 { font: 600 1.75rem/1.2 var(--display); letter-spacing: -0.015em; margin: 72px 0 6px; scroll-margin-top: 24px; }
main > h2:first-child { margin-top: 0; }
h2 + .lede { color: var(--ink-2); margin: 0 0 22px; max-width: 70ch; }
h3 { font: 600 0.8rem/1 var(--text); letter-spacing: 0.08em; text-transform: uppercase; color: var(--ink-2); margin: 34px 0 10px; }
.first { counter-reset: n; list-style: none; padding: 0; margin: 0 0 8px; }
.first li { counter-increment: n; display: grid; grid-template-columns: 2.2rem minmax(0, 1fr); padding: 14px 0; border-top: 1px solid var(--rule); }
.first li::before { content: counter(n); font: 600 1.5rem/1.1 var(--display); color: var(--crit); }
.first a { font-weight: 600; text-decoration: none; }
.first a:hover { text-decoration: underline; }
.first small { display: block; color: var(--ink-2); margin-top: 2px; }
.row { border-top: 1px solid var(--rule); }
.row:last-child { border-bottom: 1px solid var(--rule); }
.row summary { display: flex; flex-wrap: wrap; align-items: baseline; gap: 6px 12px; padding: 14px 4px; cursor: pointer; list-style: none; }
.row summary::-webkit-details-marker { display: none; }
.row summary:hover .title { text-decoration: underline; text-decoration-color: var(--rule); }
.row[open] summary { background: var(--paper-2); }
.sev { font: 600 0.72rem/1 var(--text); letter-spacing: 0.06em; text-transform: uppercase; padding: 4px 7px; border-radius: 5px; color: var(--paper); }
.sev-critical .sev { background: var(--crit); } .sev-high .sev { background: var(--high-ink); } .sev-medium .sev { background: var(--med-ink); } .sev-low .sev { background: var(--low); }
.title { font-weight: 600; flex: 1 1 320px; }
.loc { font: 0.82rem var(--mono); color: var(--ink-2); flex-basis: 100%; padding-left: 0; overflow-wrap: anywhere; }
.chip { font-size: 0.75rem; padding: 2px 8px; border-radius: 999px; white-space: nowrap; }
.chip-proof { background: var(--crit); color: var(--paper); }
.chip-static { box-shadow: inset 0 0 0 1px var(--ink-2); color: var(--ink-2); }
.chip-warn { background: var(--med-ink); color: var(--paper); }
.chip-muted { box-shadow: inset 0 0 0 1px var(--gap); color: var(--ink-2); }
.body { padding: 4px 4px 22px; max-width: 78ch; }
.body h4 { font: 600 0.78rem/1 var(--text); letter-spacing: 0.06em; text-transform: uppercase; color: var(--ink-2); margin: 20px 0 6px; }
.body p, .body li { margin: 0.3em 0; }
.body .meta { color: var(--ink-2); font-size: 0.85rem; margin-top: 18px; }
.good, .gap { list-style: none; padding: 0; margin: 0; }
.good li, .gap li { display: grid; grid-template-columns: 22px minmax(0, 1fr); gap: 0 12px; padding: 12px 0; border-top: 1px solid var(--rule); }
.good svg { color: var(--safe); margin-top: 3px; } .gap svg { color: var(--gap); margin-top: 3px; }
.good .why, .gap .why { color: var(--ink-2); font-size: 0.94rem; display: block; max-width: 72ch; }
.good code { font-size: 0.8rem; }
details.cat > summary { cursor: pointer; padding: 10px 0; font-weight: 600; list-style: none; display: flex; justify-content: space-between; border-top: 1px solid var(--rule); }
details.cat > summary::-webkit-details-marker { display: none; }
details.cat > summary span { color: var(--safe); font-weight: 500; }
.band-safe { background: var(--tint-safe); border-radius: 14px; padding: 6px 20px 14px; }
.band-gap { background: var(--tint-gap); border-radius: 14px; padding: 6px 20px 14px; }
table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
th { text-align: left; font: 600 0.74rem/1 var(--text); letter-spacing: 0.06em; text-transform: uppercase; color: var(--ink-2); padding: 10px 8px; border-bottom: 1px solid var(--rule); }
td { padding: 9px 8px; border-bottom: 1px solid var(--rule); vertical-align: top; }
td.mono { font: 0.8rem var(--mono); overflow-wrap: anywhere; }
td.where { width: 46%; }
.score { display: inline-block; height: 6px; border-radius: 3px; background: var(--high); vertical-align: middle; margin-right: 8px; }
.tablewrap { overflow-x: auto; }
.empty { color: var(--ink-2); padding: 14px 0; border-top: 1px solid var(--rule); }
footer { grid-column: 1 / -1; border-top: 1px solid var(--rule); padding: 24px 0 48px; color: var(--ink-2); font-size: 0.85rem; }
@media (max-width: 860px) {
  .wrap { grid-template-columns: 1fr; gap: 0; }
  nav { position: static; padding-top: 20px; }
  nav ol { display: flex; flex-wrap: wrap; gap: 4px 16px; }
  nav a { gap: 6px; min-height: 44px; align-items: center; }
}
@media print { nav, .ledger { display: none; } .wrap { display: block; } h2 { break-after: avoid; } .row { break-inside: avoid; } }
</style>
</head>
<body>
<div class="wrap">
<header>
<p class="meta">Security audit · ${esc(d.date)}${d.commit ? ` · commit ${esc(d.commit)}` : ""}${d.summary ? ` · deps: ${esc(d.summary.deps.status)} · secrets: ${esc(d.summary.secrets.status)}` : ""}</p>
<h1>${esc(d.project)}</h1>
<p class="verdict">${esc(verdict)}</p>
<p class="secondary">${esc(secondary)}${raw.length ? ` · <strong>${raw.length} finding(s) still unverified</strong>` : ""}</p>
<div class="ledger" role="img" aria-label="${esc(bar.map(([, , l]) => l).join(", "))}">${bar.map(([k, n]) => `<span class="c-${k}" style="--n:${n}"></span>`).join("")}</div>
<ul class="legend">${bar.map(([k, , l]) => `<li><i class="c-${k}"></i>${esc(l)}</li>`).join("")}</ul>
${d.incremental ? `<p class="scope">${d.incremental.mode === "incremental" ? `<strong>Incremental audit.</strong> Re-audited ${d.incremental.targets.length} of ${d.incremental.total} entry points and config files changed since commit ${esc(d.incremental.since.slice(0, 12))}; ${d.items.filter((f) => f.carriedFrom).length} findings carried over from commit ${esc(d.incremental.carried_from.slice(0, 12))}.` : `<strong>Full audit</strong> instead of the requested incremental one: ${esc(d.incremental.reason)}.`}</p>` : ""}
${d.scope ? `<p class="scope"><strong>Partial audit.</strong> Scope: ${esc(d.scope.label)} (${d.scope.entries} of ${d.scope.total} entry points and config files). Everything outside it was not assessed.</p>` : ""}
</header>
<nav aria-label="Sections"><ol>${nav.map(([id, label, n]) => `<li><a href="#${id}">${esc(label)} <b>${n}</b></a></li>`).join("")}</ol></nav>
<main>
<h2 id="fix">To fix</h2>
<p class="lede">Verified findings, most severe first. “Failing test” means a regression test in the project’s own runner fails today; “code reading only” means it was confirmed by tracing the code.</p>
${toFix.length ? `<h3>Fix first</h3>
<ol class="first">${toFix.slice(0, 3).map((f) => `<li><div><a href="#${esc(f.id)}">${inline(f.title)}</a><small>${esc(f.severity.toLowerCase())}${["CRITICAL", "HIGH"].includes(f.severity) ? ` · ${f.proof === "test" ? "failing test" : "code reading only"}` : ""} · ${esc(f.loc)}</small></div></li>`).join("")}</ol>
${bySev.map(([s, list]) => `<h3>${esc(s.toLowerCase())} · ${list.length}</h3>${list.map(findingRow).join("\n")}`).join("\n")}` : `<p class="empty">No open findings.</p>`}
${fixed.length ? `<h3>Fixed · ${fixed.length}</h3><ul class="good">${fixed.map((f) => `<li>${ICON.check}<div><strong>${inline(f.title)}</strong><span class="why">${esc(f.severity.toLowerCase())} · fix in ${esc(f.fixEvidence.join(", ") || "code (no evidence recorded)")}</span></div></li>`).join("")}</ul>` : ""}
${accepted.length ? `<h3>Accepted risk · ${accepted.length}</h3><ul class="gap">${accepted.map((f) => `<li>${ICON.dash}<div><strong>${inline(f.title)}</strong><span class="why">${esc(f.severity.toLowerCase())}</span></div></li>`).join("")}</ul>` : ""}

<h2 id="safe">Verified safe</h2>
<p class="lede">Areas the audit examined and found protected, each with the control that protects it.</p>
<div class="band-safe">${safeByCat.length ? safeByCat.map(([cat, list], i) => `<details class="cat"${i < 2 ? " open" : ""}><summary>${esc(CATEGORY[cat] ?? cat)} <span>${list.length}</span></summary><ul class="good">${list.map((n) => `<li>${ICON.check}<div>${inline(n.area)}<span class="why">${inline(n.why.split("\n")[0].slice(0, 320))}${n.loc ? ` · <code>${esc(n.loc)}</code>` : ""}</span></div></li>`).join("")}</ul></details>`).join("") : `<p class="empty">No verified-safe areas recorded.</p>`}</div>

<h2 id="gaps">Not assessed</h2>
<p class="lede">Nobody checked these. They are unknown, not safe.</p>
<div class="band-gap">${gaps.length ? `<ul class="gap">${gaps.map(([cat, check, why]) => `<li>${ICON.dash}<div><strong>${esc(check || cat)}</strong><span class="why">${esc(why ?? "")}${cat && check ? ` · ${esc(cat)}` : ""}</span></div></li>`).join("")}</ul>` : `<p class="empty">${d.notAssessed ? "No coverage gaps recorded." : "This audit predates coverage-gap tracking: unknown, not empty."}</p>`}</div>

${d.hotspots.length ? `<h2 id="hotspots">Hotspots</h2>
<p class="lede">Where the audit started: entry points and configuration ranked by risk signals. A ranking, not a verdict.</p>
<div class="tablewrap"><table><thead><tr><th>#</th><th>Score</th><th>Where</th><th>Why</th></tr></thead><tbody>${d.hotspots.filter((h) => h.inScope !== false).slice(0, 20).map((h, i) => `<tr><td>${i + 1}</td><td><span class="score" style="width:${Math.min(60, h.score * 4)}px"></span>${h.score}</td><td class="mono where">${esc(`${h.file}:${h.line}`)}<br>${esc(h.kind)} ${esc(h.name)}</td><td>${esc(h.reasons.join("; "))}</td></tr>`).join("")}</tbody></table></div>` : ""}

${d.summary ? `<h2 id="deps">Dependencies</h2>
<p class="lede">${esc(d.summary.deps.status)}</p>
${d.summary.deps.rows.length ? `<div class="tablewrap"><table><thead><tr><th>Package</th><th>Version</th><th>Scope</th><th>CVSS</th><th>Fixed in</th><th>Advisories</th></tr></thead><tbody>${d.summary.deps.rows.map((r) => `<tr><td><strong>${esc(r.name)}</strong></td><td class="mono">${esc(r.version)}</td><td>${esc(r.scope)}</td><td>${esc(r.cvss)}</td><td class="mono">${esc(r.fixed.join(", "))}</td><td class="mono">${esc(r.ids.slice(0, 4).join(", "))}${r.ids.length > 4 ? ` +${r.ids.length - 4}` : ""}</td></tr>`).join("")}</tbody></table></div>` : `<p class="empty">No vulnerable packages reported.</p>`}

<h2 id="secrets">Secrets</h2>
<p class="lede">${esc(d.summary.secrets.status)}. Values are redacted; anything real that was ever committed must be rotated.</p>
${d.summary.secrets.rows.length ? `<div class="tablewrap"><table><thead><tr><th>Rule</th><th>Where</th><th>Commit</th><th>Still in tree</th></tr></thead><tbody>${d.summary.secrets.rows.map((r) => `<tr><td>${esc(r.rule)}</td><td class="mono">${esc(`${r.file}:${r.line}`)}</td><td class="mono">${esc(r.commit)} ${esc(r.date)}</td><td>${esc(r.present)}</td></tr>`).join("")}</tbody></table></div>` : `<p class="empty">No secrets found.</p>`}` : ""}

<h2 id="filtered">Filtered out</h2>
<p class="lede">Candidates the verifier rejected after reading the code. Kept for the record; none of them needs action.</p>
${rejected.length ? `<div class="tablewrap"><table><thead><tr><th>Finding</th><th>Reason</th></tr></thead><tbody>${rejected.map((f) => `<tr><td>${inline(f.title)}<br><span class="mono">${esc(f.id)}</span></td><td>${esc(f.rejection.split(/\s+[—-]\s+/)[0])}</td></tr>`).join("")}</tbody></table></div>` : `<p class="empty">Nothing was rejected.</p>`}
</main>
<footer>Generated from <code>.security-audit/</code> by report-html.mjs. Names unfixed weaknesses with file and line: keep it private, never publish or commit it. A public page must redact unfixed findings (see public_safe in remediation.json).</footer>
</div>
<script>${script}</script>
</body>
</html>
`;
}

const ICON = {
  check: `<svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="9" cy="9" r="7.2"/><path d="M5.8 9.2l2.2 2.2 4.2-4.6"/></svg>`,
  dash: `<svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true" stroke-dasharray="2.2 2.4"><circle cx="9" cy="9" r="7.2"/></svg>`,
};

export function renderReport(dir) {
  return render(load(dir));
}

// realpath on both sides: the skill is usually run through a symlink (~/.claude/skills/...).
if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const opt = (n, d) => (args.indexOf(n) >= 0 ? args[args.indexOf(n) + 1] : d);
  const dir = resolve(opt("--dir", ".security-audit"));
  const out = resolve(opt("--out", join(dir, "report.html")));
  writeFileSync(out, renderReport(dir));
  console.log(`report.html written: ${out}`);
}
