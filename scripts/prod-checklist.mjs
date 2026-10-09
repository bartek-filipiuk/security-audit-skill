#!/usr/bin/env node
// Production checklist (roadmap R14): deployment and runtime checks a code audit cannot settle, built
// from the Not Assessed rows (coverage ledger + not-assessed.md + pre-pass tool status, see coverage.mjs).
//   node prod-checklist.mjs [--dir .security-audit]
// An item is "from this audit" when a Not Assessed row matches it (by keyword in the row's check, reason
// or target, or by a whole class nobody looked at); the baseline items are listed for every audit. Each
// item says how to verify it on your own deployment: read-only checks, never attack steps.
// Report rendering only: it reads the audit files and never changes what the audit finds.

import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { notAssessedRows } from "./coverage.mjs";

// classes: a "whole class" gap in one of these flags the item. match: keywords in check / reason / target.
// baseline: listed even when no row matches.
export const ITEMS = [
  {
    id: "headers", title: "Security headers", baseline: true, classes: ["config"],
    match: /\bheaders?\b|\bcsp\b|content-security|\bhsts\b|strict-transport|x-frame|frame-ancestors|clickjack|nosniff|referrer-policy|permissions-policy|\bcors\b/i,
    how: "`curl -sI https://<your-host>/` and look for `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `frame-ancestors` (or `X-Frame-Options`) and `Referrer-Policy`. Repeat on an API route and on an error page; a CDN or proxy can add or strip them.",
  },
  {
    id: "tls", title: "TLS and HTTPS redirect", baseline: true, classes: [],
    match: /\btls\b|\bssl\b|\bhttps\b|certificate/i,
    how: "`curl -sI http://<your-host>/` should answer with a redirect to `https://`. `openssl s_client -connect <your-host>:443 -servername <your-host> </dev/null | openssl x509 -noout -dates` shows the certificate expiry; confirm renewal is automated.",
  },
  {
    id: "limits", title: "Request size, upload and rate limits", baseline: true, classes: ["rate-limit", "upload"],
    match: /rate.?limit|throttl|brute|lockout|login attempts?|\blimits?\b|body size|payload size|upload size|file size|request size|max.?size|timeout/i,
    how: "Write down the limits the deployment actually applies: reverse-proxy body size (e.g. `client_max_body_size`), the framework's body parser limit, the upload maximum, the login throttle. On staging, with your own test account, confirm an oversized upload is refused (413) and repeated failed logins get throttled.",
  },
  {
    id: "env", title: "Environment variables and debug flags", baseline: true, classes: ["config"],
    match: /\benv\b|\.env\b|environment var|\bdebug\b|node_env|app_env|app_debug|production (value|setting|config)|default (password|key|secret|credential)/i,
    how: "List the variables the code reads (search for `process.env`, `getenv`, `os.environ`) and confirm each one is set in production with a non-default value. Debug is off (`NODE_ENV=production`, `APP_DEBUG=false`, `DEBUG=False`), and an error page on https://<your-host>/ shows no stack trace.",
  },
  {
    id: "secrets", title: "Secrets storage and rotation", baseline: true, classes: ["exposure"],
    match: /secrets?\b|credential|api.?keys?\b|private key|gitleaks|\bvault\b/i,
    how: "Production secrets live in the platform's secret store, not in the repository or the image: run `gitleaks detect` over the full git history and check `docker history <image>` for baked-in values. Rotate any value that was ever committed, and check who can read the secret store.",
  },
  {
    id: "backups", title: "Backups and a tested restore", baseline: true, classes: [],
    match: /backups?\b|restore|snapshot|disaster|recovery|retention|point.in.time/i,
    how: "Check the time of the last backup and that it is stored off the production host. Restore it into a scratch database, compare row counts of the main tables with production, and note how long the restore took.",
  },
  {
    id: "logging", title: "Logging, monitoring and alerts", baseline: true, classes: ["logging"],
    match: /\blog(s|ging|ged)?\b|monitor|alert|audit trail|observab/i,
    how: "On staging, cause a harmless error (a 404, a failed login with your own test account) and confirm it reaches the log store with a timestamp and request id, and without passwords, tokens or session ids. Confirm someone is alerted on a burst of 5xx responses or failed logins.",
  },
  {
    id: "deps", title: "Dependency and runtime updates", baseline: true, classes: ["dependency"],
    match: /dependenc|osv|npm audit|composer audit|pip-audit|\bcve\b|advisor|outdated|lockfile|base image|runtime version|trivy/i,
    how: "Run the ecosystem's audit on the lockfile that is deployed (`npm audit --omit=dev`, `composer audit`, `pip-audit`). Check that the runtime and base image versions in production are still supported, and that update pull requests (Dependabot, Renovate) have an owner.",
  },
  {
    id: "network", title: "Exposed services and ports", baseline: true, classes: [],
    match: /\bports?\b|firewall|security group|admin panel|exposed service|internal service|bind address/i,
    how: "In the hosting provider's firewall or security-group view, only 80 and 443 are public for <your-host>; the database, cache, queue and admin ports are bound to a private network. Repeat after every infrastructure change.",
  },
  {
    id: "cookies", title: "Session cookie flags", baseline: false, classes: [],
    match: /cookies?\b|samesite|httponly/i,
    how: "Sign in on https://<your-host>/ with your own account and read the `Set-Cookie` header (browser devtools or `curl -sI`): the session cookie has `Secure`, `HttpOnly` and `SameSite=Lax` or `Strict`.",
  },
];

// Rows that describe the audit's own bookkeeping, not a deployment question.
const bookkeeping = (r) => r.by === "coverage.mjs" && r.check !== "whole class";

function matches(item, r) {
  if (bookkeeping(r)) return false;
  if (r.check === "whole class") return item.classes.includes(r.class);
  return item.match.test([r.check, r.why, r.target].filter(Boolean).join(" "));
}

// rows: notAssessedRows(dir) (null = nothing about coverage was recorded). Flagged items first, in
// catalogue order, then the baseline items no row matched.
export function productionChecklist(rows) {
  const list = Array.isArray(rows) ? rows : [];
  // Specific rows before "whole class" ones, which say less about what to check.
  const items = ITEMS.map((it) => ({ ...it, rows: list.filter((r) => matches(it, r)).sort((a, b) => (a.check === "whole class") - (b.check === "whole class")) }))
    .map((it) => ({ ...it, flagged: it.rows.length > 0 }));
  const used = new Set(items.flatMap((it) => it.rows));
  return {
    recorded: Array.isArray(rows),
    items: [...items.filter((it) => it.flagged), ...items.filter((it) => !it.flagged && it.baseline)],
    flagged: items.filter((it) => it.flagged).length,
    unmatched: list.filter((r) => !used.has(r) && !bookkeeping(r)).length,
  };
}

export const SHOW_ROWS = 3;
export const rowLabel = (r) => [r.class, r.check, r.target].filter(Boolean).join(" · ") + (r.why ? ` (${r.why})` : "");

export const INTRO = "Deployment and runtime checks the code audit cannot settle. Items marked \"from this audit\" come from rows under Not Assessed; the baseline items apply to any production deploy. Each says how to verify it on your own host; none of them changes anything.";
export const NO_COVERAGE = "Nothing about coverage was recorded for this audit, so no item below comes from it: this is the baseline list.";

export function renderProdChecklistMd(rows) {
  const c = productionChecklist(rows);
  const flat = (s) => String(s ?? "").replace(/\s*\n\s*/g, " ");
  const L = ["## Production checklist", "", INTRO, ""];
  if (!c.recorded) L.push(NO_COVERAGE, "");
  for (const it of c.items) {
    L.push(`- [ ] **${it.title}** · ${it.flagged ? "from this audit" : "baseline"}`);
    for (const r of it.rows.slice(0, SHOW_ROWS)) L.push(`  - Not assessed: ${flat(rowLabel(r))}`);
    if (it.rows.length > SHOW_ROWS) L.push(`  - and ${it.rows.length - SHOW_ROWS} more under Not Assessed`);
    L.push(`  - How to check: ${it.how}`);
  }
  L.push("");
  if (c.unmatched) L.push(`${c.unmatched} other Not Assessed row(s) are code checks rather than deployment checks; they stay in the Not Assessed table.`, "");
  return L.join("\n");
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const dir = resolve(args.indexOf("--dir") >= 0 ? args[args.indexOf("--dir") + 1] : ".security-audit");
  console.log(renderProdChecklistMd(notAssessedRows(dir)));
}
