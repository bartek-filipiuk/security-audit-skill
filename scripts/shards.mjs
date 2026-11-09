#!/usr/bin/env node
// Plans Phase 3. Raw findings that cite the same place are duplicate candidates (two auditors often file the
// same weakness); this script groups them and splits the raw findings into verifier shards that never
// separate a group, so a duplicate is decided once, next to its partner, and not by a later COMBINE pass.
//   node shards.mjs [--dir .security-audit] [--size 15] [--single 25]
// Up to --single raw findings: one shard (one verifier, no COMBINE pass). More: even shards of at most --size.
// Sizes come from one measured Ledgerly run (shards of 26, 21 and 9 findings took 11.9, 13.8 and 7.2 minutes,
// COMBINE 5 to 8): a shard costs about 4 minutes before its first finding, so smaller shards buy wall-clock
// time with tokens, and splitting 25 findings in two would only pay for the COMBINE pass it adds.
// Writes <dir>/shards/<a,b,...>.md, one per verifier, and prints one line per shard.
// A group is a hint, never a verdict: the verifier decides duplicates with rule 6d (same class and same sink).

import { mkdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadAudit, primaryLocation, titleOf } from "./audit-state.mjs";

// Lines between two findings in one file that still count as the same place. On Ledgerly 16 of 17 duplicates
// were within 15 lines of their partner (11 within 2).
export const SAME_PLACE = 15;

// Category families that are verified together (SKILL.md, Phase 3), in shard order.
const FAMILIES = [
  ["auth", "rate-limit", "business-logic", "docs-vs-reality"],
  ["injection", "exposure", "config", "crypto", "logging", "dependency"],
  ["concurrency", "upload", "test-gap", "chain"],
];
const family = (category) => { const i = FAMILIES.findIndex((f) => f.includes(category)); return i < 0 ? FAMILIES.length : i; };

// Raw findings of this run: carried ones were verified by the previous audit.
export function rawFindings(audit) {
  return audit.findings
    .filter((f) => f.data?.status === "raw" && !f.data.carried_from)
    .map((f) => ({ id: f.stem, category: f.data.category, severity: f.data.severity, title: titleOf(f.data, f.body), loc: primaryLocation(f.text) }));
}

const samePlace = (a, b) =>
  a && b && a.file === b.file && a.start !== null && b.start !== null &&
  Math.max(a.start, b.start) - Math.min(a.end, b.end) <= SAME_PLACE;

// Groups of findings linked by a same-place pair (single linkage), each sorted by line. Singletons included.
export function groups(items) {
  const parent = items.map((_, i) => i);
  const find = (i) => (parent[i] === i ? i : (parent[i] = find(parent[i])));
  for (let i = 0; i < items.length; i++)
    for (let j = i + 1; j < items.length; j++) if (samePlace(items[i].loc, items[j].loc)) parent[find(i)] = find(j);
  const by = new Map();
  items.forEach((it, i) => by.set(find(i), [...(by.get(find(i)) ?? []), it]));
  const line = (it) => it.loc?.start ?? 0;
  return [...by.values()]
    .map((g) => g.sort((a, b) => line(a) - line(b) || a.id.localeCompare(b.id)))
    .sort((a, b) => family(a[0].category) - family(b[0].category) || (a[0].loc?.file ?? "~").localeCompare(b[0].loc?.file ?? "~") || line(a[0]) - line(b[0]) || a[0].id.localeCompare(b[0].id));
}

// Shards of at most `size` findings, as even as the groups allow; a group larger than `size` gets its own shard.
export function plan(items, { size = 15, single = 25 } = {}) {
  const gs = groups(items);
  if (items.length <= single) return items.length ? [gs] : [];
  const target = Math.ceil(items.length / Math.ceil(items.length / size));
  const shards = [[]];
  let count = 0;
  for (const g of gs) {
    if (count && (count >= target || count + g.length > size)) { shards.push([]); count = 0; }
    shards.at(-1).push(g);
    count += g.length;
  }
  return shards;
}

const where = (loc) => (loc ? `${loc.file}${loc.start === null ? "" : `:${loc.start}${loc.end > loc.start ? `-${loc.end}` : ""}`}` : "no file cited");
const cell = (s) => String(s ?? "").replace(/\|/g, "/").replace(/\s+/g, " ").trim();

export function renderShard(name, shard, total) {
  const items = shard.flat();
  const dupes = shard.filter((g) => g.length > 1);
  const L = [
    `# Verifier shard ${name} (${items.length} findings${total > 1 ? `, one of ${total} shards` : ", the only shard"})`,
    "",
    "| Finding file | Category | Severity (auditor) | Cited place | Title |",
    "|---|---|---|---|---|",
    ...items.map((it) => `| findings/${it.id}.md | ${cell(it.category)} | ${cell(it.severity)} | ${cell(where(it.loc))} | ${cell(it.title).slice(0, 100)} |`),
    "",
    "## Same-place groups",
    "",
  ];
  if (!dupes.length) L.push("None: no two findings in this shard cite the same place.");
  else {
    L.push(`Findings that cite the same file within ${SAME_PLACE} lines. Candidates only: read the code once per group and decide`,
      "with rule 6d. Same class and same sink: keep the most complete one, reject the others as duplicates.",
      "A different class, or a different sink a few lines away: distinct findings, keep both.", "");
    for (const g of dupes) L.push(`- ${g.map((it) => `${it.id} (${it.category}, ${where(it.loc).split(":").pop()})`).join(", ")}: ${g[0].loc.file}`);
  }
  return L.join("\n") + "\n";
}

export function writeShards(dir, opts) {
  const items = rawFindings(loadAudit(dir));
  const shards = plan(items, opts);
  const out = join(dir, "shards");
  rmSync(out, { recursive: true, force: true }); // a plan from an earlier pass lists findings that are no longer raw
  mkdirSync(out, { recursive: true });
  const names = shards.map((_, i) => String.fromCharCode(97 + i % 26) + (i >= 26 ? Math.floor(i / 26) : ""));
  shards.forEach((s, i) => writeFileSync(join(out, `${names[i]}.md`), renderShard(names[i], s, shards.length)));
  return { items, shards, names, out };
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const opt = (n, d) => (args.indexOf(n) >= 0 ? args[args.indexOf(n) + 1] : d);
  const num = (n, d) => { const v = Number(opt(n, d)); if (!Number.isInteger(v) || v < 1) { console.log(`shards: ${n} must be a positive integer`); process.exit(2); } return v; };
  const { items, shards, names, out } = writeShards(resolve(opt("--dir", ".security-audit")), { size: num("--size", 15), single: num("--single", 25) });
  const dupes = shards.flat().filter((g) => g.length > 1);
  console.log(`shards: ${items.length} raw findings -> ${shards.length} shard(s) in ${out}; ${dupes.length} same-place group(s) covering ${dupes.flat().length} findings`);
  shards.forEach((s, i) => {
    const cats = s.flat().reduce((m, it) => ((m[it.category] = (m[it.category] ?? 0) + 1), m), {});
    console.log(`  ${names[i]}.md: ${s.flat().length} findings (${Object.entries(cats).map(([c, n]) => `${c} ${n}`).join(", ")})`);
  });
  if (shards.length === 1) console.log("  one shard: dispatch a single verifier, no COMBINE pass");
  if (!items.length) console.log("  nothing is raw: no verifier to dispatch");
}
