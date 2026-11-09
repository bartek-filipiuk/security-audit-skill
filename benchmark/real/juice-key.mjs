#!/usr/bin/env node
// OWASP Juice Shop support for the real benchmarks (roadmap R33): the answer-key generator and the marker
// stripper that benchmark/real/fetch.mjs runs on a fetched release.
//   node benchmark/real/juice-key.mjs --tarball FILE [--version V] [--out FILE]
//   node benchmark/real/juice-key.mjs --src DIR --version V [--out FILE]
// Juice Shop marks its coding challenges in the source with comments (verified on 20.3.0, the parser is the
// release's lib/codingChallenges.ts):
//   // vuln-code-snippet start <key> [<key>...]      opens the snippet of one or more challenges
//   // vuln-code-snippet end <key> [<key>...]        closes it
//   <code> // vuln-code-snippet vuln-line <key>...    the line is the vulnerable one (what a player must select)
//   <code> // vuln-code-snippet neutral-line <key>... selecting the line is neither right nor wrong
//   <code> // vuln-code-snippet hide-line             not shown in the snippet
//   // vuln-code-snippet hide-start / hide-end        a hidden region
// (`#` instead of `//` in YAML). The key has one entry per group of challenges whose vuln-lines overlap: each
// group's locations are the files and line runs marked `vuln-line` for its challenges. Challenges that share a
// line are one entry because the scorer gives a finding to every entry at the same distance, so separate
// entries would count one finding several times (and `fetch.mjs --check` refuses overlapping ranges). Names,
// categories and difficulties come from the release's data/static/challenges.yml; descriptions and hints are
// not copied (they read as attack steps). The markers are hints to an auditor, so fetch.mjs blanks them in app/
// with stripMarkersInTree(): each marker comment is cut from its line and the line stays, so line numbers in
// app/ equal those of the release and of this key.
// --tarball reads a release archive pinned in npm/juice-shop/manifest.json (sha256 checked, extracted safely
// with fetch.mjs's extractor into a temporary directory and removed afterwards); --src reads an extracted,
// unstripped module root (tests). Without --out the key goes to npm/juice-shop/answer-key-<version>.json.

import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
export const MODULE = "npm/juice-shop";
export const MARKER_KINDS = ["start", "end", "vuln-line", "neutral-line", "hide-line", "hide-start", "hide-end"];
// A marker comment at the end of a line: `//` or `#`, the tool name, a kind and challenge keys up to the end.
// Code that merely mentions the tool name (Juice Shop's own parser, regex literals) does not end like this.
export const MARKER = new RegExp(String.raw`[ \t]*(?:\/\/|#)[ \t]*vuln-code-snippet[ \t]+(${MARKER_KINDS.join("|")})((?:[ \t]+[A-Za-z0-9_]+)*)[ \t]*$`);
// Where the release looks for snippets (SNIPPET_PATHS in lib/codingChallenges.ts, 20.3.0).
export const SNIPPET_PATHS = ["server.ts", "routes", "lib", "data", "frontend/src/app", "models", "infrastructure"];

const splitLines = (text) => text.split("\n").map((l) => (l.endsWith("\r") ? l.slice(0, -1) : l));

// Markers of one file: [{ line, kind, keys }], 1-based lines.
export function parseMarkers(text) {
  const out = [];
  splitLines(text).forEach((l, i) => {
    const m = l.match(MARKER);
    if (m) out.push({ line: i + 1, kind: m[1], keys: m[2].trim().split(/\s+/).filter(Boolean) });
  });
  return out;
}

// The text with every marker comment cut from its line; the number of lines (and CRLF endings) stay as they are.
export function stripMarkers(text) {
  let count = 0;
  const lines = text.split("\n").map((l) => {
    const cr = l.endsWith("\r") ? "\r" : "";
    const body = cr ? l.slice(0, -1) : l;
    const cut = body.replace(MARKER, "");
    if (cut !== body) count++;
    return cut + cr;
  });
  return { text: lines.join("\n"), count };
}

const isText = (buf) => !buf.includes(0);
function walk(dir, base, skip, out) {
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, ent.name);
    const rel = relative(base, p).split("\\").join("/");
    if (skip.some((s) => rel === s || rel.startsWith(s + "/"))) continue;
    if (ent.isDirectory()) walk(p, base, skip, out);
    else if (ent.isFile()) out.push(rel);
  }
  return out;
}

// Strips markers from every text file under `dir`; returns { files: [relative paths changed], lines }.
export function stripMarkersInTree(dir) {
  const files = [];
  let lines = 0;
  for (const rel of walk(dir, dir, [".git"], [])) {
    const p = join(dir, rel);
    const buf = readFileSync(p);
    if (!isText(buf) || !buf.includes("vuln-code-snippet")) continue;
    const r = stripMarkers(buf.toString("utf8"));
    if (!r.count) continue;
    writeFileSync(p, r.text);
    files.push(rel);
    lines += r.count;
  }
  return { files: files.sort(), lines };
}

// A YAML string scalar as Juice Shop writes them: 'single' ('' escapes a quote), "double" or plain.
const scalar = (s) => {
  const t = s.trim();
  if (t.startsWith("'") && t.endsWith("'")) return t.slice(1, -1).replace(/''/g, "'");
  if (t.startsWith('"') && t.endsWith('"')) return JSON.parse(t);
  return t;
};

// name, category, difficulty and key of each challenge in data/static/challenges.yml. A deliberately small
// reader for that file's shape (a top-level list of maps with two-space keys); anything else is an error.
export function parseChallenges(yml) {
  const out = [];
  let cur = null;
  for (const line of splitLines(yml)) {
    if (/^-\s*$/.test(line)) { cur = {}; out.push(cur); continue; }
    const m = line.match(/^ {2}(name|category|difficulty|key):\s*(.*)$/);
    if (m && cur) cur[m[1]] = m[1] === "difficulty" ? Number(m[2]) : scalar(m[2]);
  }
  for (const c of out) {
    if (!c.key || !c.name || !c.category || !Number.isInteger(c.difficulty)) throw new Error(`challenges.yml: incomplete entry ${JSON.stringify(c)}`);
  }
  return out;
}

// Consecutive line numbers as inclusive [start, end] ranges.
export function runs(lines) {
  const s = [...new Set(lines)].sort((a, b) => a - b);
  const out = [];
  for (const n of s) {
    const last = out[out.length - 1];
    if (last && n === last[1] + 1) last[1] = n;
    else out.push([n, n]);
  }
  return out;
}

// Vulnerable lines per challenge from the snippet files under `src` (an unstripped module root):
// Map key -> [{ file, line }]. Vuln-lines outside a start/end block of their challenge are an error, like a
// block that is never closed.
export function collectVulnLines(src, paths = SNIPPET_PATHS, skip = []) {
  const files = paths.filter((p) => existsSync(join(src, p))).flatMap((p) => (lstatSync(join(src, p)).isDirectory() ? walk(join(src, p), src, skip, []) : [p]));
  const vuln = new Map();
  for (const file of [...new Set(files)].sort()) {
    if (skip.some((s) => file === s || file.startsWith(s + "/"))) continue;
    const buf = readFileSync(join(src, file));
    if (!isText(buf) || !buf.includes("vuln-code-snippet")) continue;
    const marks = parseMarkers(buf.toString("utf8"));
    const open = new Map();
    const blocks = [];
    for (const m of marks) {
      if (m.kind === "start") for (const k of m.keys) open.set(k, m.line);
      if (m.kind === "end") for (const k of m.keys) {
        if (!open.has(k)) throw new Error(`${file}:${m.line}: end of ${k} without a start`);
        blocks.push({ key: k, from: open.get(k), to: m.line });
        open.delete(k);
      }
    }
    if (open.size) throw new Error(`${file}: snippet of ${[...open.keys()].join(", ")} is never closed`);
    for (const m of marks.filter((x) => x.kind === "vuln-line")) {
      for (const k of m.keys) {
        if (!blocks.some((b) => b.key === k && b.from < m.line && m.line < b.to)) throw new Error(`${file}:${m.line}: vuln-line of ${k} outside its snippet`);
        if (!vuln.has(k)) vuln.set(k, []);
        vuln.get(k).push({ file, line: m.line });
      }
    }
  }
  return vuln;
}

// Groups of challenges whose vuln-lines share a file and line (transitively), each with its locations.
export function groupChallenges(vuln) {
  const keys = [...vuln.keys()].sort();
  const parent = new Map(keys.map((k) => [k, k]));
  const find = (k) => (parent.get(k) === k ? k : find(parent.get(k)));
  const owner = new Map();
  for (const k of keys) for (const { file, line } of vuln.get(k)) {
    const id = `${file}:${line}`;
    if (owner.has(id)) parent.set(find(k), find(owner.get(id)));
    else owner.set(id, k);
  }
  const groups = new Map();
  for (const k of keys) {
    const r = find(k);
    if (!groups.has(r)) groups.set(r, []);
    groups.get(r).push(k);
  }
  return [...groups.values()].map((members) => {
    const byFile = new Map();
    for (const k of members) for (const { file, line } of vuln.get(k)) {
      if (!byFile.has(file)) byFile.set(file, []);
      byFile.get(file).push(line);
    }
    const locations = [...byFile.keys()].sort().flatMap((file) => runs(byFile.get(file)).map((lines) => ({ file, lines })));
    return { challenges: members, locations };
  });
}

// The answer key for one release, in the format of benchmark/answer-key.json.
export function buildKey({ src, version, skip = [] }) {
  const ymlPath = join(src, "data", "static", "challenges.yml");
  if (!existsSync(ymlPath)) throw new Error(`no data/static/challenges.yml under ${src}`);
  const meta = new Map(parseChallenges(readFileSync(ymlPath, "utf8")).map((c) => [c.key, c]));
  const vuln = collectVulnLines(src, SNIPPET_PATHS, skip);
  const missing = [...vuln.keys()].filter((k) => !meta.has(k));
  if (missing.length) throw new Error(`challenges with vuln-lines but not in challenges.yml: ${missing.join(", ")}`);
  const groups = groupChallenges(vuln).sort((a, b) => a.challenges[0].localeCompare(b.challenges[0]));
  const seeded = groups.map((g) => {
    const cs = g.challenges.map((k) => meta.get(k));
    const categories = [...new Set(cs.map((c) => c.category))];
    return {
      id: g.challenges.join("+"),
      class: cs.map((c) => `${c.category}: ${c.name}`).join("; "),
      challenges: g.challenges,
      category: categories.join(", "),
      difficulty: Math.max(...cs.map((c) => c.difficulty)),
      locations: g.locations,
      detect: "llm",
      why: `Juice Shop coding challenge${cs.length > 1 ? "s" : ""} ${cs.map((c) => `${c.key} ("${c.name}", ${c.category}, difficulty ${c.difficulty})`).join(", ")}. The locations are the lines the release marks vuln-line for ${cs.length > 1 ? "these challenges" : "it"}${cs.length > 1 ? "; they share a line, so they are one entry" : ""}.`,
    };
  });
  return {
    version: 2,
    app: `real/${MODULE}-${version}`,
    module: MODULE,
    module_version: version,
    note: `Ground truth for OWASP Juice Shop ${version}, generated by benchmark/real/juice-key.mjs from the release's own coding-challenge markers (vuln-line comments) and data/static/challenges.yml; do not edit by hand, regenerate. Never copy this file into the audited directory. One entry per group of challenges whose vulnerable lines overlap; locations are files relative to the release root (the run's app/) with 1-based inclusive line ranges. fetch.mjs blanks the marker comments in app/ without removing lines, so these numbers hold there. Juice Shop has no severities: difficulty (1 to 6) is the game's own rating, not a risk score. Only challenges with a coding challenge are keyed (${groups.reduce((n, g) => n + g.challenges.length, 0)} of ${meta.size}); the others have no marked line and are not scored, so findings about them are unmatched, not false positives. Same format and matching rules as benchmark/answer-key.json.`,
    window: 2,
    seeded,
    decoys: [],
    known_extras: [],
  };
}

const sha256 = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");

// Extracts a pinned release into a temporary directory and returns { src, cleanup }.
export async function extractPinned(tarball, version, root = here) {
  const { extractArchive, loadManifest, moduleRootOf } = await import("./fetch.mjs");
  const manifest = loadManifest(MODULE, root);
  const v = manifest.versions?.[version];
  if (!v) throw new Error(`${MODULE} has no pinned version "${version}"`);
  if (sha256(tarball) !== v.sha256) throw new Error(`sha256 mismatch for ${MODULE} ${version}`);
  const tmp = mkdtempSync(join(tmpdir(), "juice-key-"));
  const staging = join(tmp, "x");
  mkdirSync(staging);
  const type = v.archive ?? manifest.archive ?? "tar.gz";
  extractArchive(resolve(tarball), type, staging, { root: v.root, exclude: v.exclude ?? manifest.exclude ?? [] });
  return { src: moduleRootOf(staging, type, v.root), skip: v.withhold ?? manifest.withhold ?? [], cleanup: () => rmSync(tmp, { recursive: true, force: true }) };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const opt = (name) => (args.indexOf(name) >= 0 ? args[args.indexOf(name) + 1] : undefined);
  const version = opt("--version");
  try {
    if (!version || (!opt("--tarball") && !opt("--src"))) throw new Error("usage: node benchmark/real/juice-key.mjs (--tarball FILE | --src DIR) --version V [--out FILE]");
    let src = opt("--src") && resolve(opt("--src"));
    let cleanup = () => {};
    // Withheld paths hold no markers that count (codefixes are the answers, not the app); skip them like the run does.
    let skip = ["data/static/codefixes"];
    if (opt("--tarball")) ({ src, skip, cleanup } = await extractPinned(opt("--tarball"), version));
    try {
      const key = buildKey({ src, version, skip });
      const out = resolve(opt("--out") ?? join(here, MODULE, `answer-key-${version}.json`));
      writeFileSync(out, JSON.stringify(key, null, 2) + "\n");
      const n = key.seeded.reduce((s, e) => s + e.challenges.length, 0);
      console.log(`${out}\n  ${key.seeded.length} entries (${n} challenges with vuln-lines), ${key.seeded.reduce((s, e) => s + e.locations.length, 0)} locations`);
    } finally {
      cleanup();
    }
  } catch (e) {
    console.error(`juice-key.mjs: ${e.message}`);
    process.exit(1);
  }
}
