#!/usr/bin/env node
// Prepares a run directory for a real-advisory benchmark (roadmap R30, R31): a public open-source module
// pinned to one release, fetched by this script and never vendored in the repo.
//   node benchmark/real/fetch.mjs <module> <version> [--dest DIR] [--tarball FILE] [--check]
// <module> is a directory under this script with a manifest.json (release URL and sha256 per version) and one
// answer key per version: either a bare name (`miniorange_saml`) or `<ecosystem>/<package>` (`npm/fast-jwt`).
// The archive is downloaded (or copied from --tarball FILE, or from the file in $REAL_TARBALL, for offline
// runs and tests), checked against the pinned sha256, and extracted so the module root is DIR/app. Archive
// types (manifest `archive`, per version or for the whole manifest; default tar.gz): `tar.gz`, `zip`
// (WordPress plugins, Go module proxy) and `gem` (a plain tar holding data.tar.gz). Every entry is listed
// before extraction and the archive is refused if any entry is absolute, has a `..` segment or is a link;
// the extracted tree is checked for symlinks again. The module root is the version's `root` (a relative path
// inside the archive, e.g. `goshs.de/goshs/v2@v2.1.4` for a Go proxy zip), else the single top directory of a
// tar.gz or zip, else the archive root (always for a gem). Agent instruction files shipped in the release
// (`.claude/`, `CLAUDE.md`, `CLAUDE.local.md`, `.mcp.json`) are removed from app/ and listed in meta.json: they
// would steer the audit, and project settings can run hooks. DIR/app gets one git commit with a fixed date,
// like benchmark/setup.mjs; meta.json and the archive stay in DIR, outside what the audit sees. meta.json
// records the answer key's absolute path, which benchmark/score.mjs reads.
// Default DIR: $TMPDIR/real-<module with / as .>-<version>-<timestamp>.
//
// --check validates the answer key against the extracted tree: every location is a real file, every range
// sits inside it and is not blank, ids are unique and ranges in one file do not overlap. With --dest pointing
// at an existing run it checks that run; otherwise it fetches first. It also checks that the values of the
// constants listed in the manifest's `secret_constants` appear nowhere in benchmark/real/ (the value is
// compared, never printed). Exit code 1 on any problem.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

export const sha256File = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");

// `name` or `ecosystem/package`; the package part may hold `.` and `-` but never starts with them (no `..`).
export const MODULE_ID = /^[a-z0-9_]+(\/[a-z0-9_][a-z0-9_.-]*)?$/;
export const ARCHIVES = ["tar.gz", "zip", "gem"];
// Agent instruction and settings files that never reach app/.
export const AGENT_FILES = new Set([".claude", "CLAUDE.md", "CLAUDE.local.md", ".mcp.json"]);
// A module id as one path segment, for e-mail addresses and directory names.
export const moduleSlug = (module) => module.replace(/\//g, ".");

export function loadManifest(module, root = here) {
  if (!MODULE_ID.test(module ?? "")) throw new Error(`invalid module name "${module}"`);
  const path = join(root, module, "manifest.json");
  if (!existsSync(path)) throw new Error(`no manifest for "${module}" in ${root}`);
  return JSON.parse(readFileSync(path, "utf8"));
}

export function keyPath(module, version, root = here) {
  const v = loadManifest(module, root).versions?.[version];
  if (!v) throw new Error(`${module} has no pinned version "${version}"`);
  return join(root, module, v.key);
}

// Problems with an answer key against an extracted tree, as strings; [] when it is valid.
export function checkKey(key, appDir) {
  const errors = [];
  const all = [...(key.seeded ?? []), ...(key.decoys ?? []), ...(key.known_extras ?? [])];
  const ids = all.map((e) => e.id);
  for (const id of new Set(ids.filter((id, i) => ids.indexOf(id) !== i))) errors.push(`duplicate id ${id}`);
  const cache = new Map();
  const linesOf = (file) => {
    if (!cache.has(file)) {
      const p = resolve(appDir, file);
      cache.set(file, !relative(appDir, p).startsWith("..") && existsSync(p) ? readFileSync(p, "utf8").split("\n") : null);
    }
    return cache.get(file);
  };
  for (const e of all) {
    if (!e.locations?.length) { errors.push(`${e.id}: no locations`); continue; }
    for (const l of e.locations) {
      const [a, b] = l.lines ?? [];
      if (!Number.isInteger(a) || !Number.isInteger(b) || a < 1 || a > b) { errors.push(`${e.id}: ${l.file} bad range ${JSON.stringify(l.lines)}`); continue; }
      const lines = linesOf(l.file);
      if (!lines) { errors.push(`${e.id}: ${l.file} does not exist`); continue; }
      if (b > lines.length) { errors.push(`${e.id}: ${l.file}:${b} is past the end (${lines.length} lines)`); continue; }
      if (!lines.slice(a - 1, b).some((s) => s.trim())) errors.push(`${e.id}: ${l.file}:${a}-${b} is blank`);
    }
  }
  const flat = all.flatMap((e) => (e.locations ?? []).map((l) => ({ id: e.id, ...l })));
  for (let i = 0; i < flat.length; i++) for (let j = i + 1; j < flat.length; j++) {
    const [x, y] = [flat[i], flat[j]];
    if (x.file !== y.file || !Array.isArray(x.lines) || !Array.isArray(y.lines)) continue;
    if (!(x.lines[1] < y.lines[0] || y.lines[1] < x.lines[0])) errors.push(`${x.id} and ${y.id} overlap in ${x.file}`);
  }
  return errors;
}

// Files under `dir` (recursively) that contain any of `values`. Only names are returned.
export function filesContaining(dir, values) {
  const hits = [];
  const walk = (d) => {
    for (const ent of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, ent.name);
      if (ent.isDirectory()) walk(p);
      else if (ent.isFile() && values.some((v) => readFileSync(p, "utf8").includes(v))) hits.push(p);
    }
  };
  walk(dir);
  return hits;
}

// The string value of `const NAME = "..."` (or '...') in a PHP file, or null.
export function constantValue(file, name) {
  const m = existsSync(file) && readFileSync(file, "utf8").match(new RegExp(String.raw`const\s+${name}\s*=\s*(["'])(.*?)\1`));
  return m ? m[2] : null;
}

function noSymlinks(dir) {
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, ent.name);
    if (lstatSync(p).isSymbolicLink()) throw new Error(`refusing a symlink in the release: ${p}`);
    if (ent.isDirectory()) noSymlinks(p);
  }
}

// Why an archive entry name is unsafe, or null: absolute paths, drive letters and `..` segments.
export function unsafeEntryName(name) {
  if (!name) return "empty name";
  if (/^[/\\]/.test(name) || /^[A-Za-z]:/.test(name)) return "absolute path";
  if (name.split(/[/\\]/).includes("..")) return "`..` segment";
  return null;
}

// Entries of a zip archive from its central directory: { name, link }. Only what the safety check needs.
export function zipEntries(buf) {
  const min = Math.max(0, buf.length - 0xffff - 22);
  let eocd = -1;
  for (let i = buf.length - 22; i >= min; i--) if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw new Error("not a zip archive (no end of central directory)");
  let count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  if (count === 0xffff || off === 0xffffffff) {
    const loc = eocd - 20;
    if (loc < 0 || buf.readUInt32LE(loc) !== 0x07064b50) throw new Error("zip64 archive without a zip64 locator");
    const z = Number(buf.readBigUInt64LE(loc + 8));
    if (buf.readUInt32LE(z) !== 0x06064b50) throw new Error("bad zip64 end of central directory");
    count = Number(buf.readBigUInt64LE(z + 32));
    off = Number(buf.readBigUInt64LE(z + 48));
  }
  const out = [];
  for (let n = 0; n < count; n++) {
    if (off + 46 > buf.length || buf.readUInt32LE(off) !== 0x02014b50) throw new Error("corrupt zip central directory");
    const madeBy = buf.readUInt16LE(off + 4) >> 8;
    const nameLen = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const commentLen = buf.readUInt16LE(off + 32);
    const mode = buf.readUInt32LE(off + 38) >>> 16;
    const name = buf.toString("utf8", off + 46, off + 46 + nameLen);
    // Unix (3) and macOS (19) hosts keep the file mode in the upper half of the external attributes.
    out.push({ name, link: (madeBy === 3 || madeBy === 19) && (mode & 0o170000) === 0o120000 });
    off += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

// Entries of a tar archive (gzip or plain) as listed by GNU `tar -tv`: { name, link }. With
// --quoting-style=literal the name is everything after the time column, minus a link target.
function tarEntries(archive, gzip) {
  const out = execFileSync("tar", [gzip ? "-tvzf" : "-tvf", archive, "--quoting-style=literal", "--numeric-owner"], { encoding: "utf8", maxBuffer: 256 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] });
  return out.split("\n").filter(Boolean).map((line) => {
    const m = line.match(/^(\S)\S*\s+\S+\s+\S+\s+\S+\s+\S+\s(.*)$/);
    if (!m) throw new Error(`cannot read tar listing line: ${line}`);
    // Anything but a regular file or a directory (symlink, hard link, device, fifo) is refused as a link.
    const link = m[1] !== "-" && m[1] !== "d";
    return { name: m[1] === "l" || m[1] === "h" ? m[2].replace(/ (->|link to) .*$/, "") : m[2], link };
  });
}

function refuseEntries(entries, label) {
  for (const e of entries) {
    const why = unsafeEntryName(e.name);
    if (why) throw new Error(`refusing ${label}: entry "${e.name}" (${why})`);
    if (e.link) throw new Error(`refusing ${label}: entry "${e.name}" is a link or special file`);
  }
}

// Extracts `archive` of `type` into the empty directory `staging`, refusing unsafe entries first.
export function extractArchive(archive, type, staging) {
  if (!ARCHIVES.includes(type)) throw new Error(`unknown archive type "${type}" (use ${ARCHIVES.join(", ")})`);
  const tarOpts = ["-C", staging, "--no-same-owner", "--no-same-permissions"];
  if (type === "tar.gz") {
    refuseEntries(tarEntries(archive, true), "the release");
    execFileSync("tar", ["-xzf", archive, ...tarOpts], { stdio: "pipe" });
  } else if (type === "zip") {
    refuseEntries(zipEntries(readFileSync(archive)), "the release");
    execFileSync("unzip", ["-q", archive, "-d", staging], { stdio: "pipe" });
  } else {
    const outer = tarEntries(archive, false);
    refuseEntries(outer, "the gem");
    if (!outer.some((e) => e.name === "data.tar.gz")) throw new Error("not a gem: no data.tar.gz inside");
    const data = join(dirname(staging), ".gem-data.tar.gz");
    writeFileSync(data, execFileSync("tar", ["-xOf", archive, "data.tar.gz"], { maxBuffer: 1024 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] }));
    try {
      refuseEntries(tarEntries(data, true), "the gem's data.tar.gz");
      execFileSync("tar", ["-xzf", data, ...tarOpts], { stdio: "pipe" });
    } finally {
      rmSync(data, { force: true });
    }
  }
  noSymlinks(staging);
}

// The module root inside `staging`: the explicit `root`, else the single top directory (not for gems).
export function moduleRootOf(staging, type, root) {
  if (root != null) {
    if (typeof root !== "string" || unsafeEntryName(root === "." ? "x" : root)) throw new Error(`invalid root "${root}"`);
    const p = resolve(staging, root);
    if (relative(staging, p).startsWith("..") || !existsSync(p) || !lstatSync(p).isDirectory()) throw new Error(`root "${root}" is not a directory in the release`);
    return p;
  }
  if (type === "gem") return staging;
  const top = readdirSync(staging);
  return top.length === 1 && lstatSync(join(staging, top[0])).isDirectory() ? join(staging, top[0]) : staging;
}

// Removes agent instruction files anywhere under `dir`; returns their paths relative to `dir`.
export function stripAgentFiles(dir, base = dir) {
  const removed = [];
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, ent.name);
    if (AGENT_FILES.has(ent.name)) {
      rmSync(p, { recursive: true, force: true });
      removed.push(relative(base, p));
    } else if (ent.isDirectory()) removed.push(...stripAgentFiles(p, base));
  }
  return removed.sort();
}

export async function fetchRun({ module, version, dest, tarball, root = here, now = new Date() }) {
  const manifest = loadManifest(module, root);
  const v = manifest.versions?.[version];
  if (!v) throw new Error(`${module} has no pinned version "${version}" (pinned: ${Object.keys(manifest.versions ?? {}).join(", ")})`);
  const stamp = now.toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const runDir = resolve(dest ?? join(tmpdir(), `real-${moduleSlug(module)}-${version}-${stamp}`));
  const app = join(runDir, "app");
  if (existsSync(app)) throw new Error(`${app} already exists: pick an empty --dest`);
  mkdirSync(runDir, { recursive: true });

  const archive = join(runDir, basename(new URL(v.url).pathname));
  if (tarball) copyFileSync(resolve(tarball), archive);
  else {
    const res = await fetch(v.url, { redirect: "follow" });
    if (!res.ok) throw new Error(`download failed: ${v.url} -> HTTP ${res.status}`);
    writeFileSync(archive, Buffer.from(await res.arrayBuffer()));
  }
  const got = sha256File(archive);
  if (got !== v.sha256) {
    rmSync(archive);
    throw new Error(`sha256 mismatch for ${module} ${version}: expected ${v.sha256}, got ${got}`);
  }

  const type = v.archive ?? manifest.archive ?? "tar.gz";
  const staging = join(runDir, ".extract");
  rmSync(staging, { recursive: true, force: true });
  mkdirSync(staging);
  try {
    extractArchive(archive, type, staging);
    renameSync(moduleRootOf(staging, type, v.root), app);
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
  const stripped = stripAgentFiles(app);

  const date = `${v.released ?? "2026-01-01"}T12:00:00+00:00`;
  const git = (argv) =>
    execFileSync("git", ["-c", "user.name=App Dev", "-c", `user.email=dev@${moduleSlug(module)}.invalid`, "-c", "commit.gpgsign=false", ...argv], {
      cwd: app,
      stdio: "pipe",
      env: { ...process.env, GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date },
    });
  git(["init", "-q", "-b", "main"]);
  git(["add", "-A"]);
  git(["commit", "-q", "-m", "feat: initial version"]);

  let skillSha = "";
  let skillDirty = false;
  try {
    skillSha = execFileSync("git", ["-C", here, "rev-parse", "--short", "HEAD"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    skillDirty = execFileSync("git", ["-C", here, "status", "--porcelain"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim().length > 0;
  } catch {}
  const meta = {
    started_at: now.toISOString(),
    skill_sha: skillSha,
    skill_dirty: skillDirty,
    app,
    bench_app: `real/${module}-${version}`,
    key: join(root, module, v.key),
    source: { url: v.url, sha256: v.sha256, tarball: basename(archive), archive: type, ...(v.root != null ? { root: v.root } : {}) },
    stripped,
  };
  writeFileSync(join(runDir, "meta.json"), JSON.stringify(meta, null, 2) + "\n");
  return { runDir, app, meta };
}

// Runs every check for one version; returns { errors, notes }.
export function checkRun({ module, version, runDir, root = here }) {
  const manifest = loadManifest(module, root);
  const app = join(runDir, "app");
  const errors = [];
  const notes = [];
  const key = JSON.parse(readFileSync(keyPath(module, version, root), "utf8"));
  if (key.module_version && key.module_version !== version) errors.push(`key is for version ${key.module_version}, not ${version}`);
  const metaPath = join(runDir, "meta.json");
  if (existsSync(metaPath)) {
    const meta = JSON.parse(readFileSync(metaPath, "utf8"));
    if (meta.source?.sha256 && meta.source.sha256 !== manifest.versions[version].sha256) errors.push("run was fetched from a different tarball");
  }
  errors.push(...checkKey(key, app));
  const n = (k) => (key[k] ?? []).length;
  notes.push(`${n("seeded")} seeded, ${n("decoys")} decoys, ${n("known_extras")} known extras, ${[...(key.seeded ?? []), ...(key.decoys ?? []), ...(key.known_extras ?? [])].reduce((s, e) => s + (e.locations?.length ?? 0), 0)} locations`);
  for (const c of manifest.secret_constants ?? []) {
    const value = constantValue(join(app, c.file), c.name);
    if (value == null) { notes.push(`${c.name}: not defined in this version`); continue; }
    const hits = filesContaining(root, [value]);
    if (hits.length) errors.push(`${c.name} value appears in ${hits.map((h) => relative(root, h)).join(", ")}`);
    else notes.push(`${c.name}: value absent from benchmark/real/`);
  }
  return { errors, notes };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const opt = (name) => (args.indexOf(name) >= 0 ? args[args.indexOf(name) + 1] : undefined);
  const [module, version] = args.filter((a, i) => !a.startsWith("--") && !["--dest", "--tarball", "--root"].includes(args[i - 1]));
  const root = opt("--root") ? resolve(opt("--root")) : here;
  const dest = opt("--dest");
  if (!module || !version) {
    console.error("usage: node benchmark/real/fetch.mjs <module> <version> [--dest DIR] [--tarball FILE] [--check]");
    process.exit(2);
  }
  try {
    let runDir = dest ? resolve(dest) : null;
    if (!(args.includes("--check") && runDir && existsSync(join(runDir, "app")))) {
      const r = await fetchRun({ module, version, dest, tarball: opt("--tarball") ?? process.env.REAL_TARBALL, root });
      runDir = r.runDir;
      console.log(`Real-advisory run ready: ${runDir}
  ${module} ${version}, sha256 ${r.meta.source.sha256} verified${r.meta.stripped.length ? `
  removed agent instruction files from app/: ${r.meta.stripped.join(", ")}` : ""}
  key: ${r.meta.key} (outside the run; never copy it into app/)

1. Audit it (fresh session, skill installed):
     cd ${r.app} && CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=0 claude -p "/security-audit" --permission-mode auto --output-format json
2. Score it (the key comes from meta.json):
     node ${join(here, "..", "score.mjs")} ${runDir} --label "<what changed>"`);
    }
    if (args.includes("--check")) {
      const { errors, notes } = checkRun({ module, version, runDir, root });
      for (const n of notes) console.log(`check: ${n}`);
      if (errors.length) {
        for (const e of errors) console.error(`check FAILED: ${e}`);
        process.exit(1);
      }
      console.log(`check OK: ${module} ${version} key matches ${join(runDir, "app")}`);
    }
  } catch (e) {
    console.error(`fetch.mjs: ${e.message}`);
    process.exit(1);
  }
}
