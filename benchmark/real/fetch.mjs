#!/usr/bin/env node
// Prepares a run directory for a real-advisory benchmark (roadmap R30): a public open-source module pinned
// to one release, fetched by this script and never vendored in the repo.
//   node benchmark/real/fetch.mjs <module> <version> [--dest DIR] [--tarball FILE] [--check]
// <module> is a directory next to this script with a manifest.json (release URL and sha256 per version) and
// one answer key per version. The tarball is downloaded (or copied from --tarball FILE, or from the file in
// $REAL_TARBALL, for offline runs and tests), checked against the pinned sha256, and extracted so the module
// root is DIR/app. DIR/app gets one git commit with a fixed date, like benchmark/setup.mjs; meta.json and the
// tarball stay in DIR, outside what the audit sees. meta.json records the answer key's absolute path, which
// benchmark/score.mjs reads. Default DIR: $TMPDIR/real-<module>-<version>-<timestamp>.
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

export function loadManifest(module, root = here) {
  if (!/^[a-z0-9_]+$/.test(module ?? "")) throw new Error(`invalid module name "${module}"`);
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

export async function fetchRun({ module, version, dest, tarball, root = here, now = new Date() }) {
  const manifest = loadManifest(module, root);
  const v = manifest.versions?.[version];
  if (!v) throw new Error(`${module} has no pinned version "${version}" (pinned: ${Object.keys(manifest.versions ?? {}).join(", ")})`);
  const stamp = now.toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const runDir = resolve(dest ?? join(tmpdir(), `real-${module}-${version}-${stamp}`));
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

  const staging = join(runDir, ".extract");
  rmSync(staging, { recursive: true, force: true });
  mkdirSync(staging);
  execFileSync("tar", ["-xzf", archive, "-C", staging, "--no-same-owner", "--no-same-permissions"], { stdio: "pipe" });
  noSymlinks(staging);
  const top = readdirSync(staging);
  const moduleRoot = top.length === 1 && lstatSync(join(staging, top[0])).isDirectory() ? join(staging, top[0]) : staging;
  renameSync(moduleRoot, app);
  rmSync(staging, { recursive: true, force: true });

  const date = `${v.released ?? "2026-01-01"}T12:00:00+00:00`;
  const git = (argv) =>
    execFileSync("git", ["-c", "user.name=App Dev", "-c", `user.email=dev@${module}.invalid`, "-c", "commit.gpgsign=false", ...argv], {
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
    source: { url: v.url, sha256: v.sha256, tarball: basename(archive) },
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
  ${module} ${version}, sha256 ${r.meta.source.sha256} verified
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
