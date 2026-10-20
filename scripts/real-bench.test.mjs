// Run: node --test scripts/*.test.mjs
// Real-advisory benchmarks (roadmap R30, R31): fetch.mjs and the answer keys under benchmark/real/. The real
// releases are not in the repo, so the line check against them runs in `fetch.mjs --check`; here the keys get
// a schema check and fetch.mjs runs end to end on synthetic tar.gz, zip and gem releases, with no network.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, linkSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { crc32 } from "node:zlib";
import { checkKey, MODULE_ID, unsafeEntryName, zipEntries } from "../benchmark/real/fetch.mjs";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
const real = join(repo, "benchmark", "real");
const fetchScript = join(real, "fetch.mjs");
// Module ids: `name` (a directory with a manifest) or `ecosystem/package` one level down.
const hasManifest = (rel) => existsSync(join(real, rel, "manifest.json"));
const dirs = (rel) => readdirSync(join(real, rel), { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name);
const modules = dirs("").flatMap((d) => (hasManifest(d) ? [d] : dirs(d).filter((p) => hasManifest(`${d}/${p}`)).map((p) => `${d}/${p}`)));
const ECOSYSTEMS = ["drupal", "wordpress", "npm", "pypi", "rubygems", "go"];
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
// The id a key's seeded entry uses for an advisory: SA-YYYY-NNN for drupal.org, else the advisory id.
const keyId = (a) => (a.sa ? a.sa.replace("CONTRIB-", "") : a.id);

test("real benchmarks: module ids, one per ecosystem directory, and the week-1 batch is there", () => {
  for (const m of ["miniorange_saml", "drupal/rest_api_authentication", "wordpress/flamingo", "npm/fast-jwt", "go/goshs"]) assert.ok(modules.includes(m), m);
  for (const m of modules) {
    assert.match(m, MODULE_ID, `${m} is a valid module id`);
    if (m.includes("/")) assert.ok(ECOSYSTEMS.includes(m.split("/")[0]), `${m} sits under a known ecosystem`);
  }
  for (const bad of ["npm/..", "npm/.hidden", "a/b/c", "NPM/x", "npm/@scope", "../x", ""]) assert.doesNotMatch(bad, MODULE_ID, bad);
});

test("real benchmarks: manifests pin a sha256 per version and every advisory has a public link", () => {
  for (const m of modules) {
    const man = JSON.parse(readFileSync(join(real, m, "manifest.json"), "utf8"));
    if (m.includes("/")) assert.equal(man.ecosystem, m.split("/")[0], `${m} ecosystem`);
    else assert.equal(man.project, m);
    assert.equal(typeof man.project, "string");
    for (const [v, x] of Object.entries(man.versions)) {
      assert.match(x.sha256, /^[0-9a-f]{64}$/, `${m} ${v} sha256`);
      assert.match(x.url, /^https:\/\//, `${m} ${v} url`);
      assert.ok(!x.url.includes("/archive/refs/"), `${m} ${v}: GitHub archive tarballs are not byte-stable`);
      assert.ok(["tar.gz", "zip", "gem"].includes(x.archive ?? man.archive ?? "tar.gz"), `${m} ${v} archive type`);
      if (x.root != null) assert.equal(unsafeEntryName(x.root), null, `${m} ${v} root is relative`);
      assert.match(x.released, /^\d{4}-\d{2}-\d{2}$/, `${m} ${v} released`);
      assert.ok(existsSync(join(real, m, x.key)), `${m} ${v} key file ${x.key}`);
    }
    assert.ok(man.advisories.length, `${m} has advisories`);
    for (const a of man.advisories) {
      if (a.sa) {
        assert.match(a.sa, /^SA-CONTRIB-\d{4}-\d{3}$/);
        assert.equal(a.url, `https://www.drupal.org/${a.sa.toLowerCase()}`);
      } else if (a.id.startsWith("GHSA-")) {
        assert.match(a.id, /^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$/);
        assert.ok(a.url.startsWith("https://github.com/") && a.url.endsWith(a.id), `${a.id} url`);
      } else {
        assert.match(a.id, /^CVE-\d{4}-\d{4,}$/);
        assert.ok(a.url.startsWith("https://") && a.url.includes(a.id), `${a.id} url`);
      }
      if (a.cve) assert.match(a.cve, /^CVE-\d{4}-\d{4,}$/);
      assert.equal(typeof a.fixed_in, "string", `${keyId(a)} fixed_in`);
    }
  }
});

test("real benchmarks: answer keys follow the benchmark key format", () => {
  for (const m of modules) {
    const man = JSON.parse(readFileSync(join(real, m, "manifest.json"), "utf8"));
    const sas = new Set(man.advisories.map(keyId));
    for (const [v, x] of Object.entries(man.versions)) {
      const key = JSON.parse(readFileSync(join(real, m, x.key), "utf8"));
      assert.equal(key.app, `real/${m}-${v}`);
      assert.equal(key.module_version, v);
      for (const k of ["seeded", "decoys", "known_extras"]) assert.ok(Array.isArray(key[k]), `${x.key} ${k}`);
      const all = [...key.seeded, ...key.decoys, ...key.known_extras];
      assert.equal(new Set(all.map((e) => e.id)).size, all.length, `${x.key} unique ids`);
      for (const e of key.seeded) {
        assert.ok(sas.has(e.id), `${e.id} is an advisory in the manifest`);
        assert.ok(SEVERITIES.includes(e.severity), `${e.id} severity`);
        for (const f of ["class", "detect", "why", "advisory_url"]) assert.equal(typeof e[f], "string", `${e.id} ${f}`);
      }
      for (const e of [...key.decoys, ...key.known_extras]) assert.equal(typeof e.why, "string", `${e.id} why`);
      for (const e of all) {
        assert.ok(!("keywords" in e) && !("files" in e), `${e.id} has no keyword matching fields`);
        assert.ok(e.locations.length, `${e.id} locations`);
        for (const l of e.locations) {
          assert.equal(typeof l.file, "string");
          assert.ok(!l.file.startsWith("/") && !l.file.includes(".."), `${e.id} ${l.file} is relative to app/`);
          const [a, b] = l.lines;
          assert.ok(Number.isInteger(a) && Number.isInteger(b) && a >= 1 && a <= b, `${e.id} ${l.file} range`);
        }
      }
      const overlaps = checkKey(key, "/nonexistent").filter((s) => / overlap in /.test(s));
      assert.deepEqual(overlaps, [], `${x.key} ranges do not overlap`);
    }
    // Every advisory in the manifest is scored on some vulnerable release, or a key says why it is not.
    const keys = Object.values(man.versions).map((x) => readFileSync(join(real, m, x.key), "utf8"));
    const seededIds = new Set(keys.flatMap((k) => JSON.parse(k).seeded.map((e) => e.id)));
    for (const a of man.advisories) assert.ok(seededIds.has(keyId(a)) || keys.some((k) => k.includes(a.sa ?? a.id)), `${m}: advisory ${keyId(a)} has a key entry`);
    // Defensive wording: the keys describe class, location and impact, never steps or payloads.
    const text = readdirSync(join(real, m)).map((f) => readFileSync(join(real, m, f), "utf8")).join("\n");
    assert.doesNotMatch(text, /<script|alert\(|curl |payload:|step \d|proof of concept|\bpoc\b|\?_format=json|exploit/i);
  }
});

test("real benchmarks: no credential-shaped literal is copied into the repo", () => {
  const files = [];
  const walk = (d) => readdirSync(d, { withFileTypes: true }).forEach((e) => (e.isDirectory() ? walk(join(d, e.name)) : files.push(join(d, e.name))));
  walk(real);
  // A mixed-case 32+ character token is what the vendor key in SA-CONTRIB-2026-148 looks like; sha256 sums
  // are lower-case hex and do not match.
  const tokenish = /(?<![A-Za-z0-9])(?=[A-Za-z0-9]*[a-z])(?=[A-Za-z0-9]*[A-Z])(?=[A-Za-z0-9]*\d)[A-Za-z0-9]{24,}(?![A-Za-z0-9])/;
  for (const f of files) assert.doesNotMatch(readFileSync(f, "utf8"), tokenish, `${f} holds no token-like literal`);
  const man = JSON.parse(readFileSync(join(real, "miniorange_saml", "manifest.json"), "utf8"));
  assert.deepEqual(man.secret_constants.map((c) => c.name), ["DEFAULT_API_KEY"], "fetch.mjs --check guards the vendor key by name");
  const rest = JSON.parse(readFileSync(join(real, "drupal", "rest_api_authentication", "manifest.json"), "utf8"));
  assert.deepEqual(rest.secret_constants.map((c) => c.name), ["FALLBACK_API_KEY"], "and the fallback vendor key of rest_api_authentication");
});

// A synthetic release: a tarball with one top directory, like drupal.org's, and a manifest pinning it.
// The constant value is generated per run, so the repo holds no secret-shaped literal.
const randomToken = () => "Tk9" + randomBytes(24).toString("base64url").replace(/[-_]/g, "x").slice(0, 29);
function fixture({ secret = randomToken() } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "sa-real-"));
  const src = join(dir, "src", "demo_mod");
  mkdirSync(join(src, "src"), { recursive: true });
  writeFileSync(join(src, "demo_mod.info.yml"), "name: Demo\ntype: module\ncore_version_requirement: ^10\n");
  writeFileSync(join(src, "src", "Demo.php"), `<?php\n\nclass Demo {\n  const API_KEY = "${secret}";\n\n  public function run() {\n    return 1;\n  }\n}\n`);
  const tgz = join(dir, "demo_mod-1.0.0.tar.gz");
  execFileSync("tar", ["-czf", tgz, "-C", join(dir, "src"), "demo_mod"]);
  const sha = createHash("sha256").update(readFileSync(tgz)).digest("hex");
  const root = join(dir, "root");
  mkdirSync(join(root, "demo_mod"), { recursive: true });
  const manifest = {
    project: "demo_mod",
    secret_constants: [{ file: "src/Demo.php", name: "API_KEY" }],
    versions: { "1.0.0": { url: "https://example.com/demo_mod-1.0.0.tar.gz", sha256: sha, released: "2026-03-04", key: "answer-key-1.0.0.json" } },
    advisories: [],
  };
  writeFileSync(join(root, "demo_mod", "manifest.json"), JSON.stringify(manifest));
  const key = { app: "real/demo_mod-1.0.0", module_version: "1.0.0", seeded: [{ id: "SA-1", locations: [{ file: "src/Demo.php", lines: [4, 4] }] }], decoys: [{ id: "D1", locations: [{ file: "src/Demo.php", lines: [6, 8] }] }], known_extras: [] };
  writeFileSync(join(root, "demo_mod", "answer-key-1.0.0.json"), JSON.stringify(key));
  return { dir, tgz, root, manifest, key, secret };
}
const runFetch = (root, ...args) => spawnSync(process.execPath, [fetchScript, "demo_mod", "1.0.0", "--root", root, ...args], { encoding: "utf8", env: { ...process.env, REAL_TARBALL: "" } });

test("fetch.mjs: verified tarball, module root at app/, one dated commit, meta.json with the key", () => {
  const fx = fixture();
  const dest = join(fx.dir, "run");
  const r = runFetch(fx.root, "--dest", dest, "--tarball", fx.tgz, "--check");
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /sha256 [0-9a-f]{64} verified/);
  assert.match(r.stdout, /check OK/);
  assert.match(r.stdout, /API_KEY: value absent/);
  assert.match(r.stdout, /claude -p "\/security-audit" --permission-mode auto --output-format json/);
  assert.ok(existsSync(join(dest, "app", "demo_mod.info.yml")), "module root is app/");
  assert.ok(!existsSync(join(dest, "app", "demo_mod")), "no extra top directory");
  assert.ok(!existsSync(join(dest, "app", "answer-key-1.0.0.json")), "the key never lands in app/");
  const log = execFileSync("git", ["-C", join(dest, "app"), "log", "--format=%ad|%s", "--date=iso-strict"], { encoding: "utf8" }).trim();
  assert.equal(log, "2026-03-04T12:00:00+00:00|feat: initial version");
  const meta = JSON.parse(readFileSync(join(dest, "meta.json"), "utf8"));
  assert.equal(meta.bench_app, "real/demo_mod-1.0.0");
  assert.equal(meta.key, join(fx.root, "demo_mod", "answer-key-1.0.0.json"));
  assert.equal(meta.app, join(dest, "app"));
  assert.equal(meta.source.sha256, fx.manifest.versions["1.0.0"].sha256);

  const again = runFetch(fx.root, "--dest", dest, "--check");
  assert.equal(again.status, 0, again.stderr);
  assert.doesNotMatch(again.stdout, /run ready/, "--check on an existing run does not fetch again");
  const clash = runFetch(fx.root, "--dest", dest, "--tarball", fx.tgz);
  assert.notEqual(clash.status, 0, "an existing app/ is never overwritten");
});

test("fetch.mjs: sha256 mismatch aborts before extracting", () => {
  const fx = fixture();
  const other = fixture();
  const dest = join(fx.dir, "run");
  const r = runFetch(fx.root, "--dest", dest, "--tarball", other.tgz);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /sha256 mismatch/);
  assert.ok(!existsSync(join(dest, "app")));
});

test("fetch.mjs --check: blank, out-of-file and overlapping ranges fail, and so does a leaked secret value", () => {
  const fx = fixture();
  const dest = join(fx.dir, "run");
  assert.equal(runFetch(fx.root, "--dest", dest, "--tarball", fx.tgz).status, 0);
  const keyFile = join(fx.root, "demo_mod", "answer-key-1.0.0.json");
  writeFileSync(keyFile, JSON.stringify({ ...fx.key, seeded: [{ id: "SA-1", locations: [{ file: "src/Demo.php", lines: [5, 5] }, { file: "src/Demo.php", lines: [40, 41] }, { file: "src/Missing.php", lines: [1, 1] }] }, { id: "SA-2", locations: [{ file: "src/Demo.php", lines: [7, 7] }] }] }));
  const bad = runFetch(fx.root, "--dest", dest, "--check");
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /SA-1: src\/Demo\.php:5-5 is blank/);
  assert.match(bad.stderr, /SA-1: src\/Demo\.php:41 is past the end/);
  assert.match(bad.stderr, /SA-1: src\/Missing\.php does not exist/);
  assert.match(bad.stderr, /D1 and SA-2 overlap|SA-2 and D1 overlap/);

  writeFileSync(keyFile, JSON.stringify({ ...fx.key, note: `the key was ${fx.secret}` }));
  const leak = runFetch(fx.root, "--dest", dest, "--check");
  assert.equal(leak.status, 1);
  assert.match(leak.stderr, /API_KEY value appears in demo_mod\/answer-key-1\.0\.0\.json/);
  assert.ok(!leak.stderr.includes(fx.secret) && !leak.stdout.includes(fx.secret), "the value is never printed");
});

// A stored (uncompressed) zip built in memory. `mode` is a Unix file mode kept in the external attributes,
// as Info-ZIP does, so 0o120777 marks a symlink whose target is the entry's data.
function makeZip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const { name, data = "", mode = 0o100644 } of entries) {
    const body = Buffer.from(data);
    const fname = Buffer.from(name);
    const crc = crc32(body);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(10, 4);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(body.length, 22);
    local.writeUInt16LE(fname.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE((3 << 8) | 20, 4);
    central.writeUInt16LE(10, 6);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(body.length, 20);
    central.writeUInt32LE(body.length, 24);
    central.writeUInt16LE(fname.length, 28);
    central.writeUInt32LE(((mode & 0xffff) << 16) >>> 0, 38);
    central.writeUInt32LE(offset, 42);
    locals.push(local, fname, body);
    centrals.push(central, fname);
    offset += local.length + fname.length + body.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

// A module under <root>/<id>/ pinning `file` as version 1.0.0, with a one-entry key on `keyFile`.
function pinModule(root, id, file, { archive, rootPath, keyFile = "src/main.js", lines = [1, 1] } = {}) {
  const dir = join(root, ...id.split("/"));
  mkdirSync(dir, { recursive: true });
  const sha = createHash("sha256").update(readFileSync(file)).digest("hex");
  const version = { url: `https://example.com/${id.split("/").pop()}-1.0.0.bin`, sha256: sha, released: "2026-05-06", key: "answer-key-1.0.0.json", ...(archive ? { archive } : {}), ...(rootPath ? { root: rootPath } : {}) };
  writeFileSync(join(dir, "manifest.json"), JSON.stringify({ project: id, versions: { "1.0.0": version }, advisories: [] }));
  writeFileSync(join(dir, "answer-key-1.0.0.json"), JSON.stringify({ app: `real/${id}-1.0.0`, module_version: "1.0.0", seeded: [{ id: "X-1", locations: [{ file: keyFile, lines }] }], decoys: [], known_extras: [] }));
}
const fetchModule = (root, id, file, dest) => spawnSync(process.execPath, [fetchScript, id, "1.0.0", "--root", root, "--tarball", file, "--dest", dest, "--check"], { encoding: "utf8", env: { ...process.env, REAL_TARBALL: "" } });

test("fetch.mjs: ecosystem/package ids, a zip release with an explicit root, agent files removed from app/", () => {
  const dir = mkdtempSync(join(tmpdir(), "sa-real-zip-"));
  const zip = join(dir, "v1.0.0.zip");
  const top = "example.org/demo/v2@v1.0.0";
  writeFileSync(zip, makeZip([
    { name: `${top}/go.mod`, data: "module example.org/demo/v2\n" },
    { name: `${top}/src/main.js`, data: "export const one = 1;\n" },
    { name: `${top}/.claude/rules/notes.md`, data: "project notes\n" },
    { name: `${top}/CLAUDE.md`, data: "notes\n" },
    { name: `${top}/pkg/.mcp.json`, data: "{}\n" },
  ]));
  assert.deepEqual(zipEntries(readFileSync(zip)).map((e) => e.link), [false, false, false, false, false]);
  const root = join(dir, "root");
  pinModule(root, "go/demo-mod.v2", zip, { archive: "zip", rootPath: top });
  const dest = join(dir, "run");
  const r = fetchModule(root, "go/demo-mod.v2", zip, dest);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /check OK: go\/demo-mod\.v2 1\.0\.0/);
  assert.match(r.stdout, /removed agent instruction files from app\/: \.claude, CLAUDE\.md, pkg\/\.mcp\.json/);
  assert.ok(existsSync(join(dest, "app", "go.mod")) && existsSync(join(dest, "app", "src", "main.js")), "the root inside the zip is app/");
  for (const f of [".claude", "CLAUDE.md", join("pkg", ".mcp.json")]) assert.ok(!existsSync(join(dest, "app", f)), `${f} removed`);
  const meta = JSON.parse(readFileSync(join(dest, "meta.json"), "utf8"));
  assert.equal(meta.bench_app, "real/go/demo-mod.v2-1.0.0");
  assert.equal(meta.key, join(root, "go", "demo-mod.v2", "answer-key-1.0.0.json"));
  assert.deepEqual(meta.source.root, top);
  assert.equal(meta.source.archive, "zip");
  assert.deepEqual(meta.stripped, [".claude", "CLAUDE.md", join("pkg", ".mcp.json")]);
  const email = execFileSync("git", ["-C", join(dest, "app"), "log", "--format=%ae"], { encoding: "utf8" }).trim();
  assert.equal(email, "dev@go.demo-mod.v2.invalid", "no / in the commit e-mail");
  const files = execFileSync("git", ["-C", join(dest, "app"), "ls-files"], { encoding: "utf8" }).trim().split("\n");
  assert.deepEqual(files.sort(), ["go.mod", "src/main.js"]);

  // Without `root` the single-top-directory rule stops at example.org/, so the key no longer matches.
  pinModule(root, "go/noroot", zip, { archive: "zip" });
  const noRoot = fetchModule(root, "go/noroot", zip, join(dir, "run-noroot"));
  assert.equal(noRoot.status, 1);
  assert.ok(existsSync(join(dir, "run-noroot", "app", "demo", `v2@v1.0.0`, "go.mod")), "heuristic root is example.org/");
  assert.match(noRoot.stderr, /src\/main\.js does not exist/);
  // A root outside the archive or missing from it is refused.
  for (const bad of ["../x", "/abs", "missing/dir"]) {
    pinModule(root, "go/badroot", zip, { archive: "zip", rootPath: bad });
    const b = fetchModule(root, "go/badroot", zip, join(dir, `run-bad-${bad.replace(/\W/g, "")}`));
    assert.equal(b.status, 1, bad);
    assert.match(b.stderr, /root/, bad);
  }
  // Invalid ids never reach the filesystem.
  const inv = spawnSync(process.execPath, [fetchScript, "npm/..", "1.0.0", "--root", root], { encoding: "utf8" });
  assert.equal(inv.status, 1);
  assert.match(inv.stderr, /invalid module name/);
});

test("fetch.mjs: a zip with a `..` entry, an absolute entry or a symlink entry is refused before extraction", () => {
  const dir = mkdtempSync(join(tmpdir(), "sa-real-zipbad-"));
  const cases = {
    dotdot: [{ name: "demo/src/main.js", data: "x\n" }, { name: "demo/../outside.txt", data: "x\n" }],
    absolute: [{ name: "demo/src/main.js", data: "x\n" }, { name: "/tmp/outside.txt", data: "x\n" }],
    symlink: [{ name: "demo/src/main.js", data: "x\n" }, { name: "demo/link", data: "/etc/hostname", mode: 0o120777 }],
  };
  for (const [name, entries] of Object.entries(cases)) {
    const zip = join(dir, `${name}.zip`);
    writeFileSync(zip, makeZip(entries));
    const root = join(dir, `root-${name}`);
    pinModule(root, "wordpress/demo", zip, { archive: "zip" });
    const dest = join(dir, `run-${name}`);
    const r = fetchModule(root, "wordpress/demo", zip, dest);
    assert.equal(r.status, 1, name);
    assert.match(r.stderr, name === "symlink" ? /entry "demo\/link" is a link/ : /refusing the release: entry .*(`\.\.` segment|absolute path)/, name);
    assert.ok(!existsSync(join(dest, "app")), `${name}: nothing extracted`);
    assert.ok(!existsSync(join(dir, "outside.txt")), `${name}: nothing written outside`);
  }
  assert.deepEqual(zipEntries(makeZip(cases.symlink)).map((e) => e.link), [false, true]);
});

test("fetch.mjs: a gem is a tar holding data.tar.gz, extracted at the archive root; links and `..` are refused", () => {
  const dir = mkdtempSync(join(tmpdir(), "sa-real-gem-"));
  const build = (name, extra = () => {}) => {
    const src = join(dir, name, "src");
    mkdirSync(join(src, "lib"), { recursive: true });
    writeFileSync(join(src, "lib", "demo.rb"), "module Demo\n  VERSION = '1.0.0'\nend\n");
    const members = extra(src) ?? ["lib"];
    const outer = join(dir, name, "outer");
    mkdirSync(outer);
    execFileSync("tar", ["-czf", join(outer, "data.tar.gz"), "-C", src, ...members], { stdio: "pipe" });
    writeFileSync(join(outer, "metadata.gz"), "");
    const gem = join(dir, `${name}.gem`);
    execFileSync("tar", ["-cf", gem, "-C", outer, "metadata.gz", "data.tar.gz"]);
    return gem;
  };
  const good = build("good");
  const root = join(dir, "root");
  pinModule(root, "rubygems/demo", good, { archive: "gem", keyFile: "lib/demo.rb", lines: [2, 2] });
  const dest = join(dir, "run");
  const r = fetchModule(root, "rubygems/demo", good, dest);
  assert.equal(r.status, 0, r.stderr);
  assert.ok(existsSync(join(dest, "app", "lib", "demo.rb")), "a gem's single lib/ directory is not taken as the root");
  assert.ok(!existsSync(join(dest, ".gem-data.tar.gz")), "the inner archive is cleaned up");

  const linked = build("linked", (src) => { symlinkSync("/etc/hostname", join(src, "lib", "link")); return ["lib"]; });
  pinModule(root, "rubygems/linked", linked, { archive: "gem", keyFile: "lib/demo.rb", lines: [2, 2] });
  const l = fetchModule(root, "rubygems/linked", linked, join(dir, "run-linked"));
  assert.equal(l.status, 1);
  assert.match(l.stderr, /refusing the gem's data\.tar\.gz: entry "lib\/link" is a link/);

  const dotdot = build("dotdot", () => ["--transform", "s,^lib/demo.rb$,../escape.rb,", "lib/demo.rb"]);
  pinModule(root, "rubygems/dotdot", dotdot, { archive: "gem", keyFile: "lib/demo.rb", lines: [2, 2] });
  const d = fetchModule(root, "rubygems/dotdot", dotdot, join(dir, "run-dotdot"));
  assert.equal(d.status, 1);
  assert.match(d.stderr, /entry "\.\.\/escape\.rb" \(`\.\.` segment\)/);
  assert.ok(!existsSync(join(dir, "escape.rb")) && !existsSync(join(dir, "run-dotdot", "escape.rb")));

  const notGem = join(dir, "plain.gem");
  execFileSync("tar", ["-cf", notGem, "-C", join(dir, "good", "outer"), "metadata.gz"]);
  pinModule(root, "rubygems/plain", notGem, { archive: "gem" });
  const n = fetchModule(root, "rubygems/plain", notGem, join(dir, "run-plain"));
  assert.equal(n.status, 1);
  assert.match(n.stderr, /not a gem: no data\.tar\.gz/);
});

test("fetch.mjs: a tar.gz with a symlink, a hard link or a `..` entry is refused before extraction", () => {
  const dir = mkdtempSync(join(tmpdir(), "sa-real-tarbad-"));
  const src = join(dir, "src", "demo");
  mkdirSync(join(src, "src"), { recursive: true });
  writeFileSync(join(src, "src", "main.js"), "x\n");
  symlinkSync("/etc/hostname", join(src, "link"));
  const hard = join(dir, "hard", "demo");
  mkdirSync(hard, { recursive: true });
  writeFileSync(join(hard, "a.js"), "x\n");
  linkSync(join(hard, "a.js"), join(hard, "b.js"));
  const cases = {
    symlink: [["-C", join(dir, "src"), "demo"], /entry "demo\/link" is a link/],
    hardlink: [["-C", join(dir, "hard"), "demo"], /entry "demo\/[ab]\.js" is a link/],
    dotdot: [["-C", join(dir, "src"), "--transform", "s,^demo/src/main.js$,demo/../../escape.js,", "demo/src/main.js"], /`\.\.` segment/],
  };
  for (const [name, [args, re]] of Object.entries(cases)) {
    const tgz = join(dir, `${name}.tar.gz`);
    spawnSync("tar", ["-czf", tgz, ...args]);
    const root = join(dir, `root-${name}`);
    pinModule(root, "npm/demo", tgz);
    const r = fetchModule(root, "npm/demo", tgz, join(dir, `run-${name}`));
    assert.equal(r.status, 1, name);
    assert.match(r.stderr, re, name);
    assert.ok(!existsSync(join(dir, `run-${name}`, "app")), `${name}: nothing extracted`);
  }
  assert.equal(unsafeEntryName("a/../b"), "`..` segment");
  assert.equal(unsafeEntryName("C:\\x"), "absolute path");
  assert.equal(unsafeEntryName("a/b..c"), null);
});
