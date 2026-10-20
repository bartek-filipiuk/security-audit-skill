// Run: node --test scripts/*.test.mjs
// Real-advisory benchmarks (roadmap R30): fetch.mjs and the answer keys under benchmark/real/. The real
// releases are not in the repo, so the line check against them runs in `fetch.mjs --check`; here the keys get
// a schema check and fetch.mjs runs end to end on a synthetic module tarball, with no network.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { checkKey } from "../benchmark/real/fetch.mjs";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
const real = join(repo, "benchmark", "real");
const fetchScript = join(real, "fetch.mjs");
const modules = readdirSync(real, { withFileTypes: true }).filter((d) => d.isDirectory() && existsSync(join(real, d.name, "manifest.json"))).map((d) => d.name);
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

test("real benchmarks: manifests pin a sha256 per version and every advisory has a drupal.org link", () => {
  assert.ok(modules.includes("miniorange_saml"));
  for (const m of modules) {
    const man = JSON.parse(readFileSync(join(real, m, "manifest.json"), "utf8"));
    assert.equal(man.project, m);
    for (const [v, x] of Object.entries(man.versions)) {
      assert.match(x.sha256, /^[0-9a-f]{64}$/, `${m} ${v} sha256`);
      assert.match(x.url, /^https:\/\//, `${m} ${v} url`);
      assert.ok(existsSync(join(real, m, x.key)), `${m} ${v} key file ${x.key}`);
    }
    for (const a of man.advisories) {
      assert.match(a.sa, /^SA-CONTRIB-\d{4}-\d{3}$/);
      assert.match(a.cve, /^CVE-\d{4}-\d{4,}$/);
      assert.equal(a.url, `https://www.drupal.org/${a.sa.toLowerCase()}`);
    }
  }
});

test("real benchmarks: answer keys follow the benchmark key format", () => {
  for (const m of modules) {
    const man = JSON.parse(readFileSync(join(real, m, "manifest.json"), "utf8"));
    const sas = new Set(man.advisories.map((a) => a.sa.replace("CONTRIB-", "")));
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
    // Defensive wording: the keys describe class, location and impact, never steps or payloads.
    const text = readdirSync(join(real, m)).map((f) => readFileSync(join(real, m, f), "utf8")).join("\n");
    assert.doesNotMatch(text, /<script|alert\(|curl |payload:|step \d|proof of concept/i);
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
