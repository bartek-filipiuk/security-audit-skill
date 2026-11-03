// Run: node --test scripts/*.test.mjs
// OWASP Juice Shop support (roadmap R33): benchmark/real/juice-key.mjs (marker parser, stripper, key generator)
// and the training-app options of benchmark/real/fetch.mjs (exclude, withhold, strip_markers). No Juice Shop
// code is in the repo: the fixtures below are synthetic files that use the release's marker syntax.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { extractArchive } from "../benchmark/real/fetch.mjs";
import { buildKey, collectVulnLines, extractPinned, groupChallenges, parseChallenges, parseMarkers, runs, stripMarkers } from "../benchmark/real/juice-key.mjs";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
const real = join(repo, "benchmark", "real");
const fetchScript = join(real, "fetch.mjs");
const M = "vuln-code" + "-snippet"; // split so this file holds no marker itself

const write = (base, rel, text) => {
  mkdirSync(dirname(join(base, rel)), { recursive: true });
  writeFileSync(join(base, rel), text);
};

// A small app tree in the release's layout, with markers in TypeScript and YAML.
function appTree(dir) {
  write(dir, "server.ts", [
    "import express from 'express'",
    `// ${M} start listingChallenge`,
    "const app = express()",
    `app.use('/files', serveIndex('files')) // ${M} vuln-line listingChallenge`,
    `app.use('/files/:f', serve()) // ${M} vuln-line listingChallenge`,
    `app.use('/x', other()) // ${M} neutral-line listingChallenge`,
    `// ${M} end listingChallenge`,
    "const parser = /[/#]{0,2} " + M + " start (?<c>.*)/g",
    "",
  ].join("\n"));
  write(dir, "routes/login.ts", [
    `// ${M} start loginAChallenge loginBChallenge`,
    "export function login (req) {",
    `  if (check(req)) { // ${M} hide-start`,
    "    solve()",
    `  } // ${M} hide-end`,
    `  return db.query('SELECT ' + req.body.email) // ${M} vuln-line loginAChallenge loginBChallenge`,
    `  audit(req) // ${M} vuln-line loginBChallenge`,
    `} // ${M} end loginAChallenge loginBChallenge`,
    "",
  ].join("\r\n"));
  write(dir, "data/static/questions.yml", [
    `# ${M} start questionChallenge`,
    "-",
    `  question: 'Favourite colour?' # ${M} vuln-line questionChallenge`,
    `# ${M} end questionChallenge`,
    "",
  ].join("\n"));
  write(dir, "data/static/challenges.yml", [
    "---",
    "-",
    "  name: 'File Listing'",
    "  category: 'Sensitive Data Exposure'",
    "  description: 'Not copied into the key.'",
    "  difficulty: 1",
    "  hints:",
    "    - 'Not copied either.'",
    "  key: listingChallenge",
    "-",
    "  name: 'Login A'",
    "  category: 'Injection'",
    "  difficulty: 2",
    "  key: loginAChallenge",
    "-",
    "  name: \"Login B's\"",
    "  category: 'Injection'",
    "  difficulty: 3",
    "  key: loginBChallenge",
    "-",
    "  name: 'Weak Question'",
    "  category: 'Broken Authentication'",
    "  difficulty: 4",
    "  key: questionChallenge",
    "-",
    "  name: 'No Snippet'",
    "  category: 'Miscellaneous'",
    "  difficulty: 1",
    "  key: noSnippetChallenge",
    "",
  ].join("\n"));
  // The app's own fixes carry markers too; they are answers, not app code.
  write(dir, "data/static/codefixes/loginAChallenge_1_correct.ts", `// ${M} start loginAChallenge\nfixed() // ${M} vuln-line loginAChallenge\n// ${M} end loginAChallenge\n`);
  write(dir, "data/static/codefixes/loginAChallenge.info.yml", "fixes:\n  - id: 1\n");
  write(dir, "frontend/src/hacking-instructor/challenges/loginA.ts", "export const steps = []\n");
  write(dir, "SOLUTIONS.md", "# Solutions\n");
  write(dir, "AGENTS.md", "# Agent notes\n");
  write(dir, "README.md", "# Demo shop\n");
}

test("juice-key: markers are parsed per line with their kind and challenge keys", () => {
  const text = [`a() // ${M} vuln-line k1 k2`, `# ${M} start k3`, "b()", `c() //${M} neutral-line k1`, `d() // ${M} hide-line`, "/[/#]{0,2} " + M + " start (?<x>.*)/"].join("\n");
  assert.deepEqual(parseMarkers(text), [
    { line: 1, kind: "vuln-line", keys: ["k1", "k2"] },
    { line: 2, kind: "start", keys: ["k3"] },
    { line: 4, kind: "neutral-line", keys: ["k1"] },
    { line: 5, kind: "hide-line", keys: [] },
  ]);
});

test("juice-key: stripping cuts the marker comment and keeps every line, CRLF included", () => {
  const dir = mkdtempSync(join(tmpdir(), "juice-strip-"));
  appTree(dir);
  for (const f of ["server.ts", "routes/login.ts", "data/static/questions.yml"]) {
    const before = readFileSync(join(dir, f), "utf8");
    const { text, count } = stripMarkers(before);
    assert.equal(text.split("\n").length, before.split("\n").length, `${f}: same number of lines`);
    assert.ok(count > 0, f);
    assert.deepEqual(parseMarkers(text), [], `${f}: no marker left`);
    before.split("\n").forEach((l, i) => assert.ok(l.startsWith(text.split("\n")[i].replace(/\r$/, "")), `${f}:${i + 1} only loses a suffix`));
  }
  const login = stripMarkers(readFileSync(join(dir, "routes/login.ts"), "utf8")).text.split("\r\n");
  assert.equal(login[5], "  return db.query('SELECT ' + req.body.email)", "the vulnerable line keeps its code");
  assert.equal(login[0], "", "a marker-only line becomes blank");
  const server = stripMarkers(readFileSync(join(dir, "server.ts"), "utf8")).text.split("\n");
  assert.equal(server[7], "const parser = /[/#]{0,2} " + M + " start (?<c>.*)/g", "code that only names the tool stays");
});

test("juice-key: the key has one entry per group of overlapping challenges, ranges from vuln-lines, metadata from challenges.yml", () => {
  const dir = mkdtempSync(join(tmpdir(), "juice-key-"));
  appTree(dir);
  assert.deepEqual(runs([7, 3, 4, 9, 4]), [[3, 4], [7, 7], [9, 9]]);
  assert.deepEqual(parseChallenges(readFileSync(join(dir, "data/static/challenges.yml"), "utf8")).map((c) => [c.key, c.name, c.difficulty]), [
    ["listingChallenge", "File Listing", 1], ["loginAChallenge", "Login A", 2], ["loginBChallenge", "Login B's", 3], ["questionChallenge", "Weak Question", 4], ["noSnippetChallenge", "No Snippet", 1],
  ]);
  const key = buildKey({ src: dir, version: "1.0.0", skip: ["data/static/codefixes"] });
  assert.equal(key.app, "real/npm/juice-shop-1.0.0");
  assert.equal(key.module_version, "1.0.0");
  assert.deepEqual(key.decoys, []);
  assert.deepEqual(key.seeded.map((e) => [e.id, e.locations]), [
    ["listingChallenge", [{ file: "server.ts", lines: [4, 5] }]],
    ["loginAChallenge+loginBChallenge", [{ file: "routes/login.ts", lines: [6, 7] }]],
    ["questionChallenge", [{ file: "data/static/questions.yml", lines: [3, 3] }]],
  ]);
  const login = key.seeded[1];
  assert.deepEqual(login.challenges, ["loginAChallenge", "loginBChallenge"]);
  assert.equal(login.class, "Injection: Login A; Injection: Login B's");
  assert.equal(login.difficulty, 3);
  assert.equal(login.detect, "llm");
  assert.match(key.note, /\(4 of 5\)/, "challenges without a snippet are counted, not keyed");
  assert.doesNotMatch(JSON.stringify(key), /Not copied/, "descriptions and hints stay out of the key");
  assert.ok(!key.seeded.some((e) => e.locations.some((l) => l.file.includes("codefixes"))), "the fixes never become key locations");
  // Without the skip, the fix file's marker would be read as a second loginA location.
  const unskipped = collectVulnLines(dir).get("loginAChallenge").map((x) => x.file);
  assert.ok(unskipped.includes("data/static/codefixes/loginAChallenge_1_correct.ts"));
});

test("juice-key: broken markers and unknown challenges are errors, not silent gaps", () => {
  const dir = mkdtempSync(join(tmpdir(), "juice-bad-"));
  appTree(dir);
  write(dir, "lib/a.ts", `x() // ${M} vuln-line loginAChallenge\n`);
  assert.throws(() => buildKey({ src: dir, version: "1.0.0", skip: ["data/static/codefixes"] }), /lib\/a\.ts:1: vuln-line of loginAChallenge outside its snippet/);
  write(dir, "lib/a.ts", `// ${M} start loginAChallenge\nx()\n`);
  assert.throws(() => buildKey({ src: dir, version: "1.0.0", skip: ["data/static/codefixes"] }), /never closed/);
  write(dir, "lib/a.ts", `// ${M} start ghostChallenge\nx() // ${M} vuln-line ghostChallenge\n// ${M} end ghostChallenge\n`);
  assert.throws(() => buildKey({ src: dir, version: "1.0.0", skip: ["data/static/codefixes"] }), /not in challenges\.yml: ghostChallenge/);
  assert.deepEqual(groupChallenges(new Map([["a", [{ file: "f", line: 1 }]], ["b", [{ file: "f", line: 1 }, { file: "f", line: 5 }]], ["c", [{ file: "f", line: 5 }]], ["d", [{ file: "g", line: 1 }]]])).map((g) => g.challenges), [["a", "b", "c"], ["d"]], "overlaps group transitively");
});

// A packaged release: one top directory, node_modules with a .bin symlink and build output beside the source.
function release(dir) {
  const top = join(dir, "src", "demo_1.0.0");
  appTree(top);
  write(top, "node_modules/dep/index.js", "module.exports = 1\n");
  mkdirSync(join(top, "node_modules", ".bin"), { recursive: true });
  symlinkSync("../dep/index.js", join(top, "node_modules", ".bin", "dep"));
  write(top, "build/server.js", `// ${M} start listingChallenge\n`);
  write(top, "frontend/dist/main.js", "x\n");
  const tgz = join(dir, "demo-1.0.0.tgz");
  execFileSync("tar", ["-czf", tgz, "-C", join(dir, "src"), "demo_1.0.0"]);
  return { tgz, top, sha: createHash("sha256").update(readFileSync(tgz)).digest("hex") };
}

function pinJuice(root, { sha, exclude = ["node_modules", "build", "frontend/dist"], rootPath = "demo_1.0.0" }) {
  const manifest = {
    project: "juice-shop", ecosystem: "npm", kind: "training-app", archive: "tar.gz",
    versions: { "1.0.0": { url: "https://example.com/demo-1.0.0.tgz", sha256: sha, released: "2026-10-11", ...(rootPath ? { root: rootPath } : {}), key: "answer-key-1.0.0.json" } },
    exclude,
    withhold: ["data/static/codefixes", "data/static/challenges.yml", "frontend/src/hacking-instructor", "SOLUTIONS.md", "not/shipped"],
    strip_markers: "vuln-code-snippet",
    advisories: [],
  };
  mkdirSync(join(root, "npm", "juice-shop"), { recursive: true });
  writeFileSync(join(root, "npm", "juice-shop", "manifest.json"), JSON.stringify(manifest));
}

test("fetch.mjs training app: excluded paths are not extracted, answers withheld, markers blanked, key lines hold", async () => {
  const dir = mkdtempSync(join(tmpdir(), "juice-fetch-"));
  const rel = release(dir);
  const root = join(dir, "root");
  pinJuice(root, { sha: rel.sha });
  // The key comes from the pinned archive, read through fetch.mjs's extractor, as the CLI does with --tarball.
  const pinned = await extractPinned(rel.tgz, "1.0.0", root);
  try {
    assert.ok(!existsSync(join(pinned.src, "node_modules")), "excluded paths are not extracted for the generator either");
    writeFileSync(join(root, "npm", "juice-shop", "answer-key-1.0.0.json"), JSON.stringify(buildKey({ src: pinned.src, version: "1.0.0", skip: pinned.skip })));
  } finally {
    pinned.cleanup();
  }
  assert.ok(!existsSync(pinned.src), "the temporary extraction is removed");

  const dest = join(dir, "run");
  const r = spawnSync(process.execPath, [fetchScript, "npm/juice-shop", "1.0.0", "--root", root, "--tarball", rel.tgz, "--dest", dest, "--check"], { encoding: "utf8", env: { ...process.env, REAL_TARBALL: "" } });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /not extracted: node_modules, build, frontend\/dist/);
  assert.match(r.stdout, /withheld from app\/ \(answers\): SOLUTIONS\.md, data\/static\/challenges\.yml, data\/static\/codefixes, frontend\/src\/hacking-instructor/);
  assert.match(r.stdout, /markers blanked: 14 lines in 3 files \(line numbers unchanged\)/);
  assert.match(r.stdout, /check OK: npm\/juice-shop 1\.0\.0/);
  const app = join(dest, "app");
  for (const p of ["node_modules", "build", "frontend/dist", "data/static/codefixes", "data/static/challenges.yml", "frontend/src/hacking-instructor", "SOLUTIONS.md", "AGENTS.md"]) assert.ok(!existsSync(join(app, p)), `${p} is not in app/`);
  assert.ok(existsSync(join(app, "README.md")) && existsSync(join(app, "server.ts")));
  const meta = JSON.parse(readFileSync(join(dest, "meta.json"), "utf8"));
  assert.deepEqual(meta.stripped, ["AGENTS.md"]);
  assert.deepEqual(meta.excluded, ["node_modules", "build", "frontend/dist"]);
  assert.deepEqual(meta.withheld, ["SOLUTIONS.md", "data/static/challenges.yml", "data/static/codefixes", "frontend/src/hacking-instructor"], "paths the release does not ship are not listed");
  assert.deepEqual(meta.markers_stripped, { files: ["data/static/questions.yml", "routes/login.ts", "server.ts"], lines: 14 });
  for (const f of ["server.ts", "routes/login.ts", "data/static/questions.yml"]) {
    const orig = readFileSync(join(rel.top, f), "utf8");
    const now = readFileSync(join(app, f), "utf8");
    assert.equal(now.split("\n").length, orig.split("\n").length, `${f}: line numbers unchanged`);
    assert.deepEqual(parseMarkers(now), [], `${f}: no marker left in app/`);
  }
  const key = JSON.parse(readFileSync(join(root, "npm", "juice-shop", "answer-key-1.0.0.json"), "utf8"));
  const login = readFileSync(join(app, "routes/login.ts"), "utf8").split("\r\n");
  const [a, b] = key.seeded.find((e) => e.id === "loginAChallenge+loginBChallenge").locations[0].lines;
  assert.deepEqual(login.slice(a - 1, b), ["  return db.query('SELECT ' + req.body.email)", "  audit(req)"], "the key's lines point at the code in the stripped app/");
  const tracked = execFileSync("git", ["-C", app, "ls-files"], { encoding: "utf8" });
  assert.doesNotMatch(tracked, /node_modules|codefixes|hacking-instructor/);
});

test("fetch.mjs training app: exclude needs a tar.gz and a root, paths stay relative, links outside it are still refused", () => {
  const dir = mkdtempSync(join(tmpdir(), "juice-excl-"));
  const rel = release(dir);
  const staging = (n) => { const s = join(dir, `st-${n}`); mkdirSync(s); return s; };
  assert.throws(() => extractArchive(rel.tgz, "tar.gz", staging("noroot"), { exclude: ["node_modules"] }), /explicit root/);
  assert.throws(() => extractArchive(rel.tgz, "zip", staging("zip"), { root: "demo_1.0.0", exclude: ["node_modules"] }), /tar\.gz/);
  for (const bad of ["../x", "/abs", "node_*", "dir/"]) assert.throws(() => extractArchive(rel.tgz, "tar.gz", staging(bad.replace(/\W/g, "")), { root: "demo_1.0.0", exclude: [bad] }), /invalid exclude path/, bad);
  // Without node_modules excluded the release's symlink is refused, as for any other module.
  assert.throws(() => extractArchive(rel.tgz, "tar.gz", staging("all"), { root: "demo_1.0.0", exclude: ["build"] }), /node_modules\/\.bin\/dep" is a link/);
  const root = join(dir, "root");
  pinJuice(root, { sha: rel.sha, exclude: ["build"] });
  writeFileSync(join(root, "npm", "juice-shop", "answer-key-1.0.0.json"), JSON.stringify({ app: "real/npm/juice-shop-1.0.0", module_version: "1.0.0", seeded: [], decoys: [], known_extras: [] }));
  const r = spawnSync(process.execPath, [fetchScript, "npm/juice-shop", "1.0.0", "--root", root, "--tarball", rel.tgz, "--dest", join(dir, "run")], { encoding: "utf8", env: { ...process.env, REAL_TARBALL: "" } });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /is a link or special file/);
  assert.ok(!existsSync(join(dir, "run", "app")));
});

test("npm/juice-shop: the pinned release, its prep options and its generated key", () => {
  const dir = join(real, "npm", "juice-shop");
  const man = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
  assert.equal(man.kind, "training-app");
  const [version, v] = Object.entries(man.versions)[0];
  assert.match(v.url, /^https:\/\/github\.com\/juice-shop\/juice-shop\/releases\/download\/v[\d.]+\/juice-shop-[\d.]+_node\d+_linux_x64\.tgz$/, "a release asset, never an archive/refs tarball");
  assert.match(v.sha256, /^[0-9a-f]{64}$/);
  assert.equal(v.root, `juice-shop_${version}`);
  for (const p of ["node_modules", "build", "frontend/dist"]) assert.ok(man.exclude.includes(p), `${p} is not extracted`);
  for (const p of ["data/static/codefixes", "data/static/challenges.yml", "frontend/src/hacking-instructor", "SOLUTIONS.md"]) assert.ok(man.withhold.includes(p), `${p} is withheld`);
  assert.equal(man.strip_markers, "vuln-code-snippet");
  const key = JSON.parse(readFileSync(join(dir, v.key), "utf8"));
  assert.equal(key.module_version, version);
  assert.match(key.note, /generated by benchmark\/real\/juice-key\.mjs/);
  assert.ok(key.seeded.length >= 20, "the release has a few dozen coding challenges");
  const gone = [...man.exclude, ...man.withhold];
  for (const e of key.seeded) for (const l of e.locations) assert.ok(!gone.some((g) => l.file === g || l.file.startsWith(g + "/")), `${e.id}: ${l.file} is in app/`);
  const ids = key.seeded.flatMap((e) => e.challenges);
  assert.equal(new Set(ids).size, ids.length, "each challenge is in one entry");
});
