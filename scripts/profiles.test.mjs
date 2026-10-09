// Run: node --test scripts/*.test.mjs
// Supabase and Firebase profile (roadmap R02): the second benchmark app, its answer key, the scorer and
// setup for more than one app, the policy scan, edge/cloud function entry points and profile briefs.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { benchApp, DEFAULT_APP, listApps } from "../benchmark/apps.mjs";
import { parseLocation, primaryLocation, score } from "../benchmark/score.mjs";
import { detectLanguages, patternsFor, profileSections, writeBriefs } from "./briefs.mjs";
import { rankHotspots, scanEntryPoints, scanPolicies, scanScope, walk } from "./surface.mjs";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
const bench = benchApp("supabase-notes");
const key = JSON.parse(readFileSync(bench.key, "utf8"));
const { files } = walk(bench.app);

const finding = (id, file, { status = "verified", category = id.split("-")[0] } = {}) => {
  const text = `---\nid: ${id}\ncategory: ${category}\nseverity: HIGH\nstatus: ${status}\n---\n\n## Title\n${id} title\n\n## Evidence\n- **File**: \`${file}\`\n\n## Impact\nx\n`;
  return { stem: id, data: { id, category, severity: "HIGH", status }, body: `## Title\n${id} title\n`, text };
};
const entriesOf = (r, id) => r.matches.find((m) => m.finding === id).entries;
const sourceFiles = (dir) => readdirSync(dir, { recursive: true }).map(String).filter((p) => statSync(join(dir, p)).isFile());

test("benchmark apps: Ledgerly is the default, other apps live in benchmark/<name>", () => {
  assert.equal(DEFAULT_APP, "ledgerly");
  assert.deepEqual(listApps().slice(0, 1), ["ledgerly"]);
  assert.ok(listApps().includes("supabase-notes"));
  assert.equal(benchApp().app, join(repo, "benchmark", "app"));
  assert.equal(benchApp().key, join(repo, "benchmark", "answer-key.json"));
  assert.equal(bench.app, join(repo, "benchmark", "supabase-notes", "app"));
  assert.equal(bench.key, join(repo, "benchmark", "supabase-notes", "answer-key.json"));
  assert.throws(() => benchApp("nope"), /unknown benchmark app "nope"/);
  assert.throws(() => benchApp("app"), /unknown benchmark app/);
});

test("every app's answer key points at real lines, has no keyword fields and no overlapping ranges", () => {
  for (const name of listApps().filter((n) => n !== DEFAULT_APP)) {
    const b = benchApp(name);
    const k = JSON.parse(readFileSync(b.key, "utf8"));
    assert.equal(k.app, name);
    assert.ok(k.seeded.length >= 5, `${name}: at least 5 seeded bugs`);
    assert.ok(k.decoys.length >= 3, `${name}: at least 3 decoys`);
    const all = [...k.seeded, ...k.decoys, ...(k.known_extras ?? [])];
    assert.equal(new Set(all.map((e) => e.id)).size, all.length, `${name}: unique ids`);
    for (const e of k.seeded) assert.ok(e.class && e.severity && e.detect && e.why, `${name} ${e.id}: class, severity, detect, why`);
    for (const e of all) {
      assert.ok(e.locations?.length, `${e.id} has locations`);
      assert.ok(!("keywords" in e) && !("files" in e), `${e.id} has no keyword matching fields`);
      for (const l of e.locations) {
        const [a, z] = l.lines;
        assert.ok(Number.isInteger(a) && Number.isInteger(z) && a >= 1 && a <= z, `${e.id} ${l.file} range`);
        const path = join(b.app, l.file);
        assert.ok(existsSync(path), `${e.id}: ${l.file} exists`);
        const lines = readFileSync(path, "utf8").split("\n");
        assert.ok(z <= lines.length, `${e.id}: ${l.file}:${z} within the file`);
        assert.ok(lines.slice(a - 1, z).some((s) => s.trim()), `${e.id}: ${l.file}:${a}-${z} is not blank`);
        assert.ok(parseLocation(`${l.file}:${a}`)?.start === a, `${e.id}: the scorer parses ${l.file} locations`);
      }
    }
    const flat = all.flatMap((e) => e.locations.map((l) => ({ id: e.id, advisory: Boolean(e.advisory), ...l })));
    for (const x of flat) for (const y of flat) {
      if (x.id >= y.id || x.file !== y.file || x.advisory !== y.advisory) continue;
      assert.ok(x.lines[1] < y.lines[0] || y.lines[1] < x.lines[0], `${name}: ${x.id} and ${y.id} overlap in ${x.file}`);
    }
  }
});

test("supabase-notes covers the profile: SQL migrations, storage policies, rules, functions, a client", () => {
  const keyed = new Set([...key.seeded, ...key.decoys].flatMap((e) => e.locations.map((l) => l.file)));
  const has = (re) => [...keyed].some((f) => re.test(f));
  assert.ok(has(/^supabase\/migrations\/.+\.sql$/));
  assert.ok(has(/storage\.sql$/));
  assert.ok(has(/^firestore\.rules$/) && has(/^storage\.rules$/));
  assert.ok(has(/^supabase\/functions\//) && has(/^supabase\/config\.toml$/));
  assert.ok(has(/^functions\/src\//) && has(/^src\/components\/.+\.tsx$/));
});

test("supabase-notes source has no hint comments, no real-looking keys and only reserved domains", () => {
  for (const rel of sourceFiles(bench.app)) {
    const text = readFileSync(join(bench.app, rel), "utf8");
    assert.ok(!/\b(?:seed(?:ed)?|vuln\w*|insecure|exploit|decoy|bug|TODO|FIXME|B\d\d|D\d\d)\b/i.test(text.replace(/"supabase"|supabase db reset/g, "")), `${rel} has a hint word`);
    assert.ok(!/eyJ[\w-]{10,}\.|sb_secret_|sb_publishable_|sk_live_|AIza[\w-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY/.test(text), `${rel} has a real-looking key`);
    for (const m of text.matchAll(/https?:\/\/([\w.-]+)/g)) {
      assert.ok(/(?:^|\.)(?:example|invalid)$|^(?:localhost|127\.0\.0\.1)$/.test(m[1]), `${rel}: ${m[1]} is not a reserved domain`);
    }
    for (const m of text.matchAll(/[\w.-]+@([\w-]+(?:\.[\w-]+)+)/g)) {
      if (/^supabase\/supabase-js@2$|\d$/.test(m[0]) || m[0].startsWith("npm:")) continue;
      assert.ok(/\.(?:example|invalid)$/.test(m[1]), `${rel}: e-mail domain ${m[1]}`);
    }
  }
});

test("scorer parses .sql, .rules and .toml locations", () => {
  assert.deepEqual(primaryLocation("- **File**: `supabase/migrations/20260501090000_init.sql:103-105`"), { file: "supabase/migrations/20260501090000_init.sql", start: 103, end: 105 });
  assert.deepEqual(primaryLocation("- **File**: `firestore.rules:10`"), { file: "firestore.rules", start: 10, end: 10 });
  assert.deepEqual(primaryLocation("- **File**: `app/supabase/config.toml:21`"), { file: "supabase/config.toml", start: 21, end: 21 });
});

test("scoring supabase-notes: a finding on every seeded range is found, decoys count as false positives", () => {
  const seeded = key.seeded.map((e, i) => finding(`auth-${100 + i}`, `${e.locations[0].file}:${e.locations[0].lines[0]}`));
  const decoys = key.decoys.map((e, i) => finding(`auth-${200 + i}`, `${e.locations[0].file}:${e.locations[0].lines[0]}`));
  const r = score([...seeded, ...decoys], key);
  assert.equal(r.found, key.seeded.length);
  assert.equal(r.recall, 1);
  assert.equal(r.decoy_fp, key.decoys.length);
  assert.deepEqual(r.unmatched, []);
});

test("scoring supabase-notes: neighbouring seeded and decoy ranges stay apart", () => {
  const r = score([
    finding("config-001", "supabase/config.toml:21"),
    finding("config-002", "supabase/config.toml:24"),
    finding("auth-001", "supabase/migrations/20260501090000_init.sql:105"),
    finding("auth-002", "supabase/migrations/20260501090000_init.sql:112"),
    finding("auth-003", "supabase/migrations/20260508090000_sharing.sql:18"),
    finding("auth-004", "supabase/migrations/20260512090000_storage.sql:14"),
    finding("auth-005", "firestore.rules:8"),
    finding("auth-006", "functions/src/index.ts:20"),
    finding("exposure-001", "src/components/share-dialog.tsx:18"),
  ], key);
  assert.deepEqual(entriesOf(r, "config-001"), ["B07"]);
  assert.deepEqual(entriesOf(r, "config-002"), ["D09"]);
  assert.deepEqual(entriesOf(r, "auth-001"), ["B02"]);
  assert.deepEqual(entriesOf(r, "auth-002"), ["D04"]);
  assert.deepEqual(entriesOf(r, "auth-003"), ["B04"]);
  assert.deepEqual(entriesOf(r, "auth-004"), ["B05"]);
  assert.ok(entriesOf(r, "auth-005").includes("B08"), "the boards match block is in reach of B08");
  assert.deepEqual(entriesOf(r, "auth-006"), ["B10"]);
  assert.deepEqual(entriesOf(r, "exposure-001"), ["B04"], "the rpc call site, not the service-role import above it");
  assert.equal(r.decoyFp.map((d) => d.decoy).join(), "D09,D04");
});

test("setup --app creates a one-commit run with bench_app in meta.json, and score reads it", () => {
  const dest = join(mkdtempSync(join(tmpdir(), "sa-r02-")), "run");
  execFileSync(process.execPath, [join(repo, "benchmark", "setup.mjs"), "--app", "supabase-notes", "--dest", dest], { stdio: "pipe" });
  const meta = JSON.parse(readFileSync(join(dest, "meta.json"), "utf8"));
  assert.equal(meta.bench_app, "supabase-notes");
  assert.equal(execFileSync("git", ["-C", join(dest, "app"), "rev-list", "--count", "HEAD"], { encoding: "utf8" }).trim(), "1");
  assert.ok(existsSync(join(dest, "app", "firestore.rules")));
  assert.ok(!existsSync(join(dest, "app", "answer-key.json")) && !existsSync(join(dest, "answer-key.json")), "the key stays in the skill repo");

  const findings = join(dest, "app", ".security-audit", "findings");
  mkdirSync(findings, { recursive: true });
  writeFileSync(join(findings, "auth-001.md"), finding("auth-001", "supabase/migrations/20260501090000_init.sql:121").text);
  writeFileSync(join(findings, "auth-002.md"), finding("auth-002", "firestore.rules:5").text);
  const out = execFileSync(process.execPath, [join(repo, "benchmark", "score.mjs"), dest, "--no-save"], { encoding: "utf8" });
  assert.match(out, /^App supabase-notes$/m);
  assert.match(out, new RegExp(`Recall 1/${key.seeded.length} `));
  assert.match(out, /decoy false positives 1/);
  const asLedgerly = execFileSync(process.execPath, [join(repo, "benchmark", "score.mjs"), dest, "--app", "ledgerly", "--no-save"], { encoding: "utf8" });
  assert.match(asLedgerly, /^App ledgerly$/m);
  assert.match(asLedgerly, /Recall 0\/\d+ /);
});

test("setup without --app still builds Ledgerly with the leaked key in a two-commit history", () => {
  const dest = join(mkdtempSync(join(tmpdir(), "sa-r02-")), "run");
  execFileSync(process.execPath, [join(repo, "benchmark", "setup.mjs"), "--dest", dest], { stdio: "pipe" });
  assert.equal(JSON.parse(readFileSync(join(dest, "meta.json"), "utf8")).bench_app, "ledgerly");
  assert.equal(execFileSync("git", ["-C", join(dest, "app"), "rev-list", "--count", "HEAD"], { encoding: "utf8" }).trim(), "2");
  assert.ok(!existsSync(join(dest, "app", ".env")));
});

test("walk reads migrations, config.toml and rules files; they are never entry points", () => {
  const paths = files.map((f) => f.path);
  for (const p of ["supabase/migrations/20260501090000_init.sql", "supabase/config.toml", "firestore.rules", "storage.rules"]) assert.ok(paths.includes(p), p);
  assert.ok(!paths.includes("README.md") && !paths.includes("firebase.json"));
  const eps = scanEntryPoints(files);
  assert.ok(!eps.some((e) => /\.(sql|rules|toml)$/.test(e.file)));
});

test("entry points: Edge Functions carry verify_jwt, Cloud Functions their auth check", () => {
  const eps = scanEntryPoints(files);
  const get = (name) => eps.find((e) => e.name === name);
  assert.deepEqual([get("export-notes").kind, get("export-notes").route, get("export-notes").verifyJwt, get("export-notes").guard], ["edge-function", "/functions/v1/export-notes", false, ""]);
  assert.equal(get("export-notes").line, 7);
  assert.equal(get("inbound-email").verifyJwt, false);
  assert.deepEqual([get("deleteBoard").kind, get("deleteBoard").route, get("deleteBoard").guard, get("deleteBoard").line], ["cloud-function", "callable", "", 20]);
  assert.equal(get("renameBoard").guard, "request.auth");
  const viaGateway = scanEntryPoints([{ path: "supabase/functions/hello/index.ts", text: "Deno.serve(() => new Response('hi'));\n" }]);
  assert.equal(viaGateway[0].guard, "gateway verify_jwt");
  assert.equal(viaGateway[0].verifyJwt, true);
});

test("policy scan flags every seeded policy and rule, and not the scoped decoys", () => {
  const rows = scanPolicies(files);
  const at = (file, line) => rows.find((r) => r.file === file && r.line === line);
  const init = "supabase/migrations/20260501090000_init.sql";
  assert.match(at(init, 120).reasons.join(), /row level security is never enabled on note_shares/);
  assert.match(at(init, 103).reasons.join(), /is `true`/);
  assert.match(at(init, 83).reasons.join(), /signed in, not that they own/);
  const share = at("supabase/migrations/20260508090000_sharing.sql", 1);
  assert.match(share.reasons.join(), /no fixed search_path.*never checks auth\.uid\(\).*EXECUTE not revoked/);
  assert.equal(at("supabase/migrations/20260508090000_sharing.sql", 20).score, 1, "decoy: search_path set, auth.uid() checked, execute revoked");
  assert.match(at("supabase/migrations/20260512090000_storage.sql", 14).reasons.join(), /scoped to the bucket/);
  assert.match(at("supabase/migrations/20260512090000_storage.sql", 3).reasons.join(), /bucket "avatars" is public/);
  assert.ok(!rows.some((r) => r.file.endsWith("storage.sql") && [6, 10].includes(r.line)), "avatar policies are owner-scoped");
  assert.ok(!rows.some((r) => r.file === init && r.line < 49), "profiles policies and the trigger function are not flagged");
  assert.match(at("firestore.rules", 10).reasons.join(), /any signed-in user/);
  assert.match(at("firestore.rules", 13).reasons.join(), /any signed-in user/);
  assert.ok(!at("firestore.rules", 5) && !at("firestore.rules", 9));
  assert.match(at("storage.rules", 12).reasons.join(), /if true/);
  assert.ok(!rows.some((r) => r.file === "storage.rules" && r.line < 11));
});

test("policy scan: semicolons inside $$ bodies, strings and comments do not split statements", () => {
  const sql = [
    "create table public.a (id int); -- ; comment",
    "/* a; block */",
    "create function public.f() returns int language plpgsql security definer set search_path = '' as $$ begin perform 1; return (select auth.uid() is not null)::int; end; $$;",
    "alter table public.a enable row level security;",
    "create table b (note text default 'x; y');",
    "create policy p on b for select using (auth.uid() is not null);",
    "create policy q on b for update using (owner_id = (select auth.uid())) with check (owner_id = (select auth.uid()));",
  ].join("\n");
  const rows = scanPolicies([{ path: "supabase/migrations/1_x.sql", text: sql }]);
  assert.deepEqual(rows.map((r) => [r.line, r.name]).sort(), [[3, "f()"], [5, "b"], [6, "p"]]);
  assert.match(rows.find((r) => r.name === "f()").reasons.join(), /EXECUTE not revoked/);
  assert.doesNotMatch(rows.find((r) => r.name === "f()").reasons.join(), /search_path|never checks/);
});

test("hotspots put every seeded bug of supabase-notes within reach of a ranked row", () => {
  const eps = scanEntryPoints(files);
  const hot = rankHotspots(files, eps, scanScope(files)).filter((h) => h.score > 0);
  for (const e of key.seeded) {
    const near = hot.some((h) => e.locations.some((l) => h.file === l.file && h.line >= l.lines[0] - 2 && h.line <= l.lines[1] + 2));
    assert.ok(near, `${e.id} has a hotspot`);
  }
  const top = hot[0];
  assert.equal(`${top.file}:${top.line}`, "supabase/functions/export-notes/index.ts:7");
  assert.match(top.reasons.join(), /verify_jwt = false.*no auth check.*service-role.*user id taken from the request body/);
  assert.ok(!hot.some((h) => h.reasons.some((r) => r.includes("NEXT_PUBLIC_FIREBASE_API_KEY"))), "the Firebase web apiKey is public by design");
});

test("briefs: profiles come from their files or SDKs; the 2.1 brief gets the profile checklist", () => {
  const root = mkdtempSync(join(tmpdir(), "sa-r02-briefs-"));
  cpSync(bench.app, root, { recursive: true });
  execFileSync("git", ["init", "-q"], { cwd: root });
  execFileSync("git", ["add", "-A"], { cwd: root });
  assert.deepEqual(detectLanguages(root), ["js", "supabase", "firebase"]);

  const dir = join(root, ".security-audit");
  writeBriefs(dir);
  const auth = readFileSync(join(dir, "briefs", "auth.md"), "utf8");
  const infra = readFileSync(join(dir, "briefs", "infra.md"), "utf8");
  assert.match(auth, /## Stack profile: Supabase[\s\S]*## Stack profile: Firebase/);
  assert.doesNotMatch(infra, /## Stack profile/);
  assert.match(infra, /## Supabase\n\| Area/);
  assert.match(infra, /## Firebase\n\| Area/);

  const sdkOnly = mkdtempSync(join(tmpdir(), "sa-r02-sdk-"));
  writeFileSync(join(sdkOnly, "package.json"), JSON.stringify({ dependencies: { "@supabase/supabase-js": "2.58.0" } }));
  writeFileSync(join(sdkOnly, "index.ts"), "export {};\n");
  execFileSync("git", ["init", "-q"], { cwd: sdkOnly });
  execFileSync("git", ["add", "-A"], { cwd: sdkOnly });
  assert.deepEqual(detectLanguages(sdkOnly), ["js", "supabase"]);

  const ledgerly = patternsFor(["js"]);
  assert.doesNotMatch(ledgerly, /## Supabase|## Firebase/);
  assert.deepEqual(profileSections(["js"]), []);
  assert.equal(relative(repo, bench.app), join("benchmark", "supabase-notes", "app"));
});
