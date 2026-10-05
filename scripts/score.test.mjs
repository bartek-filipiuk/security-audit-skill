// Run: node --test scripts/
// Exact benchmark scoring (roadmap R03): findings match the answer key by file and line only.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { claudeSecurityLocation, distance, primaryLocation, score } from "../benchmark/score.mjs";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
const key = JSON.parse(readFileSync(join(repo, "benchmark", "answer-key.json"), "utf8"));
const app = join(repo, "benchmark", "app");

const finding = (id, { status = "verified", category = id.split("-")[0], file, extra = "" }) => {
  const text = `---\nid: ${id}\ncategory: ${category}\nseverity: HIGH\nstatus: ${status}\n---\n\n## Title\n${id} title\n\n## Evidence\n${file ? `- **File**: \`${file}\`\n` : ""}${extra}`;
  return { stem: id, data: { id, category, severity: "HIGH", status }, body: `## Title\n${id} title\n`, text };
};
const run = (...fs) => score(fs, key);
const entriesOf = (r, id) => r.matches.find((m) => m.finding === id).entries;

test("primary location is the Evidence File line, with ranges, .env and app/ prefixes", () => {
  assert.deepEqual(primaryLocation("see `src/a.ts:3`\n- **File**: `src/b.ts:15-28`"), { file: "src/b.ts", start: 15, end: 28 });
  assert.deepEqual(primaryLocation("- **File**: `.env:4` (history only: added in abc)"), { file: ".env", start: 4, end: 4 });
  assert.deepEqual(primaryLocation("- **File**: `app/src/app/p/[slug]/page.tsx:7`"), { file: "src/app/p/[slug]/page.tsx", start: 7, end: 7 });
  assert.deepEqual(primaryLocation("- **File**: `src/app/(app)/invoices/actions.ts:10`"), { file: "src/app/(app)/invoices/actions.ts", start: 10, end: 10 });
  assert.deepEqual(primaryLocation("---\nid: x\n---\nNo evidence block, but `src/x.ts` and (src/y.ts:9)"), { file: "src/y.ts", start: 9, end: 9 });
  assert.deepEqual(primaryLocation("- **File**: `src/x.ts`"), { file: "src/x.ts", start: null, end: null });
});

test("distance: inside the range is 0, outside counts lines, other files never match", () => {
  const loc = { file: "src/x.ts", lines: [10, 12] };
  assert.equal(distance({ file: "src/x.ts", start: 11, end: 11 }, loc), 0);
  assert.equal(distance({ file: "src/x.ts", start: 8, end: 8 }, loc), 2);
  assert.equal(distance({ file: "src/x.ts", start: 1, end: 9 }, loc), 1);
  assert.equal(distance({ file: "src/x.ts", start: 15, end: 20 }, loc), 3);
  assert.equal(distance({ file: "app/src/x.ts", start: 11, end: 11 }, loc), 0, "a longer path ending in the key path matches");
  assert.equal(distance({ file: "x.ts", start: 11, end: 11 }, loc), Infinity, "a bare file name matches nothing");
  assert.equal(distance({ file: "src/x.ts", start: null, end: null }, loc), Infinity, "no line, no match");
});

test("window: up to two lines outside the range match, three do not", () => {
  const r = run(
    finding("auth-001", { file: "src/app/api/export/route.ts:13" }), // B03 is 10-11
    finding("auth-002", { file: "src/app/api/export/route.ts:14" }),
  );
  assert.deepEqual(entriesOf(r, "auth-001"), ["B03"]);
  assert.deepEqual(entriesOf(r, "auth-002"), []);
  assert.equal(r.matches.find((m) => m.finding === "auth-001").distance, 2);
});

test("nearest entry wins between neighbouring ranges in one file (B06 and decoy D04)", () => {
  const r = run(
    finding("auth-001", { file: "src/server/queries/dashboard.ts:22" }),
    finding("auth-002", { file: "src/server/queries/dashboard.ts:16" }),
    finding("auth-003", { file: "src/server/queries/dashboard.ts:20" }),
  );
  assert.deepEqual(entriesOf(r, "auth-001"), ["B06"]);
  assert.deepEqual(entriesOf(r, "auth-002"), ["D04"]);
  assert.deepEqual(entriesOf(r, "auth-003"), ["B06"]);
  assert.equal(r.decoy_fp, 1);
});

test("a seeded file cited only as context does not match; keywords play no part", () => {
  const chain = finding("chain-901", {
    file: "src/app/api/chat/route.ts:13",
    extra: "Stripe webhook signature not verified, see `src/app/api/webhooks/stripe/route.ts:7`; BOLA, IDOR, tenant, cross-org.\n",
  });
  const r = run(chain);
  assert.deepEqual(entriesOf(r, "chain-901"), []);
  assert.equal(r.seeded.find((s) => s.id === "B08").result, "missed");
  assert.deepEqual(r.unmatched.map((u) => u.location), ["src/app/api/chat/route.ts:13"]);
  const plain = run(finding("auth-002", { file: "src/app/api/webhooks/stripe/route.ts:7" }));
  assert.equal(plain.seeded.find((s) => s.id === "B08").result, "found", "no keyword needed");
});

test("same file, different issue: outside every range stays unmatched", () => {
  const r = run(finding("injection-001", { file: "src/lib/auth.ts:23" })); // B12 is 28-29, B16 is 36
  assert.deepEqual(entriesOf(r, "injection-001"), []);
  assert.equal(r.found, 0);
});

test("advisory entries take only dependency findings, and dependency findings only advisories", () => {
  const r = run(
    finding("dependency-001", { file: "src/server/api/index.ts:13" }), // hono advisory used in CORS, next to B16
    finding("config-001", { file: "src/server/api/index.ts:16" }),
    finding("config-002", { file: "next.config.ts:3" }),
    finding("dependency-002", { file: "next.config.ts:7" }),
    finding("dependency-003", { file: "package.json:27" }),
    finding("dependency-004", { file: "pnpm-lock.yaml:246" }),
  );
  assert.deepEqual(entriesOf(r, "dependency-001"), ["X01"]);
  assert.deepEqual(entriesOf(r, "config-001"), ["B16"]);
  assert.deepEqual(entriesOf(r, "config-002"), [], "headers finding is not the vulnerable version");
  assert.deepEqual(entriesOf(r, "dependency-002"), ["B14"]);
  assert.deepEqual(entriesOf(r, "dependency-003"), ["X01"], "hono line, not the next line below it");
  assert.deepEqual(entriesOf(r, "dependency-004"), ["X03"], "sharp inside the next snapshot block");
  assert.deepEqual(r.extras, ["dependency-001", "dependency-003", "dependency-004"]);
});

test("every match is exact and the scorer reports no loose matches", () => {
  const r = run(
    finding("auth-001", { file: "src/app/(app)/invoices/actions.ts:10" }),
    finding("auth-002", { status: "rejected", file: "src/server/trpc/routers/project.ts:24" }),
    finding("exposure-001", { file: "src/components/login-form.tsx:19" }),
  );
  assert.equal(r.matching, "exact");
  assert.equal(r.loose_matches, 0);
  const by = Object.fromEntries(r.seeded.map((s) => [s.id, [s.result, s.match]]));
  assert.deepEqual(by.B01, ["found", "exact"]);
  assert.deepEqual(by.B02, ["dropped_by_verifier", "exact"]);
  assert.deepEqual(by.B03, ["missed", "none"]);
  for (const m of r.matches) assert.ok(m.match === "none" || m.distance <= r.window);
});

test("Claude Security rows: location from file and line fields, else from the text", () => {
  assert.deepEqual(claudeSecurityLocation({ file: "src/lib/auth.ts", line: 29 }), { file: "src/lib/auth.ts", start: 29, end: 29 });
  assert.deepEqual(claudeSecurityLocation({ location: { path: "app/src/x.ts", start_line: 3, end_line: 5 } }), { file: "src/x.ts", start: 3, end: 5 });
  assert.deepEqual(claudeSecurityLocation({ file_path: "src/x.ts:7" }), { file: "src/x.ts", start: 7, end: 7 });
  assert.equal(claudeSecurityLocation({ title: "no location" }), null);
});

test("answer key: every location points at real lines of a real file, ranges do not overlap", () => {
  const all = [...key.seeded, ...key.decoys, ...key.known_extras];
  assert.equal(new Set(all.map((e) => e.id)).size, all.length, "unique ids");
  for (const e of all) {
    assert.ok(e.locations?.length, `${e.id} has locations`);
    assert.ok(!("keywords" in e) && !("files" in e), `${e.id} has no keyword matching fields`);
    for (const l of e.locations) {
      const [a, b] = l.lines;
      assert.ok(Number.isInteger(a) && Number.isInteger(b) && a >= 1 && a <= b, `${e.id} ${l.file} range`);
      if (l.file === ".env") continue; // exists only in the git history setup.mjs writes (4 lines)
      const path = join(app, l.file);
      assert.ok(existsSync(path), `${e.id}: ${l.file} exists`);
      const lines = readFileSync(path, "utf8").split("\n");
      assert.ok(b <= lines.length, `${e.id}: ${l.file}:${b} within the file`);
      assert.ok(lines.slice(a - 1, b).some((s) => s.trim()), `${e.id}: ${l.file}:${a}-${b} is not blank`);
    }
  }
  const flat = all.flatMap((e) => e.locations.map((l) => ({ id: e.id, advisory: Boolean(e.advisory), ...l })));
  for (const x of flat) for (const y of flat) {
    if (x.id >= y.id || x.file !== y.file || x.advisory !== y.advisory) continue;
    assert.ok(x.lines[1] < y.lines[0] || y.lines[1] < x.lines[0], `${x.id} and ${y.id} overlap in ${x.file}`);
  }
});
