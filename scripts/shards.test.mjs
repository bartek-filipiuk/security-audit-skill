// Run: node --test scripts/*.test.mjs
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { applySets, loadAudit, parseFrontmatter, parseSets, setFields, validate } from "./audit-state.mjs";
import { groups, plan, rawFindings, writeShards } from "./shards.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const finding = (id, file, line, { status = "raw", category = id.replace(/-\d+$/, ""), extra = "" } = {}) =>
  `---\nid: ${id}\ncategory: ${category}\nseverity: HIGH\nstatus: ${status}\nsource_agent: auditor-x\n${extra}---\n\n## Title\nTitle of ${id} | with a pipe\n\n## Evidence\n- **File**: \`${file}:${line}\`\n\n## Impact\nA signed-in user can read another organization's rows.\n`;

function auditDir(files) {
  const dir = mkdtempSync(join(tmpdir(), "sa-shards-"));
  mkdirSync(join(dir, "findings"));
  for (const [id, text] of Object.entries(files)) writeFileSync(join(dir, "findings", `${id}.md`), text);
  return dir;
}
const item = (id, file, start, end = start, category = id.replace(/-\d+$/, "")) => ({ id, category, severity: "HIGH", title: id, loc: file ? { file, start, end } : null });

test("groups: findings in one file within 15 lines are one group, whatever their category; farther apart or in another file they are not", () => {
  const gs = groups([
    item("auth-101", "src/a.ts", 10, 15), item("auth-215", "src/a.ts", 10), item("concurrency-404", "src/a.ts", 22, 25),
    item("auth-102", "src/a.ts", 80), item("injection-201", "src/b.ts", 10), item("config-301", null),
    item("config-302", "Dockerfile", null, null), item("config-303", "Dockerfile", null, null),
  ]);
  const ids = gs.map((g) => g.map((x) => x.id));
  assert.deepEqual(ids.find((g) => g.includes("auth-101")), ["auth-101", "auth-215", "concurrency-404"]);
  for (const alone of ["auth-102", "injection-201", "config-301", "config-302", "config-303"]) assert.deepEqual(ids.find((g) => g.includes(alone)), [alone], `${alone} stands alone`);
  // 15 lines is the edge; ranges count from their nearest ends.
  assert.equal(groups([item("a-1", "f.ts", 1, 5), item("a-2", "f.ts", 20)]).length, 1);
  assert.equal(groups([item("a-1", "f.ts", 1, 5), item("a-2", "f.ts", 21)]).length, 2);
});

test("plan: one shard up to 25 findings; above that even shards of at most 15, and a group is never split", () => {
  const many = (n) => Array.from({ length: n }, (_, i) => item(`auth-${100 + i}`, `src/f${i}.ts`, 1));
  assert.deepEqual(plan([]), []);
  assert.equal(plan(many(25)).length, 1);
  assert.deepEqual(plan(many(26)).map((s) => s.flat().length), [13, 13]);
  assert.deepEqual(plan(many(58)).map((s) => s.flat().length), [15, 15, 15, 13]);
  assert.deepEqual(plan(many(16), { size: 12, single: 15 }).map((s) => s.flat().length), [8, 8]);
  // 11 singletons, then a pair that would straddle the limit: the pair moves to the next shard whole.
  const items = [...many(11), item("auth-300", "src/z.ts", 5), item("injection-300", "src/z.ts", 7), ...Array.from({ length: 6 }, (_, i) => item(`upload-${400 + i}`, `u${i}.ts`, 1))];
  const shards = plan(items, { size: 12, single: 15 });
  const of = (id) => shards.findIndex((s) => s.flat().some((x) => x.id === id));
  assert.equal(of("auth-300"), of("injection-300"));
  assert.ok(shards.every((s) => s.flat().length <= 12));
  assert.equal(shards.flat(2).length, items.length);
  // Families stay together: auth before injection before upload.
  const order = shards.flat(2).map((x) => x.category);
  assert.ok(order.lastIndexOf("auth") < order.indexOf("upload"));
  // A group larger than the limit is kept whole in its own shard.
  const big = [...Array.from({ length: 14 }, (_, i) => item(`auth-${500 + i}`, "src/one.ts", 10 + i)), ...many(6)];
  assert.ok(plan(big, { size: 12, single: 15 }).some((s) => s.flat().length === 14 && s.length === 1));
});

test("writeShards: only raw findings of this run, one file per shard, groups listed as candidates; a second run replaces the plan", () => {
  const files = {
    "auth-101": finding("auth-101", "src/app/(app)/invoices/actions.ts", "10-15"),
    "auth-215": finding("auth-215", "src/app/(app)/invoices/actions.ts", 10),
    "injection-201": finding("injection-201", "src/x.tsx", 7),
    "auth-102": finding("auth-102", "src/a.ts", 3, { status: "verified" }),
    "auth-103": finding("auth-103", "src/a.ts", 3, { status: "rejected" }),
    "auth-104": finding("auth-104", "src/a.ts", 3, { extra: "carried_from: abc1234\ncarried_run: 2026-01-01\n" }),
  };
  const dir = auditDir(files);
  assert.deepEqual(rawFindings(loadAudit(dir)).map((x) => x.id), ["auth-101", "auth-215", "injection-201"]);
  const { shards, names } = writeShards(dir);
  assert.deepEqual(names, ["a"]);
  assert.equal(shards.length, 1);
  const text = readFileSync(join(dir, "shards", "a.md"), "utf8");
  assert.match(text, /^# Verifier shard a \(3 findings, the only shard\)/);
  assert.match(text, /\| findings\/auth-215\.md \| auth \| HIGH \| src\/app\/\(app\)\/invoices\/actions\.ts:10 \| Title of auth-215 \/ with a pipe \|/);
  assert.match(text, /- auth-101 \(auth, 10-15\), auth-215 \(auth, 10\): src\/app\/\(app\)\/invoices\/actions\.ts/);
  assert.match(text, /Candidates only/);
  assert.doesNotMatch(text, /auth-102|auth-103|auth-104/);

  // Verification moved on: the plan is rebuilt from what is still raw, and stale shard files are gone.
  for (let i = 0; i < 30; i++) writeFileSync(join(dir, "findings", `upload-${400 + i}.md`), finding(`upload-${400 + i}`, `u${i}.ts`, 1));
  assert.deepEqual(writeShards(dir).names, ["a", "b", "c"]);
  applySets(dir, Array.from({ length: 30 }, (_, i) => [`upload-${400 + i}`, { status: "rejected", rejection_reason: "no_evidence" }]));
  assert.equal(writeShards(dir).shards.length, 1);
  assert.deepEqual(readdirSync(join(dir, "shards")), ["a.md"]);
});

test("shards CLI: prints the plan, says when one verifier is enough, refuses a bad --size", () => {
  const dir = auditDir({ "auth-101": finding("auth-101", "src/a.ts", 1), "auth-102": finding("auth-102", "src/a.ts", 4) });
  const run = (...a) => spawnSync(process.execPath, [join(here, "shards.mjs"), "--dir", dir, ...a], { encoding: "utf8" });
  const out = run().stdout;
  assert.match(out, /shards: 2 raw findings -> 1 shard\(s\) in .*; 1 same-place group\(s\) covering 2 findings/);
  assert.match(out, /a\.md: 2 findings \(auth 2\)/);
  assert.match(out, /single verifier, no COMBINE pass/);
  assert.match(run("--single", "1", "--size", "1").stdout, /-> 1 shard\(s\)/, "the pair stays whole even above --size");
  const bad = run("--size", "0");
  assert.equal(bad.status, 2);
  assert.ok(existsSync(join(dir, "shards", "a.md")));
});

test("--set: changes frontmatter fields in place and leaves the body and other keys alone", () => {
  const text = `---\nid: auth-101\ncategory: auth\nseverity: MEDIUM   # preliminary\nstatus: raw\nremediation:\n  status: open\n---\n\n## Title\nT\n\n## Evidence\n- **File**: \`a.ts:1\`\nstatus: raw in the body stays\n`;
  const out = setFields(text, { status: "verified", severity: "HIGH", proof: "test", prerequisite_count: "0" });
  const fm = parseFrontmatter(out);
  assert.deepEqual(fm.errors, []);
  assert.deepEqual(fm.data, { id: "auth-101", category: "auth", severity: "HIGH", status: "verified", remediation: { status: "open" }, proof: "test", prerequisite_count: 0 });
  assert.equal(fm.body, parseFrontmatter(text).body);
  assert.match(out, /status: raw in the body stays/);
  // A reason with quotes, a dollar sign and a colon survives the round trip.
  const reason = 'duplicate_of_auth-107 — same sink: "getInvoice" $1';
  assert.equal(parseFrontmatter(setFields(text, { status: "rejected", rejection_reason: reason })).data.rejection_reason, reason);
});

test("--set: refuses unknown fields, invalid values and multi-line values", () => {
  const text = "---\nid: auth-101\nstatus: raw\n---\n";
  assert.throws(() => setFields(text, { id: "auth-999" }), /id: not settable/);
  assert.throws(() => setFields(text, { status: "fixed" }), /status: value "fixed" is not valid/);
  assert.throws(() => setFields(text, { severity: "high" }), /not valid/);
  assert.throws(() => setFields(text, { rejection_reason: "looks fine" }), /not valid/);
  assert.throws(() => setFields(text, { rejection_reason: "best_practice\nstatus: verified" }), /not valid/);
  assert.throws(() => setFields(text, { prerequisite_count: "two" }), /not valid/);
  assert.throws(() => setFields("no frontmatter", { status: "verified" }), /missing frontmatter/);
  assert.throws(() => parseSets(["--set", "auth-101"]), /needs a finding id and at least one key=value/);
  assert.throws(() => parseSets(["--set", "auth-101", "verified"]), /is not key=value/);
  assert.deepEqual(parseSets(["--dir", "x", "--set", "a-1", "status=verified", "--final", "--set", "a-2", "rejection_reason=best_practice — a=b"]), [["a-1", { status: "verified" }], ["a-2", { rejection_reason: "best_practice — a=b" }]]);
});

test("--set CLI: several findings in one call, all or nothing, never a carried finding or a path", () => {
  const dir = auditDir({
    "auth-101": finding("auth-101", "src/a.ts", 1),
    "auth-102": finding("auth-102", "src/a.ts", 1),
    "auth-103": finding("auth-103", "src/a.ts", 1, { status: "verified", extra: "proof: static\ncarried_from: abc1234\ncarried_run: 2026-01-01\n" }),
  });
  const run = (...a) => spawnSync(process.execPath, [join(here, "audit-state.mjs"), "--dir", dir, ...a], { encoding: "utf8" });
  const status = (id) => parseFrontmatter(readFileSync(join(dir, "findings", `${id}.md`), "utf8")).data.status;

  const ok = run("--set", "auth-101", "status=verified", "proof=static", "--set", "auth-102", "status=rejected", "rejection_reason=duplicate_of_auth-101 — same sink", "--final");
  assert.equal(ok.status, 0, ok.stdout);
  assert.match(ok.stdout, /frontmatter updated in 2 finding\(s\)/);
  assert.deepEqual([status("auth-101"), status("auth-102")], ["verified", "rejected"]);
  assert.deepEqual(validate(loadAudit(dir), { final: true }), []);

  // One bad --set stops the whole call.
  for (const bad of [
    ["--set", "auth-101", "severity=LOW", "--set", "auth-999", "status=verified"],
    ["--set", "auth-101", "severity=LOW", "--set", "auth-102", "status=fixed"],
    ["--set", "auth-101", "severity=LOW", "--set", "auth-103", "severity=LOW"],
    ["--set", "auth-101", "severity=LOW", "--set", "../non-issues/x", "status=verified"],
  ]) {
    const r = run(...bad);
    assert.equal(r.status, 1, bad.join(" "));
    assert.match(r.stdout, /nothing changed/);
    assert.equal(parseFrontmatter(readFileSync(join(dir, "findings", "auth-101.md"), "utf8")).data.severity, "HIGH");
  }
  assert.match(run("--set", "auth-103", "severity=LOW").stdout, /carried from a previous audit, never edited/);
  // The verdict is still validated: a verified finding without an Impact section fails as before.
  writeFileSync(join(dir, "findings", "auth-104.md"), "---\nid: auth-104\ncategory: auth\nseverity: LOW\nstatus: raw\n---\n\n## Title\nT\n");
  const noImpact = run("--set", "auth-104", "status=verified");
  assert.equal(noImpact.status, 1);
  assert.match(noImpact.stdout, /auth-104\.md: verified finding/);
});
