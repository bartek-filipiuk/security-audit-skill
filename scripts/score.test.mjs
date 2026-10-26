// Run: node --test scripts/*.test.mjs
// Exact benchmark scoring (roadmap R03): findings match the answer key by file and line only.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { citedLocations, claudeSecurityLocation, distance, primaryLocation, score, secondaryLocations } from "../benchmark/score.mjs";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
const key = JSON.parse(readFileSync(join(repo, "benchmark", "answer-key.json"), "utf8"));
const app = join(repo, "benchmark", "app");

const finding = (id, { status = "verified", category = id.split("-")[0], file, extra = "", title = `${id} title` }) => {
  const text = `---\nid: ${id}\ncategory: ${category}\nseverity: HIGH\nstatus: ${status}\n---\n\n## Title\n${title}\n\n## Evidence\n${file ? `- **File**: \`${file}\`\n` : ""}${extra}`;
  return { stem: id, data: { id, category, severity: "HIGH", status }, body: `## Title\n${title}\n`, text };
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

test("primary location understands CI workflows, Dockerfiles and IaC files", () => {
  assert.deepEqual(primaryLocation("- **File**: `.github/workflows/preview.yml:16-17`"), { file: ".github/workflows/preview.yml", start: 16, end: 17 });
  assert.deepEqual(primaryLocation("- **File**: `Dockerfile:20`"), { file: "Dockerfile", start: 20, end: 20 });
  assert.deepEqual(primaryLocation("- **File**: `app/docker/Dockerfile.worker:3`"), { file: "docker/Dockerfile.worker", start: 3, end: 3 });
  assert.deepEqual(primaryLocation("- **File**: `httpserver/middleware.go:116` (also `:145`), `httpserver/handler.go:219-350`"), { file: "httpserver/middleware.go", start: 116, end: 116 });
  for (const f of ["src/lib.rs", "src/Main.java", "app/models/user.rb", "lib/app.ex", "Controllers/Home.cs", "Sources/App.swift", "src/main.c", "deploy.sh", "go.mod"]) {
    assert.deepEqual(primaryLocation(`- **File**: \`${f}:7\``), { file: f.replace(/^app\//, ""), start: 7, end: 7 }, f);
  }
  assert.deepEqual(primaryLocation("- **File**: `infra/main.tf:12`"), { file: "infra/main.tf", start: 12, end: 12 });
  assert.deepEqual(primaryLocation("- **File**: `.npmrc:2`"), { file: ".npmrc", start: 2, end: 2 });
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

test("secondary locations: the rest of the File line, and the Evidence of a systematic finding only", () => {
  assert.deepEqual(citedLocations("`src/a.php:309,313,315` and `src/b.ts:13-17`, `:27-31`; `src/c.ts`"), [
    { file: "src/a.php", start: 309, end: 309 }, { file: "src/a.php", start: 313, end: 313 }, { file: "src/a.php", start: 315, end: 315 },
    { file: "src/b.ts", start: 13, end: 17 }, { file: "src/b.ts", start: 27, end: 31 },
  ]);
  assert.deepEqual(citedLocations("```\nsrc/x.ts:4 inside code\n```\n`src/y.ts:5`"), [{ file: "src/y.ts", start: 5, end: 5 }], "code blocks are skipped");
  const fileLine = "## Title\nT\n\n## Evidence\n- **File**: `src/a.ts:3`, `src/b.ts:9`\nsee `src/c.ts:7`\n\n## TRACE\n- **Sink**: `src/d.ts:1`\n";
  assert.deepEqual(secondaryLocations(fileLine), [{ file: "src/b.ts", start: 9, end: 9 }], "a plain finding: only the File line, never context cites");
  const systematic = "## Title\nT (systematic: 3 locations)\n\n## Evidence\n- **File**: `src/a.ts:3`\nSame class:\n- `src/b.ts:9,12`\n- `src/a.ts:3`\n\n## TRACE\n- **Sink**: `src/d.ts:1`\n";
  assert.deepEqual(secondaryLocations(systematic), [{ file: "src/b.ts", start: 9, end: 9 }, { file: "src/b.ts", start: 12, end: 12 }], "Evidence only, primary not repeated");
});

test("a systematic finding matches through a secondary location when its primary matches nothing", () => {
  const extra = "Same class, same root cause:\n- `src/server/jobs/digest.ts:34,41` interpolates names unescaped.\n";
  const r = run(finding("injection-001", { file: "src/lib/auth.ts:23", title: "HTML injection in emails (systematic: 2 locations)", extra }));
  const m = r.matches.find((x) => x.finding === "injection-001");
  assert.deepEqual(m.entries, ["B13"]);
  assert.equal(m.match, "secondary");
  assert.equal(m.secondary_location, "src/server/jobs/digest.ts:41");
  const b13 = r.seeded.find((s) => s.id === "B13");
  assert.deepEqual([b13.result, b13.match, b13.by], ["found", "secondary", ["injection-001"]]);
  assert.equal(r.found, 1);
  assert.equal(r.found_secondary, 1);
  assert.equal(r.secondary_matches, 1);
  assert.equal(r.matching, "exact", "a secondary location is still matched by file and line");
  const plain = run(finding("injection-002", { file: "src/lib/auth.ts:23", extra }));
  assert.deepEqual(entriesOf(plain, "injection-002"), [], "without the systematic marker the same cite is context");
});

test("secondary locations: one entry per finding, the nearest; the primary is always preferred", () => {
  const two = run(finding("auth-001", { file: "src/lib/auth.ts:23, src/server/jobs/digest.ts:33, src/app/api/export/route.ts:11" }));
  assert.deepEqual(entriesOf(two, "auth-001"), ["B03"], "distance 0 at B03 beats distance 2 at B13");
  assert.equal(two.found, 1, "no double counting across secondary locations");
  assert.equal(two.seeded.find((s) => s.id === "B13").result, "missed");
  const primary = run(finding("auth-002", { file: "src/app/(app)/invoices/actions.ts:10, src/app/api/export/route.ts:10" }));
  assert.deepEqual(entriesOf(primary, "auth-002"), ["B01"]);
  assert.equal(primary.matches[0].match, "exact");
  assert.equal(primary.seeded.find((s) => s.id === "B03").result, "missed", "secondaries are not tried when the primary matches");
  const both = run(
    finding("auth-003", { file: "src/app/api/export/route.ts:10" }),
    finding("auth-004", { file: "src/lib/auth.ts:23, src/app/api/export/route.ts:11" }),
  );
  const b03 = both.seeded.find((s) => s.id === "B03");
  assert.deepEqual([b03.match, b03.by], ["exact", ["auth-003", "auth-004"]], "an exact hit labels the entry exact");
});

test("decoys count only through the primary location", () => {
  const r = run(finding("concurrency-001", { file: "src/app/(app)/invoices/actions.ts:22-25; src/server/ai/billing-tools.ts:27-29" }));
  assert.equal(r.decoy_fp, 0, "a decoy hit by a secondary location is not a false positive");
  assert.deepEqual(r.decoySecondary, [{ decoy: "D13", finding: "concurrency-001", location: "src/server/ai/billing-tools.ts:27-29" }]);
  assert.deepEqual(r.unmatched.map((u) => u.id), ["concurrency-001"], "it stays listed for review");
  const next = run(finding("concurrency-002", { file: "src/app/(app)/invoices/actions.ts:22-25; src/server/ai/billing-tools.ts:13-17, :27-29" }));
  assert.deepEqual(entriesOf(next, "concurrency-002"), ["B22"], "a decoy secondary is skipped, the next location still matches");
  assert.equal(next.decoy_fp, 0);
  const prim = run(finding("concurrency-003", { file: "src/server/ai/billing-tools.ts:27, src/server/ai/billing-tools.ts:13" }));
  assert.deepEqual(entriesOf(prim, "concurrency-003"), ["D13"]);
  assert.equal(prim.decoy_fp, 1, "the primary location on a decoy still counts");
});

test("advisory entries take only dependency findings, and dependency findings only advisories", () => {
  const r = run(
    finding("dependency-001", { file: "src/server/api/index.ts:13" }), // hono advisory used in CORS, next to B16
    finding("config-001", { file: "src/server/api/index.ts:16" }),
    finding("config-002", { file: "next.config.ts:3" }),
    finding("dependency-002", { file: "next.config.ts:7" }),
    finding("dependency-003", { file: "package.json:28" }),
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

test("R08 seeds and decoys: CSRF, CI workflow, Dockerfile, install script", () => {
  const r = run(
    finding("auth-001", { file: "src/app/api/team/invite/route.ts:21" }),
    finding("config-001", { file: ".github/workflows/preview.yml:17" }),
    finding("config-002", { file: "Dockerfile:20" }),
    finding("dependency-001", { file: "package.json:14" }),
    finding("auth-002", { file: "src/app/(app)/settings/notifications/actions.ts:11" }),
    finding("config-003", { file: ".github/workflows/ci.yml:31" }),
    finding("config-004", { file: "docker-compose.yml:9" }),
  );
  assert.deepEqual(entriesOf(r, "auth-001"), ["B17"]);
  assert.deepEqual(entriesOf(r, "config-001"), ["B18"]);
  assert.deepEqual(entriesOf(r, "config-002"), ["B19"]);
  assert.deepEqual(entriesOf(r, "dependency-001"), ["B20"], "any_category: a dependency finding matches the install script");
  assert.deepEqual(entriesOf(r, "auth-002"), ["D09"]);
  assert.deepEqual(entriesOf(r, "config-003"), ["D10"]);
  assert.deepEqual(entriesOf(r, "config-004"), ["D11"]);
  assert.equal(r.decoy_fp, 3);
  const cfg = run(finding("config-005", { file: "package.json:14" }));
  assert.deepEqual(entriesOf(cfg, "config-005"), ["B20"], "the same seed filed as config also matches");
  const adv = run(finding("dependency-002", { file: "package.json:29" }));
  assert.deepEqual(entriesOf(adv, "dependency-002"), ["B14"], "next advisory line, shifted by the postinstall line");
});

test("R21 seeds and decoys: LLM output to HTML, unscoped agent tool, LLM cost", () => {
  const r = run(
    finding("injection-001", { file: "src/app/(app)/invoices/[id]/summary/page.tsx:37" }),
    finding("injection-002", { file: "src/app/(app)/invoices/[id]/summary/page.tsx:29" }),
    finding("auth-001", { file: "src/server/ai/billing-tools.ts:16" }),
    finding("rate-limit-001", { file: "src/app/api/assistant/billing/route.ts:16-18" }),
    finding("injection-003", { file: "src/app/(app)/invoices/[id]/summary/actions.ts:34" }),
    finding("auth-002", { file: "src/server/ai/billing-tools.ts:30" }),
  );
  assert.deepEqual(entriesOf(r, "injection-001"), ["B21"]);
  assert.deepEqual(entriesOf(r, "injection-002"), ["B21"], "the prompt built from notes is part of the same seed");
  assert.deepEqual(entriesOf(r, "auth-001"), ["B22"]);
  assert.deepEqual(entriesOf(r, "rate-limit-001"), ["B23"]);
  assert.deepEqual(entriesOf(r, "injection-003"), ["D12"]);
  assert.deepEqual(entriesOf(r, "auth-002"), ["D13"], "the scoped, approval-gated tool next to B22 stays a decoy");
  assert.equal(r.decoy_fp, 2);
  const between = run(finding("auth-003", { file: "src/server/ai/billing-tools.ts:22" }));
  assert.deepEqual(entriesOf(between, "auth-003"), ["D13"], "nearest wins between B22 and D13");
});

test("R21 key ranges point at the seeded statements", () => {
  const at = (file, line) => readFileSync(join(app, file), "utf8").split("\n")[line - 1];
  const loc = (id, i = 0) => [...key.seeded, ...key.decoys].find((e) => e.id === id).locations[i];
  assert.match(at(loc("B21").file, loc("B21").lines[0]), /HTML fragment/);
  assert.match(at(loc("B21", 1).file, loc("B21", 1).lines[0]), /dangerouslySetInnerHTML=\{\{ __html: summaryHtml \}\}/);
  assert.match(at(loc("B22").file, 16), /\.where\(eq\(invoices\.id, invoiceId\)\)/);
  assert.match(at(loc("B23").file, loc("B23").lines[0]), /type Body = .*model\?: string; maxTokens\?: number; maxSteps\?: number/);
  assert.match(at(loc("B23").file, 16), /body\.model/);
  assert.match(at(loc("B23").file, loc("B23").lines[1]), /body\.maxSteps/);
  assert.match(at(loc("D12").file, 34), /escapeHtml\(text\)/);
  assert.match(at(loc("D13").file, 25), /needsApproval: true/);
  assert.match(at(loc("D13").file, 30), /eq\(invoices\.orgId, ctx\.orgId\)/);
});

test("B23 range covers the request Body type through the generateText options", () => {
  const r = run(
    finding("rate-limit-001", { file: "src/app/api/assistant/billing/route.ts:6" }),
    finding("rate-limit-002", { file: "src/app/api/assistant/billing/route.ts:8" }),
    finding("rate-limit-003", { file: "src/app/api/assistant/billing/route.ts:20" }),
    finding("rate-limit-004", { file: "src/app/api/assistant/billing/route.ts:21" }),
  );
  assert.deepEqual(entriesOf(r, "rate-limit-001"), ["B23"], "cited at the Body type, as in the 2026-10-08 run");
  assert.deepEqual(entriesOf(r, "rate-limit-002"), ["B23"], "the handler signature");
  assert.deepEqual(entriesOf(r, "rate-limit-003"), ["B23"], "two lines below the generateText options");
  assert.deepEqual(entriesOf(r, "rate-limit-004"), [], "three lines below is outside the window");
  const decoys = key.decoys.flatMap((d) => d.locations).filter((l) => l.file === "src/app/api/assistant/billing/route.ts");
  assert.deepEqual(decoys, [], "no decoy shares the widened B23 file");
});

test("R23 seed and decoy: anonymous paid SMS, org-capped SMS reminder", () => {
  const r = run(
    finding("rate-limit-001", { file: "src/app/api/phone/send-code/route.ts:10" }),
    finding("rate-limit-002", { file: "src/app/api/phone/send-code/route.ts:21" }),
    finding("rate-limit-003", { file: "src/app/api/phone/send-code/route.ts:16" }),
    finding("rate-limit-004", { file: "src/app/(app)/invoices/[id]/sms-actions.ts:39" }),
    finding("rate-limit-005", { file: "src/lib/sms.ts:7" }),
  );
  assert.deepEqual(entriesOf(r, "rate-limit-001"), ["B24"], "the unauthenticated handler");
  assert.deepEqual(entriesOf(r, "rate-limit-002"), ["B24"], "the billed send");
  assert.deepEqual(entriesOf(r, "rate-limit-003"), [], "the code insert in between is outside both windows");
  assert.deepEqual(entriesOf(r, "rate-limit-004"), ["D14"], "the capped reminder stays a decoy");
  assert.deepEqual(entriesOf(r, "rate-limit-005"), [], "the shared SMS client is not the bug");
  assert.equal(r.decoy_fp, 1);
});

test("R23 key ranges point at the seeded statements", () => {
  const at = (file, line) => readFileSync(join(app, file), "utf8").split("\n")[line - 1];
  const loc = (id, i = 0) => [...key.seeded, ...key.decoys].find((e) => e.id === id).locations[i];
  assert.match(at(loc("B24").file, loc("B24").lines[0]), /export async function POST\(request: Request\)/);
  assert.match(at(loc("B24", 1).file, loc("B24", 1).lines[0]), /await sendSms\(\{ to: phone/);
  const route = readFileSync(join(app, loc("B24").file), "utf8");
  assert.doesNotMatch(route, /getSession|requireUser|requireOrg|rateLimit|captcha/i, "the seed stays unauthenticated and unthrottled");
  assert.match(at(loc("D14").file, loc("D14").lines[0]), /export async function sendSmsReminder/);
  assert.match(at(loc("D14").file, 13), /await requireOrg\(\)/);
  assert.match(at(loc("D14").file, 18), /eq\(invoices\.orgId, orgId\)/);
  assert.match(at(loc("D14").file, 24), /pg_advisory_xact_lock/);
  assert.match(at(loc("D14").file, 29), /ORG_DAILY_SMS_LIMIT/);
  assert.match(at(loc("D14").file, 33), /onConflictDoNothing/);
  assert.match(at(loc("D14").file, loc("D14").lines[1]), /^}$/);
  const gateway = readFileSync(join(app, ".env.example"), "utf8").match(/SMS_GATEWAY_URL=(\S+)/)[1];
  assert.equal(new URL(gateway).hostname, "sms.example.com", "the SMS gateway is a reserved example host");
});

test("R24 seed and decoy: org deletion that leaves stored documents, complete customer erasure", () => {
  const r = run(
    finding("exposure-001", { file: "src/app/(app)/settings/organization/actions.ts:10" }),
    finding("exposure-002", { file: "src/app/(app)/settings/organization/actions.ts:21" }),
    finding("exposure-003", { file: "src/app/(app)/settings/organization/actions.ts:15" }),
    finding("exposure-004", { file: "src/app/(app)/customers/actions.ts:33" }),
    finding("exposure-005", { file: "src/db/schema.ts:158" }),
  );
  assert.deepEqual(entriesOf(r, "exposure-001"), ["B25"], "the delete action");
  assert.deepEqual(entriesOf(r, "exposure-002"), ["B25"], "the cascading row delete");
  assert.deepEqual(entriesOf(r, "exposure-003"), [], "the owner check in between is outside both windows");
  assert.deepEqual(entriesOf(r, "exposure-004"), ["D15"], "the complete erasure stays a decoy");
  assert.deepEqual(entriesOf(r, "exposure-005"), [], "the cascade in the schema is not the bug");
  assert.equal(r.decoy_fp, 1);
});

test("R24 key ranges point at the seeded statements", () => {
  const at = (file, line) => readFileSync(join(app, file), "utf8").split("\n")[line - 1];
  const loc = (id, i = 0) => [...key.seeded, ...key.decoys].find((e) => e.id === id).locations[i];
  assert.match(at(loc("B25").file, loc("B25").lines[0]), /export async function deleteOrganization/);
  assert.match(at(loc("B25", 1).file, loc("B25", 1).lines[1]), /await db\.delete\(organization\)/);
  const action = readFileSync(join(app, loc("B25").file), "utf8");
  assert.match(action, /eq\(member\.role, "owner"\)/, "the seed is authorized: the bug is what it leaves behind");
  assert.doesNotMatch(action, /DeleteObject|s3Key|@\/lib\/s3/, "the seed never touches the stored objects");
  assert.match(readFileSync(join(app, "src/db/schema.ts"), "utf8"), /s3Key: text\("s3_key"\)/, "documents rows point at stored objects");
  assert.match(at(loc("D15").file, loc("D15").lines[0]), /export async function eraseCustomer/);
  assert.match(at(loc("D15").file, 12), /await requireOrg\(\)/);
  assert.match(at(loc("D15").file, 16), /inArray\(member\.role, \["owner", "admin"\]\)/);
  assert.match(at(loc("D15").file, 20), /db\.transaction/);
  assert.match(at(loc("D15").file, 24), /eq\(customers\.orgId, orgId\)/);
  assert.match(at(loc("D15").file, 33), /set\(\{ to: "erased" \}\)/);
  assert.match(at(loc("D15").file, loc("D15").lines[1]), /^}$/);
});

test("R25 seed and decoy: postMessage listener without an origin check, strict signing listener", () => {
  const r = run(
    finding("injection-001", { file: "src/components/payment-method-frame.tsx:14" }),
    finding("injection-002", { file: "src/components/payment-method-frame.tsx:18" }),
    finding("injection-003", { file: "src/components/payment-method-frame.tsx:30" }),
    finding("injection-004", { file: "src/components/signature-frame.tsx:22" }),
    finding("config-005", { file: "next.config.ts:3" }),
  );
  assert.deepEqual(entriesOf(r, "injection-001"), ["B26"], "the listener without an origin check");
  assert.deepEqual(entriesOf(r, "injection-002"), ["B26"], "the navigation sink");
  assert.deepEqual(entriesOf(r, "injection-003"), [], "the iframe markup is outside both windows");
  assert.deepEqual(entriesOf(r, "injection-004"), ["D16"], "the strict listener stays a decoy");
  assert.deepEqual(entriesOf(r, "config-005"), [], "missing frame-ancestors alone is not the seeded bug");
  assert.equal(r.decoy_fp, 1);
});

test("R25 key ranges point at the seeded statements", () => {
  const at = (file, line) => readFileSync(join(app, file), "utf8").split("\n")[line - 1];
  const loc = (id, i = 0) => [...key.seeded, ...key.decoys].find((e) => e.id === id).locations[i];
  assert.match(at(loc("B26").file, loc("B26").lines[0]), /function onMessage\(event: MessageEvent/);
  assert.match(at(loc("B26", 1).file, loc("B26", 1).lines[0]), /window\.location\.assign\(msg\.url\)/);
  const seed = readFileSync(join(app, loc("B26").file), "utf8");
  assert.doesNotMatch(seed, /event\.origin|event\.source|safeParse/, "the seed never checks the sender");
  assert.match(seed, /addEventListener\("message", onMessage\)/);
  assert.match(readFileSync(join(app, "src/app/(app)/settings/billing/page.tsx"), "utf8"), /<PaymentMethodFrame /, "the seed is rendered on the billing page");
  assert.match(at(loc("D16").file, loc("D16").lines[0]), /function onMessage\(event: MessageEvent\)/);
  assert.match(at(loc("D16").file, 22), /event\.origin !== SIGN_ORIGIN \|\| event\.source !== frame\.current\?\.contentWindow/);
  assert.match(at(loc("D16").file, 23), /signMessage\.safeParse\(event\.data\)/);
  assert.match(at(loc("D16").file, 27), /router\.refresh\(\)/);
  assert.match(at(loc("D16").file, loc("D16").lines[1]), /window\.removeEventListener/);
  const decoy = readFileSync(join(app, loc("D16").file), "utf8");
  assert.doesNotMatch(decoy, /location\.|innerHTML|postMessage\([^)]*"\*"/, "the decoy never navigates, renders HTML or posts to any origin");
  for (const f of [loc("B26").file, loc("D16").file]) {
    for (const u of readFileSync(join(app, f), "utf8").match(/https:\/\/[^"`/]+/g)) {
      assert.match(new URL(u).hostname, /\.example\.com$/, "widget hosts are reserved example hosts");
    }
  }
});

test("file_level: a finding citing the file with no line matches only entries that declare it", () => {
  const r = run(finding("exposure-001", { file: ".env", extra: "" }));
  assert.equal(r.matches.find((m) => m.finding === "exposure-001").distance, 0);
  assert.deepEqual(entriesOf(r, "exposure-001"), ["B15"]);
  assert.equal(r.seeded.find((s) => s.id === "B15").result, "found");
  const history = { stem: "exposure-002", data: { id: "exposure-002", category: "exposure", severity: "HIGH", status: "verified" }, body: "", text: "## Evidence\n- **File**: `.env` in commit 3ec2d73, removed in e9915ab\n" };
  assert.deepEqual(entriesOf(score([history], key), "exposure-002"), ["B15"], "the 2026-10-08 evidence line");
  assert.deepEqual(entriesOf(run(finding("exposure-003", { file: ".env:4" })), "exposure-003"), ["B15"], "a line still matches by range");
  assert.deepEqual(entriesOf(run(finding("exposure-004", { file: ".env:9" })), "exposure-004"), [], "a line outside the window does not fall back to file level");
  assert.deepEqual(entriesOf(run(finding("rate-limit-005", { file: "src/app/api/assistant/billing/route.ts" })), "rate-limit-005"), [], "entries without file_level still need a line");
  assert.deepEqual(entriesOf(run(finding("exposure-005", { file: ".env.example" })), "exposure-005"), [], "another file with the same prefix does not match");
  const keyed = [...key.seeded, ...key.decoys, ...key.known_extras].filter((e) => e.file_level).map((e) => e.id);
  assert.deepEqual(keyed, ["B15"], "file_level is the exception, not the rule");
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

test("--key and meta.key pick the answer key; a key with no seeded bugs is a control run", async () => {
  const { mkdtempSync, mkdirSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { spawnSync } = await import("node:child_process");
  const { resolveKey } = await import("../benchmark/score.mjs");
  const dir = mkdtempSync(join(tmpdir(), "sa-score-key-"));
  const keyFile = join(dir, "answer-key-1.0.0.json");
  writeFileSync(keyFile, JSON.stringify({ app: "real/demo-1.0.0", window: 2, seeded: [{ id: "SA-1", class: "demo", locations: [{ file: "src/a.php", lines: [3, 4] }] }], decoys: [], known_extras: [] }));
  const control = join(dir, "control.json");
  writeFileSync(control, JSON.stringify({ app: "real/demo-2.0.0", seeded: [], decoys: [{ id: "SA-1-fixed", locations: [{ file: "src/a.php", lines: [3, 4] }] }] }));

  assert.deepEqual(resolveKey(["run", "--key", keyFile], {}), { name: "real/demo-1.0.0", key: keyFile });
  assert.deepEqual(resolveKey(["run"], { key: keyFile, bench_app: "real/demo-1.0.0" }), { name: "real/demo-1.0.0", key: keyFile });
  assert.equal(resolveKey(["run", "--key", control], { key: keyFile }).key, control, "--key beats meta.key");
  assert.equal(resolveKey(["run", "--app", "php-tickets"], { key: keyFile }).name, "php-tickets", "--app beats meta.key");
  assert.equal(resolveKey(["run"], {}).name, "ledgerly");
  assert.equal(score([], JSON.parse(readFileSync(control, "utf8"))).recall, null);

  const run = join(dir, "run");
  mkdirSync(join(run, "app", ".security-audit", "findings"), { recursive: true });
  writeFileSync(join(run, "meta.json"), JSON.stringify({ bench_app: "real/demo-1.0.0", key: keyFile }));
  writeFileSync(join(run, "app", ".security-audit", "findings", "auth-001.md"), finding("auth-001", { file: "src/a.php:3" }).text);
  const cli = (...extra) => spawnSync(process.execPath, [join(repo, "benchmark", "score.mjs"), run, "--no-save", ...extra], { encoding: "utf8" });
  const viaMeta = cli();
  assert.equal(viaMeta.status, 0, viaMeta.stderr);
  assert.match(viaMeta.stdout, /^App real\/demo-1\.0\.0$/m);
  assert.match(viaMeta.stdout, /Recall 1\/1 \(100%\)/);
  const viaFlag = cli("--key", control, "--label", "control");
  assert.equal(viaFlag.status, 0, viaFlag.stderr);
  assert.match(viaFlag.stdout, /^App real\/demo-2\.0\.0$/m);
  assert.match(viaFlag.stdout, /Recall 0\/0 \(no seeded bugs: control run\).*decoy false positives 1/);
});
