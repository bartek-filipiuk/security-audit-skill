// Run: node --test scripts/*.test.mjs
// Rules in the agent prompts that a past run broke; each assertion keeps one of them from being edited away.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
const verifier = readFileSync(join(repo, "agents", "deep-dive-verifier.md"), "utf8");

test("verifier: unauthenticated config/admin writes are never dismissed as best practice", () => {
  const gate = verifier.match(/\*\*6c\. Vulnerability direction:\*\*[\s\S]*?(?=\*\*6d\.)/)?.[0] ?? "";
  assert.ok(gate, "6c gate present");
  assert.match(gate, /Never `best_practice`, never "framework convention", never "by design"/);
  assert.match(gate, /without authentication, or with an access requirement that passes for anonymous visitors/);
  assert.match(gate, /covers anonymous reach only/);
  assert.match(gate, /admin functionality/);
  assert.match(gate, /only valid rejection for these is a cited file:line of a control that actually blocks it/);
  assert.match(verifier, /Unauthenticated configuration or admin writes are never dismissed as accepted practice without the file:line of the control that blocks them \(6c\)/);
  assert.match(verifier, /Other findings keep the usual standard/);
});

test("checklist: the SAML/SSO service-provider subsection sits under 2.1 and its patterns reach every brief", async () => {
  const { patternsFor } = await import("./briefs.mjs");
  const ck = readFileSync(join(repo, "references", "audit-checklist.md"), "utf8");
  const auth = ck.match(/^## 2\.1 [\s\S]*?(?=^## )/m)?.[0] ?? "";
  const saml = auth.match(/^### SAML and SSO service providers[\s\S]*$/m)?.[0] ?? "";
  assert.ok(saml, "SAML subsection inside 2.1, so the auth brief carries it");
  for (const re of [
    /allow-list configured on the SP[^.]*never from the `SignatureMethod`/,
    /failed or missing signature check stops the login/,
    /`InResponseTo` matches a request id the SP issued/,
    /accepted once/,
    /`NotBefore`\/`NotOnOrAfter` are enforced/,
    /`Audience` and `Recipient`\/`Destination`/,
    /configuration, never with a certificate or key embedded in the response/,
    /constant-time function/,
    /fetched only from hosts configured by an administrator/,
    /without following redirects/,
    /disabled in production or requires an administrator permission/,
    /without escaping/,
  ]) assert.match(saml, re);
  const items = saml.split("\n").filter((l) => l.startsWith("- [ ]"));
  assert.ok(items.length >= 6);
  for (const item of items) assert.match(item, /Regression test:/, `${item.slice(0, 40)}… has a regression test idea`);
  assert.doesNotMatch(saml, /exploit|payload|attack step|proof of concept/i, "defensive wording only");
  for (const langs of [["js"], ["php"], ["python"]]) assert.match(patternsFor(langs), /## SAML and SSO \(service provider\)\n\| Area[\s\S]*\| Signature result \|[\s\S]*\| Debug \/ test ACS \|/);
});

test("checklist: token, signature and key API checks sit under 2.8 and reach the brief that owns 2.8", async () => {
  const { patternsFor } = await import("./briefs.mjs");
  const ck = readFileSync(join(repo, "references", "audit-checklist.md"), "utf8");
  const crypto = ck.match(/^## 2\.8 [\s\S]*?(?=^## )/m)?.[0] ?? "";
  assert.match(crypto, /Never skip when recon marks the project crypto-heavy/);
  assert.doesNotMatch(crypto, /^Skip if no crypto code found in recon\.$/m, "no unconditional skip");
  const api = crypto.match(/^### Token, signature and key APIs[\s\S]*$/m)?.[0] ?? "";
  assert.ok(api, "subsection inside 2.8, so the crypto brief carries it");
  for (const re of [
    /Library mode: when the project itself is a crypto, auth or token library, its exported API is the attack surface/,
    /every exported sign\/verify\/decode\/encrypt function and each of its options as an entry point/,
    /A public key, certificate or JWK in any serialisation[^.]*is never usable as an HMAC secret/,
    /never from the token header/,
    /empty string, `null`, `undefined`, zero-length buffer[^.]*throws/,
    /never means "no signature required"/,
    /explicit, separately named opt-in, and never when a key or an algorithm allow-list is also given/,
    /array, string, number, `null` or other non-object JSON is rejected before the validators/,
    /constant-time function/,
    /fresh random IV\/nonce per encryption/,
    /AEAD tags verified before any plaintext is used/,
    /CBC\/CTR only with a MAC checked first/,
    /`exp`, `nbf` and max-age are rechecked against the current time on every cache hit/,
    /Library defaults fail closed/,
  ]) assert.match(api, re);
  const items = api.split("\n").filter((l) => l.startsWith("- [ ]"));
  assert.ok(items.length >= 8);
  for (const item of items) {
    assert.match(item, /Safe control:/, `${item.slice(0, 40)}… names the safe control`);
    assert.match(item, /Regression test:/, `${item.slice(0, 40)}… has a regression test idea`);
  }
  assert.doesNotMatch(api, /exploit|attack step|proof of concept/i, "defensive wording only");
  assert.doesNotMatch(api, /\b[a-z0-9]+-jwt\b/i, "generic, no real package names");
  for (const langs of [["js"], ["php"], ["python"]]) assert.match(patternsFor(langs), /## Cryptography Red Flags[\s\S]*Algorithm taken from the token[\s\S]*Timing-unsafe compare[\s\S]*IV\/nonce reuse/);
});

test("routing: a crypto-heavy project moves 2.8 to the auth auditor and never skips it", async () => {
  const { cryptoHeavy, DEFAULT_BRIEFS } = await import("./briefs.mjs");
  const moved = cryptoHeavy(DEFAULT_BRIEFS);
  assert.ok(moved.auth.includes("2.8") && moved.auth.includes("2.1"));
  assert.ok(!moved.infra.includes("2.8"));
  assert.deepEqual(Object.values(moved).flat().sort(), Object.values(DEFAULT_BRIEFS).flat().sort(), "no section lost or doubled");
  assert.deepEqual(DEFAULT_BRIEFS.infra, ["2.5", "2.7", "2.8", "2.12"], "defaults untouched");
  const custom = cryptoHeavy({ a1: ["2.1", "2.3"], a2: ["2.10", "2.11"], infra: ["2.5", "2.8"] });
  assert.deepEqual(custom.a1, ["2.1", "2.8", "2.3"]);
  assert.deepEqual(custom.infra, ["2.5"]);
  const skill = readFileSync(join(repo, "SKILL.md"), "utf8");
  assert.match(skill, /Crypto-heavy project: add `--crypto-heavy`, which moves 2\.8 to the Auth Auditor; 2\.8 is then never skipped/);
  assert.match(skill, /no crypto → skip 2\.8, never when recon marks the project crypto-heavy/);
  const recon = readFileSync(join(repo, "agents", "recon-scanner.md"), "utf8");
  assert.match(recon, /\*\*Crypto-heavy: yes\*\* when the project is a crypto, auth or token library/);
  const format = readFileSync(join(repo, "references", "finding-format.md"), "utf8");
  assert.match(format, /- Crypto-heavy: \[yes\/no, one line of evidence\]/);
});

test("verifier: crypto and token defaults that allow forgery are never dismissed as documented behaviour", () => {
  const gate = verifier.match(/\*\*6c\. Vulnerability direction:\*\*[\s\S]*?(?=\*\*6d\.)/)?.[0] ?? "";
  const rule = gate.match(/\*\*Crypto and token defaults, never "documented behaviour":\*\*[^\n]*/)?.[0] ?? "";
  assert.ok(rule, "crypto rule inside 6c");
  assert.match(rule, /never `best_practice`, "documented behaviour" or "the caller's responsibility"/);
  assert.match(rule, /a key of the wrong type, an empty or null key, an algorithm from the token header, a non-object payload, a cache hit/);
  assert.match(rule, /Documentation of the behaviour and advice to pass a safer option are not controls/);
  assert.match(rule, /In a library, the exported function with its default options is the entry point/);
  assert.match(rule, /only valid rejection is a cited file:line of a check that blocks it/);
  assert.match(rule, /keep the usual standard/);
  assert.match(verifier, /Neither are crypto or token defaults that allow forgery or skip claim validation, whatever the documentation says \(6c\)/);
  assert.match(verifier, /\*\*Token or signature verify issue found\*\*/);
  assert.match(verifier, /Crypto and token APIs: the regression test generates its own keys inside the test/);
});
