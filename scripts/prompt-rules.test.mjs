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
