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
