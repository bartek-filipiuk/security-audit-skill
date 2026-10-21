// Run: node --test scripts/*.test.mjs
// Rules in the agent prompts that a past run broke; each assertion keeps one of them from being edited away.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
const verifier = readFileSync(join(repo, "agents", "deep-dive-verifier.md"), "utf8");

test("verifier: unauthenticated config/admin writes and shipped secrets are never dismissed as best practice", () => {
  const gate = verifier.match(/\*\*6c\. Vulnerability direction:\*\*[\s\S]*?(?=\*\*6d\.)/)?.[0] ?? "";
  assert.ok(gate, "6c gate present");
  assert.match(gate, /Never `best_practice`, never "framework convention", never "by design"/);
  assert.match(gate, /without authentication, or with an access requirement that always passes, that writes configuration/);
  assert.match(gate, /admin functionality/);
  assert.match(gate, /vendor API credentials[^.]*embedded in shipped source/);
  assert.match(gate, /only valid rejection for these is a cited file:line of a control that actually blocks it/);
  assert.match(verifier, /never dismissed without it \(6c\)/);
});
