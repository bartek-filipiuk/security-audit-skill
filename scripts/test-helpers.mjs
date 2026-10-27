// Shared by the tests: an environment in which prepass finds no scanner, docker or package manager,
// so a test never runs a real tool or touches the network, whatever is installed on the machine.
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// fakes: { name: shell script body } installed next to git, e.g. a scanner that prints a fixture.
export function toolFreeEnv(fakes = {}) {
  const bin = mkdtempSync(join(tmpdir(), "sa-bin-"));
  const git = spawnSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).stdout.trim();
  if (git) symlinkSync(git, join(bin, "git"));
  for (const [name, body] of Object.entries(fakes)) {
    writeFileSync(join(bin, name), `#!/bin/sh\n${body}\n`);
    chmodSync(join(bin, name), 0o755);
  }
  return { ...process.env, PATH: bin };
}
