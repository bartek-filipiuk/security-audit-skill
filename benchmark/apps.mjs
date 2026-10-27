// Benchmark apps. Ledgerly keeps the original layout (benchmark/app, benchmark/answer-key.json); every
// other app, such as a stack profile's (AGENTS.md), lives in benchmark/<name>/app with
// benchmark/<name>/answer-key.json next to it, outside the directory the audit sees.

import { existsSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
export const DEFAULT_APP = "ledgerly";

export function listApps(root = here) {
  const others = readdirSync(root, { withFileTypes: true })
    .filter((d) => d.isDirectory() && existsSync(join(root, d.name, "app")) && existsSync(join(root, d.name, "answer-key.json")))
    .map((d) => d.name);
  return [DEFAULT_APP, ...others.filter((n) => n !== DEFAULT_APP && n !== "app").sort()];
}

export function benchApp(name = DEFAULT_APP, root = here) {
  if (!listApps(root).includes(name)) throw new Error(`unknown benchmark app "${name}": use one of ${listApps(root).join(", ")}`);
  const base = name === DEFAULT_APP ? root : join(root, name);
  return { name, app: join(base, "app"), key: join(base, "answer-key.json") };
}
