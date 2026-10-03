#!/usr/bin/env node
// Token usage and API-price cost of one Claude Code session, its subagents included. Every number
// published about a run is counted with this script, so runs and tools stay comparable.
//   node benchmark/usage.mjs <session-id | path/to/session.jsonl> [--until 2026-10-03T10:43:00Z]
//        [--in 4] [--out 20] [--cache-read 0.2] [--cache-5m 1.25] [--cache-1h 2]
// Prices are USD per million tokens; cache writes are multipliers of the input price. Defaults are the
// Opus 5.5 prices used for the 2026-10-03 Ledgerly run; pass the current ones for another model.
import { existsSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";

export function sumUsage(files, until = Infinity) {
  // One API response is written once per content block, and only the last copy has the final output
  // count, so keep the largest record per response.
  const byResponse = new Map();
  for (const file of files) {
    for (const line of readFileSync(file, "utf8").split("\n")) {
      if (!line.includes('"usage"')) continue;
      let d;
      try { d = JSON.parse(line); } catch { continue; }
      const u = d.message?.usage;
      if (!u || Date.parse(d.timestamp) > until) continue;
      const key = `${file}|${d.message.id}|${d.requestId}`;
      const prev = byResponse.get(key);
      if (!prev || (u.output_tokens ?? 0) >= (prev.output_tokens ?? 0)) byResponse.set(key, u);
    }
  }
  const t = { calls: byResponse.size, input: 0, cache_5m: 0, cache_1h: 0, cache_read: 0, output: 0 };
  for (const u of byResponse.values()) {
    const c5 = u.cache_creation?.ephemeral_5m_input_tokens;
    const c1 = u.cache_creation?.ephemeral_1h_input_tokens;
    t.input += u.input_tokens ?? 0;
    t.cache_5m += c5 ?? (c1 === undefined ? u.cache_creation_input_tokens ?? 0 : 0);
    t.cache_1h += c1 ?? 0;
    t.cache_read += u.cache_read_input_tokens ?? 0;
    t.output += u.output_tokens ?? 0;
  }
  t.total = t.input + t.cache_5m + t.cache_1h + t.cache_read + t.output;
  return t;
}

export function cost(t, p) {
  return (t.input * p.in + t.cache_5m * p.in * p.c5 + t.cache_1h * p.in * p.c1 + t.cache_read * p.cr + t.output * p.out) / 1e6;
}

function sessionFiles(arg) {
  let main = arg;
  if (!arg.endsWith(".jsonl")) {
    const root = join(homedir(), ".claude", "projects");
    const hit = readdirSync(root).map((d) => join(root, d, `${arg}.jsonl`)).find(existsSync);
    if (!hit) throw new Error(`session ${arg} not found under ${root}`);
    main = hit;
  }
  // Subagents live under <session>/subagents/, workflow agents one level deeper (subagents/workflows/<id>/).
  const sub = join(dirname(main), basename(main, ".jsonl"), "subagents");
  const found = existsSync(sub) ? readdirSync(sub, { recursive: true }).filter((n) => String(n).endsWith(".jsonl")).map((n) => join(sub, String(n))) : [];
  return [main, ...found];
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const opt = (name, def) => (args.includes(name) ? Number(args[args.indexOf(name) + 1]) : def);
  const until = args.includes("--until") ? Date.parse(args[args.indexOf("--until") + 1]) : Infinity;
  const target = args.find((a, i) => !a.startsWith("--") && !args[i - 1]?.startsWith("--"));
  if (!target) { console.error("usage: node benchmark/usage.mjs <session-id | session.jsonl> [--until ISO]"); process.exit(1); }
  const files = sessionFiles(target);
  const t = sumUsage(files, until);
  const usd = cost(t, { in: opt("--in", 4), out: opt("--out", 20), cr: opt("--cache-read", 0.2), c5: opt("--cache-5m", 1.25), c1: opt("--cache-1h", 2) });
  const m = (n) => (n / 1e6).toFixed(2) + "M";
  console.log(`${files.length} transcript(s), ${t.calls} API calls`);
  console.log(`total ${m(t.total)} = input ${m(t.input)} + cache write ${m(t.cache_5m + t.cache_1h)} + cache read ${m(t.cache_read)} (${Math.round((t.cache_read / t.total) * 100)}%) + output ${m(t.output)}`);
  console.log(`API-price cost: ${usd.toFixed(2)} USD`);
}
