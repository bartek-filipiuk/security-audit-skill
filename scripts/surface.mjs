// Static entry-point scan for the security-audit pre-pass. No dependencies.
// 1. Entry points by framework convention (Next.js App/Pages Router, server actions, proxy/middleware,
//    tRPC, Hono/Express, pg-boss/BullMQ/cron, AI SDK / MCP tools, Drupal routing.yml, Supabase Edge
//    Functions, Firebase Cloud Functions, Laravel routes/*.php, Symfony #[Route] attributes and
//    config/routes*.yaml).
// 2. Drizzle scope scan: query sites on tables that carry an owner/tenant column but whose statement
//    never references that column.
// 3. Policy scan (roadmap R02): Supabase migrations (RLS, policies, SECURITY DEFINER functions, storage
//    buckets) and Firebase security rules; its rows join the hotspot ranking.
// ponytail: regex heuristics over source text, not an AST. Every row is a candidate for an agent to
// verify, never a verdict. Known ceilings: aliased table imports, scope applied through a helper or a
// pre-built `where` variable, inserts (owner taken from the request body) are not checked. Upgrade
// path: ts-morph/TypeScript compiler API if the false-candidate rate gets annoying.

import { lstatSync, readdirSync, readFileSync } from "node:fs";
import { basename, join, relative, sep } from "node:path";

export const SKIP_DIRS = new Set([
  "node_modules", ".git", ".next", "dist", "build", "out", "coverage", ".turbo", ".vercel",
  ".security-audit", "vendor", ".svelte-kit", ".output", ".cache", "storybook-static",
]);
const CODE_RE = /\.(?:[cm]?[jt]sx?)$/;
const DRUPAL_RE = /\.routing\.yml$/;
// PHP profile (roadmap R05): PHP sources and Blade/Twig templates, Symfony route and security config.
const PHP_RE = /\.(?:php|module|inc|theme|install)$/;
const TWIG_RE = /\.twig$/;
const SYMFONY_CFG_RE = /(^|\/)config\/(?:routes(?:\/[^/]+)?|packages\/security)\.ya?ml$/;
// Read for the policy scan only, never scanned as code.
const POLICY_RE = /(^|\/)supabase\/(?:migrations\/[^/]+\.sql|config\.toml)$|(^|\/)(?:firestore|storage)\.rules$/;
export const LOCKFILES = new Set([
  "pnpm-lock.yaml", "package-lock.json", "yarn.lock", "bun.lock", "composer.lock",
  "poetry.lock", "uv.lock", "requirements.txt", "go.sum", "Cargo.lock", "Gemfile.lock",
]);

export function walk(root) {
  const files = [];
  const lockfiles = [];
  (function rec(dir) {
    for (const name of readdirSync(dir)) {
      if (SKIP_DIRS.has(name)) continue;
      const p = join(dir, name);
      const st = lstatSync(p);
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) { rec(p); continue; }
      const rel = relative(root, p).split(sep).join("/");
      if (LOCKFILES.has(name)) lockfiles.push(rel);
      if ((CODE_RE.test(name) || DRUPAL_RE.test(name) || POLICY_RE.test(rel) || PHP_RE.test(name) || TWIG_RE.test(name) || SYMFONY_CFG_RE.test(rel)) && st.size < 1_000_000) {
        files.push({ path: rel, text: readFileSync(p, "utf8") });
      }
    }
  })(root);
  return { files, lockfiles };
}

function lineIndex(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === "\n") starts.push(i + 1);
  return (idx) => {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= idx) lo = mid; else hi = mid - 1;
    }
    return lo + 1;
  };
}

// Walks forward from `from`, skipping strings and comments, and returns the index where `stop` says so.
function scan(text, from, stop) {
  let depth = 0;
  for (let i = from; i < text.length; i++) {
    const c = text[i];
    if (c === '"' || c === "'" || c === "`") {
      for (i++; i < text.length && text[i] !== c; i++) if (text[i] === "\\") i++;
      continue;
    }
    if (c === "/" && text[i + 1] === "/") { i = text.indexOf("\n", i); if (i < 0) return text.length; continue; }
    if (c === "/" && text[i + 1] === "*") { i = text.indexOf("*/", i + 2); if (i < 0) return text.length; i++; continue; }
    if (c === "(" || c === "{" || c === "[") depth++;
    else if (c === ")" || c === "}" || c === "]") depth--;
    const r = stop(c, depth, i);
    if (r !== undefined) return r;
  }
  return text.length;
}

const matchClose = (text, open) => scan(text, open, (c, depth, i) => (depth === 0 ? i : undefined));

function splitTopLevel(body) {
  const parts = [];
  let last = 0;
  scan(body, 0, (c, depth, i) => {
    if (c === "," && depth === 0) { parts.push(body.slice(last, i)); last = i + 1; }
  });
  parts.push(body.slice(last));
  return parts.map((s) => s.trim()).filter(Boolean);
}

// ---------------------------------------------------------------- entry points

const HTTP = "GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS";
// Guard-like calls by naming family (requireTenant, ensureMember, getServerSession, withAuth, ...).
const GUARD_RE = /\b((?:require)[A-Z]\w*|(?:ensure|assert)(?:Auth|User|Admin|Role|Access|Tenant|Member|Org|Owner|Permission|Can|Session|Logged)\w*|(?:authenticate|authorize|authorise)\w*|verify(?:ApiKey|Key|Token|Session|Auth|Jwt|Signature|Webhook)\w*|get\w*Session|getCurrent\w*|currentUser|getUser|with(?:Auth|Session|Tenant|User|Admin|Org|Role|Permission)\w*|auth\.api\.getSession|auth\(\)|checkPermission|hasPermission|can[A-Z]\w*|validateRequest|protect)\b/g;
const HONO_RECEIVER = /^(app|api|router|server|hono|route|routes|admin|v1|v2|\w*(?:Router|App|Api|Routes))$/;

function guardsIn(snippet) {
  return [...new Set([...snippet.matchAll(GUARD_RE)].map((m) => m[1]))].join(", ");
}

function bodyAt(text, idx) {
  const next = text.slice(idx + 1).search(/\nexport\s/);
  return next < 0 ? text.slice(idx) : text.slice(idx, idx + 1 + next);
}

function appRoute(path) {
  const parts = path.split("/");
  const from = Math.max(0, parts.indexOf("src"));
  const i = parts.indexOf("app", from) >= 0 ? parts.indexOf("app", from) : parts.indexOf("pages", from);
  const segs = parts.slice(i + 1, -1).filter((s) => !s.startsWith("(") && !s.startsWith("@"));
  return "/" + segs.join("/");
}

// `verify_jwt` for one function from supabase/config.toml: false, true, or null when not set (default on).
function edgeVerifyJwt(files, fnPath, name) {
  const cfgPath = fnPath.replace(/supabase\/functions\/.*$/, "supabase/config.toml");
  const cfg = files.find((x) => x.path === cfgPath)?.text ?? "";
  const block = cfg.split(/^\s*\[/m).find((b) => b.startsWith(`functions.${name}]`)) ?? "";
  const v = block.match(/^\s*verify_jwt\s*=\s*(true|false)/m)?.[1];
  return v ? v === "true" : null;
}

export function scanEntryPoints(files) {
  const out = [];
  const add = (f, line, kind, name, route, guard) => out.push({ kind, name, route, file: f.path, line, guard: guard || "" });

  for (const f of files) {
    const { text, path } = f;
    if (NON_RUNTIME.test(path) || POLICY_RE.test(path)) continue;
    const lineAt = lineIndex(text);
    const fname = basename(path);

    if (PHP_RE.test(path) || TWIG_RE.test(path) || SYMFONY_CFG_RE.test(path)) {
      for (const e of phpEntryPoints(f, files)) out.push(e);
      continue;
    }

    // Supabase Edge Functions: public HTTPS endpoints; the gateway checks a JWT unless verify_jwt = false.
    const edge = path.match(/(?:^|\/)supabase\/functions\/([\w-]+)\/index\.[cm]?[jt]sx?$/);
    if (edge && edge[1] !== "_shared") {
      const verifyJwt = edgeVerifyJwt(files, path, edge[1]);
      const at = text.search(/\bDeno\.serve\(|\bserve\(|export\s+default\b/);
      add(f, at < 0 ? 1 : lineAt(at), "edge-function", edge[1], `/functions/v1/${edge[1]}`, [verifyJwt === false ? "" : "gateway verify_jwt", guardsIn(text)].filter(Boolean).join(", "));
      out[out.length - 1].verifyJwt = verifyJwt !== false;
      continue;
    }
    // Firebase Cloud Functions (v1 and v2): run with the Admin SDK, so security rules do not apply.
    for (const m of text.matchAll(/export\s+const\s+(\w+)\s*=\s*(?:functions(?:\s*\.\s*\w+\([^)]*\))*\s*\.\s*https\s*\.\s*|https\s*\.\s*)?(onCall|onRequest)\s*\(/g)) {
      const body = bodyAt(text, m.index);
      const auth = /\b(?:request|context)\.auth\b/.test(body) ? "request.auth" : "";
      add(f, lineAt(m.index), "cloud-function", m[1], m[2] === "onCall" ? "callable" : "https", [auth, guardsIn(body)].filter(Boolean).join(", "));
    }

    if (DRUPAL_RE.test(path)) {
      for (const m of text.matchAll(/^([\w.]+):\s*\n((?:[ \t]+.*\n?|\s*\n)*)/gm)) {
        const block = m[2];
        const route = block.match(/^\s*path:\s*['"]?([^'"\n]+)/m)?.[1] ?? "";
        const reqs = [...block.matchAll(/^\s*(_(?:permission|access|role|custom_access|entity_access|csrf_token|user_is_logged_in|format))\s*:\s*(.+)$/gm)]
          .map((r) => `${r[1]}: ${r[2].trim()}`).join("; ");
        if (!route) continue;
        add(f, lineAt(m.index), "drupal-route", m[1], route, reqs || "NO REQUIREMENTS");
        const ctl = block.match(/^\s*_(?:controller|form)\s*:\s*['"]?\\?([\w\\]+?)(?:::(\w+))?['"]?\s*$/m);
        if (ctl) out[out.length - 1].phpHandler = { cls: ctl[1].split("\\").pop(), method: ctl[2] ?? "" };
        const methods = block.match(/^\s*methods\s*:\s*\[([^\]]*)\]/m)?.[1];
        if (methods) out[out.length - 1].methods = methods.replace(/['"\s]/g, "").toUpperCase();
      }
      continue;
    }

    // Next.js App Router route handlers + pages
    if (/(^|\/)app\/(.+\/)?route\.[cm]?[jt]sx?$/.test(path)) {
      const route = appRoute(path);
      const kind = /webhook/i.test(route) ? "webhook" : "route-handler";
      const seen = new Set();
      const push = (method, idx) => {
        if (seen.has(method)) return;
        seen.add(method);
        add(f, lineAt(idx), kind, method, route, guardsIn(bodyAt(text, idx)));
      };
      for (const m of text.matchAll(new RegExp(`export\\s+(?:async\\s+)?function\\s+(${HTTP})\\b`, "g"))) push(m[1], m.index);
      for (const m of text.matchAll(new RegExp(`export\\s+const\\s+(${HTTP})\\b`, "g"))) push(m[1], m.index);
      for (const m of text.matchAll(/export\s+(?:const\s*)?\{([^}]*)\}/g)) {
        for (const part of m[1].split(",")) {
          const name = part.trim().split(/\s+as\s+/).pop()?.trim();
          if (name && new RegExp(`^(${HTTP})$`).test(name)) push(name, m.index);
        }
      }
      continue;
    }
    if (/(^|\/)app\/(.+\/)?page\.[cm]?[jt]sx?$/.test(path)) {
      add(f, 1, "page", "page", appRoute(path), guardsIn(text));
    }
    if (/(^|\/)pages\/api\//.test(path) && CODE_RE.test(path)) {
      add(f, 1, "api-route", "default", "/" + path.split("pages/")[1].replace(CODE_RE, "").replace(/\/index$/, ""), guardsIn(text));
    }

    // proxy.ts / middleware.ts
    if (/^(?:src\/)?(?:middleware|proxy)\.[cm]?[jt]s$/.test(path) || /\/(?:middleware|proxy)\.[cm]?[jt]s$/.test(path) && /export\s+(?:async\s+)?function\s+(?:middleware|proxy)\b/.test(text)) {
      const matcher = text.match(/matcher\s*:\s*(\[[\s\S]*?\]|["'`][^"'`]*["'`])/)?.[1]?.replace(/\s+/g, " ") ?? "NO MATCHER (runs on every route)";
      add(f, 1, "middleware", fname.replace(/\.\w+$/, ""), "*", `matcher: ${matcher}`);
    }

    // Server actions: file-level directive, then inline ones
    const fileLevel = /^(?:\s*(?:\/\/[^\n]*|\/\*[\s\S]*?\*\/))*\s*['"]use server['"]/.test(text);
    if (fileLevel) {
      for (const m of text.matchAll(/export\s+(?:async\s+)?function\s+(\w+)|export\s+const\s+(\w+)\s*=/g)) {
        add(f, lineAt(m.index), "server-action", m[1] ?? m[2], "POST (action id)", guardsIn(bodyAt(text, m.index)));
      }
    } else {
      // Only a directive statement on its own line, not the string inside a lint rule or a test.
      for (const m of text.matchAll(/^[ \t]*['"]use server['"];?[ \t]*$/gm)) {
        const before = text.slice(Math.max(0, m.index - 400), m.index);
        const fn = [...before.matchAll(/(?:async\s+function\s+(\w+)|(?:const|let)\s+(\w+)\s*=\s*async)/g)].pop();
        add(f, lineAt(m.index), "server-action", fn ? fn[1] ?? fn[2] : "(inline)", "POST (action id)", guardsIn(text.slice(m.index, m.index + 1500)));
      }
    }

    // tRPC procedures
    const routerDefs = [...text.matchAll(/(?:const|let)\s+(\w+)\s*=\s*(?:\w+\.)?(?:router|createTRPCRouter)\s*\(/g)];
    const procs = [...text.matchAll(/(\w+)\s*:\s*(\w*[Pp]rocedure)\b/g)];
    procs.forEach((m, i) => {
      const end = i + 1 < procs.length ? procs[i + 1].index : m.index + 3000;
      const kind = text.slice(m.index, end).match(/\.(query|mutation|subscription)\s*\(/)?.[1];
      if (!kind) return;
      const owner = routerDefs.filter((r) => r.index < m.index).pop()?.[1];
      add(f, lineAt(m.index), "trpc", owner ? `${owner}.${m[1]}` : m[1], kind, m[2]);
    });

    // Hono / Express style routes
    const basePath = text.match(/basePath\(\s*["'`]([^"'`]+)["'`]/)?.[1] ?? "";
    const fileUses = /\.use\(\s*["'`*]/.test(text) ? "file has .use() middleware" : "";
    for (const m of text.matchAll(/\b([A-Za-z_$][\w$]*)\.(get|post|put|patch|delete|all|options)\(\s*(["'`])(\/[^"'`]*)\3/g)) {
      if (!HONO_RECEIVER.test(m[1])) continue;
      add(f, lineAt(m.index), "http-route", m[2].toUpperCase(), basePath + m[4], guardsIn(text.slice(m.index, m.index + 800)) || fileUses);
    }
    for (const m of text.matchAll(/\b([A-Za-z_$][\w$]*)\.route\(\s*(["'`])(\/[^"'`]*)\2/g)) {
      if (HONO_RECEIVER.test(m[1])) add(f, lineAt(m.index), "http-mount", "route", basePath + m[3], "");
    }

    // Hand-rolled routers (node:http, Bun.serve, Deno.serve): route maps, path comparisons, prefixes.
    // ponytail: string-literal heuristics; a dynamic router built from data is invisible here.
    if (!/(^|\/)app\//.test(path)) {
      const seen = new Set();
      const addPath = (m, kind, route, handler) => {
        if (seen.has(route) || route.length < 2) return;
        seen.add(route);
        add(f, lineAt(m.index), kind, handler ?? route, route, guardsIn(text.slice(m.index, m.index + 1500)));
        if (handler) out[out.length - 1].handler = handler;
      };
      for (const m of text.matchAll(/["'`](\/[\w\-./:]*)["'`]\s*:\s*([A-Za-z_$][\w$]*)\s*[,}\n]/g)) addPath(m, "http-path", m[1], m[2]);
      for (const m of text.matchAll(/["'`](\/[\w\-./:]*)["'`]\s*:\s*["'`]([\w-]+)["'`]/g)) addPath(m, "http-path", m[1]);
      for (const m of text.matchAll(/(?:const|let)\s+(\w*(?:PATH|PREFIX|ROUTE)\w*)\s*=\s*["'`](\/[\w\-./:]*)["'`]/g)) addPath(m, "http-path", m[2]);
      for (const set of text.matchAll(/new\s+Set\s*(?:<[^>]*>)?\(\s*\[([^\]]*)\]/g)) {
        for (const m of set[1].matchAll(/["'`](\/[\w\-./:]+)["'`]/g)) addPath({ index: set.index }, "http-path", m[1]);
      }
      for (const m of text.matchAll(/\b(?:pathname|path|route|\w+\.pathname)\s*===?\s*["'`](\/[\w\-./:]*)["'`]/g)) addPath(m, "http-path", m[1]);
      for (const m of text.matchAll(/\bcase\s+["'`](\/[\w\-./:]*)["'`]\s*:/g)) addPath(m, "http-path", m[1]);
      for (const m of text.matchAll(/\b(?:pathname|path|\w+\.pathname)\.startsWith\(\s*["'`](\/[\w\-./]*)["'`]/g)) addPath(m, "http-prefix", m[1] + "*");
    }

    // Background jobs and schedules
    for (const m of text.matchAll(/\.work\s*(?:<[^>]*>)?\(\s*["'`]([^"'`]+)["'`]/g)) add(f, lineAt(m.index), "job", m[1], "queue", "");
    for (const m of text.matchAll(/new\s+Worker\s*(?:<[^>]*>)?\(\s*["'`]([^"'`]+)["'`]/g)) add(f, lineAt(m.index), "job", m[1], "queue", "");
    for (const m of text.matchAll(/\.schedule\(\s*["'`]([^"'`]+)["'`]\s*,\s*["'`]([^"'`]+)["'`]/g)) add(f, lineAt(m.index), "cron", m[1], m[2], "");

    // LLM tools (AI SDK `name: tool({`, Claude Agent SDK / MCP `tool("name"`)
    const toolLines = new Set();
    for (const m of text.matchAll(/(\w+)\s*:\s*tool\(\s*\{/g)) { toolLines.add(lineAt(m.index)); add(f, lineAt(m.index), "ai-tool", m[1], "model-invoked", "args come from the prompt"); }
    for (const m of text.matchAll(/(?:\.(?:tool|registerTool)|\btool)\(\s*["'`]([\w.-]+)["'`]/g)) {
      if (!toolLines.has(lineAt(m.index))) add(f, lineAt(m.index), "ai-tool", m[1], "model-invoked", "args come from the prompt");
    }
  }
  return out;
}

// ---------------------------------------------------------------- PHP entry points (roadmap R05)

// Laravel routes/*.php (with group middleware and prefixes), Symfony #[Route]/@Route attributes and
// config/routes*.yaml (with the access_control rule that covers the path). Drupal routing.yml is above.
// ponytail: regex over source text; routes registered from a loop, a package or RouteServiceProvider
// prefixes other than routes/api.php are invisible. Each row is a candidate, never a verdict.
const LARAVEL_ROUTES_RE = /(^|\/)routes\/(?!console\.php$|channels\.php$)[\w-]+\.php$/;
const LARAVEL_VERB = "get|post|put|patch|delete|options|any|match|resource|apiResource";
const LARAVEL_AUTH_MW = /^(?:auth(?::[\w,]+)?|can:.+|verified|signed|password\.confirm|role:.+|permission:.+|admin|abilities:.+|ability:.+)$/;
const quoted = (s) => [...(s ?? "").matchAll(/['"]([^'"]+)['"]/g)].map((m) => m[1]);
const joinPath = (...parts) => "/" + parts.map((p) => p.replace(/^\/+|\/+$/g, "")).filter(Boolean).join("/");

function laravelHandler(stmt) {
  let m = stmt.match(/\[\s*\\?([\w\\]+)::class\s*,\s*['"](\w+)['"]\s*\]/);
  if (m) return { cls: m[1].split("\\").pop(), method: m[2] };
  m = stmt.match(/['"]([\w\\]+)@(\w+)['"]/);
  if (m) return { cls: m[1].split("\\").pop(), method: m[2] };
  m = stmt.match(/,\s*\\?([\w\\]+)::class\s*[,)]/);
  if (m) return { cls: m[1].split("\\").pop(), method: "__invoke" };
  return null;
}

export function scanLaravelRoutes(f) {
  const { text, path } = f;
  const lineAt = lineIndex(text);
  const base = /(^|\/)routes\/api\.php$/.test(path) ? "/api" : "";
  const groups = [];
  for (const m of text.matchAll(/Route::((?:\w+\((?:[^()]|\([^()]*\))*\)\s*->\s*)*)group\s*\(/g)) {
    const open = text.indexOf("{", m.index + m[0].length);
    if (open < 0) continue;
    const chain = m[1];
    const arr = chain ? "" : text.slice(m.index + m[0].length, open);
    const mw = chain
      ? [...chain.matchAll(/middleware\(\s*(\[[^\]]*\]|['"][^'"]*['"])/g)].flatMap((x) => quoted(x[1]))
      : quoted(arr.match(/['"]middleware['"]\s*=>\s*(\[[^\]]*\]|['"][^'"]*['"])/)?.[1]);
    const prefix = (chain.match(/prefix\(\s*['"]([^'"]*)['"]/) ?? arr.match(/['"]prefix['"]\s*=>\s*['"]([^'"]*)['"]/))?.[1] ?? "";
    groups.push({ open, close: matchClose(text, open), mw, prefix });
  }
  const out = [];
  const re = new RegExp(`Route::((?:\\w+\\((?:[^()]|\\([^()]*\\))*\\)\\s*->\\s*)*)(${LARAVEL_VERB})\\s*\\(\\s*(?:\\[[^\\]]*\\]\\s*,\\s*)?(['"])([^'"]*)\\3`, "g");
  for (const m of text.matchAll(re)) {
    const end = scan(text, m.index, (c, depth, i) => (c === ";" && depth <= 0 ? i : undefined));
    const stmt = text.slice(m.index, end);
    const outer = groups.filter((g) => g.open < m.index && m.index < g.close).sort((a, b) => a.open - b.open);
    const own = [...`${m[1]}${stmt.slice(m[0].length)}`.matchAll(/(?<!without)middleware\(\s*(\[[^\]]*\]|['"][^'"]*['"])/gi)].flatMap((x) => quoted(x[1]));
    const without = [...stmt.matchAll(/withoutMiddleware\(\s*(\[[^\]]*\]|['"][^'"]*['"])/g)].flatMap((x) => quoted(x[1]));
    const middleware = [...new Set([...outer.flatMap((g) => g.mw), ...own])].filter((x) => !without.includes(x));
    const verb = m[2];
    const name = /^(?:resource|apiResource)$/.test(verb) ? "RESOURCE" : verb === "match" ? quoted(stmt.match(/match\(\s*(\[[^\]]*\])/)?.[1]).join(",").toUpperCase() : verb.toUpperCase();
    out.push({
      kind: "laravel-route", name, route: joinPath(base, ...outer.map((g) => g.prefix), m[4]), file: path, line: lineAt(m.index),
      guard: middleware.length ? `middleware: ${middleware.join(", ")}` : "",
      middleware, phpHandler: laravelHandler(stmt),
    });
  }
  return out;
}

// access_control rules of a Symfony security.yaml: [{ path, roles }], first match wins.
export function accessControl(text) {
  const block = text.match(/^[ \t]*access_control\s*:\s*\n((?:[ \t]+.*\n?)*)/m)?.[1] ?? "";
  return [...block.matchAll(/-\s*\{([^}]*)\}/g)].map((m) => ({
    path: m[1].match(/path\s*:\s*['"]?([^,'"}]+)/)?.[1]?.trim() ?? "",
    roles: m[1].match(/roles\s*:\s*(\[[^\]]*\]|['"]?[\w,]+['"]?)/)?.[1]?.replace(/[[\]'"\s]/g, "") ?? "",
  })).filter((r) => r.path);
}

function symfonyAccess(files, path, route) {
  const root = path.replace(/(?:^|\/)(?:src|config)\/.*$/, "");
  const sec = files.find((x) => /(^|\/)config\/packages\/security\.ya?ml$/.test(x.path) && x.path.replace(/(?:^|\/)config\/.*$/, "") === root);
  if (!sec) return "";
  for (const r of accessControl(sec.text)) {
    try { if (new RegExp(r.path).test(route)) return `access_control ${r.path}: ${r.roles || "(no roles)"}`; } catch { /* not a regex */ }
  }
  return "";
}

export function scanSymfonyRoutes(f, files = [f]) {
  const { text, path } = f;
  const lineAt = lineIndex(text);
  const out = [];
  if (/\.ya?ml$/.test(path)) {
    if (/security\.ya?ml$/.test(path)) return out;
    for (const m of text.matchAll(/^([\w.-]+):\s*\n((?:[ \t]+.*\n?|\s*\n)*)/gm)) {
      const block = m[2];
      const route = block.match(/^\s*path\s*:\s*['"]?([^'"\n]+)/m)?.[1]?.trim();
      if (!route || /^\s*resource\s*:/m.test(block)) continue;
      const ctl = block.match(/^\s*controller\s*:\s*['"]?\\?([\w\\]+)(?:::(\w+))?/m);
      const methods = block.match(/^\s*methods\s*:\s*\[?([^\]\n]*)/m)?.[1]?.replace(/['"\s]/g, "").toUpperCase() || "ANY";
      out.push({ kind: "symfony-route", name: methods, route, file: path, line: lineAt(m.index), guard: symfonyAccess(files, path, route), phpHandler: ctl ? { cls: ctl[1].split("\\").pop(), method: ctl[2] ?? "__invoke" } : null });
    }
    return out;
  }
  const cls = text.match(/^\s*(?:final\s+|abstract\s+)?class\s+(\w+)/m);
  if (!cls) return out;
  const head = text.slice(0, cls.index);
  const routeArgs = (s) => s.match(/(?:path\s*:\s*)?['"]([^'"]*)['"]/)?.[1] ?? "";
  const prefixAttr = [...head.matchAll(/#\[Route\(((?:[^()\[\]]|\[[^\]]*\]|\([^()]*\))*)\)\]|@Route\(((?:[^()]|\([^()]*\))*)\)/g)].pop();
  const prefix = prefixAttr ? routeArgs(prefixAttr[1] ?? prefixAttr[2]) : "";
  const classGrant = [...head.matchAll(/#\[IsGranted\(((?:[^()\[\]]|\[[^\]]*\]|\([^()]*\))*)\)\]/g)].map((x) => `IsGranted(${x[1].trim()})`);
  const routes = [...text.slice(cls.index).matchAll(/#\[Route\(((?:[^()\[\]]|\[[^\]]*\]|\([^()]*\))*)\)\]|@Route\(((?:[^()]|\([^()]*\))*)\)/g)];
  for (const [i, m] of routes.entries()) {
    const at = cls.index + m.index;
    const fn = text.slice(at).match(/function\s+(\w+)\s*\(/);
    if (!fn) continue;
    const fnAt = at + fn.index;
    const nextRoute = i + 1 < routes.length ? cls.index + routes[i + 1].index : text.length;
    const attrs = text.slice(at, fnAt);
    const body = text.slice(fnAt, nextRoute);
    const args = m[1] ?? m[2];
    const route = joinPath(prefix, routeArgs(args));
    const methods = (args.match(/methods\s*[:=]\s*(?:\[([^\]]*)\]|\{([^}]*)\}|['"](\w+)['"])/) ?? []).slice(1).find(Boolean)?.replace(/['"\s]/g, "").toUpperCase() || "ANY";
    const guards = [
      ...classGrant,
      ...[...attrs.matchAll(/#\[IsGranted\(((?:[^()\[\]]|\[[^\]]*\]|\([^()]*\))*)\)\]|@IsGranted\(([^)]*)\)|@Security\(([^)]*)\)/g)].map((x) => `IsGranted(${(x[1] ?? x[2] ?? x[3]).trim()})`),
      ...(/denyAccessUnlessGranted\(|->isGranted\(/.test(body) ? ["denyAccessUnlessGranted in body"] : []),
      symfonyAccess(files, path, route),
    ].filter(Boolean);
    out.push({ kind: "symfony-route", name: methods, route, file: path, line: lineAt(at), guard: guards.join("; "), phpHandler: { cls: cls[1], method: fn[1] } });
  }
  return out;
}

function phpEntryPoints(f, files) {
  if (LARAVEL_ROUTES_RE.test(f.path) && /Route::/.test(f.text)) return scanLaravelRoutes(f);
  if (SYMFONY_CFG_RE.test(f.path) || (PHP_RE.test(f.path) && /#\[Route\(|@Route\(/.test(f.text))) return scanSymfonyRoutes(f, files);
  return [];
}

// Body of `Class::method` among the PHP files: { file, line, body } or null.
function phpMethodBody(files, h) {
  if (!h?.cls) return null;
  for (const f of files) {
    if (!PHP_RE.test(f.path) || !new RegExp(`\\bclass\\s+${h.cls}\\b`).test(f.text)) continue;
    const m = h.method ? f.text.match(new RegExp(`function\\s+${h.method}\\s*\\(`)) : null;
    if (!m) return { file: f.path, line: 1, body: f.text.slice(0, 6000) };
    const rest = f.text.slice(m.index + 1);
    const next = rest.search(/\n[ \t]*(?:#\[[^\n]*\]\s*)*(?:(?:public|protected|private|static|final)\s+)+function\b/);
    return { file: f.path, line: f.text.slice(0, m.index).split("\n").length, body: f.text.slice(m.index, next < 0 ? m.index + 6000 : m.index + 1 + next) };
  }
  return null;
}

// Bodies of the methods a handler calls on injected services or repositories (`$repo->searchByNumber(`),
// one level deep, when exactly one PHP class defines that method name: the query usually lives there.
function phpCallees(files, body) {
  const names = [...new Set([...body.matchAll(/\$(?!this\b)\w+->(\w+)\s*\(/g)].map((m) => m[1]))].slice(0, 8);
  let extra = "";
  for (const n of names) {
    const defs = files.filter((f) => PHP_RE.test(f.path) && new RegExp(`function\\s+${n}\\s*\\(`).test(f.text));
    if (defs.length !== 1) continue;
    const cls = defs[0].text.match(/^\s*(?:final\s+|abstract\s+)?class\s+(\w+)/m)?.[1];
    const m = cls && phpMethodBody(defs, { cls, method: n });
    if (m) extra += "\n" + m.body;
  }
  return extra;
}

// ---------------------------------------------------------------- Drizzle scope scan

// Access-scope columns are checked on every verb. Authorship columns only on update/delete: editing
// someone else's comment is BOLA, reading it usually is not. Business entities (companyId, customerId)
// are not scope: in a single-tenant CRM they are just relations.
const OWNER_RE = /^(?:user|owner|org|organization|workspace|tenant|team|account)(?:_?id)?$/i;
const AUTHOR_RE = /^(?:(?:author|creator)(?:_?id)?|(?:created|uploaded|owned)_?by)$/i;
const TABLE_RE = /(?:export\s+)?const\s+(\w+)\s*=\s*(\w*[Tt]able)\s*\(\s*["'`]([\w.-]+)["'`]\s*,\s*(?:\(\s*\w*\s*\)\s*=>\s*\(\s*)?\{/g;
const NON_RUNTIME = /(^|\/)(__tests__|tests?|e2e|migrations?|drizzle|seeds?|fixtures)\/|\.(test|spec)\.[cm]?[jt]sx?$|(^|\/)seed[^/]*$/;

// `schemaSource` lets a monorepo package audit read table definitions from the workspace root.
export function scanScope(files, schemaSource = files) {
  const tables = new Map(); // var -> { name, owners, authors, fks: [{col, parent}], file }
  const schemaFiles = new Set();

  for (const f of schemaSource) {
    if (!f.text.includes("drizzle-orm")) continue;
    for (const m of f.text.matchAll(TABLE_RE)) {
      const open = m.index + m[0].length - 1;
      const close = matchClose(f.text, open);
      const owners = [];
      const authors = [];
      const fks = [];
      for (const part of splitTopLevel(f.text.slice(open + 1, close))) {
        const kv = part.match(/^(\w+)\s*:\s*([\s\S]*)$/);
        if (!kv) continue;
        if (OWNER_RE.test(kv[1])) owners.push(kv[1]);
        else if (AUTHOR_RE.test(kv[1])) authors.push(kv[1]);
        const ref = kv[2].match(/\.references\(\s*\(\)\s*(?::\s*\w+\s*)?=>\s*(\w+)\.(\w+)/);
        if (ref) fks.push({ col: kv[1], parent: ref[1] });
      }
      tables.set(m[1], { name: m[3], owners, authors, fks, file: f.path });
      schemaFiles.add(f.path);
    }
  }

  // Tables with no owner column of their own that hang off an owner-scoped table (fixpoint over FKs).
  const scoped = new Set([...tables].filter(([, t]) => t.owners.length).map(([v]) => v));
  const indirect = new Map(); // var -> [{col, parent}]
  for (let changed = true; changed;) {
    changed = false;
    for (const [v, t] of tables) {
      if (scoped.has(v) || indirect.has(v)) continue;
      const via = t.fks.filter((fk) => scoped.has(fk.parent) || indirect.has(fk.parent));
      if (via.length) { indirect.set(v, via); changed = true; }
    }
  }
  const ancestorsOwnerRefs = (v, seen = new Set()) => {
    if (seen.has(v)) return [];
    seen.add(v);
    if (scoped.has(v)) return tables.get(v).owners.map((o) => `${v}.${o}`);
    return (indirect.get(v) ?? []).flatMap((fk) => ancestorsOwnerRefs(fk.parent, seen));
  };

  const sites = [];
  for (const f of files) {
    if (schemaFiles.has(f.path) || NON_RUNTIME.test(f.path) || !CODE_RE.test(f.path)) continue;
    const { text } = f;
    const lineAt = lineIndex(text);
    const hits = [
      ...[...text.matchAll(/(?<!\bArray|\bBuffer|\bObject|\bUint8Array|\bSet|\bMap)\.(from|update|delete)\(\s*(?:schema\.)?(\w+)\s*[,)]/g)]
        .map((m) => ({ idx: m.index, verb: m[1] === "from" ? "select" : m[1], table: m[2], relational: false })),
      ...[...text.matchAll(/\.query\.(\w+)\.(findFirst|findMany)\s*\(/g)]
        .map((m) => ({ idx: m.index, verb: m[2], table: m[1], relational: true })),
    ];
    for (const h of hits) {
      const t = tables.get(h.table);
      if (!t) continue;
      const write = h.verb === "update" || h.verb === "delete";
      const authorOnly = !scoped.has(h.table) && !indirect.has(h.table) && t.authors.length;
      if (!scoped.has(h.table) && !indirect.has(h.table) && !(authorOnly && write)) continue;
      const end = scan(text, h.idx, (c, depth, i) => (depth < 0 || (c === ";" && depth <= 0) ? i : undefined));
      const stmt = text.slice(h.idx, Math.min(end, h.idx + 4000));
      const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      let status;
      if (scoped.has(h.table) || authorOnly) {
        const cols = scoped.has(h.table) ? t.owners : t.authors;
        const re = h.relational
          ? new RegExp(`\\b(${cols.join("|")})\\b`)
          : new RegExp(`\\b${esc(h.table)}\\.(${cols.join("|")})\\b`);
        status = re.test(stmt) ? "scoped" : authorOnly ? "AUTHOR-UNCHECKED" : "UNSCOPED";
      } else {
        const viaJoin = ancestorsOwnerRefs(h.table).some((ref) => stmt.includes(ref));
        const viaFk = indirect.get(h.table).some((fk) => new RegExp(`\\b(${esc(h.table)}\\.)?${fk.col}\\b`).test(stmt));
        status = viaJoin ? "scoped" : viaFk ? "PARENT-ONLY" : "UNSCOPED";
      }
      const before = text.slice(Math.max(0, h.idx - 2500), h.idx);
      const encl = [...before.matchAll(/(?:function\s+(\w+)|(?:const|let)\s+(\w+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>|(\w+)\s*:\s*\w*[Pp]rocedure|(\w+)\s*:\s*tool\(|\.(?:get|post|put|patch|delete)\(\s*["'`]([^"'`]+))/g)].pop();
      sites.push({
        status, verb: h.verb, table: h.table, file: f.path, line: lineAt(h.idx),
        enclosing: encl ? encl.slice(1).find(Boolean) : "",
      });
    }
  }

  return {
    tables: [...tables].map(([v, t]) => ({
      var: v, name: t.name, file: t.file,
      owners: t.owners,
      authors: t.authors,
      via: (indirect.get(v) ?? []).map((fk) => `${fk.col} -> ${fk.parent}`),
    })).filter((t) => t.owners.length || t.authors.length || t.via.length),
    sites,
  };
}

// ---------------------------------------------------------------- hotspot ranking

// Where to look first. Each entry point (and each auth/CORS/env config file) collects points for
// signals that real leaks in this stack keep coming from. ponytail: hand-tuned weights; measure them
// on benchmark/ (selftest prints how many seeded bugs land in the top 10/20) before trusting a change.
export const AREAS = {
  auth: /(log-?in|sign-?in|sign-?up|register|sso|saml|oidc|oauth|callback|magic|reset|password|forgot|verify|2fa|mfa|totp|otp|session|impersonat|invite|\bauth(?!or))/i,
  admin: /(admin|\brole|permission|staff|superuser|impersonat|internal)/i,
  payments: /(billing|checkout|payment|stripe|subscription|invoice|\bplan|price|refund|payout|wallet)/i,
  webhooks: /webhook/i,
  files: /(upload|download|\bfile|document|attachment|media|avatar|export|import|presign|csv)/i,
  ai: /(chat|assistant|\bai\b|llm|agent|completion|prompt|\btools?\b|\bmcp\b)/i,
};
const AREA_WEIGHT = { auth: 3, admin: 3, webhooks: 3, payments: 2, files: 2, ai: 2, jobs: 1, api: 0 };
const KIND_WEIGHT = { "server-action": [2, "callable directly as a POST"], webhook: [2, "public by design"], "ai-tool": [2, "arguments chosen by the model"], job: [1, "trusts its payload"], cron: [1, ""], "route-handler": [1, ""], "api-route": [1, ""], "http-route": [1, ""], "http-path": [1, ""], "http-prefix": [1, ""], trpc: [1, ""], "edge-function": [2, "public HTTPS endpoint"], "cloud-function": [2, "callable by any client of the project"], "laravel-route": [1, ""], "symfony-route": [1, ""], "drupal-route": [1, ""] };
const SINKS = [
  [/\b(?:fetch|axios(?:\.\w+)?|got|ky)\(\s*(?!["'`](?:https?:\/\/[\w.-]+[\/"'`?:]|\/))[^)\s]/, 3, "outbound request to a non-constant URL (SSRF)"],
  [/\{[^}]*\b(?:userId|user_id|ownerId|owner_id|orgId|org_id|tenantId|tenant_id)\b[^}]*\}\s*=\s*(?:await\s+)?(?:req|request|c\.req)\.json\(\)/, 3, "tenant/user id taken from the request body"],
  [/sql\.raw\(|\$(?:query|execute)RawUnsafe|\.unsafe\(|\.(?:execute|query)\(\s*`[^`]*\$\{/, 3, "raw SQL built from strings"],
  [/\b(?:execSync|execFile|spawnSync|spawn)\(|child_process/, 3, "shell/process execution"],
  [/dangerouslySetInnerHTML|\.innerHTML\s*=|v-html/, 2, "raw HTML rendering"],
  [/redirect\([^)]*(?:searchParams|params|\.get\(|query|body|input)/, 2, "redirect target from the request"],
  [/getSignedUrl\(|createPresignedPost\(|presignedPutObject|generatePresignedUrl/, 2, "presigned storage URL"],
  [/searchParams\.get\(\s*["'`](?:org|orgId|organization|tenant|tenantId|user|userId|account|accountId|workspace|workspaceId)["'`]|\b(?:input|body|args|params)\.(?:orgId|organizationId|userId|tenantId|workspaceId|accountId)\b/, 3, "tenant/user id taken from the request"],
  [/\b(?:inputSchema|parameters)\s*:\s*z\.object\(\{[^}]*\b(?:orgId|organizationId|userId|tenantId|workspaceId)\s*:/, 3, "tool schema lets the model choose the tenant/user"],
  [/\.(?:set|values|create|insert)\(\s*(?:input|body|data|patch|req\.body)\s*[,)]/, 2, "request object written to the database as-is"],
  [/\bsendEmail\(|\bemails\.send\(|\bsendMail\(|SendEmailCommand/, 2, "sends email (who are the recipients?)"],
  [/\b(?:model|maxOutputTokens|max_tokens|maxTokens|max_completion_tokens|stopWhen|maxSteps)\s*:\s*[^,\n]*\b(?:body|input|req\.body|args|params)\.\w+/, 2, "LLM model or token budget taken from the request (cost)"],
  [/^(?=[\s\S]*\b(?:generateText|streamText|generateObject|messages\.create|completions\.create|responses\.create|\.invoke)\()[\s\S]*(?:dangerouslySetInnerHTML|\.innerHTML\s*=|v-html)/, 1, "LLM output may reach raw HTML"],
  // PHP (roadmap R05)
  [/\b(?:whereRaw|orWhereRaw|orderByRaw|havingRaw|selectRaw|groupByRaw|DB::raw|DB::select|DB::statement|DB::unprepared)\(\s*(?:"[^"]*\$|'[^']*'\s*\.|\$)/, 3, "raw SQL with request data interpolated (Eloquent *Raw / DB::)"],
  [/\b(?:createQuery|query|db_query|executeQuery|executeStatement|prepare)\(\s*(?:"[^"]*(?:\$\w|"\s*\.)|'[^']*'\s*\.|\$\w+\s*\.)/, 3, "SQL/DQL string built by concatenation"],
  [/->(?:update|create|fill|forceFill|insert|update)\(\s*\$request->(?:all|input|post)\(\)|::create\(\s*\$request->all\(\)/, 3, "request input written to the model as-is (mass assignment)"],
  [/\b(?:storeAs|storePubliclyAs|putFileAs|move)\([^;]*getClientOriginalName\(\)/, 2, "upload stored under the client's file name"],
  [/Markup::create\(\s*(?!['"][^'"$]*['"]\s*\))/, 3, "Markup::create on dynamic content skips Drupal's XSS filtering"],
  [/['"]#markup['"]\s*=>\s*(?!\$this->t\(|t\(|new\s+TranslatableMarkup)[^,\]\n]*\$/, 2, "#markup built from a variable"],
  [/\bunserialize\(/, 3, "unserialize() of data"],
  [/\b(?:shell_exec|passthru|proc_open|popen)\s*\(/, 3, "shell/process execution"],
];
// A record loaded by id, and nothing in the handler that ties it to the caller.
const PHP_ID_LOAD = /::(?:find|findOrFail)\(\s*\$|->(?:find|findOrFail)\(\s*\$|\bWHERE\s+id\s*=\s*:id\b/i;
const PHP_OWNER = /authorize\(|Gate::|->user\(\)|currentUser\(\)|abort_unless|abort_if|denyAccessUnlessGranted|isGranted\(|->can\(|\b(?:uid|user_id|owner_id|customer_id)\s*(?:=|=>)|condition\(\s*['"](?:uid|user_id|owner_id)['"]|getUser\(\)|->(?:where|andWhere)\(\s*['"][\w.]*(?:user|owner|customer|tenant)/i;
const STATE_CHANGE_PATH = /\/(?:delete|remove|close|cancel|approve|reject|publish|unpublish|toggle|reopen|enable|disable|block|unblock|confirm|archive)\b/;
const DISPATCH = /\b(?:handle|toNextJsHandler|fetchRequestHandler|createRouteHandler|createNextRouteHandler)\(/;
const SIGNATURE = /constructEvent|\.verify\(|svix|signature|timingSafeEqual|createHmac|verifyWebhook/i;
const SECRET_ENV = /\b((?:NEXT_PUBLIC|VITE|EXPO_PUBLIC)_\w*(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE)\w*)/g;
const PUBLIC_BY_DESIGN = /PUBLISHABLE|POSTHOG|SENTRY|ANALYTICS|_GA_|GTM|MAPBOX|ANON_KEY|SITE_KEY|RECAPTCHA|ALGOLIA_SEARCH|VAPID_PUBLIC|PUBLIC_KEY|FIREBASE_API_KEY/;
const PRIVILEGED_CLIENT = /SERVICE_ROLE_KEY|service_role|from\s+["'`]firebase-admin|require\(\s*["'`]firebase-admin/;

export function areasOf(e) {
  const hay = `${e.route} ${e.name} ${e.file}${e.phpHandler ? ` ${e.phpHandler.cls} ${e.phpHandler.method}` : ""}`;
  const areas = Object.keys(AREAS).filter((a) => AREAS[a].test(hay));
  if (e.kind === "ai-tool") areas.push("ai");
  if (e.kind === "job" || e.kind === "cron") areas.push("jobs");
  if (e.kind !== "page") areas.push("api");
  return [...new Set(areas)];
}

// --scope: comma list of areas (auth, admin, payments, webhooks, files, ai, jobs, api), paths, or topN.
export const SCOPE_AREAS = [...Object.keys(AREAS), "jobs", "api"];
export function inScope(spec, hotspots) {
  const parts = spec.split(",").map((p) => p.trim()).filter(Boolean);
  const bad = parts.filter((p) => !SCOPE_AREAS.includes(p) && !/^top\d+$/.test(p) && !/[/.]/.test(p));
  if (bad.length) throw new Error(`unknown scope "${bad.join(", ")}": use ${SCOPE_AREAS.join(", ")}, a path, or topN`);
  const top = new Set(parts.filter((p) => /^top\d+$/.test(p)).flatMap((p) => hotspots.slice(0, Number(p.slice(3))).map((h) => `${h.file}:${h.line}`)));
  const paths = parts.filter((p) => /[/.]/.test(p)).map((p) => p.replace(/^\.\//, "").replace(/\/$/, ""));
  return (h) =>
    top.has(`${h.file}:${h.line}`) ||
    h.areas.some((a) => parts.includes(a)) ||
    paths.some((p) => h.file === p || h.file.startsWith(p + "/"));
}

export function rankHotspots(files, entries, scope = { sites: [] }) {
  const text = new Map(files.map((f) => [f.path, f.text]));
  const lines = new Map();
  const linesOf = (p) => lines.get(p) ?? lines.set(p, (text.get(p) ?? "").split("\n")).get(p);
  const out = [];

  const byFile = new Map();
  for (const e of entries) byFile.set(e.file, [...(byFile.get(e.file) ?? []), e]);
  // `export const { GET, POST } = ...` yields one entry per method on the same line: rank them once.
  const merged = [];
  for (const e of entries) {
    const twin = merged.find((m) => m.file === e.file && m.line === e.line && m.kind === e.kind);
    if (twin) twin.name += `, ${e.name}`; else merged.push({ ...e });
  }
  // A job registered as `boss.work("q", handler)` is defined elsewhere: rank the handler's own body.
  const handlerBody = (e) => {
    const name = e.handler ?? linesOf(e.file)[e.line - 1]?.match(/\.work\s*(?:<[^>]*>)?\(\s*["'`][^"'`]+["'`]\s*,\s*(?:\{[^}]*\}\s*,\s*)?(\w+)\s*\)/)?.[1];
    if (!name) return null;
    const own = text.get(e.file) ?? "";
    for (const f of [{ path: e.file, text: own }, ...files.filter((x) => x.path !== e.file)]) {
      const m = f.text.match(new RegExp(`(?:async\\s+)?function\\s+${name}\\b|(?:const|let)\\s+${name}\\s*=\\s*(?:async\\s*)?\\(`));
      if (m) return { file: f.path, line: f.text.slice(0, m.index).split("\n").length, body: f.text.slice(m.index, m.index + 6000) };
    }
    return null;
  };

  for (const e of merged) {
    if (e.kind === "middleware" || NON_RUNTIME.test(e.file)) continue;
    const next = byFile.get(e.file).filter((x) => x.line > e.line).map((x) => x.line).sort((a, b) => a - b)[0];
    const from = e.line - 1;
    let body = linesOf(e.file).slice(from, next ? next - 1 : from + 120).join("\n");
    const job = e.kind === "job" || e.handler ? handlerBody(e) : null;
    if (job) {
      body = job.body;
      if (!e.guard) e.guard = guardsIn(job.body.slice(0, 1500));
    }
    // PHP routes: rank the controller method the route points at.
    const php = e.phpHandler ? phpMethodBody(files, e.phpHandler) : null;
    if (php) body = php.body + phpCallees(files, php.body);
    let score = 0;
    const reasons = [];
    const add = (n, why) => { if (n) { score += n; if (why) reasons.push(why); } };

    const uniq = areasOf(e);
    add(Math.min(5, uniq.reduce((s, a) => s + AREA_WEIGHT[a], 0)), uniq.filter((a) => AREA_WEIGHT[a]).map((a) => `${a} area`).join(", "));

    const [kw, kwhy] = KIND_WEIGHT[e.kind] ?? [0, ""];
    add(kw, kwhy && `${e.kind}: ${kwhy}`);
    const dispatcher = e.kind === "route-handler" && DISPATCH.test(text.get(e.file) ?? "");
    if (dispatcher) {
      reasons.push("dispatcher: the routes it mounts are ranked separately");
    } else if (e.kind === "webhook") {
      if (!SIGNATURE.test(body)) add(3, "no signature verification seen");
    } else if (e.kind === "edge-function" || e.kind === "cloud-function") {
      if (e.verifyJwt === false) add(1, "verify_jwt = false: the gateway lets anonymous callers in");
      if (!e.guard && !SIGNATURE.test(body)) add(3, "no auth check in the function");
      if (PRIVILEGED_CLIENT.test(text.get(e.file) ?? "")) add(2, "service-role / Admin SDK client: RLS and security rules do not apply");
    } else if (e.kind === "page" && !e.guard && /\bdb\.|\.query\.\w+\.find|prisma\.|\bsupabase\s*\.from\(/.test(body)) {
      add(3, "page without a guard reads the database (what reaches the client?)");
    } else if (/\/(health|healthz|ready|readyz|live|livez|ping|status|version|robots\.txt|sitemap)\b/.test(e.route) && !/\bdb\.|\.query\.|->query\(|::find/.test(body)) {
      reasons.push("health/status route");
    } else if (e.kind === "laravel-route" || e.kind === "symfony-route" || e.kind === "drupal-route") {
      const signed = SIGNATURE.test(body) || /hash_hmac|hash_equals|hasValidSignature/.test(body);
      if (e.kind === "laravel-route" && !(e.middleware ?? []).some((m) => LARAVEL_AUTH_MW.test(m))) {
        if (signed) reasons.push("no auth middleware; signature check seen in the handler");
        else add(3, "no auth middleware on the route or its groups");
      }
      if (e.kind === "symfony-route" && !e.guard) add(signed ? 0 : 3, "no #[IsGranted], access check or access_control rule");
      if (e.kind === "drupal-route") {
        if (/_access: '?TRUE'?/i.test(e.guard)) add(3, "open to everyone (_access: 'TRUE')");
        else if (e.guard === "NO REQUIREMENTS") add(3, "route has no access requirements");
        if (!/_csrf_token/.test(e.guard) && !/POST|PUT|PATCH|DELETE/.test(e.methods ?? "") && STATE_CHANGE_PATH.test(e.route)) add(2, "changes state on GET without _csrf_token");
      }
      if (PHP_ID_LOAD.test(body) && !PHP_OWNER.test(body)) add(3, "record loaded by id without an ownership or policy check");
    } else if (["server-action", "route-handler", "api-route"].includes(e.kind) && !e.guard) {
      add(3, "no auth check in the handler");
    } else if (["http-route", "http-path", "http-prefix"].includes(e.kind) && !e.guard) {
      add(3, "no auth check in the route or file middleware");
    } else if (e.kind === "trpc" && /^public/i.test(e.guard)) {
      add(2, "publicProcedure");
    }

    const cands = job
      ? scope.sites.filter((s) => s.status !== "scoped" && s.file === job.file && s.line >= job.line && s.line < job.line + 150)
      : scope.sites.filter((s) => s.status !== "scoped" && s.file === e.file && s.line >= e.line && (!next || s.line < next));
    if (cands.length) add(3, `unscoped query on ${[...new Set(cands.map((c) => c.table))].join(", ")}`);
    for (const [re, n, why] of SINKS) if (re.test(body)) add(n, why);

    if (job) reasons.push(`handler: ${job.file}:${job.line}`);
    if (php) reasons.push(`handler: ${php.file}:${php.line}`);
    out.push({ score, kind: e.kind, name: e.name, route: e.route, file: e.file, line: e.line, areas: uniq, reasons });
  }

  // Configuration that decides access for everything behind it.
  for (const f of files) {
    if (NON_RUNTIME.test(f.path) || !CODE_RE.test(f.path)) continue;
    let score = 0;
    const reasons = [];
    const add = (n, why) => { score += n; reasons.push(why); };
    const t = f.text;
    const authCfg = t.match(/\b(betterAuth|NextAuth|passport\.use|clerkMiddleware|new Lucia|lucia)\(/);
    if (authCfg) {
      add(4, `auth configuration (${authCfg[1]})`);
      const af = t.match(/additionalFields\s*:\s*\{/);
      if (af) {
        const open = af.index + af[0].length - 1;
        for (const part of splitTopLevel(t.slice(open + 1, matchClose(t, open)))) {
          const key = part.match(/^(\w+)\s*:/)?.[1];
          if (key && /role|plan|admin|permission|credit|tier|status|verified|banned|org/i.test(key) && !/input\s*:\s*false/.test(part)) {
            add(4, `additionalFields.${key} is writable at sign-up (no input: false)`);
          }
        }
      }
      if (/sameSite\s*:\s*["']none["']/i.test(t)) add(2, "SameSite=None session cookies");
      if (/disableCSRFCheck|disableOriginCheck|trustedOrigins\s*:\s*\[\s*["']\*["']/.test(t)) add(3, "CSRF/origin checks disabled");
    }
    const cors = t.match(/cors\(\s*\{[\s\S]{0,400}?\}\s*\)/);
    if (cors && /credentials\s*:\s*true/.test(cors[0]) && /origin\s*:\s*(?:\(\s*(\w+)\s*\)\s*=>\s*\1\s*[,}\n]|true\b|["']\*["'])/.test(cors[0])) {
      add(6, "CORS reflects any origin with credentials");
    }
    // unstable_cache over a zero-argument closure: the key has no per-user/per-tenant part.
    for (const m of t.matchAll(/unstable_cache\(\s*async\s*\(\s*\)\s*=>/g)) {
      add(5, `unstable_cache over a zero-argument function at line ${t.slice(0, m.index).split("\n").length}: cache key may be shared across users/tenants`);
    }
    const leaked = [...new Set([...t.matchAll(SECRET_ENV)].map((m) => m[1]).filter((n) => !PUBLIC_BY_DESIGN.test(n)))];
    if (leaked.length) add(5, `${leaked.join(", ")} looks like a secret and is shipped to the browser`);
    if (score) out.push({ score, kind: authCfg || reasons.some((r) => r.startsWith("CORS")) ? "config" : "code", name: basename(f.path), route: "", file: f.path, line: 1, areas: authCfg ? ["auth", "config"] : ["config"], reasons });
  }
  for (const r of scanPhpFiles(files)) out.push(r);
  for (const p of scanPolicies(files)) {
    out.push({ score: p.score, kind: "policy", name: p.name, route: "", file: p.file, line: p.line, areas: ["auth", "config"], reasons: p.reasons });
  }
  for (const m of entries.filter((e) => e.kind === "middleware")) {
    out.push({ score: 3, kind: "middleware", name: m.name, route: "*", file: m.file, line: m.line, areas: ["auth", "config"], reasons: [`gate for listed paths only (${m.guard.slice(0, 120)})`] });
  }

  return out.sort((a, b) => b.score - a.score || a.file.localeCompare(b.file) || a.line - b.line);
}

// ---------------------------------------------------------------- PHP file signals (roadmap R05)

// Lines in templates, models and middleware that decide escaping, mass assignment and CSRF for every
// route behind them: unescaped Blade `{!! !!}` and Twig `|raw`, `$guarded = []`, CSRF exceptions,
// debug forced on in config. ponytail: regex per line; each row is a candidate to verify.
export function scanPhpFiles(files) {
  const rows = [];
  const row = (f, line, kind, name, score, why) => rows.push({ score, kind, name, route: "", file: f.path, line, areas: ["config"], reasons: [why] });
  for (const f of files) {
    if (NON_RUNTIME.test(f.path) || !(PHP_RE.test(f.path) || TWIG_RE.test(f.path))) continue;
    const lines = f.text.split("\n");
    const blade = /\.blade\.php$/.test(f.path);
    lines.forEach((l, i) => {
      if (blade) {
        for (const m of l.matchAll(/\{!!\s*(.*?)\s*!!\}/g)) {
          if (!/^(?:nl2br\(\s*)?e\(|^(?:csrf_field|method_field)\(|^\$__env/.test(m[1])) row(f, i + 1, "template", basename(f.path), 3, `unescaped Blade output {!! ${m[1]} !!}`);
        }
      }
      if (TWIG_RE.test(f.path) && /\|\s*raw\b/.test(l)) row(f, i + 1, "template", basename(f.path), 3, "Twig |raw output");
      if (/\$guarded\s*=\s*\[\s*\]/.test(l)) row(f, i + 1, "model", basename(f.path), 3, "$guarded = []: every column is mass assignable");
      if (/['"]debug['"]\s*=>\s*(?:true\b|\(bool\)\s*env\(\s*['"]APP_DEBUG['"]\s*,\s*true\s*\))/.test(l)) row(f, i + 1, "config", basename(f.path), 3, "debug mode on by default");
    });
    // CSRF exceptions: Laravel VerifyCsrfToken::$except or validateCsrfTokens(except: [...]).
    const ex = f.text.match(/\$except\s*=\s*\[([^\]]*)\]|validateCsrfTokens\(\s*except\s*:\s*\[([^\]]*)\]/);
    if (ex && /VerifyCsrfToken|validateCsrfTokens/.test(f.text)) {
      const start = ex.index + ex[0].indexOf("[");
      for (const m of (ex[1] ?? ex[2]).matchAll(/['"]([^'"]+)['"]/g)) {
        if (/webhook|stripe|paddle|callback|hook\b/i.test(m[1])) continue;
        const line = f.text.slice(0, start + 1 + m.index).split("\n").length;
        row(f, line, "config", basename(f.path), 3, `CSRF verification skipped for "${m[1]}"`);
      }
    }
  }
  return rows;
}

// Psalm taint analysis (`--taint-analysis`) is a candidate source the pre-pass never runs itself: Psalm loads
// the project's composer autoloader and the plugins in psalm.xml, which is the audited code. For a PHP
// project the status is NOT RUN with how to run it; null when there is no PHP. Dependency advisories for
// composer.lock come from osv-scanner (Packagist), with `composer audit` as the fallback in prepass.mjs.
export function phpTaintStatus(files) {
  if (!files.some((f) => PHP_RE.test(f.path) && !/\.blade\.php$/.test(f.path))) return null;
  return "NOT RUN: Psalm loads the project's autoloader and plugins, so the pre-pass does not run it. To add it, in a sandbox: `composer require --dev vimeo/psalm`, `vendor/bin/psalm --init`, `vendor/bin/psalm --taint-analysis --output-format=json`; TaintedSql, TaintedHtml, TaintedShell, TaintedInclude and TaintedSSRF results are candidates for the injection auditor";
}

// ---------------------------------------------------------------- policy scan (Supabase, Firebase)

// Candidates in the files that decide data access when the client talks to the database directly:
// Supabase migrations (tables without RLS, permissive or login-only policies, bucket-wide storage
// policies, public buckets, SECURITY DEFINER functions) and Firebase rules (`if true`, signed-in only).
// ponytail: regex over SQL and rules text, not a parser; later migrations that drop or replace a policy
// are not replayed. Every row is a candidate for an auditor to verify in the code, never a finding.
const SIGNED_IN_ONLY = /auth\.role\(\)\s*=\s*'authenticated'|auth\.uid\(\)\s+is\s+not\s+null|auth\.jwt\(\)\s+is\s+not\s+null/i;
const OWNER_CHECK = /auth\.uid\(\)\s*\)?\s*(?:=|in\b)|=\s*\(?\s*(?:select\s+)?auth\.uid\(\)|auth\.jwt\(\)\s*->>?\s*'(?:sub|email)'|storage\.foldername|\bowner(?:_id)?\s*=/i;

// SQL statements with their start offsets; `;` inside $$ bodies, strings and comments does not split.
function sqlStatements(text) {
  const out = [];
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === "-" && text[i + 1] === "-") { const nl = text.indexOf("\n", i); i = nl < 0 ? text.length : nl; continue; }
    if (c === "/" && text[i + 1] === "*") { const end = text.indexOf("*/", i + 2); i = end < 0 ? text.length : end + 1; continue; }
    if (c === "'") { for (i++; i < text.length && !(text[i] === "'" && text[i + 1] !== "'"); i++) if (text[i] === "'") i++; continue; }
    if (c === "$") {
      const tag = text.slice(i).match(/^\$\w*\$/)?.[0];
      if (tag) { const end = text.indexOf(tag, i + tag.length); i = end < 0 ? text.length : end + tag.length - 1; continue; }
    }
    if (c === ";") { out.push({ text: text.slice(start, i), at: start }); start = i + 1; }
  }
  if (text.slice(start).trim()) out.push({ text: text.slice(start), at: start });
  return out.map((st) => { const lead = st.text.match(/^(?:\s+|--[^\n]*|\/\*[\s\S]*?\*\/)*/)[0].length; return { text: st.text.slice(lead), at: st.at + lead }; });
}

// The text inside the parentheses that follow `keyword` in `stmt`, or null.
function clause(stmt, keyword) {
  const m = stmt.match(new RegExp(`\\b${keyword}\\s*\\(`, "i"));
  if (!m) return null;
  const open = m.index + m[0].length - 1;
  let depth = 0;
  for (let i = open; i < stmt.length; i++) {
    if (stmt[i] === "(") depth++;
    else if (stmt[i] === ")" && --depth === 0) return stmt.slice(open + 1, i).trim();
  }
  return null;
}

const ident = (s) => s.replace(/"/g, "").replace(/^public\./i, "").toLowerCase();

export function scanPolicies(files) {
  const rows = [];
  const sql = files.filter((f) => /(^|\/)supabase\/migrations\/[^/]+\.sql$/.test(f.path)).sort((a, b) => a.path.localeCompare(b.path));
  const tables = [];
  const rls = new Set();
  const revoked = new Set();
  const fns = [];
  for (const f of sql) {
    const lineAt = lineIndex(f.text);
    for (const st of sqlStatements(f.text)) {
      const t = st.text;
      const line = lineAt(st.at);
      let m;
      if ((m = t.match(/^create\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?((?:"?public"?\.)?"?\w+"?)\s*\(/i))) {
        tables.push({ name: ident(m[1]), file: f.path, line });
      } else if ((m = t.match(/^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?((?:"?\w+"?\.)?"?\w+"?)\s+(?:force|enable)\s+row\s+level\s+security/i))) {
        rls.add(ident(m[1]));
      } else if ((m = t.match(/^revoke\s+(?:execute|all)[\s\S]*?\bon\s+function\s+((?:"?\w+"?\.)?"?\w+"?)[\s\S]*\bfrom\b([\s\S]*)$/i)) && /\b(public|anon)\b/i.test(m[2])) {
        revoked.add(ident(m[1]));
      } else if ((m = t.match(/^create\s+policy\s+("[^"]+"|\w+)\s+on\s+((?:"?\w+"?\.)?"?\w+"?)/i))) {
        const name = m[1].replace(/"/g, "");
        const table = m[2].replace(/"/g, "").toLowerCase();
        const exprs = [clause(t, "using"), clause(t, "with\\s+check")].filter((x) => x != null);
        const reasons = [];
        let score = 0;
        if (exprs.some((x) => /^true$/i.test(x))) { score = 4; reasons.push(`policy "${name}" on ${table} is \`true\` for everyone in its roles (fine only for public data)`); }
        else if (exprs.some((x) => SIGNED_IN_ONLY.test(x)) && !exprs.some((x) => OWNER_CHECK.test(x))) { score = 4; reasons.push(`policy "${name}" on ${table} checks that the caller is signed in, not that they own the row`); }
        else if (table === "storage.objects" && exprs.length && !exprs.some((x) => OWNER_CHECK.test(x) || /auth\.uid\(\)/i.test(x))) { score = 4; reasons.push(`storage policy "${name}" is scoped to the bucket, not to the object's owner`); }
        if (score) rows.push({ score, name, file: f.path, line, reasons });
      } else if (/^insert\s+into\s+storage\.buckets\b/i.test(t)) {
        for (const b of t.matchAll(/\(\s*'([\w-]+)'\s*,\s*'[\w-]+'\s*,\s*true\b/g)) {
          rows.push({ score: 2, name: `bucket ${b[1]}`, file: f.path, line: lineAt(st.at + b.index), reasons: [`storage bucket "${b[1]}" is public: every object is readable by URL (by design?)`] });
        }
      } else if ((m = t.match(/^create\s+(?:or\s+replace\s+)?function\s+((?:"?\w+"?\.)?"?\w+"?)\s*\(/i)) && /\bsecurity\s+definer\b/i.test(t) && !/\breturns\s+(?:trigger|event_trigger)\b/i.test(t)) {
        fns.push({ name: ident(m[1]), file: f.path, line, text: t });
      }
    }
  }
  for (const t of tables) {
    if (!rls.has(t.name)) rows.push({ score: 6, name: t.name, file: t.file, line: t.line, reasons: [`row level security is never enabled on ${t.name}: the Data API serves it to anyone holding the anon key`] });
  }
  for (const fn of fns) {
    const reasons = ["SECURITY DEFINER function: runs as its owner and bypasses RLS"];
    let score = 1;
    if (!/\bset\s+search_path\b/i.test(fn.text)) { score += 2; reasons.push("no fixed search_path"); }
    if (!/auth\.uid\(\)|auth\.jwt\(\)/i.test(fn.text)) { score += 3; reasons.push("never checks auth.uid()"); }
    if (!revoked.has(fn.name)) { score += 1; reasons.push("EXECUTE not revoked from public/anon: callable with the anon key through /rpc"); }
    rows.push({ score, name: `${fn.name}()`, file: fn.file, line: fn.line, reasons });
  }

  for (const f of files.filter((x) => /(^|\/)(?:firestore|storage)\.rules$/.test(x.path))) {
    const lineAt = lineIndex(f.text);
    for (const m of f.text.matchAll(/\ballow\s+([\w\s,]+?)\s*:\s*if\s+([^;]+);/g)) {
      const cond = m[2].replace(/\s+/g, " ").trim();
      const where = [...f.text.slice(0, m.index).matchAll(/match\s+(\/\S+?)\s*\{/g)].pop()?.[1] ?? "";
      const ops = m[1].replace(/\s+/g, " ").trim();
      if (/^true$/.test(cond)) rows.push({ score: 6, name: where, file: f.path, line: lineAt(m.index), reasons: [`allow ${ops}: if true on ${where}: anyone, signed in or not`] });
      else if (/^request\.auth\s*!=\s*null$/.test(cond)) rows.push({ score: 4, name: where, file: f.path, line: lineAt(m.index), reasons: [`allow ${ops} on ${where} for any signed-in user: no ownership check`] });
    }
  }
  return rows;
}
