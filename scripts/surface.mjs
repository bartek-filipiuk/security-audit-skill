// Static entry-point scan for the security-audit pre-pass. No dependencies.
// 1. Entry points by framework convention (Next.js App/Pages Router, server actions, proxy/middleware,
//    tRPC, Hono/Express, pg-boss/BullMQ/cron, AI SDK / MCP tools, Drupal routing.yml, Supabase Edge
//    Functions, Firebase Cloud Functions, Laravel routes/*.php, Symfony #[Route] attributes and
//    config/routes*.yaml, Django urls.py, FastAPI and Flask route decorators).
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
// Python profile (roadmap R06): Python sources and Django/Jinja templates under a templates/ directory.
const PY_RE = /\.py$/;
const PY_TEMPLATE_RE = /(^|\/)templates\/.+\.html?$/;
// Read for the policy scan only, never scanned as code.
const POLICY_RE = /(^|\/)supabase\/(?:migrations\/[^/]+\.sql|config\.toml)$|(^|\/)(?:firestore|storage)\.rules$/;
export const LOCKFILES = new Set([
  "pnpm-lock.yaml", "package-lock.json", "yarn.lock", "bun.lock", "composer.lock",
  "poetry.lock", "uv.lock", "requirements.txt", "Pipfile.lock", "go.sum", "Cargo.lock", "Gemfile.lock",
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
      if ((CODE_RE.test(name) || DRUPAL_RE.test(name) || POLICY_RE.test(rel) || PHP_RE.test(name) || TWIG_RE.test(name) || SYMFONY_CFG_RE.test(rel) || PY_RE.test(name) || PY_TEMPLATE_RE.test(rel)) && st.size < 1_000_000) {
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
    if (PY_TEMPLATE_RE.test(path)) continue;
    if (PY_RE.test(path)) {
      for (const e of pyEntryPoints(f, files)) out.push(e);
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

// ---------------------------------------------------------------- Python entry points (roadmap R06)

// Django urls.py (path/re_path/url with include() prefixes, DRF router.register), FastAPI and Flask route
// decorators (router and blueprint prefixes, include_router/register_blueprint mounts). Each route carries
// the auth markers found on it: login_required and friends, auth mixins, DRF permission_classes (or the
// REST_FRAMEWORK default, AllowAny when unset), Depends()/Security() on the route, its router, its app or
// its mount, Flask *_required decorators and before_request hooks.
// ponytail: regex and indentation over source text, not an AST. Routes added in loops, DRF @action routes,
// i18n_patterns, app factories that register blueprints under computed names and Python imports for
// --since are invisible. Each row is a candidate, never a verdict.
const PY_KINDS = new Set(["django-route", "fastapi-route", "flask-route"]);

// Like scan() for Python source: skips strings (triple-quoted too) and # comments.
function pyScan(text, from, stop) {
  let depth = 0;
  for (let i = from; i < text.length; i++) {
    const c = text[i];
    if (c === "#") { const nl = text.indexOf("\n", i); if (nl < 0) return text.length; i = nl - 1; continue; }
    if (c === '"' || c === "'") {
      const q3 = c.repeat(3);
      if (text.startsWith(q3, i)) { const end = text.indexOf(q3, i + 3); if (end < 0) return text.length; i = end + 2; continue; }
      for (i++; i < text.length && text[i] !== c && text[i] !== "\n"; i++) if (text[i] === "\\") i++;
      continue;
    }
    if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") depth--;
    const r = stop(c, depth, i);
    if (r !== undefined) return r;
  }
  return text.length;
}
const pyMatchClose = (text, open) => pyScan(text, open, (c, depth, i) => (depth === 0 ? i : undefined));

// Top-level arguments of the call whose `(` is at `open`.
function pyArgs(text, open) {
  const close = pyMatchClose(text, open);
  const body = text.slice(open + 1, close);
  const parts = [];
  let last = 0;
  pyScan(body, 0, (c, depth, i) => { if (c === "," && depth === 0) { parts.push(body.slice(last, i)); last = i + 1; } });
  parts.push(body.slice(last));
  return { close, parts: parts.map((s) => s.trim()).filter(Boolean) };
}
const pyStr = (s) => s?.match(/^[rRbBuU]{0,2}(["'])(.*?)\1/s)?.[2] ?? null;
const pyKw = (parts, name) => parts.find((p) => new RegExp(`^${name}\\s*=`).test(p))?.replace(new RegExp(`^${name}\\s*=\\s*`), "") ?? null;
// Dependencies in `Depends(x)` / `Security(x)` whose name looks like an auth check (get_db does not).
const AUTH_DEP = /user|auth|login|token|staff|admin|permission|role|verify|require|principal|current|api_?key|scope|guard|jwt|bearer/i;
const authDeps = (s) => [...new Set([...(s ?? "").matchAll(/\b(?:Depends|Security)\(\s*([\w.]+)/g)].map((m) => m[1]).filter((n) => AUTH_DEP.test(n)))];

// The `def`/`class` statement on `line` (1-based) and every following line indented deeper.
function pyBlock(text, line, max = 250) {
  const lines = text.split("\n");
  const i = line - 1;
  const indent = (lines[i] ?? "").match(/^[ \t]*/)[0].length;
  let j = i + 1;
  for (; j < lines.length && j < i + max; j++) {
    const l = lines[j];
    if (!l.trim() || /^\s*#/.test(l) || /^[ \t]*[)\]}]/.test(l)) continue;
    if (l.match(/^[ \t]*/)[0].length <= indent) break;
  }
  return lines.slice(i, j).join("\n").replace(/\s+$/, "");
}

// Decorator lines stacked directly above the `def`/`class` on `line`.
function pyDecorators(text, line) {
  const lines = text.split("\n");
  const indent = (lines[line - 1] ?? "").match(/^[ \t]*/)[0].length;
  const out = [];
  for (let j = line - 2; j >= 0; j--) {
    const l = lines[j];
    if (!l.trim()) break;
    const ind = l.match(/^[ \t]*/)[0].length;
    if (ind < indent || (ind === indent && !/^\s*[@)\]]/.test(l))) break;
    out.unshift(l);
  }
  return out.join("\n");
}

function pyBlockAt(files, h) {
  const f = files.find((x) => x.path === h.file);
  return f ? { file: f.path, line: h.line, body: pyBlock(f.text, h.line) } : null;
}

// Top-level `def name`/`class name`, preferring <mod>.py next to the file that names it.
function pyFindDef(files, name, near, mod) {
  const re = new RegExp(`^(?:async\\s+)?(def|class)\\s+${name}\\b`, "m");
  const dirOf = (p) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");
  const rank = (f) => (basename(f.path) === `${mod}.py` ? 2 : 0) + (dirOf(f.path) === dirOf(near) ? 1 : 0);
  const hit = files.filter((f) => PY_RE.test(f.path) && !NON_RUNTIME.test(f.path) && re.test(f.text)).sort((a, b) => rank(b) - rank(a))[0];
  if (!hit) return null;
  const m = hit.text.match(re);
  return { file: hit.path, line: hit.text.slice(0, m.index).split("\n").length, kind: m[1], text: hit.text };
}

const DJ_DECOR_GUARD = /^\s*@(login_required|permission_required|user_passes_test|staff_member_required|superuser_required)\b/gm;
const DJ_MIXIN = /\b(LoginRequiredMixin|PermissionRequiredMixin|UserPassesTestMixin|AccessMixin|StaffRequiredMixin|SuperuserRequiredMixin)\b/;
const DRF_VIEW = /\b(?:APIView|GenericAPIView|\w*ViewSet|(?:List|Retrieve|Create|Update|Destroy|ListCreate|RetrieveUpdate|RetrieveDestroy|RetrieveUpdateDestroy)APIView)\b/;
const DRF_READ_ONLY = /\b(?:ReadOnlyModelViewSet|ListAPIView|RetrieveAPIView)\b/;
const lastNames = (s) => s.split(",").map((x) => x.trim().replace(/^["']|["']$/g, "").split(".").pop()).filter(Boolean);

// DEFAULT_PERMISSION_CLASSES of settings.REST_FRAMEWORK; DRF's own default is AllowAny.
export function drfDefaultPermissions(files) {
  const s = files.find((f) => PY_RE.test(f.path) && /^REST_FRAMEWORK\s*=\s*\{/m.test(f.text));
  const m = s?.text.match(/["']DEFAULT_PERMISSION_CLASSES["']\s*:\s*[[(]([^\])]*)[\])]/);
  const names = m ? lastNames(m[1]) : [];
  return names.length ? names : ["AllowAny"];
}

// What a urls.py view expression resolves to, with its guards.
function djangoView(files, urlFile, expr, drfDefault) {
  const res = { guards: [], csrfExempt: false, methods: "ANY", allowAny: false, readOnly: false, handler: null };
  let e = expr.trim();
  const WRAP = /^(login_required|staff_member_required|superuser_required|csrf_exempt|never_cache|permission_required\([^()]*\)|user_passes_test\([^()]*\)|cache_page\([^()]*\))\(\s*([\s\S]*)\)$/;
  for (let m; (m = e.match(WRAP));) {
    const w = m[1].replace(/\([\s\S]*$/, "");
    if (w === "csrf_exempt") res.csrfExempt = true;
    else if (!/^(?:never_cache|cache_page)$/.test(w)) res.guards.push(`${w} (in urls)`);
    e = m[2].trim();
  }
  const ref = e.match(/^((?:\w+\.)*)(\w+)(?:\.as_view\([\s\S]*\))?$/);
  if (!ref) return res;
  const def = pyFindDef(files, ref[2], urlFile, ref[1].replace(/\.$/, "").split(".").pop());
  if (!def) return res;
  res.handler = { file: def.file, line: def.line, name: ref[2] };
  const decos = pyDecorators(def.text, def.line);
  const block = pyBlock(def.text, def.line);
  res.guards.push(...[...decos.matchAll(DJ_DECOR_GUARD)].map((m) => m[1]));
  if (/@(?:method_decorator\(\s*)?csrf_exempt\b/.test(decos)) res.csrfExempt = true;
  const listed = decos.match(/@(?:require_http_methods|api_view)\(\s*\[([^\]]*)\]/)?.[1];
  const verb = decos.match(/@require_(POST|GET|safe)\b/)?.[1];
  if (verb) res.methods = verb === "POST" ? "POST" : "GET";
  else if (listed) res.methods = quoted(listed).map((x) => x.toUpperCase()).join(",") || "ANY";
  let perms = null;
  let drf = false;
  if (def.kind === "class") {
    const bases = block.match(/^class\s+\w+\s*\(([^)]*)\)/)?.[1] ?? "";
    const mixin = bases.match(DJ_MIXIN)?.[1];
    if (mixin) res.guards.push(mixin);
    const md = (decos + "\n" + block).match(/method_decorator\(\s*(login_required|permission_required|user_passes_test|staff_member_required)/)?.[1];
    if (md) res.guards.push(`method_decorator(${md})`);
    if (/csrf_exempt/.test(decos + block.split("\n").slice(0, 3).join("\n"))) res.csrfExempt = true;
    const pc = block.match(/^\s+permission_classes\s*=\s*[[(]([^\])]*)[\])]/m);
    if (pc) perms = lastNames(pc[1]);
    drf = DRF_VIEW.test(bases);
    res.readOnly = DRF_READ_ONLY.test(bases) || /http_method_names\s*=\s*\[\s*["']get["']\s*(?:,\s*["'](?:head|options)["']\s*)*\]/.test(block);
    if (/ViewSet\b/.test(bases)) res.methods = "VIEWSET";
  } else {
    const pc = decos.match(/@permission_classes\(\s*[[(]([^\])]*)[\])]/);
    if (pc) perms = lastNames(pc[1]);
    drf = /@api_view\b/.test(decos);
    res.readOnly = res.methods === "GET";
  }
  if (perms || drf) {
    const list = perms ?? drfDefault;
    if (list.every((n) => n === "AllowAny")) res.allowAny = true;
    res.guards.push(`${perms ? "permission_classes" : "DRF default permission"}: ${list.join(", ")}`);
  }
  return res;
}

const djangoCache = new WeakMap();
// Every Django route of the project: urls.py `path`/`re_path`/`url` rows (with the prefixes of the
// include() chain that reaches them) and DRF `router.register` rows, each resolved to its view.
export function scanDjangoUrls(files) {
  if (djangoCache.has(files)) return djangoCache.get(files);
  const urlFiles = files.filter((f) => PY_RE.test(f.path) && !NON_RUNTIME.test(f.path) && /^urlpatterns\s*\+?=/m.test(f.text));
  const modFile = (mod) => {
    const rel = mod.replace(/\./g, "/") + ".py";
    return files.find((f) => f.path === rel || f.path.endsWith("/" + rel))?.path ?? null;
  };
  const includes = [];
  const raw = [];
  for (const f of urlFiles) {
    const lineAt = lineIndex(f.text);
    const routerPrefix = new Map();
    for (const m of f.text.matchAll(/(?<![\w.])(path|re_path|url)\(/g)) {
      const { parts } = pyArgs(f.text, m.index + m[0].length - 1);
      const route = pyStr(parts[0]);
      if (route == null || parts.length < 2) continue;
      const r = m[1] === "path" ? route : route.replace(/^\^/, "").replace(/\$$/, "");
      const inc = parts[1].match(/^include\(\s*\(?\s*([\s\S]*)\)$/);
      if (inc) {
        const target = pyStr(inc[1]) && modFile(pyStr(inc[1]));
        if (target) includes.push({ from: f.path, prefix: r, target });
        const rv = inc[1].match(/^(\w+)\.urls\b/);
        if (rv) routerPrefix.set(rv[1], r);
        continue;
      }
      if (/^admin\.site\.urls$/.test(parts[1])) continue;
      raw.push({ file: f.path, line: lineAt(m.index), route: r, view: parts[1] });
    }
    for (const m of f.text.matchAll(/(?<![\w.])(\w+)\.register\(/g)) {
      const { parts } = pyArgs(f.text, m.index + m[0].length - 1);
      const route = pyStr(parts[0]);
      if (route == null || !parts[1]) continue;
      raw.push({ file: f.path, line: lineAt(m.index), route: joinPath(routerPrefix.get(m[1]) ?? "", route), view: parts[1], viewset: true });
    }
  }
  const prefixOf = (file, seen = new Set()) => {
    if (seen.has(file)) return "";
    seen.add(file);
    const inc = includes.find((i) => i.target === file);
    return inc ? joinPath(prefixOf(inc.from, seen), inc.prefix) : "";
  };
  const drfDefault = drfDefaultPermissions(files);
  const out = raw.map((x) => {
    const v = djangoView(files, x.file, x.view, drfDefault);
    return {
      kind: "django-route", name: x.viewset ? "VIEWSET" : v.methods, route: joinPath(prefixOf(x.file), x.route), file: x.file, line: x.line,
      guard: v.guards.join("; "), pyHandler: v.handler,
      ...(v.allowAny ? { allowAny: true } : {}), ...(v.readOnly ? { readOnly: true } : {}), ...(v.csrfExempt ? { csrfExempt: true } : {}),
    };
  });
  djangoCache.set(files, out);
  return out;
}

const PY_DECOR_RE = /^([ \t]*)@(\w+)\.(get|post|put|patch|delete|options|head|route|api_route|websocket)\(/gm;
const FLASK_GUARD_RE = /^\s*@((?:\w+\.)*(?:\w*(?:login|auth|admin|role|roles|permission|permissions|staff|token|jwt|key)_required|requires_auth|roles_accepted))\b/gm;
const FLASK_VIEW_CHECK = /current_user\.is_authenticated|current_user\.is_anonymous|\babort\(\s*40[13]\b|verify_jwt_in_request\(/;

// `name = FastAPI(...) | APIRouter(...) | Flask(...) | Blueprint(...)` in one file.
function pyReceivers(text) {
  const out = new Map();
  for (const m of text.matchAll(/^(\w+)\s*(?::\s*[\w.]+\s*)?=\s*(?:\w+\.)?(FastAPI|APIRouter|Flask|Blueprint)\s*\(/gm)) {
    const { parts } = pyArgs(text, m.index + m[0].length - 1);
    const fast = m[2] === "FastAPI" || m[2] === "APIRouter";
    out.set(m[1], { kind: fast ? "fastapi" : "flask", app: m[2] === "FastAPI" || m[2] === "Flask", prefix: pyStr(pyKw(parts, fast ? "prefix" : "url_prefix")) ?? "", deps: authDeps(pyKw(parts, "dependencies")) });
  }
  return out;
}

const mountCache = new WeakMap();
// `app.include_router(x.router, prefix=..., dependencies=...)` and `app.register_blueprint(bp, url_prefix=...)`:
// "<file of the router>::<variable>" -> { prefix, deps } (deps include the app's own dependencies).
function pyMounts(files) {
  if (mountCache.has(files)) return mountCache.get(files);
  const out = new Map();
  const py = files.filter((f) => PY_RE.test(f.path) && !NON_RUNTIME.test(f.path));
  const top = (p) => p.split("/")[0];
  for (const f of py) {
    if (!/\.(?:include_router|register_blueprint)\(/.test(f.text)) continue;
    const appDeps = [...pyReceivers(f.text).values()].filter((r) => r.app).flatMap((r) => r.deps);
    for (const m of f.text.matchAll(/\b\w+\.(include_router|register_blueprint)\(/g)) {
      const { parts } = pyArgs(f.text, m.index + m[0].length - 1);
      const t = parts[0]?.match(/^(?:(\w+)\.)?(\w+)$/);
      if (!t) continue;
      const v = t[2];
      const mod = t[1] ?? f.text.match(new RegExp(`^from\\s+\\.*([\\w.]*)\\s+import\\s+[^\\n]*\\b${v}\\b`, "m"))?.[1]?.split(".").pop();
      const def = new RegExp(`^${v}\\s*(?::[^=\\n]+)?=\\s*(?:\\w+\\.)?(?:APIRouter|Blueprint)\\s*\\(`, "m");
      const cands = py.filter((x) => def.test(x.text));
      const pick = cands.find((x) => basename(x.path) === `${mod}.py` && top(x.path) === top(f.path)) ?? cands.find((x) => basename(x.path) === `${mod}.py`) ?? (cands.length === 1 ? cands[0] : null);
      if (!pick) continue;
      out.set(`${pick.path}::${v}`, { prefix: pyStr(pyKw(parts, m[1] === "include_router" ? "prefix" : "url_prefix")), deps: [...new Set([...authDeps(pyKw(parts, "dependencies")), ...appDeps])] });
    }
  }
  mountCache.set(files, out);
  return out;
}

// Flask `@bp.before_request` hooks that check the session: receiver -> hook name.
function flaskHooks(text) {
  const out = new Map();
  for (const m of text.matchAll(/^[ \t]*@(\w+)\.before_(?:app_)?request\b[^\n]*\n(?:[ \t]*@[^\n]*\n)*[ \t]*def\s+(\w+)/gm)) {
    const body = pyBlock(text, text.slice(0, m.index + m[0].length).split("\n").length);
    if (FLASK_VIEW_CHECK.test(body) || /\bsession\.get\(\s*["']\w*user|redirect\(\s*url_for\(\s*["'][\w.]*login/.test(body)) out.set(m[1], m[2]);
  }
  return out;
}

// FastAPI and Flask routes declared with decorators in one file.
export function scanPyRoutes(f, files = [f]) {
  const { text, path } = f;
  const out = [];
  if (!/^[ \t]*@\w+\.(?:get|post|put|patch|delete|options|head|route|api_route|websocket)\(/m.test(text)) return out;
  const recv = pyReceivers(text);
  const fileKind = /^\s*(?:from|import)\s+fastapi\b/m.test(text) ? "fastapi" : /^\s*(?:from|import)\s+flask\b/m.test(text) ? "flask" : null;
  const mounts = pyMounts(files);
  const hooks = flaskHooks(text);
  const appHook = [...recv].filter(([, r]) => r.app).map(([n]) => hooks.get(n)).find(Boolean);
  const lineAt = lineIndex(text);
  for (const m of text.matchAll(PY_DECOR_RE)) {
    const r = recv.get(m[2]);
    const kind = r?.kind ?? fileKind;
    if (!kind || (kind === "flask" && m[3] === "websocket")) continue;
    const { close, parts } = pyArgs(text, m.index + m[0].length - 1);
    const p = pyStr(parts[0]) ?? pyStr(pyKw(parts, "path")) ?? pyStr(pyKw(parts, "rule"));
    if (p == null) continue;
    const d = text.slice(close).match(/\n[ \t]*(?:async\s+)?def\s+(\w+)\s*\(/);
    if (!d) continue;
    const defIdx = close + d.index + 1;
    const defLine = lineAt(defIdx);
    const sigOpen = defIdx + text.slice(defIdx).indexOf("(");
    const sig = text.slice(sigOpen, pyMatchClose(text, sigOpen));
    const listed = quoted(pyKw(parts, "methods") ?? "").map((x) => x.toUpperCase());
    const methods = m[3] === "websocket" ? "WEBSOCKET" : /^(?:route|api_route)$/.test(m[3]) ? listed.join(",") || "GET" : m[3].toUpperCase();
    const mount = mounts.get(`${path}::${m[2]}`);
    const guards = [];
    let route;
    const entry = {};
    if (kind === "fastapi") {
      route = joinPath(mount?.prefix ?? "", r?.prefix ?? "", p);
      const own = authDeps(sig);
      if (own.length) guards.push(`Depends(${own.join(", ")})`);
      const dec = authDeps(pyKw(parts, "dependencies"));
      if (dec.length) guards.push(`route dependencies: ${dec.join(", ")}`);
      if (r?.deps.length) guards.push(`${r.app ? "app" : "router"} dependencies: ${r.deps.join(", ")}`);
      if (mount?.deps.length) guards.push(`include_router dependencies: ${mount.deps.join(", ")}`);
      const model = pyKw(parts, "response_model")?.match(/(\w+)\]*\s*$/)?.[1];
      if (model && model !== "None") entry.responseModel = model;
    } else {
      route = joinPath(mount?.prefix ?? r?.prefix ?? "", p);
      const dec = [...pyDecorators(text, defLine).matchAll(FLASK_GUARD_RE)].map((x) => x[1]);
      if (dec.length) guards.push(dec.join(", "));
      const hook = hooks.get(m[2]) ?? appHook;
      if (hook) guards.push(`before_request: ${hook}`);
      if (FLASK_VIEW_CHECK.test(pyBlock(text, defLine))) guards.push("check in the view");
    }
    out.push({ kind: `${kind}-route`, name: methods, route, file: path, line: lineAt(m.index), guard: guards.join("; "), pyHandler: { file: path, line: defLine, name: d[1] }, ...entry });
  }
  return out;
}

function pyEntryPoints(f, files) {
  return [...scanDjangoUrls(files).filter((e) => e.file === f.path), ...scanPyRoutes(f, files)];
}

// Models that belong to a user: Django models with a ForeignKey/OneToOneField to the user model, SQLAlchemy
// models with an owner-like `*_id` column (not the account table itself). The Python half of the scope scan.
const ownerCache = new WeakMap();
export function pyOwnerModels(files) {
  if (ownerCache.has(files)) return ownerCache.get(files);
  const out = new Set();
  for (const f of files) {
    if (!PY_RE.test(f.path) || NON_RUNTIME.test(f.path)) continue;
    const lineAt = lineIndex(f.text);
    for (const m of f.text.matchAll(/^class\s+(\w+)\s*\(([^)]*)\)\s*:/gm)) {
      const body = pyBlock(f.text, lineAt(m.index));
      if (/\bModel\b/.test(m[2]) && /\b(?:ForeignKey|OneToOneField)\(\s*(?:settings\.AUTH_USER_MODEL|get_user_model\(\)|["'](?:auth\.)?User["']|User\b)/.test(body)) out.add(m[1]);
      else if (/__tablename__/.test(body) && !/^(?:User|Account|Member|Staff|Person|Profile)s?$/.test(m[1]) && /^[ \t]+(?:user|owner|patient|customer|tenant|org|organization|account|team)_id\b\s*[:=]/m.test(body)) out.add(m[1]);
    }
  }
  ownerCache.set(files, out);
  return out;
}

// Field names of a pydantic (or any) class, its bases defined in the project included.
function pyModelFields(files, name, depth = 0) {
  if (depth > 3) return [];
  const re = new RegExp(`^class\\s+${name}\\s*\\(([^)]*)\\)\\s*:`, "m");
  for (const f of files) {
    if (!PY_RE.test(f.path)) continue;
    const m = f.text.match(re);
    if (!m) continue;
    const body = pyBlock(f.text, f.text.slice(0, m.index).split("\n").length);
    const own = [...body.matchAll(/^[ \t]+(\w+)\s*:/gm)].map((x) => x[1]).filter((n) => n !== "model_config");
    const inherited = m[1].split(",").map((b) => b.trim()).filter((b) => /^\w+$/.test(b) && b !== "BaseModel").flatMap((b) => pyModelFields(files, b, depth + 1));
    return [...new Set([...inherited, ...own])];
  }
  return [];
}

// ---------------------------------------------------------------- Drizzle scope scan

// Access-scope columns are checked on every verb. Authorship columns only on update/delete: editing
// someone else's comment is BOLA, reading it usually is not. Business entities (companyId, customerId)
// are not scope: in a single-tenant CRM they are just relations.
const OWNER_RE = /^(?:user|owner|org|organization|workspace|tenant|team|account)(?:_?id)?$/i;
const AUTHOR_RE = /^(?:(?:author|creator)(?:_?id)?|(?:created|uploaded|owned)_?by)$/i;
const TABLE_RE = /(?:export\s+)?const\s+(\w+)\s*=\s*(\w*[Tt]able)\s*\(\s*["'`]([\w.-]+)["'`]\s*,\s*(?:\(\s*\w*\s*\)\s*=>\s*\(\s*)?\{/g;
export const NON_RUNTIME = /(^|\/)(__tests__|tests?|e2e|migrations?|drizzle|seeds?|fixtures)\/|\.(test|spec)\.[cm]?[jt]sx?$|(^|\/)seed[^/]*$|(^|\/)(?:test_[^/]*|[^/]*_test|conftest)\.py$/;

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
const KIND_WEIGHT = { "server-action": [2, "callable directly as a POST"], webhook: [2, "public by design"], "ai-tool": [2, "arguments chosen by the model"], job: [1, "trusts its payload"], cron: [1, ""], "route-handler": [1, ""], "api-route": [1, ""], "http-route": [1, ""], "http-path": [1, ""], "http-prefix": [1, ""], trpc: [1, ""], "edge-function": [2, "public HTTPS endpoint"], "cloud-function": [2, "callable by any client of the project"], "laravel-route": [1, ""], "symfony-route": [1, ""], "drupal-route": [1, ""], "django-route": [1, ""], "fastapi-route": [1, ""], "flask-route": [1, ""] };
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
  // Python (roadmap R06)
  [/\.(?:raw|extra|execute|executemany)\(\s*f["']|\btext\(\s*f["']|\.(?:raw|execute)\(\s*["'][^"'\n]*["']\s*(?:%|\.format\(|\+)|\btext\(\s*["'][^"'\n]*["']\s*(?:%|\.format\(|\+)/, 3, "raw SQL built with an f-string, % or format (Django raw/extra, cursor.execute, SQLAlchemy text)"],
  [/\brender_template_string\(\s*(?!["'][^"'\n]*["']\s*[,)])/, 3, "render_template_string on a built string (server-side template injection)"],
  [/\bsend_file\(\s*(?!["'])[^)\n]*(?:request\.|os\.path\.join|\bname\b|\bpath\b)/, 3, "send_file with a path from the request"],
  [/\bpickle\.loads?\(|\byaml\.load\((?![^)]*SafeLoader)|\byaml\.unsafe_load\(|\bmarshal\.loads?\(|\bjsonpickle\.decode\(/, 3, "unsafe deserialization (pickle, yaml.load without SafeLoader)"],
  [/\bmark_safe\(\s*(?!["'][^"'\n]*["']\s*\))|\bMarkup\(\s*(?!["'][^"'\n]*["']\s*\))/, 2, "mark_safe/Markup on dynamic content"],
  [/os\.path\.join\((?![^)\n]*(?:secure_filename|get_valid_filename|basename))[^)\n]*(?:\.(?:name|filename)\b|request\.(?:POST|GET|FILES|form|args|files|user)|\b(?:name|filename)\s*\))/, 2, "file path built from the request or the client's file name"],
  [/\badd_task\(\s*\w+\s*,[^)\n]*\b\w*(?:url|callback|webhook)\w*/i, 3, "background task gets a URL from the request (SSRF)"],
  [/\b(?:requests|httpx)\.(?:get|post|put|patch|delete|head|request|stream)\(\s*(?!["']https?:\/\/)(?:\w+\.)*\w*(?:url|uri|callback|webhook|target|endpoint)\w*/i, 3, "outbound request to a URL from the request (SSRF)"],
  [/\*\*request\.(?:data|POST|GET|json|form|args)\b|\*\*request\.get_json\(\)/, 3, "request data unpacked into a model (mass assignment)"],
  [/\bsubprocess\.\w+\([^)\n]*shell\s*=\s*True|\bos\.(?:system|popen)\(/, 3, "shell/process execution"],
];
// A record loaded by id, and nothing in the handler that ties it to the caller.
const PHP_ID_LOAD = /::(?:find|findOrFail)\(\s*\$|->(?:find|findOrFail)\(\s*\$|\bWHERE\s+id\s*=\s*:id\b/i;
const PHP_OWNER = /authorize\(|Gate::|->user\(\)|currentUser\(\)|abort_unless|abort_if|denyAccessUnlessGranted|isGranted\(|->can\(|\b(?:uid|user_id|owner_id|customer_id)\s*(?:=|=>)|condition\(\s*['"](?:uid|user_id|owner_id)['"]|getUser\(\)|->(?:where|andWhere)\(\s*['"][\w.]*(?:user|owner|customer|tenant)/i;
// Python routes (roadmap R06): a record loaded by id, or a query on a model that has an owner, with nothing
// in the view that ties it to the caller.
const PY_ID_LOAD = /get_object_or_404\((?:[^()]|\([^()]*\))*\b(?:pk|id)\s*=|\.objects(?:\.\w+\((?:[^()]|\([^()]*\))*\))*\.get\(\s*(?:pk|id)\s*=|\bget_or_404\(|\.query\.get\(|\b(?:db|session|self\.db|db\.session)\.get\(\s*[A-Z]\w*\s*,|\.where\(\s*[A-Z]\w*\.id\s*==|\.filter(?:_by)?\(\s*(?:[A-Z]\w*\.)?id\s*==?/;
const PY_OWNER = /\brequest\.user\b|\bcurrent_user\b|\buser\.(?:id|pk|\w+_id)\b|\b(?:owner|patient|user|author|customer|account|tenant)(?:_id)?\s*=\s*(?:self\.)?(?:request\.user|user\b|current_user)|\.(?:user|owner|patient|customer|tenant|account|author)_id\s*==|\bhas_perm\(|has_object_permission|check_object_permissions/;
const PY_MODEL_USE = /\b([A-Z]\w*)\.objects\b|get_object_or_404\(\s*([A-Z]\w*)\b|\bselect\(\s*([A-Z]\w*)\b|\.get(?:_or_404)?\(\s*([A-Z]\w*)\s*,|\.query\(\s*([A-Z]\w*)\b|\b([A-Z]\w*)\.query\./g;
const SENSITIVE_FIELD = /password|passwd|secret|token|hash|totp|otp|api_?key|private|ssn/i;
const PUBLIC_PAGE = /\b(?:log-?in|log-?out|sign-?in|sign-?up|register|password[-_]reset|forgot)\b/i;
const PY_NO_AUTH = {
  "django-route": "no login_required, auth mixin or permission class on the view",
  "fastapi-route": "no auth dependency on the route, its router or its include_router",
  "flask-route": "no login_required (or similar) decorator and no before_request check",
};

// [points, reason] pairs for one Python route; 0 points means a note without weight.
function pyRouteSignals(e, body, files) {
  const out = [];
  const signed = SIGNATURE.test(body) || /\bhmac\.(?:new|compare_digest)\(/.test(body);
  if (!e.guard || e.allowAny) {
    if (e.allowAny && e.readOnly) out.push([0, "AllowAny on a read-only view (public by design?)"]);
    else if (signed) out.push([0, "no auth check on the route; signature check seen in the handler"]);
    else if (PUBLIC_PAGE.test(`${e.route} ${e.pyHandler?.name ?? ""}`)) out.push([0, "sign-in page: public by design"]);
    else out.push([3, e.allowAny ? "AllowAny on a view that writes" : PY_NO_AUTH[e.kind]]);
  }
  if (e.csrfExempt && !signed) out.push([2, "csrf_exempt on a view without a signature check"]);
  const owners = pyOwnerModels(files);
  const used = [...new Set([...body.matchAll(PY_MODEL_USE)].map((m) => m.slice(1).find(Boolean)).filter((n) => owners.has(n)))];
  if (signed) { /* a verified webhook acts for the sender, not for a signed-in user */ }
  else if (PY_ID_LOAD.test(body) && !PY_OWNER.test(body)) out.push([3, "record loaded by id without an ownership check"]);
  else if (used.length && !PY_OWNER.test(body)) out.push([3, `query on ${used.join(", ")} (owned by a user) without a filter on the current user`]);
  if (e.responseModel) {
    const leaked = pyModelFields(files, e.responseModel).filter((n) => SENSITIVE_FIELD.test(n));
    if (leaked.length) out.push([3, `response_model ${e.responseModel} returns ${leaked.join(", ")}`]);
  }
  return out;
}
const STATE_CHANGE_PATH = /\/(?:delete|remove|close|cancel|approve|reject|publish|unpublish|toggle|reopen|enable|disable|block|unblock|confirm|archive)\b/;
const DISPATCH = /\b(?:handle|toNextJsHandler|fetchRequestHandler|createRouteHandler|createNextRouteHandler)\(/;
const SIGNATURE = /constructEvent|\.verify\(|svix|signature|timingSafeEqual|createHmac|verifyWebhook/i;
const SECRET_ENV = /\b((?:NEXT_PUBLIC|VITE|EXPO_PUBLIC)_\w*(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE)\w*)/g;
const PUBLIC_BY_DESIGN = /PUBLISHABLE|POSTHOG|SENTRY|ANALYTICS|_GA_|GTM|MAPBOX|ANON_KEY|SITE_KEY|RECAPTCHA|ALGOLIA_SEARCH|VAPID_PUBLIC|PUBLIC_KEY|FIREBASE_API_KEY/;
const PRIVILEGED_CLIENT = /SERVICE_ROLE_KEY|service_role|from\s+["'`]firebase-admin|require\(\s*["'`]firebase-admin/;

export function areasOf(e) {
  const hay = `${e.route} ${e.name} ${e.file}${e.phpHandler ? ` ${e.phpHandler.cls} ${e.phpHandler.method}` : ""}${e.pyHandler ? ` ${e.pyHandler.name}` : ""}`;
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
    // Python routes: rank the view function or class the route resolves to.
    const py = e.pyHandler ? pyBlockAt(files, e.pyHandler) : null;
    if (py) body = py.body;
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
    } else if (PY_KINDS.has(e.kind)) {
      for (const [n, why] of pyRouteSignals(e, body, files)) if (n) add(n, why); else reasons.push(why);
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
    if (py && py.file !== e.file) reasons.push(`handler: ${py.file}:${py.line}`);
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
  for (const r of scanPyFiles(files)) out.push(r);
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

// ---------------------------------------------------------------- Python file signals (roadmap R06)

// Lines that decide escaping, sessions and CSRF for everything behind them: `|safe` and autoescape off
// in templates, DEBUG on by default, ALLOWED_HOSTS ['*'], a literal SECRET_KEY / Flask secret_key (or a
// literal fallback), Flask debug, csrf_exempt without a signature check, CORS that allows any origin with
// credentials (Starlette CORSMiddleware, django-cors-headers, Flask-CORS). ponytail: regex per line.
export function scanPyFiles(files) {
  const rows = [];
  const row = (f, line, kind, score, why) => rows.push({ score, kind, name: basename(f.path), route: "", file: f.path, line, areas: ["config"], reasons: [why] });
  for (const f of files) {
    if (NON_RUNTIME.test(f.path)) continue;
    const lines = f.text.split("\n");
    if (PY_TEMPLATE_RE.test(f.path)) {
      lines.forEach((l, i) => {
        if (/\|\s*safe\b/.test(l)) row(f, i + 1, "template", 3, "unescaped template output (|safe)");
        if (/\{%-?\s*autoescape\s+(?:off|false)\b/i.test(l)) row(f, i + 1, "template", 3, "autoescape turned off");
      });
      continue;
    }
    if (!PY_RE.test(f.path)) continue;
    const t = f.text;
    const lineAt = lineIndex(t);
    lines.forEach((l, i) => {
      if (/^\s*DEBUG\s*=\s*True\b/.test(l) || /^\s*DEBUG\s*=.*\bget(?:env)?\(\s*["']\w+["']\s*,\s*["']?(?:1|True|true|yes|on)["']?\s*\)/.test(l)) row(f, i + 1, "config", 3, "DEBUG on by default");
      if (/^\s*ALLOWED_HOSTS\s*=\s*\[\s*["']\*["']/.test(l)) row(f, i + 1, "config", 2, "ALLOWED_HOSTS = ['*']");
      if (/^\s*SECRET_KEY\s*=\s*["'][^"']+["']/.test(l)) row(f, i + 1, "config", 3, "SECRET_KEY is a literal in the source");
      else if (/^\s*SECRET_KEY\s*=\s*os\.(?:environ\.get|getenv)\(\s*["']\w+["']\s*,\s*["'][^"']+["']/.test(l)) row(f, i + 1, "config", 3, "SECRET_KEY falls back to a literal when the variable is missing");
      if (/\.secret_key\s*=\s*["']|\.config\[\s*["'](?:SECRET_KEY|JWT_SECRET_KEY)["']\s*\]\s*=\s*["']/.test(l)) row(f, i + 1, "config", 3, "Flask secret key is a literal: anyone who reads it can sign sessions");
      else if (/\.secret_key\s*=\s*os\.(?:environ\.get|getenv)\([^,)]+,\s*["']|\.config\[\s*["']SECRET_KEY["']\s*\]\s*=\s*os\.(?:environ\.get|getenv)\([^,)]+,\s*["']/.test(l)) row(f, i + 1, "config", 3, "Flask secret key falls back to a literal");
      if (/\.run\([^)]*\bdebug\s*=\s*True/.test(l) || /\.config\[\s*["']DEBUG["']\s*\]\s*=\s*True\b/.test(l)) row(f, i + 1, "config", 3, "Flask debug mode on (the debugger runs code)");
      if (/^\s*@csrf_exempt\b/.test(l)) {
        const j = lines.findIndex((x, k) => k > i && /^\s*(?:async\s+)?(?:def|class)\s/.test(x));
        const body = j < 0 ? "" : pyBlock(t, j + 1);
        if (!(SIGNATURE.test(body) || /\bhmac\./.test(body))) row(f, i + 1, "config", 3, "csrf_exempt on a view without a signature check");
      }
    });
    for (const m of t.matchAll(/\badd_middleware\(\s*CORSMiddleware\b/g)) {
      const { parts } = pyArgs(t, t.indexOf("(", m.index));
      const any = /["']\*["']/.test(pyKw(parts, "allow_origins") ?? "") || /^r?["']\.\*["']$/.test(pyKw(parts, "allow_origin_regex") ?? "");
      if (any && pyKw(parts, "allow_credentials") === "True") {
        const at = t.indexOf("allow_origin", m.index);
        row(f, lineAt(at), "config", 6, "CORS allows any origin with credentials (Starlette then echoes the caller's origin)");
      }
    }
    const allowAll = t.match(/^\s*CORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True\b/m);
    if (allowAll && /^\s*CORS_ALLOW_CREDENTIALS\s*=\s*True\b/m.test(t)) row(f, lineAt(allowAll.index + allowAll[0].search(/\S/)), "config", 6, "CORS allows any origin with credentials (django-cors-headers)");
    for (const m of t.matchAll(/\bCORS\(\s*\w+\b/g)) {
      const { parts } = pyArgs(t, t.indexOf("(", m.index));
      if (pyKw(parts, "supports_credentials") === "True" && !/["'][^*"']+["']/.test(pyKw(parts, "origins") ?? pyKw(parts, "resources") ?? "")) row(f, lineAt(m.index), "config", 6, "Flask-CORS with credentials and no origin list");
    }
  }
  return rows;
}

// bandit is a candidate source the pre-pass has no runner for yet (roadmap R07 adds tool runners). It only
// parses the code (it never imports or runs it), so the user can run it safely. NOT RUN with how to run it
// for a Python project; null when there is no Python. Dependency advisories for requirements.txt,
// poetry.lock, uv.lock and Pipfile.lock come from osv-scanner, with pip-audit as the fallback in prepass.mjs.
export function pythonToolStatus(files) {
  if (!files.some((f) => PY_RE.test(f.path) && !NON_RUNTIME.test(f.path))) return null;
  return "NOT RUN: the pre-pass has no bandit runner yet (roadmap R07). bandit only parses the code, it never imports or runs it, so it is safe to run: `pipx run bandit -r . -f json -o .security-audit/tools/bandit.json -x ./.venv,./node_modules,./tests`; B608 (SQL built from strings), B201 (Flask debug), B301/B506 (pickle, yaml.load), B602/B605 (shell), B105/B106 (hardcoded secrets), B310 (urlopen) and B703/B308 (mark_safe) results are candidates for the auditors";
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
