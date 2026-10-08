// Stack detection for the security-audit pre-pass (roadmap R04). No dependencies, no network.
// Reads manifests (package.json, composer.json, pyproject.toml, requirements*.txt, go.mod, Cargo.toml,
// Gemfile, pom.xml, build.gradle, *.csproj) up to MAX_DEPTH levels below the root, names the language
// and frameworks of each stack, and picks the profile the pre-pass applies, with what that profile covers
// and what it does not. `--stack <name>` forces a profile; a forced profile that the code does not match
// is applied anyway, with a warning.
// ponytail: manifest names and dependency names only, no lockfile resolution and no source parsing.
// A dependency that is declared but unused still counts; a framework vendored without a manifest is missed.

import { existsSync, lstatSync, readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";

const MAX_DEPTH = 3;
// Dependency trees, build output, and test or example code that is not the application.
const SKIP = new Set([
  "node_modules", "vendor", "dist", "build", "out", "coverage", "target", "venv", "env", "__pycache__",
  "storybook-static", "test", "tests", "__tests__", "e2e", "fixtures", "examples", "example", "docs",
]);

const JS_FRAMEWORKS = [
  // [dependency, label, supported by the dedicated pre-pass profile]
  ["next", "Next.js", true], ["hono", "Hono", true], ["express", "Express", true],
  ["@trpc/server", "tRPC", true], ["drizzle-orm", "Drizzle", true], ["better-auth", "Better-Auth", true],
  ["ai", "AI SDK", true], ["@modelcontextprotocol/sdk", "MCP SDK", true],
  ["pg-boss", "pg-boss", true], ["bullmq", "BullMQ", true],
  ["fastify", "Fastify", false], ["koa", "Koa", false], ["@nestjs/core", "NestJS", false],
  ["nuxt", "Nuxt", false], ["@sveltejs/kit", "SvelteKit", false], ["@remix-run/node", "Remix", false],
  ["@react-router/node", "React Router (framework mode)", false], ["astro", "Astro", false],
  ["@prisma/client", "Prisma", false], ["prisma", "Prisma", false], ["typeorm", "TypeORM", false],
  ["sequelize", "Sequelize", false], ["mongoose", "Mongoose", false], ["@apollo/server", "Apollo GraphQL", false],
  ["graphql-yoga", "GraphQL Yoga", false], ["firebase-admin", "Firebase Admin", false],
  ["@supabase/supabase-js", "Supabase", false],
];
// A package.json without any of these, next to another backend manifest, is frontend build tooling.
const JS_SERVER = new Set(["next", "hono", "express", "@trpc/server", "fastify", "koa", "@nestjs/core", "nuxt",
  "@sveltejs/kit", "@remix-run/node", "@react-router/node", "astro", "pg-boss", "bullmq", "@apollo/server", "graphql-yoga"]);

const PHP_FRAMEWORKS = [
  ["laravel/framework", "Laravel"], ["symfony/framework-bundle", "Symfony"], ["drupal/core", "Drupal"],
  ["drupal/core-recommended", "Drupal"], ["slim/slim", "Slim"], ["cakephp/cakephp", "CakePHP"],
  ["yiisoft/yii2", "Yii"], ["laminas/laminas-mvc", "Laminas"], ["roots/wordpress", "WordPress"],
  ["johnpbloch/wordpress", "WordPress"],
];
const PY_FRAMEWORKS = [
  ["django", "Django"], ["djangorestframework", "Django REST framework"], ["fastapi", "FastAPI"],
  ["flask", "Flask"], ["starlette", "Starlette"], ["litestar", "Litestar"], ["aiohttp", "aiohttp"],
  ["tornado", "Tornado"], ["sanic", "Sanic"], ["sqlalchemy", "SQLAlchemy"], ["celery", "Celery"],
];
const GO_FRAMEWORKS = [["github.com/gin-gonic/gin", "Gin"], ["github.com/labstack/echo", "Echo"],
  ["github.com/gofiber/fiber", "Fiber"], ["github.com/go-chi/chi", "chi"], ["github.com/gorilla/mux", "gorilla/mux"],
  ["gorm.io/gorm", "GORM"]];
const RUST_FRAMEWORKS = [["actix-web", "Actix Web"], ["axum", "Axum"], ["rocket", "Rocket"], ["warp", "warp"],
  ["diesel", "Diesel"], ["sqlx", "SQLx"]];
const RUBY_FRAMEWORKS = [["rails", "Rails"], ["sinatra", "Sinatra"], ["hanami", "Hanami"], ["grape", "Grape"]];
const JAVA_FRAMEWORKS = [["spring-boot", "Spring Boot"], ["org.springframework.boot", "Spring Boot"],
  ["quarkus", "Quarkus"], ["micronaut", "Micronaut"]];

// Libraries that are not frameworks (no entry points, no profile gap) but pick semgrep rulesets (tools.mjs).
const JS_LIBRARIES = [["react", "React"]];
const COMMON_GAPS = [
  "rule scanners (semgrep, zizmor, hadolint, trivy) run only when installed or docker is available; one that did not run is listed in not-assessed.md",
];

// Profiles the pre-pass can apply. `dedicated: false` means: the general checklist only.
export const PROFILES = {
  js: {
    name: "JavaScript/TypeScript (Node)", dedicated: true, lang: "js",
    covers: [
      "entry points by convention: Next.js route handlers, pages, server actions, proxy/middleware matcher, tRPC procedures, Hono/Express routes, hand-rolled node:http/Bun/Deno routers, pg-boss/BullMQ/cron jobs, AI SDK and MCP tools",
      "Drizzle tenant-scope scan (query sites that never reference the owner column)",
      "hotspot ranking with Better-Auth, CORS and browser-exposed env configuration checks",
      "JS/TS stack patterns for the auditors",
      "dependency advisories (osv-scanner) and secrets in git history (gitleaks)",
    ],
    gaps: [
      "tenant-scope scan for ORMs other than Drizzle (Prisma, TypeORM, Sequelize, Mongoose)",
      "entry-point conventions of NestJS, Fastify plugins, Remix/React Router, SvelteKit, Nuxt, Astro and GraphQL resolvers",
      ...COMMON_GAPS,
    ],
  },
  php: {
    name: "PHP", dedicated: false, lang: "php", roadmap: "R05",
    covers: [
      "Drupal *.routing.yml entry points with their access requirements",
      "PHP stack patterns for the auditors",
      "dependency advisories on composer.lock (osv-scanner, composer audit as fallback) and secrets in git history (gitleaks)",
    ],
    gaps: [
      "Laravel and Symfony routes, controllers and middleware are not enumerated: recon finds entry points by reading the code",
      "no Eloquent or Doctrine tenant-scope scan",
      "no Psalm taint analysis (roadmap R05)",
      ...COMMON_GAPS,
    ],
  },
  python: {
    name: "Python", dedicated: false, lang: "python", roadmap: "R06",
    covers: [
      "Python stack patterns for the auditors",
      "dependency advisories on the Python lockfile or requirements (osv-scanner) and secrets in git history (gitleaks)",
    ],
    gaps: [
      "Django URLconfs, FastAPI and Flask routes are not enumerated: recon finds entry points by reading the code",
      "no Django ORM or SQLAlchemy tenant-scope scan",
      "bandit and pip-audit are not run (roadmap R06)",
      ...COMMON_GAPS,
    ],
  },
  go: {
    name: "Go", dedicated: false, lang: "go", roadmap: "R09",
    covers: ["Go stack patterns for the auditors", "dependency advisories on go.sum (osv-scanner) and secrets in git history (gitleaks)"],
    gaps: ["routes are not enumerated: recon finds entry points by reading the code", "no ORM tenant-scope scan", "gosec is not run (roadmap R09)", ...COMMON_GAPS],
  },
  rust: {
    name: "Rust", dedicated: false, lang: null, roadmap: "R10",
    covers: ["dependency advisories on Cargo.lock (osv-scanner) and secrets in git history (gitleaks)"],
    gaps: ["no Rust stack patterns", "routes are not enumerated: recon finds entry points by reading the code", "cargo-audit and unsafe review are not run (roadmap R10)", ...COMMON_GAPS],
  },
  ruby: {
    name: "Ruby", dedicated: false, lang: "ruby", roadmap: "R16",
    covers: ["Ruby and Rails stack patterns for the auditors", "dependency advisories on Gemfile.lock (osv-scanner) and secrets in git history (gitleaks)"],
    gaps: ["Rails routes are not enumerated: recon finds entry points by reading the code", "no ActiveRecord tenant-scope scan", "brakeman is not run (roadmap R16)", ...COMMON_GAPS],
  },
  java: {
    name: "Java/Kotlin (JVM)", dedicated: false, lang: "java",
    covers: ["Java stack patterns for the auditors", "dependency advisories where a supported lockfile exists (osv-scanner) and secrets in git history (gitleaks)"],
    gaps: ["controllers and routes are not enumerated: recon finds entry points by reading the code", "no JPA/Hibernate tenant-scope scan", ...COMMON_GAPS],
  },
  dotnet: {
    name: ".NET", dedicated: false, lang: null,
    covers: ["secrets in git history (gitleaks)", "dependency advisories where a supported lockfile exists (osv-scanner)"],
    gaps: ["no .NET stack patterns", "controllers and routes are not enumerated: recon finds entry points by reading the code", ...COMMON_GAPS],
  },
  generic: {
    name: "Generic", dedicated: false, lang: null,
    covers: ["the general checklist", "secrets in git history (gitleaks)", "dependency advisories if a supported lockfile exists (osv-scanner)"],
    gaps: ["no language-specific entry points, scans or patterns", ...COMMON_GAPS],
  },
};

// `--stack` accepts a profile id or a framework/language alias.
const ALIASES = {
  js: "js", javascript: "js", typescript: "js", ts: "js", node: "js", nodejs: "js", next: "js", nextjs: "js",
  hono: "js", express: "js", trpc: "js",
  php: "php", laravel: "php", symfony: "php", drupal: "php", wordpress: "php",
  python: "python", py: "python", django: "python", fastapi: "python", flask: "python",
  go: "go", golang: "go", rust: "rust", ruby: "ruby", rails: "ruby", java: "java", kotlin: "java", spring: "java",
  dotnet: "dotnet", csharp: "dotnet", generic: "generic", none: "generic",
};
export const STACK_NAMES = Object.keys(ALIASES);

export function resolveStack(name) {
  const id = ALIASES[String(name ?? "").trim().toLowerCase()];
  if (!id) throw new Error(`unknown stack "${name}": use one of ${[...new Set(Object.values(ALIASES))].join(", ")} (or a framework alias such as laravel, django, nextjs)`);
  return id;
}

const read = (p) => {
  try {
    return readFileSync(p, "utf8");
  } catch {
    return "";
  }
};
const json = (p) => {
  try {
    return JSON.parse(readFileSync(p, "utf8"));
  } catch {
    return null;
  }
};
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
// A dependency name as a whole token in a manifest's text (requirements, pyproject, Gemfile, Cargo.toml).
const declares = (text, dep) => new RegExp(`(^|[\\s"'\\[,(])${esc(dep)}([\\s"'\\]<>=~!;,:@)]|$)`, "im").test(text);

// One directory: which stacks its manifests declare.
function detectDir(dir) {
  const names = new Set(readdirSync(dir));
  const has = (n) => names.has(n);
  const found = [];
  const add = (id, manifests, frameworks, extra = {}) => found.push({ id, manifests, frameworks: [...new Set(frameworks)], ...extra });

  if (has("composer.json")) {
    const c = json(join(dir, "composer.json")) ?? {};
    const deps = { ...(c.require ?? {}), ...(c["require-dev"] ?? {}) };
    const fw = PHP_FRAMEWORKS.filter(([d]) => d in deps).map(([, l]) => l);
    if (has("artisan")) fw.push("Laravel");
    if (has("bin") && existsSync(join(dir, "bin", "console")) && existsSync(join(dir, "config", "bundles.php"))) fw.push("Symfony");
    add("php", ["composer.json"], fw);
  }

  const pyManifests = [...names].filter((n) => /^(pyproject\.toml|requirements[\w.-]*\.txt|Pipfile|setup\.py|setup\.cfg|poetry\.lock|uv\.lock)$/.test(n)).sort();
  if (pyManifests.length || has("manage.py")) {
    const text = pyManifests.map((n) => read(join(dir, n))).join("\n");
    const fw = PY_FRAMEWORKS.filter(([d]) => declares(text, d)).map(([, l]) => l);
    if (has("manage.py")) fw.push("Django");
    add("python", pyManifests.length ? pyManifests : ["manage.py"], fw);
  }

  if (has("go.mod")) {
    const text = read(join(dir, "go.mod"));
    add("go", ["go.mod"], GO_FRAMEWORKS.filter(([d]) => text.includes(d)).map(([, l]) => l));
  }
  if (has("Cargo.toml")) {
    const text = read(join(dir, "Cargo.toml"));
    add("rust", ["Cargo.toml"], RUST_FRAMEWORKS.filter(([d]) => declares(text, d)).map(([, l]) => l));
  }
  if (has("Gemfile")) {
    const text = read(join(dir, "Gemfile"));
    add("ruby", ["Gemfile"], RUBY_FRAMEWORKS.filter(([d]) => new RegExp(`^\\s*gem\\s+["']${esc(d)}["']`, "m").test(text)).map(([, l]) => l));
  }
  const jvm = ["pom.xml", "build.gradle", "build.gradle.kts"].filter(has);
  if (jvm.length) {
    const text = jvm.map((n) => read(join(dir, n))).join("\n");
    add("java", jvm, JAVA_FRAMEWORKS.filter(([d]) => text.includes(d)).map(([, l]) => l));
  }
  const cs = [...names].filter((n) => /\.(csproj|fsproj)$/.test(n));
  if (cs.length) add("dotnet", cs, []);

  if (has("package.json")) {
    const p = json(join(dir, "package.json")) ?? {};
    const deps = { ...(p.dependencies ?? {}), ...(p.devDependencies ?? {}), ...(p.peerDependencies ?? {}) };
    const server = Object.keys(deps).some((d) => JS_SERVER.has(d));
    if (found.length && !server) {
      // Laravel, Django or Rails apps ship a package.json for vite/webpack: not a second backend.
      for (const f of found) f.notes = [...(f.notes ?? []), "package.json is frontend build tooling (no server framework)"];
    } else {
      const fw = JS_FRAMEWORKS.filter(([d]) => d in deps).map(([, l, ok]) => ({ l, ok }));
      add("js", ["package.json"], fw.map((f) => f.l), {
        libraries: JS_LIBRARIES.filter(([d]) => d in deps).map(([, l]) => l),
        unsupported: [...new Set(fw.filter((f) => !f.ok).map((f) => f.l))],
        workspace: Array.isArray(p.workspaces) || Array.isArray(p.workspaces?.packages) || has("pnpm-workspace.yaml"),
      });
    }
  }
  return found;
}

export function detectStack(root, { force = null } = {}) {
  const groups = new Map(); // id -> { id, dirs, manifests, frameworks, unsupported, notes }
  (function rec(dir, depth) {
    const rel = relative(root, dir).split(sep).join("/") || ".";
    for (const s of detectDir(dir)) {
      const g = groups.get(s.id) ?? { id: s.id, dirs: [], manifests: [], frameworks: [], libraries: [], unsupported: [], notes: [] };
      // A workspace root with no framework of its own is not a stack location.
      if (!(s.id === "js" && s.workspace && !s.frameworks.length)) g.dirs.push(rel);
      g.manifests.push(...s.manifests.map((m) => (rel === "." ? m : `${rel}/${m}`)));
      g.frameworks = [...new Set([...g.frameworks, ...s.frameworks])];
      g.libraries = [...new Set([...g.libraries, ...(s.libraries ?? [])])];
      g.unsupported = [...new Set([...g.unsupported, ...(s.unsupported ?? [])])];
      g.notes.push(...(s.notes ?? []).map((n) => (rel === "." ? n : `${rel}: ${n}`)));
      groups.set(s.id, g);
    }
    if (depth >= MAX_DEPTH) return;
    for (const name of readdirSync(dir).sort()) {
      if (SKIP.has(name) || name.startsWith(".")) continue;
      const p = join(dir, name);
      if (lstatSync(p).isDirectory()) rec(p, depth + 1);
    }
  })(root, 0);

  // A stack seen only at a framework-less workspace root still has a location: the root.
  const detected = [...groups.values()]
    .map((g) => ({ ...g, dirs: g.dirs.length ? g.dirs : ["."] }))
    .sort((a, b) => Number(b.dirs.includes(".")) - Number(a.dirs.includes(".")) || b.dirs.length - a.dirs.length || a.id.localeCompare(b.id));

  let applied;
  let warning = "";
  if (force) {
    const id = resolveStack(force);
    applied = [id];
    const others = detected.filter((d) => d.id !== id);
    if (id !== "generic" && !detected.some((d) => d.id === id)) {
      warning = `--stack ${force} overrides detection: the code looks like ${detected.length ? detected.map(label).join(" + ") : "no known stack"}. The forced profile is applied anyway; check that this is intended.`;
    } else if (others.length) {
      warning = `--stack ${force} applies only the ${PROFILES[id].name} profile; also detected: ${others.map(label).join(", ")} (listed as not covered).`;
    }
  } else {
    applied = detected.length ? detected.map((d) => d.id) : ["generic"];
  }

  const profiles = applied.map((id) => {
    const p = PROFILES[id];
    const d = detected.find((x) => x.id === id);
    const fw = d?.frameworks ?? [];
    const covers = p.covers.filter((c) => !(id === "php" && /Drupal/.test(c) && !fw.includes("Drupal")));
    const gaps = [...p.gaps];
    if (d?.unsupported.length) gaps.unshift(`detected without a pre-pass convention: ${d.unsupported.join(", ")} (auditors find these entry points and queries by hand)`);
    return { id, name: p.name, dedicated: p.dedicated, roadmap: p.roadmap ?? "", frameworks: fw, dirs: d?.dirs ?? [], covers, gaps };
  });
  if (force) {
    for (const d of detected.filter((x) => x.id !== applied[0])) {
      profiles[0].gaps.push(`${label(d)}: detected but not profiled because --stack forced ${PROFILES[applied[0]].name}`);
    }
  }
  return { detected, applied, forced: force ? resolveStack(force) : null, forced_as: force ?? null, warning, profiles };
}

export function label(d) {
  const where = d.dirs.length === 1 && d.dirs[0] === "." ? "" : ` in ${d.dirs.join(", ")}`;
  return `${PROFILES[d.id].name}${d.frameworks.length ? ` (${d.frameworks.join(", ")})` : ""}${where}`;
}

// One line per profile for reports: "Profile: X. Covers ... Does not cover ...".
export function profileHeadline(p) {
  return p.dedicated
    ? `${p.name}${p.frameworks.length ? ` (${p.frameworks.join(", ")})` : ""}: dedicated profile`
    : `${p.name}${p.frameworks.length ? ` (${p.frameworks.join(", ")})` : ""}: no dedicated profile, the general checklist applies${p.roadmap ? ` (profile planned as ${p.roadmap})` : ""}`;
}

// Markdown block shared by prepass.md and report.md.
export function stackMarkdown(stack, heading = "##") {
  if (!stack) return [];
  const L = [`${heading} Stack and Profile`, ""];
  L.push(`Detected: ${stack.detected.length ? stack.detected.map(label).join("; ") : "no known manifest"}.${stack.forced ? ` Forced with --stack ${stack.forced_as}.` : ""}`);
  if (stack.warning) L.push("", `**Warning:** ${stack.warning}`);
  for (const p of stack.profiles) {
    L.push("", `**Profile: ${profileHeadline(p)}${p.dirs.length && !(p.dirs.length === 1 && p.dirs[0] === ".") ? `, in ${p.dirs.join(", ")}` : ""}.**`, "");
    L.push(`- Covers: ${p.covers.join("; ")}.`);
    L.push(`- Does not cover: ${p.gaps.join("; ")}.`);
  }
  const notes = stack.detected.flatMap((d) => d.notes);
  if (notes.length) L.push("", `Notes: ${notes.join("; ")}.`);
  L.push("");
  return L;
}
