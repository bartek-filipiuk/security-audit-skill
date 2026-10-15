// Run: node --test scripts/*.test.mjs
// PHP profile (roadmap R05): Laravel, Symfony and Drupal entry points, PHP hotspot signals, the Psalm
// NOT RUN status, profile briefs and the php-tickets benchmark app with its answer key.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { benchApp, listApps } from "../benchmark/apps.mjs";
import { primaryLocation, score } from "../benchmark/score.mjs";
import { detectLanguages, patternsFor, profileSections, writeBriefs } from "./briefs.mjs";
import { accessControl, phpTaintStatus, rankHotspots, scanEntryPoints, scanLaravelRoutes, scanPhpFiles, scanScope, scanSymfonyRoutes, walk } from "./surface.mjs";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
const bench = benchApp("php-tickets");
const key = JSON.parse(readFileSync(bench.key, "utf8"));
const { files } = walk(bench.app);
const PORTAL = "portal/web/modules/custom/helpdesk_portal";

const finding = (id, file, { status = "verified", category = id.split("-")[0] } = {}) => {
  const text = `---\nid: ${id}\ncategory: ${category}\nseverity: HIGH\nstatus: ${status}\n---\n\n## Title\n${id} title\n\n## Evidence\n- **File**: \`${file}\`\n\n## Impact\nx\n`;
  return { stem: id, data: { id, category, severity: "HIGH", status }, body: `## Title\n${id} title\n`, text };
};
const entriesOf = (r, id) => r.matches.find((m) => m.finding === id).entries;
const sourceFiles = (dir) => readdirSync(dir, { recursive: true }).map(String).filter((p) => statSync(join(dir, p)).isFile());
const lineOf = (file, n) => readFileSync(join(bench.app, file), "utf8").split("\n")[n - 1];

// ---------------------------------------------------------------- benchmark app and key

test("php-tickets is a benchmark app in benchmark/php-tickets", () => {
  assert.ok(listApps().includes("php-tickets"));
  assert.equal(bench.app, join(repo, "benchmark", "php-tickets", "app"));
  assert.equal(bench.key, join(repo, "benchmark", "php-tickets", "answer-key.json"));
  assert.equal(key.app, "php-tickets");
  assert.ok(key.seeded.length >= 6 && key.decoys.length >= 4);
  assert.ok(!existsSync(join(bench.app, "vendor")) && !existsSync(join(bench.app, "composer.lock")), "no vendor/, no install");
});

test("php-tickets seeds and decoys cover Laravel, Symfony and Drupal", () => {
  const files = (list) => new Set(list.flatMap((e) => e.locations.map((l) => l.file)));
  for (const list of [key.seeded, key.decoys]) {
    const f = [...files(list)];
    assert.ok(f.some((p) => p.startsWith("app/") || p.startsWith("routes/")), "Laravel");
    assert.ok(f.some((p) => p.startsWith("billing/")), "Symfony");
    assert.ok(f.some((p) => p.startsWith("portal/")), "Drupal");
  }
});

test("php-tickets key ranges sit on the statements they describe", () => {
  const at = (id) => [...key.seeded, ...key.decoys].find((e) => e.id === id).locations;
  const expect = {
    B01: /function show/, B02: /whereRaw\("subject LIKE/, B03: /update\(\$request->all\(\)\)/, B04: /reports\/export/,
    B05: /\{!! \$comment->body !!\}/, B06: /'account\/\*'/, B07: /getClientOriginalName/, B08: /function searchByNumber/,
    B09: /#\[Route\('\/\{id\}'/, B10: /helpdesk_portal\.ticket_json:/, B11: /\$mail = \$request/, B12: /helpdesk_portal\.close:/,
    B13: /Markup::create/, D02: /Ticket::query/, D06: /nl2br\(e\(/, D10: /helpdesk_portal\.status:/, D12: /helpdesk_portal\.reopen:/,
    D14: /APP_DEBUG=true/,
  };
  for (const [id, re] of Object.entries(expect)) {
    const l = at(id)[0];
    assert.match(lineOf(l.file, l.lines[0]), re, `${id} starts at ${l.file}:${l.lines[0]}`);
  }
  assert.match(lineOf("app/Models/User.php", at("B03")[1].lines[0]), /\$guarded = \[\]/);
  assert.match(lineOf("config/app.php", at("D14")[1].lines[0]), /APP_DEBUG', false/);
});

test("php-tickets source has no hint comments, no real-looking keys and only reserved domains", () => {
  for (const rel of sourceFiles(bench.app)) {
    const text = readFileSync(join(bench.app, rel), "utf8");
    assert.ok(!/\b(?:seed(?:ed|ers?)?|vuln\w*|insecure|exploit|decoy|bug|TODO|FIXME|B\d\d|D\d\d)\b/i.test(text), `${rel} has a hint word`);
    assert.ok(!/base64:[A-Za-z0-9+/]{20,}|sk_live_|AKIA[0-9A-Z]{16}|eyJ[\w-]{10,}\.|-----BEGIN [A-Z ]*PRIVATE KEY/.test(text), `${rel} has a real-looking key`);
    assert.ok(!/^(?:APP_KEY|DB_PASSWORD|MAIL_WEBHOOK_SECRET)=\S/m.test(text), `${rel} sets a secret value`);
    for (const m of text.matchAll(/https?:\/\/([\w.-]+)/g)) {
      assert.ok(/(?:^|\.)(?:example|invalid)$|^(?:localhost|127\.0\.0\.1)$/.test(m[1]), `${rel}: ${m[1]} is not a reserved domain`);
    }
    for (const m of text.matchAll(/[\w.-]+@([\w-]+(?:\.[\w-]+)+)/g)) assert.ok(/\.(?:example|invalid)$/.test(m[1]), `${rel}: e-mail domain ${m[1]}`);
  }
});

test("scorer parses PHP, Blade, Twig and Drupal locations, and Laravel's own app/ directory", () => {
  assert.deepEqual(primaryLocation("- **File**: `resources/views/tickets/show.blade.php:20`"), { file: "resources/views/tickets/show.blade.php", start: 20, end: 20 });
  assert.deepEqual(primaryLocation(`- **File**: \`${PORTAL}/helpdesk_portal.routing.yml:9-15\``), { file: `${PORTAL}/helpdesk_portal.routing.yml`, start: 9, end: 15 });
  assert.equal(primaryLocation("- **File**: `billing/templates/invoice/show.html.twig:4`").file, "billing/templates/invoice/show.html.twig");
  assert.equal(primaryLocation("- **File**: `web/modules/custom/x/x.module:12`").file, "web/modules/custom/x/x.module");
  // A finding may cite app/Http/... (relative to the app) or app/app/Http/... (relative to the run dir).
  for (const cited of ["app/Http/Controllers/TicketController.php:32", "app/app/Http/Controllers/TicketController.php:32", "Http/Controllers/TicketController.php:32"]) {
    const r = score([finding("auth-001", cited)], key);
    assert.deepEqual(entriesOf(r, "auth-001"), ["B01"], cited);
  }
  const other = score([finding("auth-001", "src/app/Http/Controllers/TicketController.php:32")], { seeded: [{ id: "B01", locations: [{ file: "app/Http/Controllers/TicketController.php", lines: [30, 35] }] }], decoys: [] });
  assert.equal(other.found, 1, "a longer cited path still ends with the key file");
});

test("scoring php-tickets: a finding on every seeded range is found, decoys count as false positives", () => {
  const seeded = key.seeded.map((e, i) => finding(`auth-${100 + i}`, `${e.locations[0].file}:${e.locations[0].lines[0]}`));
  const decoys = key.decoys.map((e, i) => finding(`auth-${200 + i}`, `${e.locations[0].file}:${e.locations[0].lines[0]}`));
  const r = score([...seeded, ...decoys], key);
  assert.equal(r.found, key.seeded.length);
  assert.equal(r.recall, 1);
  assert.equal(r.decoy_fp, key.decoys.length);
});

test("scoring php-tickets: neighbouring seeded and decoy ranges stay apart", () => {
  const ctl = `${PORTAL}/src/Controller/PortalController.php`;
  const r = score([
    finding("injection-001", `${ctl}:17`),
    finding("injection-002", `${ctl}:22`),
    finding("xss-001", `${ctl}:28`),
    finding("xss-002", `${ctl}:31`),
    finding("config-001", "app/Http/Middleware/VerifyCsrfToken.php:15"),
    finding("config-002", "app/Http/Middleware/VerifyCsrfToken.php:16"),
    finding("auth-001", `${PORTAL}/helpdesk_portal.routing.yml:17`),
    finding("auth-002", `${PORTAL}/helpdesk_portal.routing.yml:25`),
    finding("injection-003", "app/Http/Controllers/TicketController.php:16"),
    finding("auth-003", "billing/src/Controller/InvoiceController.php:40"),
    finding("auth-004", "billing/src/Controller/InvoiceController.php:48"),
    finding("xss-003", "resources/views/tickets/show.blade.php:8"),
  ], key);
  assert.deepEqual(entriesOf(r, "injection-001"), ["D11"]);
  assert.deepEqual(entriesOf(r, "injection-002"), ["B11"]);
  assert.deepEqual(entriesOf(r, "xss-001"), ["D13"]);
  assert.deepEqual(entriesOf(r, "xss-002"), ["B13"]);
  assert.deepEqual(entriesOf(r, "config-001"), ["D04"]);
  assert.deepEqual(entriesOf(r, "config-002"), ["B06"]);
  assert.deepEqual(entriesOf(r, "auth-001"), ["B12"]);
  assert.deepEqual(entriesOf(r, "auth-002"), ["D12"]);
  assert.deepEqual(entriesOf(r, "injection-003"), ["B02"]);
  assert.deepEqual(entriesOf(r, "auth-003"), ["B09"]);
  assert.deepEqual(entriesOf(r, "auth-004"), ["D09"]);
  assert.deepEqual(entriesOf(r, "xss-003"), ["D06"]);
});

test("setup --app php-tickets builds a one-commit run, and score reads app/ paths of a Laravel tree", () => {
  const dest = join(mkdtempSync(join(tmpdir(), "sa-r05-")), "run");
  execFileSync(process.execPath, [join(repo, "benchmark", "setup.mjs"), "--app", "php-tickets", "--dest", dest], { stdio: "pipe" });
  assert.equal(JSON.parse(readFileSync(join(dest, "meta.json"), "utf8")).bench_app, "php-tickets");
  assert.equal(execFileSync("git", ["-C", join(dest, "app"), "rev-list", "--count", "HEAD"], { encoding: "utf8" }).trim(), "1");
  assert.ok(existsSync(join(dest, "app", "routes", "web.php")) && !existsSync(join(dest, "answer-key.json")));
  const dir = join(dest, "app", ".security-audit", "findings");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "auth-001.md"), finding("auth-001", "app/Http/Controllers/TicketController.php:32").text);
  writeFileSync(join(dir, "xss-001.md"), finding("xss-001", "resources/views/tickets/show.blade.php:8").text);
  const out = execFileSync(process.execPath, [join(repo, "benchmark", "score.mjs"), dest, "--no-save"], { encoding: "utf8" });
  assert.match(out, /^App php-tickets$/m);
  assert.match(out, new RegExp(`Recall 1/${key.seeded.length} `));
  assert.match(out, /decoy false positives 1/);
});

// ---------------------------------------------------------------- Laravel routes

test("Laravel: verbs, chained and array groups, nested prefixes, own and removed middleware, handlers", () => {
  const text = `<?php
use Illuminate\\Support\\Facades\\Route;

Route::get('/', [HomeController::class, 'index']);
Route::post('/hooks/stripe', StripeWebhookController::class);

Route::middleware(['auth', 'verified'])->prefix('app')->group(function () {
    Route::get('/projects/{id}', [ProjectController::class, 'show'])->name('projects.show');
    Route::delete('/projects/{id}', 'ProjectController@destroy')->middleware('can:delete-projects');
    Route::get('/feed', [FeedController::class, 'index'])->withoutMiddleware('auth');
    Route::prefix('team')->group(function () {
        Route::resource('members', MemberController::class);
    });
});

Route::group(['middleware' => 'auth:sanctum', 'prefix' => 'v2'], function () {
    Route::match(['get', 'post'], '/search', [SearchController::class, 'run']);
});
Route::middleware('throttle:10,1')->post('/login', [LoginController::class, 'store']);
`;
  const eps = scanLaravelRoutes({ path: "routes/web.php", text });
  const by = (route, name) => eps.find((e) => e.route === route && (!name || e.name === name));
  assert.equal(eps.length, 8);
  assert.deepEqual([by("/").guard, by("/").phpHandler, by("/").line], ["", { cls: "HomeController", method: "index" }, 4]);
  assert.deepEqual(by("/hooks/stripe").phpHandler, { cls: "StripeWebhookController", method: "__invoke" });
  assert.deepEqual(by("/app/projects/{id}", "GET").middleware, ["auth", "verified"]);
  assert.deepEqual(by("/app/projects/{id}", "DELETE").middleware, ["auth", "verified", "can:delete-projects"]);
  assert.deepEqual(by("/app/projects/{id}", "DELETE").phpHandler, { cls: "ProjectController", method: "destroy" });
  assert.deepEqual(by("/app/feed").middleware, ["verified"]);
  assert.deepEqual([by("/app/team/members").name, by("/app/team/members").guard], ["RESOURCE", "middleware: auth, verified"]);
  assert.deepEqual([by("/v2/search").name, by("/v2/search").guard], ["GET,POST", "middleware: auth:sanctum"]);
  assert.deepEqual(by("/login").middleware, ["throttle:10,1"]);
  assert.equal(scanLaravelRoutes({ path: "routes/api.php", text: "<?php\nRoute::get('/me', [MeController::class, 'show']);\n" })[0].route, "/api/me");
});

test("Laravel: php-tickets routes, with Route::view skipped and console routes ignored", () => {
  const eps = scanEntryPoints(files).filter((e) => e.kind === "laravel-route");
  assert.equal(eps.length, 16);
  const at = (file, line) => eps.find((e) => e.file === file && e.line === line);
  assert.deepEqual([at("routes/api.php", 12).route, at("routes/api.php", 12).guard], ["/api/reports/export", ""]);
  assert.equal(at("routes/web.php", 19).guard, "middleware: auth");
  assert.equal(at("routes/web.php", 32).guard, "middleware: auth, can:admin");
  assert.equal(at("routes/web.php", 32).route, "/admin/users/{user}");
  assert.deepEqual(scanEntryPoints([{ path: "routes/console.php", text: "<?php\nArtisan::command('x', fn () => 1);\n" }]), []);
});

// ---------------------------------------------------------------- Symfony routes

test("Symfony: attribute routes with class prefix, IsGranted, methods, annotations and access_control", () => {
  const security = { path: "config/packages/security.yaml", text: "security:\n    access_control:\n        - { path: ^/admin, roles: ROLE_ADMIN }\n        - { path: '^/(account|orders)', roles: [ROLE_USER] }\n" };
  const ctl = {
    path: "src/Controller/OrderController.php",
    text: `<?php
namespace App\\Controller;

#[Route('/orders', name: 'order_')]
class OrderController extends AbstractController
{
    #[Route('/{id}', name: 'show', methods: ['GET'])]
    public function show(Order $order): Response
    {
        return $this->render('order/show.html.twig', ['order' => $order]);
    }

    #[Route('/{id}/cancel', name: 'cancel', methods: ['POST'])]
    #[IsGranted('EDIT', subject: 'order')]
    public function cancel(Order $order): Response
    {
        return $this->redirectToRoute('order_show');
    }

    /**
     * @Route("/export", methods={"GET"})
     */
    public function export(): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');
        return new Response('');
    }
}
`,
  };
  const eps = scanSymfonyRoutes(ctl, [ctl, security]);
  assert.deepEqual(eps.map((e) => [e.name, e.route, e.line]), [["GET", "/orders/{id}", 7], ["POST", "/orders/{id}/cancel", 13], ["GET", "/orders/export", 21]]);
  assert.equal(eps[0].guard, "access_control ^/(account|orders): ROLE_USER");
  assert.equal(eps[1].guard, "IsGranted('EDIT', subject: 'order'); access_control ^/(account|orders): ROLE_USER");
  assert.match(eps[2].guard, /denyAccessUnlessGranted in body/);
  assert.deepEqual(eps[1].phpHandler, { cls: "OrderController", method: "cancel" });
  assert.deepEqual(accessControl(security.text), [{ path: "^/admin", roles: "ROLE_ADMIN" }, { path: "^/(account|orders)", roles: "ROLE_USER" }]);

  const yaml = { path: "config/routes.yaml", text: "controllers:\n    resource: ../src/Controller/\n    type: attribute\n\nadmin_stats:\n    path: /admin/stats\n    controller: App\\Controller\\StatsController::show\n" };
  const [stats] = scanSymfonyRoutes(yaml, [yaml, security]);
  assert.deepEqual([stats.name, stats.route, stats.line, stats.guard, stats.phpHandler.method], ["ANY", "/admin/stats", 5, "access_control ^/admin: ROLE_ADMIN", "show"]);
});

test("Symfony: php-tickets billing routes carry the class IsGranted and the access_control rule", () => {
  const eps = scanEntryPoints(files).filter((e) => e.kind === "symfony-route");
  assert.deepEqual(eps.map((e) => e.route).sort(), ["/health", "/invoices", "/invoices/search", "/invoices/{id}", "/invoices/{id}/pdf"]);
  const show = eps.find((e) => e.route === "/invoices/{id}");
  assert.deepEqual([show.file, show.line, show.guard], ["billing/src/Controller/InvoiceController.php", 37, "IsGranted('ROLE_USER'); access_control ^/invoices: ROLE_USER"]);
  assert.equal(eps.find((e) => e.route === "/health").guard, "");
});

// ---------------------------------------------------------------- Drupal routes

test("Drupal: routing.yml rows keep their requirements and point at the controller method", () => {
  const eps = scanEntryPoints(files).filter((e) => e.kind === "drupal-route");
  assert.equal(eps.length, 5);
  const by = (name) => eps.find((e) => e.name === `helpdesk_portal.${name}`);
  assert.deepEqual([by("ticket_json").line, by("ticket_json").guard], [9, "_access: 'TRUE'"]);
  assert.deepEqual(by("ticket_json").phpHandler, { cls: "PortalController", method: "ticketJson" });
  assert.match(by("reopen").guard, /_csrf_token: 'TRUE'/);
  const post = scanEntryPoints([{ path: "x/x.routing.yml", text: "x.delete:\n  path: '/x/{id}/delete'\n  defaults:\n    _form: '\\Drupal\\x\\Form\\DeleteForm'\n  methods: [POST]\n  requirements:\n    _permission: 'administer x'\n" }]);
  assert.deepEqual([post[0].methods, post[0].phpHandler], ["POST", { cls: "DeleteForm", method: "" }]);
});

// ---------------------------------------------------------------- hotspots

test("hotspots: PHP routes are ranked by their controller method, seeded ones carry the reason", () => {
  const eps = scanEntryPoints(files);
  const hot = rankHotspots(files, eps, scanScope(files)).filter((h) => h.score > 0);
  const at = (file, line) => hot.find((h) => h.file === file && h.line === line);
  const why = (file, line) => at(file, line).reasons.join("; ");
  assert.match(why("routes/api.php", 12), /no auth middleware on the route.*handler: app\/Http\/Controllers\/ReportController\.php:23/);
  assert.match(why("routes/web.php", 19), /record loaded by id without an ownership or policy check/);
  assert.match(why("routes/web.php", 17), /raw SQL with request data interpolated/);
  assert.match(why("routes/web.php", 26), /mass assignment/);
  assert.match(why("routes/web.php", 23), /client's file name/);
  assert.match(why("billing/src/Controller/InvoiceController.php", 27), /SQL\/DQL string built by concatenation/, "the repository method the controller calls");
  assert.match(why("billing/src/Controller/InvoiceController.php", 37), /record loaded by id/);
  assert.match(why(`${PORTAL}/helpdesk_portal.routing.yml`, 9), /open to everyone \(_access: 'TRUE'\).*record loaded by id/);
  assert.match(why(`${PORTAL}/helpdesk_portal.routing.yml`, 17), /changes state on GET without _csrf_token/);
  assert.match(why(`${PORTAL}/helpdesk_portal.routing.yml`, 1), /SQL\/DQL string built by concatenation.*Markup::create/);
  assert.match(why("resources/views/tickets/show.blade.php", 20), /unescaped Blade output/);
  assert.match(why("app/Models/User.php", 13), /\$guarded = \[\]/);
  assert.match(why("app/Http/Middleware/VerifyCsrfToken.php", 16), /CSRF verification skipped for "account\/\*"/);

  // Decoys: no signal of their own.
  assert.doesNotMatch(why("routes/web.php", 14), /no auth middleware on the route/, "signed webhook");
  assert.doesNotMatch(why("routes/web.php", 33), /raw SQL/, "bound whereRaw");
  assert.doesNotMatch(why("routes/web.php", 27), /client's file name/, "generated avatar name");
  assert.doesNotMatch(why("routes/web.php", 20), /record loaded by id/);
  assert.doesNotMatch(why("billing/src/Controller/InvoiceController.php", 45), /record loaded by id|no #\[IsGranted\]/);
  assert.doesNotMatch(why(`${PORTAL}/helpdesk_portal.routing.yml`, 25), /_csrf_token/);
  assert.equal(why(`${PORTAL}/helpdesk_portal.routing.yml`, 34).includes("open to everyone"), false, "the public status route");
  assert.ok(!hot.some((h) => h.file === "resources/views/tickets/show.blade.php" && h.line === 8), "nl2br(e()) is escaped");
  assert.ok(!hot.some((h) => h.file === "app/Http/Middleware/VerifyCsrfToken.php" && h.line === 15), "webhook CSRF exception");
});

test("PHP file signals: Blade, Twig, $guarded, debug defaults and CSRF exceptions", () => {
  const rows = scanPhpFiles([
    { path: "resources/views/a.blade.php", text: "{!! $x !!}\n{!! e($y) !!} {!! csrf_field() !!}\n{{ $z }}\n" },
    { path: "templates/a.html.twig", text: "{{ a }}\n{{ b|raw }}\n" },
    { path: "app/Models/Post.php", text: "<?php\nclass Post extends Model {\n    protected $guarded = [];\n}\n" },
    { path: "config/app.php", text: "<?php\nreturn [\n    'debug' => (bool) env('APP_DEBUG', true),\n];\n" },
    { path: "bootstrap/app.php", text: "<?php\n$m->validateCsrfTokens(except: [\n    'stripe/*',\n    'settings/*',\n]);\n" },
    { path: "tests/Feature/a.blade.php", text: "{!! $x !!}\n" },
  ]);
  assert.deepEqual(rows.map((r) => `${r.file}:${r.line}`), ["resources/views/a.blade.php:1", "templates/a.html.twig:2", "app/Models/Post.php:3", "config/app.php:3", "bootstrap/app.php:4"]);
  assert.match(rows[4].reasons[0], /"settings\/\*"/);
});

test("Psalm taint analysis is reported NOT RUN for PHP projects and omitted otherwise", () => {
  assert.match(phpTaintStatus(files), /^NOT RUN: .*--taint-analysis/);
  assert.equal(phpTaintStatus([{ path: "src/index.ts", text: "" }]), null);
  assert.equal(phpTaintStatus([{ path: "resources/views/a.blade.php", text: "" }]), null);
  const prepass = readFileSync(join(repo, "scripts", "prepass.mjs"), "utf8");
  assert.match(prepass, /PHP taint analysis \(Psalm\): \$\{phpTaint\}/);
});

// ---------------------------------------------------------------- briefs

test("briefs: Laravel, Symfony and Drupal come from their files or composer.json", () => {
  const root = mkdtempSync(join(tmpdir(), "sa-r05-briefs-"));
  cpSync(bench.app, root, { recursive: true });
  execFileSync("git", ["init", "-q"], { cwd: root });
  execFileSync("git", ["add", "-A"], { cwd: root });
  assert.deepEqual(detectLanguages(root), ["php", "laravel", "symfony", "drupal"]);

  const dir = join(root, ".security-audit");
  writeBriefs(dir);
  const auth = readFileSync(join(dir, "briefs", "auth.md"), "utf8");
  const injection = readFileSync(join(dir, "briefs", "injection.md"), "utf8");
  assert.match(auth, /## Stack profile: Laravel[\s\S]*## Stack profile: Symfony[\s\S]*## Stack profile: Drupal/);
  assert.doesNotMatch(injection, /## Stack profile/);
  for (const s of ["Laravel", "Symfony", "Drupal"]) assert.match(injection, new RegExp(`## ${s}\\n\\| Area`));
  assert.match(injection, /## PHP-Specific Patterns/);

  const composerOnly = mkdtempSync(join(tmpdir(), "sa-r05-composer-"));
  writeFileSync(join(composerOnly, "composer.json"), JSON.stringify({ require: { "symfony/framework-bundle": "^7.1" } }));
  writeFileSync(join(composerOnly, "index.php"), "<?php\n");
  execFileSync("git", ["init", "-q"], { cwd: composerOnly });
  execFileSync("git", ["add", "-A"], { cwd: composerOnly });
  assert.deepEqual(detectLanguages(composerOnly), ["php", "symfony"]);

  assert.doesNotMatch(patternsFor(["js"]), /## Laravel|## Symfony|## Drupal/);
  assert.doesNotMatch(patternsFor(["php"]), /## Laravel|## Symfony|## Drupal\n/);
  assert.deepEqual(profileSections(["php"]), []);
});
