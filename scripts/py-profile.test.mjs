// Run: node --test scripts/
// Python profile (roadmap R06): Django, FastAPI and Flask entry points, Python hotspot signals, bandit in the
// R07 tool runner and the pip-audit fallback, profile briefs and the py-clinic benchmark app with its answer key.
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
import { inventory, runTools } from "./tools.mjs";
import { drfDefaultPermissions, pyOwnerModels, rankHotspots, scanDjangoUrls, scanEntryPoints, scanPyFiles, scanPyRoutes, scanScope, walk } from "./surface.mjs";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
const bench = benchApp("py-clinic");
const key = JSON.parse(readFileSync(bench.key, "utf8"));
const { files, lockfiles } = walk(bench.app);

const finding = (id, file, { status = "verified", category = id.split("-")[0] } = {}) => {
  const text = `---\nid: ${id}\ncategory: ${category}\nseverity: HIGH\nstatus: ${status}\n---\n\n## Title\n${id} title\n\n## Evidence\n- **File**: \`${file}\`\n\n## Impact\nx\n`;
  return { stem: id, data: { id, category, severity: "HIGH", status }, body: `## Title\n${id} title\n`, text };
};
const entriesOf = (r, id) => r.matches.find((m) => m.finding === id).entries;
const sourceFiles = (dir) => readdirSync(dir, { recursive: true }).map(String).filter((p) => statSync(join(dir, p)).isFile());
const lineOf = (file, n) => readFileSync(join(bench.app, file), "utf8").split("\n")[n - 1];

// ---------------------------------------------------------------- benchmark app and key

test("py-clinic is a benchmark app in benchmark/py-clinic, with nothing installed", () => {
  assert.ok(listApps().includes("py-clinic"));
  assert.equal(bench.app, join(repo, "benchmark", "py-clinic", "app"));
  assert.equal(bench.key, join(repo, "benchmark", "py-clinic", "answer-key.json"));
  assert.equal(key.app, "py-clinic");
  assert.ok(key.seeded.length >= 8 && key.decoys.length >= 6);
  const all = sourceFiles(bench.app);
  assert.ok(!all.some((p) => /(^|\/)(?:\.venv|venv|site-packages|__pycache__|node_modules)(\/|$)|\.pyc$|\.sqlite3?$|\.db$/.test(p)), "no venv, caches or databases");
  assert.deepEqual(lockfiles.sort(), ["backoffice/requirements.txt", "labs/requirements.txt", "requirements.txt"]);
  for (const req of lockfiles) {
    for (const l of readFileSync(join(bench.app, req), "utf8").split("\n").filter(Boolean)) assert.match(l, /^[\w.[\]-]+==[\w.]+$/, `${req}: ${l} is pinned`);
  }
});

test("py-clinic seeds and decoys cover Django, FastAPI and Flask", () => {
  for (const list of [key.seeded, key.decoys]) {
    const f = [...new Set(list.flatMap((e) => e.locations.map((l) => l.file)))];
    assert.ok(f.some((p) => /^(?:appointments|records|payments|clinic)\//.test(p)), "Django");
    assert.ok(f.some((p) => p.startsWith("labs/")), "FastAPI");
    assert.ok(f.some((p) => p.startsWith("backoffice/")), "Flask");
  }
  assert.ok(key.seeded.some((e) => e.locations.some((l) => l.file.endsWith(".html"))), "a template seed");
});

test("py-clinic key ranges sit on the statements they describe", () => {
  const at = (id) => [...key.seeded, ...key.decoys].find((e) => e.id === id).locations;
  const expect = {
    B01: /def appointment_detail/, B02: /Appointment\.objects\.raw\($/, B03: /class PrescriptionViewSet/, B04: /def export_patients/,
    B05: /\{\{ message\.body\|safe \}\}/, B06: /@csrf_exempt/, B07: /SECRET_KEY = os\.environ\.get/, B08: /request\.POST\.get\("filename"\)/,
    B09: /yaml\.load\(.*Loader=yaml\.Loader/, B10: /@router\.get\("\/\{result_id\}\/pdf"\)/, B11: /rows = db\.execute\($/, B12: /if body\.callback_url/,
    B13: /@router\.get\("\/technicians"/, B14: /allow_origins=\["\*"\]/, B15: /template = /, B16: /name = request\.args/,
    B17: /@bp\.route\("\/staff\/<int:user_id>\/role"/, B18: /app\.secret_key = "/,
    D01: /filter\(patient=request\.user\)/, D02: /Appointment\.objects\.raw\($/, D03: /patient=request\.user/, D04: /def get_queryset/,
    D05: /class DoctorViewSet/, D06: /format_html/, D07: /@csrf_exempt/, D08: /DEBUG = os\.environ\.get\("DJANGO_DEBUG"\) == "1"/,
    D09: /owner=request\.user/, D10: /@router\.get\("\/\{result_id\}"/, D11: /rows = db\.execute\($/, D12: /dependencies=\[Depends\(require_staff\)\]/,
    D13: /@app\.get\("\/health"\)/, D14: /def letter_send/, D15: /def report/, D16: /yaml\.safe_load/, D17: /FLASK_DEBUG"\) == "1"/,
    D18: /@bp\.route\("\/login"/,
  };
  for (const [id, re] of Object.entries(expect)) {
    const l = at(id)[0];
    assert.match(lineOf(l.file, l.lines[0]), re, `${id} starts at ${l.file}:${l.lines[0]}`);
  }
  assert.match(lineOf("labs/schemas.py", at("B13")[1].lines[0]), /class AccountRecord/);
  assert.match(lineOf("labs/routers/orders.py", at("B12")[1].lines[0]), /def notify_callback/);
  assert.match(lineOf(".env.example", at("D08")[1].lines[0]), /^DJANGO_DEBUG=1$/);
  assert.match(lineOf(".env.example", at("D17")[1].lines[0]), /^FLASK_DEBUG=1$/);
});

test("py-clinic source has no hint comments, no real-looking keys and only reserved domains", () => {
  for (const rel of sourceFiles(bench.app)) {
    const text = readFileSync(join(bench.app, rel), "utf8");
    assert.ok(!/\b(?:seed(?:ed|ers?)?|vuln\w*|insecure|exploit|decoy|bug|TODO|FIXME|B\d\d|D\d\d)\b/i.test(text), `${rel} has a hint word`);
    assert.ok(!/django-insecure-|sk_live_|AKIA[0-9A-Z]{16}|eyJ[\w-]{10,}\.|ghp_\w{20,}|-----BEGIN [A-Z ]*PRIVATE KEY|[A-Za-z0-9+/]{40,}/.test(text), `${rel} has a real-looking key`);
    assert.ok(!/^(?:DJANGO_SECRET_KEY|DB_PASSWORD|PAYMENT_WEBHOOK_SECRET)=\S/m.test(text), `${rel} sets a secret value`);
    for (const m of text.matchAll(/https?:\/\/([\w.-]+)/g)) {
      assert.ok(/(?:^|\.)(?:example|invalid)$|^(?:localhost|127\.0\.0\.1)$/.test(m[1]), `${rel}: ${m[1]} is not a reserved domain`);
    }
    for (const m of text.matchAll(/[\w.-]+@([\w-]+(?:\.[\w-]+)+)/g)) assert.ok(/\.(?:example|invalid)$/.test(m[1]), `${rel}: e-mail domain ${m[1]}`);
  }
  assert.match(readFileSync(join(bench.app, "clinic", "settings.py"), "utf8"), /ALLOWED_HOSTS = .*"clinic\.example"/);
});

test("scorer parses Python, template and requirements locations", () => {
  assert.deepEqual(primaryLocation("- **File**: `labs/routers/results.py:49-54`"), { file: "labs/routers/results.py", start: 49, end: 54 });
  assert.deepEqual(primaryLocation("- **File**: `appointments/templates/appointments/detail.html:13`"), { file: "appointments/templates/appointments/detail.html", start: 13, end: 13 });
  assert.equal(primaryLocation("- **File**: `labs/requirements.txt:4`").file, "labs/requirements.txt");
  assert.equal(primaryLocation("- **File**: `setup.cfg:3`").file, "setup.cfg");
  assert.equal(primaryLocation("- **File**: `app/backoffice/views.py:55`").file, "backoffice/views.py", "the run directory prefix is dropped");
});

test("scoring py-clinic: a finding on every seeded range is found, decoys count as false positives", () => {
  const seeded = key.seeded.map((e, i) => finding(`auth-${100 + i}`, `${e.locations[0].file}:${e.locations[0].lines[0]}`));
  const decoys = key.decoys.map((e, i) => finding(`auth-${200 + i}`, `${e.locations[0].file}:${e.locations[0].lines[0]}`));
  const r = score([...seeded, ...decoys], key);
  assert.equal(r.found, key.seeded.length);
  assert.equal(r.recall, 1);
  assert.equal(r.decoy_fp, key.decoys.length);
  assert.deepEqual(r.unmatched, []);
});

test("scoring py-clinic: neighbouring seeded and decoy ranges stay apart", () => {
  const r = score([
    finding("injection-001", "appointments/views.py:29"),
    finding("injection-002", "appointments/views.py:19"),
    finding("auth-001", "appointments/views.py:36"),
    finding("auth-002", "appointments/views.py:44"),
    finding("config-001", "appointments/views.py:49"),
    finding("auth-003", "appointments/api.py:24"),
    finding("auth-004", "appointments/api.py:20"),
    finding("injection-003", "labs/routers/results.py:26"),
    finding("injection-004", "labs/routers/results.py:35"),
    finding("auth-005", "labs/routers/results.py:43"),
    finding("auth-006", "labs/routers/results.py:51"),
    finding("upload-001", "backoffice/views.py:78"),
    finding("upload-002", "backoffice/views.py:84"),
    finding("config-002", "clinic/settings.py:6"),
    finding("config-003", "clinic/settings.py:8"),
    finding("exposure-001", "labs/routers/staff.py:19"),
    finding("auth-007", "labs/routers/staff.py:10"),
  ], key);
  const want = {
    "injection-001": "B02", "injection-002": "D02", "auth-001": "B01", "auth-002": "D03", "config-001": "B06", "auth-003": "B03", "auth-004": "D05",
    "injection-003": "B11", "injection-004": "D11", "auth-005": "D10", "auth-006": "B10", "upload-001": "B16", "upload-002": "D15",
    "config-002": "B07", "config-003": "D08", "exposure-001": "B13", "auth-007": "D12",
  };
  for (const [f, id] of Object.entries(want)) assert.deepEqual(entriesOf(r, f), [id], f);
});

test("setup --app py-clinic builds a one-commit run, and score reads it", () => {
  const dest = join(mkdtempSync(join(tmpdir(), "sa-r06-")), "run");
  execFileSync(process.execPath, [join(repo, "benchmark", "setup.mjs"), "--app", "py-clinic", "--dest", dest], { stdio: "pipe" });
  assert.equal(JSON.parse(readFileSync(join(dest, "meta.json"), "utf8")).bench_app, "py-clinic");
  assert.equal(execFileSync("git", ["-C", join(dest, "app"), "rev-list", "--count", "HEAD"], { encoding: "utf8" }).trim(), "1");
  assert.ok(existsSync(join(dest, "app", "manage.py")) && existsSync(join(dest, "app", "clinic", "__init__.py")) && !existsSync(join(dest, "answer-key.json")));
  const dir = join(dest, "app", ".security-audit", "findings");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "auth-001.md"), finding("auth-001", "labs/routers/results.py:50").text);
  writeFileSync(join(dir, "xss-001.md"), finding("xss-001", "appointments/templatetags/clinic_tags.py:12").text);
  const out = execFileSync(process.execPath, [join(repo, "benchmark", "score.mjs"), dest, "--no-save"], { encoding: "utf8" });
  assert.match(out, /^App py-clinic$/m);
  assert.match(out, new RegExp(`Recall 1/${key.seeded.length} `));
  assert.match(out, /decoy false positives 1/);
});

// ---------------------------------------------------------------- Django

test("Django: include() prefixes, re_path, urls wrappers, mixins, DRF defaults, routers and csrf_exempt", () => {
  const fx = [
    { path: "site/urls.py", text: `from django.contrib.auth.decorators import login_required
from django.urls import include, path, re_path
from shop import views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("shop/", include("shop.urls")),
    re_path(r"^legacy/(?P<id>\\d+)/$", login_required(views.legacy)),
    path("api/", include(router.urls)),
]
router.register(r"orders", views.OrderViewSet, basename="order")
` },
    { path: "shop/urls.py", text: `from django.urls import path
from . import views

urlpatterns = [
    path("<int:pk>/", views.OrderDetail.as_view(), name="detail"),
    path("cart/", views.cart),
    path("hook/", views.hook),
    path("stats/", views.stats),
    path("open/", views.OpenList.as_view()),
]
` },
    { path: "shop/views.py", text: `from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes


class OrderDetail(LoginRequiredMixin, DetailView):
    model = Order


@require_POST
def cart(request):  # a comment with (parens
    return None


@csrf_exempt
def hook(request):
    return None


@api_view(["GET"])
@permission_classes([IsAdminUser])
def stats(request):
    return None


class OpenList(generics.ListAPIView):
    queryset = Product.objects.all()


class OrderViewSet(viewsets.ModelViewSet):
    permission_classes = [permissions.AllowAny]


def legacy(request, id):
    return None
` },
  ];
  const eps = scanDjangoUrls(fx);
  const by = (route) => eps.find((e) => e.route === route);
  assert.deepEqual(eps.map((e) => e.route).sort(), ["/api/orders", "/legacy/(?P<id>\\d+)", "/shop/<int:pk>", "/shop/cart", "/shop/hook", "/shop/open", "/shop/stats"]);
  assert.deepEqual([by("/shop/<int:pk>").guard, by("/shop/<int:pk>").file, by("/shop/<int:pk>").line], ["LoginRequiredMixin", "shop/urls.py", 5]);
  assert.deepEqual(by("/shop/<int:pk>").pyHandler, { file: "shop/views.py", line: 6, name: "OrderDetail" });
  assert.deepEqual([by("/shop/cart").guard, by("/shop/cart").name], ["", "POST"]);
  assert.equal(by("/shop/hook").csrfExempt, true);
  assert.deepEqual([by("/shop/stats").guard, by("/shop/stats").name], ["permission_classes: IsAdminUser", "GET"]);
  assert.deepEqual([by("/shop/open").guard, by("/shop/open").allowAny, by("/shop/open").readOnly], ["DRF default permission: AllowAny", true, true], "no REST_FRAMEWORK setting: DRF allows anyone");
  assert.equal(by("/legacy/(?P<id>\\d+)").guard, "login_required (in urls)");
  assert.deepEqual([by("/api/orders").name, by("/api/orders").guard, by("/api/orders").allowAny, by("/api/orders").readOnly], ["VIEWSET", "permission_classes: AllowAny", true, undefined]);
  assert.ok(!eps.some((e) => e.route.startsWith("/admin")), "the Django admin is not a project route");
  assert.deepEqual(drfDefaultPermissions([{ path: "s/settings.py", text: 'REST_FRAMEWORK = {\n    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),\n}\n' }]), ["IsAuthenticated"]);
});

test("Django: py-clinic routes carry their include prefix, view and guards", () => {
  const eps = scanEntryPoints(files).filter((e) => e.kind === "django-route");
  assert.equal(eps.length, 17);
  const by = (route) => eps.find((e) => e.route === route);
  assert.deepEqual([by("/appointments/<int:pk>").guard, by("/appointments/<int:pk>").pyHandler.file, by("/appointments/<int:pk>").pyHandler.line], ["login_required", "appointments/views.py", 35]);
  assert.deepEqual([by("/appointments/contact").name, by("/appointments/contact").csrfExempt], ["POST", true]);
  assert.equal(by("/records/export/patients.csv").guard, "");
  assert.equal(by("/api/prescriptions").guard, "DRF default permission: IsAuthenticated");
  assert.deepEqual([by("/api/doctors").allowAny, by("/api/doctors").readOnly], [true, true]);
  assert.deepEqual([by("/payments/webhook").file, by("/payments/webhook").line, by("/payments/webhook").csrfExempt], ["payments/urls.py", 8, true]);
});

test("Django and SQLAlchemy models owned by a user", () => {
  const owners = pyOwnerModels(files);
  for (const m of ["Appointment", "Message", "Prescription", "ContactDetails", "Record", "HistoryEntry", "LabResult", "LabOrder"]) assert.ok(owners.has(m), m);
  for (const m of ["Doctor", "Account", "StaffUser", "PriceItem", "LabResultOut"]) assert.ok(!owners.has(m), m);
});

// ---------------------------------------------------------------- FastAPI and Flask

test("FastAPI: router prefix, include_router prefix and dependencies, Depends vs get_db, api_route, response_model", () => {
  const routes = { path: "svc/routes/items.py", text: `from fastapi import APIRouter, Depends, Security

router = APIRouter(prefix="/items")


@router.get("/{item_id}", response_model=list[ItemOut])
async def get_item(item_id: int, db=Depends(get_db)):
    return None


@router.post("", dependencies=[Depends(verify_api_key)])
def create(db=Depends(get_db)):
    return None


@router.api_route("/bulk", methods=["PUT", "PATCH"])
def bulk(user=Security(current_principal, scopes=["items"])):
    return None
` };
  const main = { path: "svc/main.py", text: `from fastapi import FastAPI, Depends
from .routes import items

app = FastAPI(dependencies=[Depends(rate_limit)])
app.include_router(items.router, prefix="/v1", dependencies=[Depends(get_current_user)])


@app.get("/ping")
def ping():
    return "pong"
` };
  const all = [routes, main];
  const eps = scanPyRoutes(routes, all);
  assert.deepEqual(eps.map((e) => [e.kind, e.name, e.route, e.line]), [["fastapi-route", "GET", "/v1/items/{item_id}", 6], ["fastapi-route", "POST", "/v1/items", 11], ["fastapi-route", "PUT,PATCH", "/v1/items/bulk", 16]]);
  assert.equal(eps[0].guard, "include_router dependencies: get_current_user");
  assert.equal(eps[0].responseModel, "ItemOut");
  assert.deepEqual(eps[0].pyHandler, { file: "svc/routes/items.py", line: 7, name: "get_item" });
  assert.match(eps[1].guard, /^route dependencies: verify_api_key; include_router/);
  assert.match(eps[2].guard, /^Depends\(current_principal\)/);
  const unmounted = scanPyRoutes(routes, [routes]);
  assert.deepEqual([unmounted[0].route, unmounted[0].guard], ["/items/{item_id}", ""], "get_db is not an auth dependency");
  assert.deepEqual(scanPyRoutes(main, all).map((e) => [e.route, e.guard]), [["/ping", ""]], "rate_limit is not an auth dependency");
});

test("Flask: blueprint and register_blueprint prefixes, *_required decorators, before_request hooks, methods", () => {
  const views = { path: "web/admin.py", text: `from flask import Blueprint, abort
from flask_login import current_user, login_required

admin = Blueprint("admin", __name__, url_prefix="/admin")
public = Blueprint("public", __name__)


@admin.before_request
def only_staff():
    if not current_user.is_authenticated:
        abort(401)


@admin.route("/users", methods=["GET", "POST"])
def users():
    return ""


@public.get("/about")
def about():
    return ""


@public.post("/notes/<int:note_id>/delete")
@login_required
@roles_required("editor")
def delete_note(note_id):
    return ""
` };
  const app = { path: "web/app.py", text: `from flask import Flask
from .admin import admin, public

app = Flask(__name__)
app.register_blueprint(admin, url_prefix="/staff")
app.register_blueprint(public)
` };
  const eps = scanPyRoutes(views, [views, app]);
  assert.deepEqual(eps.map((e) => [e.kind, e.name, e.route, e.guard]), [
    ["flask-route", "GET,POST", "/staff/users", "before_request: only_staff"],
    ["flask-route", "GET", "/about", ""],
    ["flask-route", "POST", "/notes/<int:note_id>/delete", "login_required, roles_required"],
  ]);
  assert.equal(scanPyRoutes(views, [views])[0].route, "/admin/users", "the Blueprint's own url_prefix without a mount");
  assert.deepEqual(scanPyRoutes({ path: "x.py", text: "import os\n\n@cache.get(\"/x\")\ndef x():\n    pass\n" }), [], "not a FastAPI or Flask file");
});

test("FastAPI and Flask: py-clinic routes with their mounts and guards", () => {
  const eps = scanEntryPoints(files);
  const fast = eps.filter((e) => e.kind === "fastapi-route");
  const flask = eps.filter((e) => e.kind === "flask-route");
  assert.equal(fast.length, 10);
  assert.equal(flask.length, 8);
  const at = (file, line) => eps.find((e) => e.file === file && e.line === line);
  assert.deepEqual([at("labs/routers/results.py", 49).route, at("labs/routers/results.py", 49).guard], ["/results/{result_id}/pdf", ""]);
  assert.equal(at("labs/routers/results.py", 41).guard, "Depends(get_current_user)");
  assert.deepEqual([at("labs/routers/staff.py", 18).guard, at("labs/routers/staff.py", 18).responseModel], ["router dependencies: require_staff", "AccountRecord"]);
  assert.deepEqual([at("backoffice/views.py", 53).route, at("backoffice/views.py", 53).guard], ["/backoffice/staff/<int:user_id>/role", ""]);
  assert.equal(at("backoffice/views.py", 46).guard, "login_required, admin_required");
  assert.ok(!eps.some((e) => /\.html$|requirements\.txt$/.test(e.file)), "templates and requirements are never entry points");
});

// ---------------------------------------------------------------- hotspots and file signals

test("hotspots: every seeded bug of py-clinic has a ranked row with its reason, decoys have none", () => {
  const hot = rankHotspots(files, scanEntryPoints(files), scanScope(files)).filter((h) => h.score > 0);
  const why = (file, line) => {
    const h = hot.find((x) => x.file === file && x.line === line);
    assert.ok(h, `${file}:${line} is ranked`);
    return h.reasons.join("; ");
  };
  const seeds = {
    B01: ["appointments/urls.py", 11, /record loaded by id without an ownership check.*handler: appointments\/views\.py:35/],
    B02: ["appointments/urls.py", 10, /raw SQL built with an f-string/],
    B03: ["appointments/api_urls.py", 8, /query on Prescription \(owned by a user\) without a filter/],
    B04: ["records/urls.py", 12, /no login_required, auth mixin or permission class/],
    B05: ["appointments/templates/appointments/detail.html", 13, /\|safe/],
    B06: ["appointments/views.py", 49, /csrf_exempt on a view without a signature check/],
    B07: ["clinic/settings.py", 6, /SECRET_KEY falls back to a literal/],
    B08: ["records/urls.py", 9, /file path built from the request/],
    B09: ["records/urls.py", 11, /unsafe deserialization/],
    B10: ["labs/routers/results.py", 49, /no auth dependency.*record loaded by id/],
    B11: ["labs/routers/results.py", 23, /raw SQL built with an f-string/],
    B12: ["labs/routers/orders.py", 28, /background task gets a URL from the request/],
    B13: ["labs/routers/staff.py", 18, /response_model AccountRecord returns password_hash, totp_secret/],
    B14: ["labs/main.py", 10, /CORS allows any origin with credentials/],
    B15: ["backoffice/views.py", 61, /render_template_string on a built string/],
    B16: ["backoffice/views.py", 74, /send_file with a path from the request/],
    B17: ["backoffice/views.py", 53, /no login_required \(or similar\) decorator/],
    B18: ["backoffice/app.py", 9, /Flask secret key is a literal/],
  };
  assert.deepEqual(Object.keys(seeds), key.seeded.map((e) => e.id), "one row per seeded bug");
  for (const [id, [file, line, re]] of Object.entries(seeds)) assert.match(why(file, line), re, id);
  assert.match(why("appointments/urls.py", 13), /csrf_exempt on a view without a signature check/, "B06 also on its route");

  const quiet = /no login_required|no auth dependency|record loaded by id|query on \w+ \(owned|raw SQL|csrf_exempt|send_file|file path|deserialization|template_string|SSRF/;
  for (const [file, line] of [["appointments/urls.py", 8], ["appointments/urls.py", 9], ["appointments/urls.py", 12], ["appointments/api_urls.py", 6], ["payments/urls.py", 8],
    ["records/urls.py", 10], ["labs/routers/results.py", 41], ["labs/routers/results.py", 32], ["labs/routers/staff.py", 13], ["backoffice/views.py", 68], ["backoffice/views.py", 81], ["backoffice/views.py", 87]]) {
    const h = hot.find((x) => x.file === file && x.line === line);
    assert.ok(h, `${file}:${line} is ranked`);
    assert.doesNotMatch(h.reasons.join("; "), quiet, `${file}:${line}`);
  }
  assert.match(why("appointments/api_urls.py", 7), /AllowAny on a read-only view \(public by design\?\)/);
  assert.match(why("payments/urls.py", 8), /signature check seen in the handler/);
  assert.match(why("backoffice/views.py", 36), /sign-in page: public by design/);
  assert.match(why("labs/main.py", 21), /health\/status route/);
  assert.ok(!hot.some((h) => h.file === "payments/views.py" || h.file === "appointments/templatetags/clinic_tags.py"), "signed webhook and format_html have no file signal");
  assert.ok(!hot.some((h) => (h.file === "clinic/settings.py" && h.line !== 6) || (h.file === "backoffice/app.py" && h.line !== 9)), "DEBUG and ALLOWED_HOSTS from the environment");
});

test("Python file signals: templates, settings, Flask secrets and debug, csrf_exempt, CORS", () => {
  const rows = scanPyFiles([
    { path: "t/templates/a.html", text: "{{ a }}\n{{ b|safe }}\n{% autoescape off %}{{ c }}{% endautoescape %}\n" },
    { path: "s/settings.py", text: 'DEBUG = True\nALLOWED_HOSTS = ["*"]\nSECRET_KEY = "abc"\nCORS_ALLOW_ALL_ORIGINS = True\nCORS_ALLOW_CREDENTIALS = True\n' },
    { path: "s/prod.py", text: 'DEBUG = os.getenv("DEBUG", "1") == "1"\nSECRET_KEY = os.environ["SECRET_KEY"]\n' },
    { path: "f/app.py", text: 'app.config["SECRET_KEY"] = "dev"\nCORS(app, supports_credentials=True)\nif __name__ == "__main__":\n    app.run(debug=True)\n' },
    { path: "f/ok.py", text: 'app.secret_key = os.environ["FLASK_SECRET"]\nCORS(app, origins=["https://app.example"], supports_credentials=True)\n' },
    { path: "v/views.py", text: "@csrf_exempt\ndef a(request):\n    return None\n\n\n@csrf_exempt\ndef b(request):\n    if not hmac.compare_digest(sig, expected):\n        return None\n" },
    { path: "api/main.py", text: 'app.add_middleware(\n    CORSMiddleware,\n    allow_origin_regex=".*",\n    allow_credentials=True,\n)\napp.add_middleware(CORSMiddleware, allow_origins=["https://app.example"], allow_credentials=True)\n' },
    { path: "tests/test_views.py", text: "DEBUG = True\n" },
  ]);
  assert.deepEqual(rows.map((r) => `${r.file}:${r.line}`), [
    "t/templates/a.html:2", "t/templates/a.html:3", "s/settings.py:1", "s/settings.py:2", "s/settings.py:3", "s/settings.py:4",
    "s/prod.py:1", "f/app.py:1", "f/app.py:4", "f/app.py:2", "v/views.py:1", "api/main.py:3",
  ]);
  assert.equal(rows.find((r) => r.file === "s/settings.py" && r.line === 4).score, 6);
});

test("bandit runs in the R07 tool runner for Python projects (native only), pip-audit is a read-only dependency fallback", () => {
  const inv = inventory(bench.app);
  assert.ok(inv.python > 0);
  const none = runTools({ root: bench.app, inv, stack: [], only: ["bandit"], runner: { installed: () => false, run: () => assert.fail("must not run"), dockerOk: true } });
  assert.equal(none[0].state, "not-run");
  assert.match(none[0].status, /^NOT RUN: bandit not installed \(no docker fallback\); to enable: `pipx install bandit`/);

  const out = JSON.stringify({ errors: [], results: [
    { filename: "./appointments/views.py", line_number: 29, test_id: "B608", test_name: "hardcoded_sql_expressions", issue_severity: "MEDIUM", issue_confidence: "LOW", issue_text: "Possible SQL injection vector through string-based query construction." },
  ] });
  const calls = [];
  const ran = runTools({ root: bench.app, inv, stack: [], only: ["bandit"], runner: { installed: (c) => c === "bandit", run: (c, a) => { calls.push([c, a]); return { status: 1, stdout: out, stderr: "" }; } } });
  assert.deepEqual(calls[0].slice(0, 1), ["bandit"]);
  for (const a of ["-r", ".", "-f", "json"]) assert.ok(calls[0][1].includes(a), a);
  assert.equal(ran[0].status, "bandit: 1 candidates");
  assert.deepEqual([ran[0].rows[0].file, ran[0].rows[0].line, ran[0].rows[0].rule, ran[0].rows[0].severity], ["appointments/views.py", 29, "B608 hardcoded_sql_expressions", "medium"]);

  const testsOnly = mkdtempSync(join(tmpdir(), "sa-r06-bandit-"));
  mkdirSync(join(testsOnly, "tests"));
  writeFileSync(join(testsOnly, "tests", "test_x.py"), "x = 1\n");
  const skipped = runTools({ root: testsOnly, inv: inventory(testsOnly), stack: [], only: ["bandit"], runner: { installed: () => true, run: () => assert.fail("must not run") } });
  assert.equal(skipped[0].status, "skipped: no Python source outside tests", "test files alone are not a Python project");

  const prepass = readFileSync(join(repo, "scripts", "prepass.mjs"), "utf8");
  assert.match(prepass, /"bandit\.json"/, "a previous run's bandit output is removed");
  assert.match(prepass, /\["requirements\.txt", "pip-audit", \["-r", "requirements\.txt", "--no-deps", "--disable-pip"/);
  assert.match(prepass, /"pip-audit\.json"/, "a previous run's pip-audit output is removed");
});

// ---------------------------------------------------------------- briefs

test("briefs: Django from its files or requirements, FastAPI and Flask from requirements or pyproject", () => {
  const root = mkdtempSync(join(tmpdir(), "sa-r06-briefs-"));
  cpSync(bench.app, root, { recursive: true });
  execFileSync("git", ["init", "-q"], { cwd: root });
  execFileSync("git", ["add", "-A"], { cwd: root });
  assert.deepEqual(detectLanguages(root), ["python", "django", "fastapi", "flask"]);

  const dir = join(root, ".security-audit");
  writeBriefs(dir);
  const auth = readFileSync(join(dir, "briefs", "auth.md"), "utf8");
  const injection = readFileSync(join(dir, "briefs", "injection.md"), "utf8");
  assert.match(auth, /## Stack profile: Django[\s\S]*## Stack profile: FastAPI[\s\S]*## Stack profile: Flask/);
  assert.doesNotMatch(injection, /## Stack profile/);
  for (const s of ["Django", "FastAPI", "Flask"]) assert.match(injection, new RegExp(`## ${s}\\n\\| Area`));
  assert.doesNotMatch(injection, /## Laravel|## Supabase|## PHP-Specific/);

  const only = (name, content) => {
    const d = mkdtempSync(join(tmpdir(), "sa-r06-req-"));
    writeFileSync(join(d, name), content);
    writeFileSync(join(d, "main.py"), "\n");
    execFileSync("git", ["init", "-q"], { cwd: d });
    execFileSync("git", ["add", "-A"], { cwd: d });
    return detectLanguages(d);
  };
  assert.deepEqual(only("requirements.txt", "Flask-Login==0.6.3\ndjangorestframework==3.16.0\nfastapi-users==14.0.1\n"), ["python"], "extensions alone are not the framework");
  assert.deepEqual(only("requirements-prod.txt", "fastapi[standard]>=0.115\n"), ["python", "fastapi"]);
  assert.deepEqual(only("pyproject.toml", '[project]\ndependencies = ["flask>=3.1", "Django~=5.2"]\n'), ["python", "django", "flask"]);

  assert.doesNotMatch(patternsFor(["js"]), /## Django|## FastAPI|## Flask/);
  assert.doesNotMatch(patternsFor(["python"]), /## Django\n|## FastAPI|## Flask/);
  assert.deepEqual(profileSections(["python"]), []);
});
