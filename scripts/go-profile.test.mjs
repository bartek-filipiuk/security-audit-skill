// Run: node --test scripts/*.test.mjs
// Go profile (roadmap R09): stack detection, net/http, chi, gin, echo, gorilla/mux and fiber entry points with
// their middleware, Go hotspot signals, gosec and govulncheck in the R07 tool runner, checklist and patterns.
// Fixtures are small inline Go files; no scanner and no Go toolchain runs.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { patternsFor, profileSections } from "./briefs.mjs";
import { detectStack, profileHeadline } from "./stack.mjs";
import { inventory, jsonStream, parseGosec, parseGovulncheck, runTools } from "./tools.mjs";
import { rankHotspots, scanEntryPoints, scanGoFiles, scanGoRoutes, scanScope, walk } from "./surface.mjs";
import { toolFreeEnv } from "./test-helpers.mjs";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");

function project(files) {
  const dir = mkdtempSync(join(tmpdir(), "sa-r09-"));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  return dir;
}
const lineOf = (text, re) => text.split("\n").findIndex((l) => re.test(l)) + 1;
const routes = (files) => scanGoRoutes(files).map((e) => [e.kind, e.name, e.route, e.line, e.guard]);

// ---------------------------------------------------------------- stack

test("Go is a dedicated profile with or without a router framework; the R09 gap lines are gone", () => {
  const chi = detectStack(project({ "go.mod": "module example.com/notes\n\ngo 1.23\n\nrequire github.com/go-chi/chi/v5 v5.2.0\n", "main.go": "package main\n" }));
  assert.deepEqual(chi.applied, ["go"]);
  assert.deepEqual(chi.detected[0].frameworks, ["chi"]);
  const p = chi.profiles[0];
  assert.equal(p.dedicated, true);
  assert.equal(p.roadmap, "");
  assert.equal(profileHeadline(p), "Go (chi): dedicated profile");
  assert.ok(p.covers.some((c) => c.startsWith("Go entry points of net/http ServeMux")));
  assert.ok(p.covers.some((c) => c.startsWith("gosec and govulncheck through the rule-scanner runner")));
  assert.ok(!p.gaps.some((g) => /roadmap R09|routes are not enumerated/.test(g)));
  const plain = detectStack(project({ "go.mod": "module example.com/tool\n\ngo 1.23\n", "main.go": "package main\n" }));
  assert.equal(plain.profiles[0].dedicated, true, "net/http is the standard library: no framework needed");
});

// ---------------------------------------------------------------- entry points

test("net/http: Go 1.22 method patterns, handler wrappers, StripPrefix mounts and a wrapped server handler", () => {
  const text = `package main

import (
	"net/http"
	"time"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /items/{id}", getItem)
	mux.Handle("POST /items", requireAuth(http.HandlerFunc(createItem)))
	mux.HandleFunc("/healthz", health)
	api := http.NewServeMux()
	api.HandleFunc("GET /notes", listNotes)
	mux.Handle("/api/", http.StripPrefix("/api", requireAuth(api)))
	srv := &http.Server{Addr: ":8080", Handler: logRequests(mux), ReadHeaderTimeout: 5 * time.Second}
	srv.ListenAndServe()
}

func requireAuth(next http.Handler) http.Handler {
	return next
}

func logRequests(next http.Handler) http.Handler {
	return next
}

func getItem(w http.ResponseWriter, r *http.Request) {}

func createItem(w http.ResponseWriter, r *http.Request) {}

func health(w http.ResponseWriter, r *http.Request) {}

func listNotes(w http.ResponseWriter, r *http.Request) {}
`;
  const files = [{ path: "cmd/server/main.go", text }];
  assert.deepEqual(routes(files), [
    ["nethttp-route", "GET", "/items/{id}", 10, ""],
    ["nethttp-route", "POST", "/items", 11, "middleware: requireAuth"],
    ["nethttp-route", "ANY", "/healthz", 12, ""],
    ["nethttp-route", "GET", "/api/notes", 14, "middleware: requireAuth"],
  ]);
  const [item, , , notes] = scanGoRoutes(files);
  assert.deepEqual(item.middleware, ["logRequests"], "the server handler wraps every route; logging is not a guard");
  assert.deepEqual(item.goHandler, { file: "cmd/server/main.go", line: lineOf(text, /^func getItem/), name: "getItem" });
  assert.deepEqual(notes.middleware, ["logRequests", "requireAuth"]);
});

test("chi: Use order, Route and Group closures, With, Mount of a router built in a function, handlers in another file", () => {
  const routesGo = `package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/jwtauth/v5"
)

func Routes(h *Handler) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Get("/status", h.status)
	r.Use(h.requireUser)
	r.Get("/me", h.me)
	r.Route("/projects", func(r chi.Router) {
		r.Get("/", h.listProjects)
		r.With(h.adminOnly).Delete("/{projectID}", h.deleteProject)
	})
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Authenticator)
		r.Post("/upload", h.upload)
	})
	r.Mount("/admin", adminRouter(h))
	return r
}

func adminRouter(h *Handler) chi.Router {
	r := chi.NewRouter()
	r.Get("/users", h.listUsers)
	return r
}
`;
  const handlersGo = `package api

import "net/http"

func (h *Handler) status(w http.ResponseWriter, r *http.Request) {}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) {}

func (h *Handler) listProjects(w http.ResponseWriter, r *http.Request) {}

func (h *Handler) deleteProject(w http.ResponseWriter, r *http.Request) {}

func (h *Handler) upload(w http.ResponseWriter, r *http.Request) {}

func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {}
`;
  const files = [{ path: "internal/api/routes.go", text: routesGo }, { path: "internal/api/handlers.go", text: handlersGo }];
  assert.deepEqual(routes(files), [
    ["chi-route", "GET", "/status", 14, ""],
    ["chi-route", "GET", "/me", 16, "middleware: h.requireUser"],
    ["chi-route", "GET", "/projects", 18, "middleware: h.requireUser"],
    ["chi-route", "DELETE", "/projects/{projectID}", 19, "middleware: h.requireUser, h.adminOnly"],
    ["chi-route", "POST", "/upload", 23, "middleware: h.requireUser, jwtauth.Authenticator"],
    ["chi-route", "GET", "/admin/users", 31, "middleware: h.requireUser"],
  ]);
  const status = scanGoRoutes(files)[0];
  assert.deepEqual(status.middleware, ["middleware.Logger"], "Use after a route does not cover it");
  assert.deepEqual(status.goHandler, { file: "internal/api/handlers.go", line: 5, name: "status" });
  assert.equal(scanGoRoutes(files)[5].goHandler.line, 15);
});

test("gin: groups with middleware, Use on a group, a router passed to a function in another file", () => {
  const files = [
    { path: "main.go", text: `package main

import (
	"github.com/gin-gonic/gin"

	"example.com/shop/routes"
)

func main() {
	r := gin.Default()
	v1 := r.Group("/v1")
	routes.Register(v1, routes.NewHandlers())
	r.Run()
}
` },
    { path: "routes/routes.go", text: `package routes

import "github.com/gin-gonic/gin"

func Register(r *gin.RouterGroup, h *Handlers) {
	r.POST("/login", h.Login)
	api := r.Group("/api", AuthRequired())
	api.GET("/orders/:id", h.GetOrder)
	admin := api.Group("/admin")
	admin.Use(RoleRequired("admin"))
	admin.DELETE("/users/:id", h.DeleteUser)
	public := r.Group("/public")
	public.GET("/files/*path", h.Download)
}
` },
  ];
  assert.deepEqual(routes(files), [
    ["gin-route", "POST", "/v1/login", 6, ""],
    ["gin-route", "GET", "/v1/api/orders/:id", 8, "middleware: AuthRequired"],
    ["gin-route", "DELETE", "/v1/api/admin/users/:id", 11, "middleware: AuthRequired, RoleRequired"],
    ["gin-route", "GET", "/v1/public/files/*path", 13, ""],
  ]);
});

test("echo (handler first, middleware after it), gorilla/mux (subrouters, Methods) and fiber (groups, inline middleware)", () => {
  const echo = [{ path: "server.go", text: `package main

import (
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	e := echo.New()
	e.Use(middleware.Logger())
	e.GET("/health", health)
	g := e.Group("/v1", echojwt.WithConfig(cfg))
	g.GET("/reports/:id", getReport)
	e.POST("/hooks/payment", paymentHook)
	e.PUT("/settings", updateSettings, requireAdmin)
	e.Logger.Fatal(e.Start(":8080"))
}
` }];
  assert.deepEqual(routes(echo), [
    ["echo-route", "GET", "/health", 12, ""],
    ["echo-route", "GET", "/v1/reports/:id", 14, "middleware: echojwt.WithConfig"],
    ["echo-route", "POST", "/hooks/payment", 15, ""],
    ["echo-route", "PUT", "/settings", 16, "middleware: requireAdmin"],
  ]);
  const gorilla = [{ path: "web/router.go", text: `package web

import (
	"net/http"

	"github.com/gorilla/mux"
)

func NewRouter() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/login", loginHandler).Methods("POST")
	s := r.PathPrefix("/account").Subrouter()
	s.Use(authMiddleware)
	s.HandleFunc("/profile", profileHandler).Methods("GET", "PUT")
	r.Handle("/files/{name}", http.HandlerFunc(serveFile))
	return r
}
` }];
  assert.deepEqual(routes(gorilla), [
    ["gorilla-route", "POST", "/login", 11, ""],
    ["gorilla-route", "GET,PUT", "/account/profile", 14, "middleware: authMiddleware"],
    ["gorilla-route", "ANY", "/files/{name}", 15, ""],
  ]);
  const fiber = [{ path: "app.go", text: `package main

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/keyauth"
)

func main() {
	app := fiber.New()
	app.Get("/", index)
	api := app.Group("/api", keyauth.New(keyauth.Config{}))
	api.Post("/jobs", createJob)
	app.Get("/items/:id", protected, getItem)
	app.Listen(":3000")
}
` }];
  assert.deepEqual(routes(fiber), [
    ["fiber-route", "GET", "/", 10, ""],
    ["fiber-route", "POST", "/api/jobs", 12, "middleware: keyauth.New"],
    ["fiber-route", "GET", "/items/:id", 13, "middleware: protected"],
  ]);
});

test("Go: test files, testdata and files without a router import are not entry points; walk reads .go files", () => {
  const root = project({
    "go.mod": "module example.com/svc\n\ngo 1.23\n",
    "main.go": 'package main\n\nimport "net/http"\n\nfunc main() {\n\thttp.HandleFunc("/ping", ping)\n\thttp.ListenAndServe(":8080", nil)\n}\n\nfunc ping(w http.ResponseWriter, r *http.Request) {}\n',
    "main_test.go": 'package main\n\nimport "net/http"\n\nfunc setup() {\n\thttp.HandleFunc("/test-only", ping)\n}\n',
    "testdata/fixture.go": 'package fixture\n\nimport "net/http"\n\nfunc f() {\n\thttp.HandleFunc("/fixture", nil)\n}\n',
    "cache/store.go": 'package cache\n\nfunc f(c *Client) {\n\tc.Get("/not-a-route", 1)\n}\n',
  });
  const { files } = walk(root);
  assert.ok(files.some((f) => f.path === "main.go"));
  const eps = scanEntryPoints(files);
  assert.deepEqual(eps.map((e) => [e.kind, e.name, e.route, e.file]), [["nethttp-route", "ANY", "/ping", "main.go"]]);
});

// ---------------------------------------------------------------- hotspots and file signals

const handlersGo = `package files

import (
	"crypto/hmac"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
)

type Server struct {
	db   *sql.DB
	root string
}

func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /download", s.download)
	mux.HandleFunc("GET /archive", s.archive)
	mux.HandleFunc("POST /convert", s.requireUser(s.convert))
	mux.HandleFunc("GET /search", s.requireUser(s.search))
	mux.HandleFunc("POST /import", s.requireUser(s.importData))
	mux.HandleFunc("GET /docs/{id}", s.requireUser(s.getDoc))
	mux.HandleFunc("GET /my/docs/{id}", s.requireUser(s.getMyDoc))
	mux.HandleFunc("POST /hooks/billing", s.billingHook)
	mux.HandleFunc("GET /healthz", s.health)
	return mux
}

func (s *Server) requireUser(next http.HandlerFunc) http.HandlerFunc {
	return next
}

func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	http.ServeFile(w, r, filepath.Join(s.root, name))
}

func (s *Server) archive(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	p := filepath.Join(s.root, filepath.Clean("/"+name))
	if !strings.HasPrefix(p, s.root) {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	http.ServeFile(w, r, p)
}

func (s *Server) convert(w http.ResponseWriter, r *http.Request) {
	exec.Command("convert", r.FormValue("src"), "out.png").Run()
}

func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	rows, err := s.db.Query(fmt.Sprintf("SELECT id FROM docs WHERE title LIKE '%%%s%%'", q))
	_, _ = rows, err
}

func (s *Server) importData(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	_, _ = body, err
}

func (s *Server) getDoc(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	row := s.db.QueryRow("SELECT body FROM docs WHERE id = $1", id)
	_ = row
}

func (s *Server) getMyDoc(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	uid := userID(r.Context())
	row := s.db.QueryRow("SELECT body FROM docs WHERE id = $1 AND owner_id = $2", id, uid)
	_ = row
}

func (s *Server) billingHook(w http.ResponseWriter, r *http.Request) {
	if !hmac.Equal(signature(r), expected(r)) {
		http.Error(w, "bad signature", http.StatusBadRequest)
	}
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {}
`;

test("hotspots: Go routes are ranked by their handler body", () => {
  const files = [{ path: "internal/server/server.go", text: handlersGo }];
  const hot = rankHotspots(files, scanEntryPoints(files), scanScope(files));
  const why = (route) => {
    const h = hot.find((x) => x.route === route);
    assert.ok(h, `${route} is ranked`);
    return h.reasons.join("; ");
  };
  assert.match(why("/download"), /no auth middleware on the route, its group or its router/);
  assert.match(why("/download"), /path traversal/);
  assert.match(why("/download"), /http\.ServeFile with a computed path/);
  assert.doesNotMatch(why("/archive"), /path traversal/, "Clean plus a prefix check");
  assert.match(why("/convert"), /process execution \(os\/exec\)/);
  assert.doesNotMatch(why("/convert"), /no auth middleware/);
  assert.match(why("/search"), /SQL built with fmt\.Sprintf/);
  assert.match(why("/import"), /request body read whole without http\.MaxBytesReader/);
  assert.match(why("/docs/{id}"), /record loaded by an id from the request without an ownership check/);
  assert.doesNotMatch(why("/my/docs/{id}"), /ownership/);
  assert.match(why("/hooks/billing"), /signature check seen in the handler/);
  assert.doesNotMatch(why("/hooks/billing"), /no auth middleware on the route, its group/);
  assert.match(why("/healthz"), /health\/status route/);
  assert.doesNotMatch(why("/healthz"), /no auth middleware/);
});

test("Go file signals: TLS, math/rand, timeouts, templates, FileServer, zip slip, shared maps, CORS, JWT, discarded errors", () => {
  const bad = `package web

import (
	"archive/zip"
	"crypto/tls"
	"math/rand"
	"net/http"
	"path/filepath"
	"text/template"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
)

var visits = map[string]int{}

func client() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
}

func resetToken() string {
	b := make([]byte, 16)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func count(w http.ResponseWriter, r *http.Request) {
	visits[r.URL.Path]++
	w.Write([]byte(template.HTML(r.FormValue("bio"))))
}

func extract(zr *zip.Reader, dest string) {
	for _, f := range zr.File {
		path := filepath.Join(dest, f.Name)
		_ = path
	}
}

func parse(s string) {
	token, _ := jwt.Parse(s, func(t *jwt.Token) (any, error) { return key, nil })
	_ = token
	bcrypt.CompareHashAndPassword(hash, []byte(s))
}

func serve() {
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
	})
	http.Handle("/", http.FileServer(http.Dir(".")))
	http.ListenAndServe(":8080", c.Handler(http.DefaultServeMux))
}
`;
  const good = `package web

import (
	"crypto/rand"
	"html/template"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/cors"
)

var (
	mu     sync.Mutex
	visits = map[string]int{}
)

func count(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	visits[r.URL.Path]++
	mu.Unlock()
	_ = template.HTML("<b>static</b>")
}

func token() []byte {
	b := make([]byte, 32)
	rand.Read(b)
	return b
}

func parse(s string) (*jwt.Token, error) {
	return jwt.Parse(s, keyFunc, jwt.WithValidMethods([]string{"HS256"}))
}

func serve(h http.Handler) error {
	c := cors.New(cors.Options{AllowedOrigins: []string{"https://app.example.com"}, AllowCredentials: true})
	srv := &http.Server{Addr: ":8080", Handler: c.Handler(h), ReadHeaderTimeout: 5 * time.Second}
	return srv.ListenAndServe()
}
`;
  const rows = scanGoFiles([{ path: "web/bad.go", text: bad }, { path: "web/good.go", text: good }, { path: "web/bad_test.go", text: bad }]);
  const at = (re) => rows.filter((r) => re.test(r.reasons[0])).map((r) => `${r.file}:${r.line}`);
  const L = (re) => `web/bad.go:${lineOf(bad, re)}`;
  assert.deepEqual(at(/InsecureSkipVerify/), [L(/InsecureSkipVerify/)]);
  assert.deepEqual(at(/math\/rand used for a token/), [L(/rand\.Intn/)]);
  assert.deepEqual(at(/package-level map visits written without a lock/), [L(/visits\[r\.URL\.Path\]\+\+/)]);
  assert.deepEqual(at(/template\.HTML \(or JS\/URL\) on dynamic content/), [L(/template\.HTML\(r\.FormValue/)]);
  assert.deepEqual(at(/text\/template renders HTML/), [L(/"text\/template"/)]);
  assert.deepEqual(at(/zip slip/), [L(/filepath\.Join\(dest, f\.Name\)/)]);
  assert.deepEqual(at(/jwt\.Parse without an algorithm check/), [L(/jwt\.Parse\(/)]);
  assert.deepEqual(at(/error of a security check thrown away/), [L(/jwt\.Parse\(/), L(/bcrypt\.CompareHashAndPassword/)]);
  assert.deepEqual(at(/CORS allows any origin with credentials/), [L(/cors\.New\(cors\.Options/)]);
  assert.equal(rows.find((r) => /CORS/.test(r.reasons[0])).score, 6);
  assert.deepEqual(at(/FileServer serves the working directory/), [L(/http\.FileServer/)]);
  assert.deepEqual(at(/http\.ListenAndServe runs a server without/), [L(/http\.ListenAndServe\(":8080"/)]);
  assert.ok(!rows.some((r) => r.file !== "web/bad.go"), "the safe file and the test file give no rows");
});

// ---------------------------------------------------------------- tools

const goProject = () => project({
  "go.mod": "module example.com/svc\n\ngo 1.23\n",
  "main.go": 'package main\n\nimport "net/http"\n\nfunc main() {\n\thttp.HandleFunc("/ping", ping)\n}\n\nfunc ping(w http.ResponseWriter, r *http.Request) {}\n',
});

test("gosec and govulncheck: native only, NOT RUN with how to enable them, no downloads, skipped without Go", () => {
  const root = goProject();
  const inv = inventory(root);
  assert.equal(inv.go, 1);
  assert.deepEqual(inv.gomods, ["go.mod"]);
  const none = runTools({ root, inv, stack: [], only: ["gosec", "govulncheck"], runner: { installed: () => false, run: () => assert.fail("must not run"), dockerOk: true } });
  assert.deepEqual(none.map((r) => r.state), ["not-run", "not-run"]);
  assert.match(none[0].status, /^NOT RUN: gosec not installed \(no docker fallback\); to enable: `go install github\.com\/securego\/gosec\/v2\/cmd\/gosec@latest`/);
  assert.match(none[1].status, /^NOT RUN: govulncheck not installed \(no docker fallback\); to enable: `go install golang\.org\/x\/vuln\/cmd\/govulncheck@latest`/);
  assert.deepEqual(none.map((r) => r.category), ["code", "dependency"]);

  const gosecOut = JSON.stringify({ "Golang errors": {}, Issues: [
    { severity: "MEDIUM", confidence: "HIGH", cwe: { id: "22" }, rule_id: "G304", details: "Potential file inclusion via variable", file: `${root}/main.go`, line: "9-10" },
  ], Stats: {} });
  const calls = [];
  const ran = runTools({ root, inv, stack: [], only: ["gosec"], runner: { installed: (c) => c === "gosec", run: (c, a, o) => { calls.push([c, a, o]); return { status: 0, stdout: gosecOut, stderr: "" }; } } });
  assert.equal(ran[0].status, "gosec: 1 candidates");
  assert.deepEqual([ran[0].rows[0].file, ran[0].rows[0].line, ran[0].rows[0].rule, ran[0].rows[0].severity], ["main.go", 9, "G304 CWE-22", "medium"]);
  const [cmd, argv, opts] = calls[0];
  assert.equal(cmd, "gosec");
  for (const a of ["-fmt=json", "-no-fail", "./..."]) assert.ok(argv.includes(a), a);
  assert.equal(opts.cwd, root);
  assert.deepEqual([opts.env.GOTOOLCHAIN, opts.env.GOFLAGS, opts.env.GOPROXY], ["local", "-mod=readonly", "off"]);

  const testsOnly = project({ "go.mod": "module example.com/x\n", "x_test.go": "package x\n" });
  const skipped = runTools({ root: testsOnly, inv: inventory(testsOnly), stack: [], only: ["gosec", "govulncheck"], runner: { installed: () => true, run: () => assert.fail("must not run") } });
  assert.deepEqual(skipped.map((r) => r.status), ["skipped: no Go source outside tests", "skipped: no Go source outside tests"]);
  const noMod = project({ "main.go": "package main\n" });
  assert.equal(runTools({ root: noMod, inv: inventory(noMod), stack: [], only: ["gosec"], runner: { installed: () => true, run: () => assert.fail("must not run") } })[0].status, "skipped: no go.mod (gosec loads packages in module mode)");
});

test("the Go tools run in the shallowest module and report paths from the project root", () => {
  const root = project({ "backend/go.mod": "module example.com/b\n", "backend/api/h.go": "package api\n", "tools/go.mod": "module example.com/t\n", "tools/x.go": "package main\n" });
  const inv = inventory(root);
  const out = JSON.stringify({ Issues: [{ severity: "HIGH", rule_id: "G204", details: "Subprocess launched with variable", file: `${root}/backend/api/h.go`, line: "3" }] });
  const calls = [];
  const ran = runTools({ root, inv, stack: [], only: ["gosec"], runner: { installed: () => true, run: (c, a, o) => { calls.push(o.cwd); return { status: 0, stdout: out }; } } });
  assert.deepEqual(calls, [join(root, "backend")]);
  assert.equal(ran[0].rows[0].file, "backend/api/h.go");
  assert.equal(ran[0].status, "gosec: 1 candidates (module backend); 1 more go.mod not scanned (tools/go.mod)");
});

test("govulncheck -json stream: called symbols are high, imported or required-only modules are low", () => {
  const root = "/w";
  const stream = [
    { config: { protocol_version: "v1.0.0", scanner_name: "govulncheck" } },
    { progress: { message: "Scanning your code" } },
    { osv: { id: "GO-2099-0001", summary: "Path traversal in an example archive package" } },
    { finding: { osv: "GO-2099-0001", fixed_version: "v1.4.2", trace: [
      { module: "example.com/archive", version: "v1.4.0", package: "example.com/archive/unpack", function: "Extract" },
      { module: "example.com/svc", package: "example.com/svc/files", function: "Import", position: { filename: "/w/files/import.go", line: 41 } },
    ] } },
    { finding: { osv: "GO-2099-0002", trace: [{ module: "example.com/yaml", version: "v0.3.0", package: "example.com/yaml" }] } },
  ].map((m) => JSON.stringify(m, null, 2)).join("\n");
  assert.equal(jsonStream(stream).length, 5);
  const rows = parseGovulncheck(stream, root);
  assert.deepEqual(rows.map((r) => [r.file, r.line, r.rule, r.severity]), [["files/import.go", 41, "GO-2099-0001", "high"], ["go.mod", 0, "GO-2099-0002", "low"]]);
  assert.match(rows[0].note, /^called: example\.com\/archive@v1\.4\.0 example\.com\/archive\/unpack\.Extract, fixed in v1\.4\.2\. Path traversal/);
  assert.match(rows[1].note, /^imported, not called/);
  assert.throws(() => parseGovulncheck("not json", root));
  assert.throws(() => parseGosec(JSON.stringify({ errors: [] }), root));
});

test("prepass on a Go project: dedicated profile, Go routes in the table, gosec and govulncheck NOT RUN rows", () => {
  const root = goProject();
  spawnSync("git", ["init", "-q"], { cwd: root });
  spawnSync("git", ["add", "-A"], { cwd: root });
  const r = spawnSync(process.execPath, [join(repo, "scripts", "prepass.mjs"), "--root", root, "--no-docker", "--new-run"], { encoding: "utf8", env: toolFreeEnv() });
  assert.equal(r.status, 0, r.stderr);
  const md = readFileSync(join(root, ".security-audit", "prepass.md"), "utf8");
  assert.match(md, /\*\*Profile: Go: dedicated profile\.\*\*/);
  assert.match(md, /\| nethttp-route \| ANY \| \/ping \| main\.go:6 \|/);
  for (const t of ["gosec", "govulncheck"]) assert.match(md, new RegExp(`^- ${t}: NOT RUN: ${t} not installed \\(no docker fallback\\)`, "m"));
  const na = readFileSync(join(root, ".security-audit", "not-assessed.md"), "utf8");
  assert.match(na, /\| code \| Go static analysis \(gosec\) \| NOT RUN/);
  assert.match(na, /\| dependency \| Go vulnerability check with call reachability \(govulncheck\) \| NOT RUN/);
});

// ---------------------------------------------------------------- briefs

test("briefs: the Go checklist section and Go patterns only for Go projects", () => {
  const go = patternsFor(["go"]);
  assert.match(go, /^## Go\n/m);
  assert.match(go, /\| Paths \| `filepath\\.Join/);
  assert.doesNotMatch(patternsFor(["js"]), /^## Go\n/m);
  assert.doesNotMatch(patternsFor(["python"]), /^## Go\n/m);
  const sections = profileSections(["go"]);
  assert.equal(sections.length, 1);
  assert.match(sections[0], /^## Stack profile: Go\n/);
  assert.match(sections[0], /zip slip/);
  assert.deepEqual(profileSections(["js"]), []);
});
