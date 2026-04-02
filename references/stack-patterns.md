# Stack-Specific Search Patterns

Use these grep/ripgrep patterns during Phase 2 to find relevant code.
Adapt based on the stack identified in Phase 1. Not exhaustive — use judgment.

## SQL Injection

| Language | Patterns to search |
|----------|-------------------|
| Python | `execute\(.*%`, `execute\(.*f"`, `execute\(.*\.format`, `raw\(`, `extra\(.*where` |
| JS/TS | `query\(.*\$\{`, `query\(.*\+`, `\.raw\(`, `sequelize\.literal`, `knex\.raw` |
| Go | `fmt\.Sprintf.*SELECT`, `db\.Exec\(.*\+`, `db\.Query\(.*\+` |
| Ruby | `find_by_sql`, `where\(.*#\{`, `execute\(`, `sanitize_sql` (verify usage) |
| Java | `createQuery\(.*\+`, `executeQuery\(.*\+`, `Statement` (vs PreparedStatement) |
| PHP | `mysql_query\(.*\$`, `mysqli_query\(.*\$`, `->query\(.*\$`, `PDO.*\$` without prepare |

## XSS

| Framework | Patterns to search |
|-----------|-------------------|
| React | `dangerouslySetInnerHTML` |
| Vue | `v-html` |
| Angular | `bypassSecurityTrust`, `\[innerHTML\]` |
| Python/Jinja | `\|safe`, `Markup\(`, `autoescape false`, `{% raw %}` |
| EJS | `<%-` (unescaped output) |
| Handlebars | `\{\{\{` (triple-brace, unescaped) |
| Go templates | `template\.HTML\(` |
| PHP | `echo \$`, `<?=` without `htmlspecialchars` |

## Command Injection

| Language | Patterns to search |
|----------|-------------------|
| Python | `subprocess\..*shell=True`, `os\.system\(`, `os\.popen\(`, `exec\(`, `eval\(` |
| JS/TS | `child_process`, `exec\(`, `execSync\(`, `spawn\(.*shell`, `eval\(` |
| Go | `exec\.Command\(.*\+`, `os/exec` with user input |
| Ruby | `system\(`, `exec\(`, `` `...` `` (backticks), `%x\(`, `Open3` |
| PHP | `exec\(`, `shell_exec\(`, `system\(`, `passthru\(`, `proc_open\(` |

## Path Traversal

| Pattern | What to look for |
|---------|-----------------|
| All languages | `\.\./`, `\.\.\\`, path join/concat with user input |
| Python | `os\.path\.join\(.*request`, `open\(.*request`, `send_file\(` |
| JS/TS | `path\.join\(.*req`, `path\.resolve\(.*req`, `res\.sendFile\(` |
| Go | `filepath\.Join\(.*r\.`, `http\.ServeFile\(` |
| PHP | `file_get_contents\(.*\$_`, `include\(.*\$_`, `require\(.*\$_` |

## Secrets & Hardcoded Credentials

| Pattern | What to look for |
|---------|-----------------|
| All | `password\s*=\s*["']`, `secret\s*=\s*["']`, `api_key\s*=\s*["']`, `token\s*=\s*["']` |
| All | `BEGIN (RSA|DSA|EC) PRIVATE KEY`, `AKIA[0-9A-Z]{16}` (AWS key) |
| Config | `default.*password`, `fallback.*secret`, hardcoded in `if env missing` blocks |

## Cryptography Red Flags

| Pattern | Issue |
|---------|-------|
| `MD5\(`, `md5\(`, `hashlib\.md5` | Broken hash for security |
| `SHA1\(`, `sha1\(`, `hashlib\.sha1` | Broken hash for security |
| `DES`, `RC4`, `ECB` | Broken cipher/mode |
| `Math\.random`, `random\.random`, `rand\(\)` | Non-cryptographic RNG |
| `AES.*128` with `ECB` | Insecure mode |

## Deserialization

| Language | Patterns to search |
|----------|-------------------|
| Python | `pickle\.load`, `yaml\.load\(` (without SafeLoader), `marshal\.load` |
| Java | `ObjectInputStream`, `readObject\(`, `XMLDecoder` |
| PHP | `unserialize\(`, `maybe_unserialize\(` |
| Ruby | `Marshal\.load`, `YAML\.load\(` (without safe_load) |
| JS | `JSON\.parse` on unvalidated blobs is usually safe, but check `eval\(`, `Function\(` |

## Mass Assignment

| Language | Patterns to search |
|----------|-------------------|
| JS/TS | `\.create\(req\.body`, `\.build\(req\.body`, `Object\.assign\(.*req\.body`, `\{\.\.\.req\.body\}` |
| Python | `\*\*request\.data`, `serializer\.save\(`, `Model\.objects\.create\(\*\*` |
| Ruby | `\.create\(params`, `\.new\(params`, `\.update\(params` without `permit` |
| PHP | `fill\(\$request->all`, `create\(\$request->all`, `::create\(\$_POST` |

## JSONP / Cross-Domain Data Leakage

| Pattern | What to look for |
|---------|-----------------|
| All | `callback`, `jsonp`, `\?callback=`, `res\.jsonp`, `JSONP` |
| JS/TS | `res\.jsonp\(`, `\.jsonp\(`, `req\.query\.callback` |

## Null Byte Injection

| Pattern | What to look for |
|---------|-----------------|
| All | `%00`, `\x00`, `null.byte`, `nullByte`, `poisonNull` |
| JS/TS | `decodeURIComponent.*%00`, validation BEFORE null-byte strip (order-of-operations) |

## Unsafe YAML / Deserialization (JS/TS specific)

| Pattern | What to look for |
|---------|-----------------|
| JS/TS | `yaml\.load\(` (without `{ schema: SAFE_SCHEMA }`), `js-yaml` with default loader |
| All | `noent:\s*true` (XML entity expansion enabled), `yaml\.load` without safe option |

## Sensitive Field Storage

| Pattern | What to look for |
|---------|-----------------|
| All | `totpSecret`, `secret.*=.*plain`, `mfaSecret`, `otpSecret` stored without encryption |
| All | `req\.body\.UserId` or `req\.body\.userId` used in queries instead of authenticated user ID from token/session |

## Open Redirect

| Language | Patterns to search |
|----------|-------------------|
| JS/TS | `res\.redirect\(.*req`, `location\s*=.*req\.query`, `window\.location\s*=` |
| Python | `redirect\(.*request`, `HttpResponseRedirect\(.*request`, `return redirect\(` |
| PHP | `header\("Location:.*\$_`, `header\("location:.*\$_`, `wp_redirect\(.*\$_` |
| Go | `http\.Redirect\(.*r\.`, `w\.Header\(\).Set\("Location"` |
| Ruby | `redirect_to\s+params`, `redirect_to\s+request` |

## NoSQL Injection

| Language | Patterns to search |
|----------|-------------------|
| JS/TS | `\$where`, `\$gt`, `\$ne`, `\$regex`, `\$or.*req\.body`, `\.find\(.*req\.body`, `\.findOne\(.*req\.body`, `\.update\(.*req\.body` |
| Python | `\$where`, `\$gt`, `\$ne`, `collection\.find\(.*request` |
| PHP | `\$where`, `\$gt`, `\$ne`, `->find\(.*\$_` |

## SSTI (Server-Side Template Injection)

| Language | Patterns to search |
|----------|-------------------|
| Python/Jinja2 | `render_template_string\(`, `Template\(.*request`, `Environment\(.*\.from_string` |
| JS/TS | `res\.render\(.*req`, `Handlebars\.compile\(.*req`, `ejs\.render\(.*req`, `pug\.render\(.*req`, `nunjucks\.renderString\(` |
| PHP/Twig | `\->render\(.*\$_`, `Twig.*createTemplate\(`, `Blade::compileString\(` |
| Java | `Velocity.*evaluate\(`, `Freemarker.*Template\(`, `process\(.*getParameter` |
| Ruby | `ERB\.new\(.*params`, `render\s+inline:.*params` |

## Prototype Pollution

| Pattern | What to look for |
|---------|-----------------|
| JS/TS | `__proto__`, `constructor\.prototype`, `Object\.assign\(.*req`, `_\.merge\(.*req`, `_\.defaultsDeep\(.*req`, `deepmerge\(.*req`, `lodash\.merge` |
| Detection | Any recursive merge/extend function that accepts user input without filtering `__proto__` and `constructor` keys |

## Host Header Injection

| Language | Patterns to search |
|----------|-------------------|
| JS/TS | `req\.headers\.host`, `req\.headers\['x-forwarded-host'\]`, `req\.hostname` used in URL construction |
| Python | `request\.META\['HTTP_HOST'\]`, `request\.get_host\(\)` used in URL construction |
| PHP | `\$_SERVER\['HTTP_HOST'\]`, `\$_SERVER\['SERVER_NAME'\]` used in URL/link construction |

## LDAP Injection

| Language | Patterns to search |
|----------|-------------------|
| All | `ldap_search\(.*\$`, `ldap\.search\(.*req`, `search_s\(.*%s`, `(&(uid=` with string concatenation |

## PHP-Specific Patterns

| Pattern | Issue |
|---------|-------|
| `mysqli_real_escape_string` used for XSS protection | SQL escaping ≠ HTML encoding. Must also use `htmlspecialchars()` for output |
| `include\(.*\$_GET`, `include\(.*\$_POST`, `require\(.*\$_` | Local/Remote File Inclusion (LFI/RFI) |
| `extract\(\$_GET`, `extract\(\$_POST`, `extract\(\$_REQUEST` | Variable injection — overwrites local variables with user input |
| `\$\$` (variable variables) with user input | Variable variable injection |
| `preg_replace\(.*\/e` | Code execution via `/e` modifier (deprecated but still in legacy code) |
| `assert\(.*\$_` | Code execution via assert with user input |
| `create_function\(.*\$_` | Code execution via create_function with user input |
| `setcookie\(` without `httponly` or `secure` flags | Session cookie flags missing |
| `session_regenerate_id\(` missing after login | Session fixation vulnerability |

## GraphQL

| Pattern | What to look for |
|---------|-----------------|
| All | `introspection.*true`, `introspectionQuery`, `__schema`, `__type` — introspection should be disabled in production |
| All | `depthLimit`, `queryComplexity`, `costAnalysis` — if missing, DoS via deeply nested queries possible |

## WebSocket Security

| Pattern | What to look for |
|---------|-----------------|
| JS/TS | `ws\.on\('message'`, `socket\.on\('` — check if messages are validated/sanitized same as HTTP input |
| All | `cors.*origin` on WebSocket/Socket.IO config — verify origin allowlist, not wildcard |

## Insecure Randomness

| Language | Patterns to search |
|----------|-------------------|
| JS/TS | `Math\.random\(\)` used for tokens/session IDs/secrets (should use `crypto.randomBytes`) |
| PHP | `rand\(`, `mt_rand\(`, `array_rand\(` for security purposes (should use `random_bytes`, `random_int`) |
| Python | `random\.random\(`, `random\.randint\(` for security (should use `secrets` module) |
| Java | `java\.util\.Random` for security (should use `SecureRandom`) |
