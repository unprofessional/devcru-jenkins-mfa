# Task 9 handoff — written for a Sebastian with wiped context

**Written 2026-08-19, by Sebastian, at mads's direction (session reset
immediately follows).** Everything below is verified state as of this
moment — commit hashes, API shapes, failure modes, and rulings are
factual, not aspirational. Read top to bottom; it is self-contained by
design, but the "read these first" list at the bottom is still required
bedside reading.

---

## 1. One-paragraph status

`devcru-mfa` (repo `/home/hunter/dev/devcru-jenkins-mfa`, branch
**`develop`**, remote `github.com:unprofessional/devcru-jenkins-mfa.git`)
is at **`19e8498`** (A21 landed 2026-08-19, this session — see note
below the paragraph), pushed, CI-mirror green: Tasks 0–8 complete **plus
A21**, the home-grown Bearer API-token authenticator
(`BearerTokenFilter`, mads-ordered dependency of Task 9). The
live MFA gate (`MfaFilter`), the login page + verify/resend endpoints
(`MfaController`, mounted at **`/mfa`** per mads's 2026-08-19 ruling),
the TOTP core, email-code machinery, trust/rate-limit stores, and the
8-case end-to-end integration test (`MfaFilterIT`, Jenkins booted in-JVM)
all work. **Task 9 — the user-facing factor management page on *Manage
account → Security* — is the next and only remaining development task
** before Task 10 (deploy to `jenkins.devcru.org`). The plan's Task 9
section (`docs/plans/2026-08-17-jenkins-mfa-plugin.md`) was rewritten
today with two corrections verified against the actual jenkins-core
2.528.3 sources; a fresh reader who trusts the *old* plan text will hit
a silent-failure view path (details in §5.1) — the plan is now
correct.

**A21 landed 2026-08-19 (commit `19e8498`, this session):** Bearer
`Authorization` + `X-Jenkins-User` now authenticates as the API-token
owner and is exempt from the gate exactly like the Basic path —
**zero change to the gate itself** (it reads the same api-token request
attribute; A21 merely sets it, and the security context, for Bearer).
`BearerTokenFilter` is registered *ahead* of `MfaFilter` in
`DevcruMfaPlugin`. Task 9 therefore needs **no filter work**: enroll /
disable / revoke endpoints and the security-tab section run on the same
gate as today, and a Bearer client hitting any of them is exempt just
like any other API-token request. Full forensics (incl. the
access-modifier-checker constraint that shaped the public-API design)
are in `docs/todo/TECH_DEBT.md` A21 (status: LANDED), and the new booted
IT is `MfaFilterIT#bearerTokenExemptFromGate` (positive + no-oracle
mismatch negative).

## 2. Operating environment (exact commands)

```bash
# The ONLY toolchain on this host that works — no system Java/Maven exists:
export PATH="$HOME/opt/jdk-21.0.12+8/bin:$HOME/opt/apache-maven-3.9.11/bin:$PATH"
cd /home/hunter/dev/devcru-jenkins-mfa

# Offline Maven is the norm (no network in the build):
mvn -o -B -ntp test-compile                     # fast syntax/compile gate
mvn -o -B -ntp test -Dtest=MfaFilterIT          # only the IT (~40–80 s)
mvn -o -B -ntp clean verify                     # CI-mirror: the ONLY full validation
```

Rules (from `AGENTS.md` — read it, it is required-reading):
- **`mvn clean verify`, never bare `mvn test`,** for anything that counts:
  the parent POM binds SpotBugs into `verify`, so `mvn test` silently
  skips the linter. This exact gap once shipped a default-charset bug.
- Tests must be **BDD-documented** (WHAT / GIVEN-WHEN-THEN / WHY) —
  `src/test/java/org/sebcru/mfa/TotpTest.java` is the reference shape.
  A test commit without its documentation blocks review, even when green.
- **Same-commit rule:** code + tests + docs + `TECH_DEBT.md` + README
  "Practical usage" section all land together when a ruling changes
  narrated design.
- Commit identity is already configured: `Sebastian <sebastian@devcru.org>`.
  Push with plain `git push origin develop` (SSH works; `gh` CLI and any
  GitHub token do NOT exist on this host). No force-push, ever; `master`
  advances only on explicit mads per-step approval.
- `rg` is not installed — use `grep -rn`.

## 3. What exists right now (verified inventory)

Main sources, `src/main/java/org/sebcru/mfa/`:

| class | shape | notes for Task 9 |
|---|---|---|
| `MfaUserProperty` | `UserProperty`, category **Security** (its `DescriptorImpl` already sets `UserPropertyCategory.Security`) | The factor state. Fields: `Secret totpSecret`, `Secret emailCodeSecret`, `String registeredEmail` (enrolled ⇔ non-blank), **server-managed:** `trustedUntilMs`, `lastVerifiedFactor`, `failedAttemptStreak`, `pendingCodeHash`, `codeIssuedAt`, `lastResendAt`. **`@DataBoundSetter` is on ONLY `setTotpSecret` + `setRegisteredEmail`** — deliberately. The other fields must stay out of form binding or the profile page can forge 30-day trust / zero out lockout counters. Static helper: `getOrCreate(User)`. Predicates: `isMfaEnabled()`, `hasTotpFactor()`, `hasEmailFactor()`. |
| `MfaController` | `RootAction`, `getUrlName()` = **`"mfa"`** (mads's ruling; the old `securityRealm/mfa` path is gone and 404s by design) | Existing endpoints, both already `@RequirePOST @WebMethod(name=…)`: `postVerify`, `postResendEmail`. Pure seams: `resolveRedirectTarget(redirectParam, referer, requestPath, securityPath)` (unit-pinned), `classifyFactor`, `maskEmail`, `verifyTotp(...)`, `ensureEmailCodeSecret(p)` (the **A2 single mint seam** — idempotent, 128-bit, Secret-encrypted, only behind `hasEmailFactor()`; Task 9's email test-code endpoint MUST route through it). |
| `crypto/Totp` | static | `newBase32Secret()` (128-bit unpadded Base32), `codeAt(key, epochMillis)`, `verify(key, input, epochMillis, window)` (±window, constant-time, whitespace-stripped), `decodeSecret(base32)`. RFC 6238, 30 s, 6 digits, HMAC-SHA1 — Authy/GA-compatible. |
| `gate/TrustStore` | instance, `static final` in `MfaFilter` | `isTrusted(p, cfg, now)`, `trust(p, cfg, now)`, **`revoke(p)`** (Task 9's "revoke remembered devices"), `effectiveTrustHours(cfg)`. |
| `gate/RateLimiter` | instance | Lockout window/limit; `DevcruMfaConfig` supplies the numbers. |
| `email/EmailCodeIssuer` | instance | 8-char code over `CODE_ALPHABET` (unambiguous), `hashOf`, `issue(p, perUserSecret, now, ttl, sender)`, `resend(...)` (returns null on cooldown), `verify(...)` → `VerifyResult` enum. |
| `email/JenkinsEmailSender` | implements `EmailSender` | Mailer-plugin delivery; **code is in the body only, never the subject**; from-address via the admin's "Send test email" convention. |
| `VerifyOutcome` | plain value type | The JSON contract: ok ⇒ `{ok, rememberHours, redirect}` or resent ⇒ `{ok, "resent":true, cooldown}`; fail ⇒ `{ok:false, error[, retrySeconds]}`. Stable error constants on the class. `toJSONObject()` via `net.sf.json` (nulls omitted — field *presence* is part of the contract). |
| `DevcruMfaConfig` | `@Extension GlobalConfiguration` | Kill switch, policy (`REQUIRED`/opt-in), trust hours, resend cooldown, code TTL, TOTP window. Read via `currentSafe()` (A1 ruling — descriptor instance with `get()` fallback; the single runtime reader). |
| `MfaFilter` | jakarta `Filter` | The gate. Registered by `DevcruMfaPlugin` (`@Extension`, plain class, `@Initializer(after = EXTENSIONS_AUGMENTED)` + `@Terminator`, one shared `static final` instance). Decision chain: kill switch → API-token attribute exemption → anonymous → ERROR dispatch → path allow-list → policy → exemptions → unenrolled pass → `sessionVerified || trustLive` → 302 to `<ctx>/mfa?redirect=<validated>`. Allow-list prefixes (line ~130): `/login /logout /postlogout /logoutpost /signup /j_acegi /mfa /static/ /images/ /adjuncts/ /scripts/ /css/ /crumbIssuer`. |

Resources: `src/main/resources/org/sebcru/mfa/MfaController/index.jelly`
(the login page — the visual/JS contract for Task 9's section to match);
`DevcruMfaConfig/config.jelly` (global config UI — the pattern for an
`f:`-bound section).

Tests, `src/test/java/org/sebcru/mfa/`: `TotpTest`, `DevcruMfaConfigTest`,
`FilterLogicTest` (pure gate decision table), `MfaControllerTest` (pure
seams), `MfaUserPropertyTest`, `gate/TrustStoreTest`, `gate/RateLimiterTest`,
`email/EmailCodeIssuerTest` (+ `CaptureEmailSender` in-JVM mail sink),
and **`MfaFilterIT`** — the booted end-to-end suite, 8/8 green
(7 Task-8 cases + the A21 Bearer case, `bearerTokenExemptFromGate`,
landed 2026-08-19), plus `BearerTokenFilterTest` (8 pure-parse cases).

## 4. How the IT works (you will extend it, or add a sibling file)

`MfaFilterIT` boots a **real Jenkins in-JVM** under a **non-root context
(`/jenkins/`)** on `HudsonPrivateSecurityRealm` (the local realm — the
production shape). Every request URL is built through the helpers
`href(base, rel)` / `hostAbs(base, path)` / `ctxOf/base` which keep that
context path; do not hardcode `http://localhost:PORT/...` paths. Helper
map (line numbers drifted — grep, don't trust):

- `enrollTotp(name, pw, secret)` / `enrollEmail(…)` / `enrollEmailAndReturn`
  — create real password users + write a fully-enrolled `MfaUserProperty`
  (in-JVM, so the IT drives the *gate*, not enrolment — Task 9 inverts
  that: it drives enrolment).
- `rawGet(c, base, path)` — raw GET, **redirects disabled** (A19).
  Returns whatever the server first answers: 302 with `Location`, 403
  with a crumb body, etc. `followGet`/`follow` is the redirect-following
  twin.
- `mfaPage(…)` → `HtmlPage`; `crumbFromPage(page)` — extracts the hidden
  crumb (name + value) from the rendered page.
- `postMfaForm(c, base, endpoint, …)` — POSTs with crumb, parses the JSON
  envelope into `net.sf.json.JSONObject`.

Verified mechanics worth knowing *before* your first red (Task 8 forensics,
now in `references/task8-it-and-defects.md` under the jenkins-plugin-operations
skill):
- **The booted 404 body is the truth-teller.** When a URL 404s, the page
  text says *exactly* which object resolved and which token failed, and
  enumerates the object's real URL mappings. Read it before guessing.
- **`c.login()` follows redirects** (HtmlUnit default). If a case looks
  like "I'm already on the target page," the gate's 302 was consumed —
  that is correct gate behaviour, not a green.
- ~5–9 s per case; the suite is ~40 s targeted, ~25 s inside `verify`.
  Not "minutes per case" — don't over-batch.

## 5. Task 9 — what to build, and the traps

### 5.1 The view (biggest trap — silent failure)

Core's *Manage account → Security* page is
`hudson/model/userproperty/UserPropertyCategorySecurityAction/index.jelly`
(verified from the 2.528.3 jar). It renders each property's section via:

```jelly
<f:form method="post" action="configSubmit" name="config">
  ...
  <f:rowSet name="userProperty${loop.index}">
    <st:include from="${d}" page="${d.configPage}"/>   <!-- descriptor-relative! -->
  </f:rowSet>
  ...
</f:form>
```

Consequences, all verified:
1. `Descriptor.getConfigPage()` defaults to `"config"`, and the view
   resolves **relative to the descriptor** — so the file must be
   **`src/main/resources/org/sebcru/mfa/MfaUserProperty/config.jelly`**.
   The original plan text said `org/sebcru/mfa/views/MfaUserProperty.jelly`
   — **that path is wrong and fails silently** (empty section, green build,
   happy CI). The corrected plan text has the right path; if you see the
   old one anywhere, it is a copy of the pre-correction wording.
2. **Do NOT wrap the section in an `<f:form>`** (or put a save button in
   it). The tab already supplies the form + `f:rowSet`; nested forms break
   the browser's field scoping and the `configSubmit` binding.
3. The core working example to model on:
   `jenkins/console/ConsoleUrlProviderUserProperty/config.jelly` — it
   starts `<j:if test="${descriptor.enabled}">`, opens with a
   `<f:invisibleEntry>` dummy checkbox (keeps the rowSet always
   non-empty), then fields.
4. `configSubmit` binds through `reconfigure(JsonObject)` →
   `@DataBoundSetter`s only. In the current `MfaUserProperty` that is
   `registeredEmail` (+ the dummy). The TOTP seed does **not** go through
   `configSubmit` (see §5.2) — it arrives over a JSON endpoint.

### 5.2 Endpoints (six, on the existing `/mfa` mount)

Per the corrected plan section: `postEnroll`, `postEnrollConfirm`,
`postEmailTestCode`, `postDisableTotp`, `postDisableEmail`,
`postRevokeTrust`. Each: `@RequirePOST` **and**
**`@WebMethod(name = "…")`** (annotation-only-attribute on this Stapler:
`String[] name()` — there is no `posterJelly`).

**A20 — the rule, non-negotiable:** Stapler's dynamic dispatch maps only
get/is/do-prefixed methods (+`@WebMethod`); `@RequirePOST` is *policy*,
it declares nothing. Task 8's `postVerify`/`postResendEmail` shipped
unroutable until the IT's 404 body proved it — every one of the six new
endpoints must carry `@WebMethod` **in the same commit** as the method.
The booted 404 test is the guard (plan lists it).

Enrollment commit safety (plan ruling): **seed + code arrive in ONE POST**
(`postEnrollConfirm` with `{seed, code}`); verify
`Totp.verify(decodeSecret(seed), code, now, cfg.getTotpWindow())`
*before* writing `MfaUserProperty.totpSecret`. The form holds the
uncommitted seed in a hidden input between "Generate" (`postEnroll`,
returns `{ok, seed, otpauthUri, dataUriPng}`) and "Confirm". No
server-side pre-commit state — that would be a credential-in-session
problem with its own lifecycle. Regenerate = POST `postEnroll` again.

`postEmailTestCode` reuses the existing
`EmailCodeIssuer.issue/resend` + cooldown path, **through
`ensureEmailCodeSecret(p)`** (A2: one mint seam, no second
implementation). `postRevokeTrust` → `TrustStore.revoke(p)`.

### 5.3 QR

zxing 3.5.3 is already in `pom.xml` (declared, unused so far).
`MultiFormatWriter().encode(otpauthUri, BarcodeFormat.QR_CODE, 300, 300)`
→ `MatrixToImageWriter` → `ByteArrayOutputStream` → Base64 →
`<img src="data:image/png;base64,…" …>`. Keep the builder as a pure,
unit-testable seam (URI string in, data-URI out) — TDD it before wiring.

### 5.4 What the IT must cover (from the corrected plan section)

Extend `MfaFilterIT` (it already has login/crumb/POST helpers) — or add
`MfaProfileIT` if the suite gets unwieldy; same boot mechanics. Minimum:
(a) login as an enrolled user, GET the security page, **assert the MFA
section actually renders** (guards 5.1's silent-failure mode — search for
a known element id in the HTML); (b) `postEnroll` → seed in JSON;
`postEnrollConfirm` with correct `Totp.codeAt` → `ok:true` AND
`hasTotpFactor()` true on the persisted property; bad code →
`wrong_code` AND property unchanged; (c) each disable/revoke endpoint
flips exactly the right flag; (d) all six endpoints 404-free. Every test
BDD-documented per AGENTS.md.

## 6. Standing rulings & open items (do not re-litigate)

- **Mount is `/mfa`** (mads, 2026-08-19). Old path 404s by design; stale
  bookmarks break — that is intended, and Task 10's checkbox says so.
- **A15 ruled, tracked as A21:** Bearer API-token auth is a *real gap* to
  build, **home-grown, no new dependency** (Spring Security 6.5.3 is a
  `provided` transitive of jenkins-core; Jenkins does not run Spring's web
  filter chain — "built-in" is a mirage; full forensics in TECHNO_DEBT
  A15/A21 + plan AMENDMENTS). Implementation: a `jakarta.servlet.Filter`
  registered ahead of the gate, parses `Authorization: *** caller
  identity from a companion header (tokens are opaque 40-hex, no embedded
  id — hence a documented client contract header, not an O(N) scan),
  checks `ApiTokenProperty.matchesPassword`, sets the api-token request
  attribute the gate already exempts. **Sequencing: mads has not yet
  ordered it; my recommendation standing is A21 → Task 9 → Task 10.**
- **A21** spec + acceptance live in `docs/todo/TECH_DEBT.md` — that file
  is also where every defect/ruling gets recorded; A1–A21 current.
- Task 10 (deploy) plan: snapshot-first, `hpi:run` staging, manual
  acceptance checklist — all in the plan doc; the live box is
  `jenkins.devcru.org` (this host is the agent).

## 7. Recurring pitfalls (cost me days in prior sessions)

1. **`<x:out>` does not exist** on this runtime's Jelly (TECH_DEBT A18).
   Use `j:out` (jelly:core) for dynamic *text*; a dynamic *attribute*
   must be interpolated raw (`value="${…}"`), as core's own crumb views
   do. A tag cannot appear inside an attribute. A render 500 will say
   `This tag does not understand the 'value' attribute` — that is this
   trap.
2. **The `patch` fuzzy-match tool mangles tricky text silently** (dropped
   a JS `)` once, corrupted an ASCII fence once). **Re-read the touched
   region on disk after every patch** — the returned diff is not proof.
3. **Jelly root must be a single `<j:jelly>`** with all namespaces bound
   inside it (`j:x:st:`, `xmlns:f="/lib/form"` etc.). `escape-by-default='false'`
   on the login page was deliberate (it carries JS) — if you touch
   `index.jelly`, keep the `j:out` escaping on the two dynamic values.
4. **`mvn test` ≠ `mvn verify`** (§2). And `InjectedTest` (boots a real
   Jenkins every build) is in the suite — a plugin that can't boot fails
   `verify`, and that has caught real registration bugs twice (plain
   `@Extension`, not a `hudson.Plugin` subclass; `EXTENSIONS_AUGMENTED`,
   not `STARTED` — see `DevcruMfaPlugin`'s class comment).
5. **Background maven runs:** the harness notifies on exit, but always
   grep the log for the surefire summary before reporting green; the exit
   code of a wrapper `echo` can mask it.
6. **Redact all secrets/tokens in logs and chat** — `[REDACTED]`.

## 8. Read these first (in this order, before touching code)

1. `README.md` (repo root) — status header, doc table, practical usage.
2. `AGENTS.md` — the rules.
3. `docs/plans/2026-08-17-jenkins-mfa-plugin.md` — the AMENDMENTS block at
   the top, then **Task 9's section** (corrected 2026-08-19), then Task 10.
4. `docs/todo/TECH_DEBT.md` — A15 (ruling), A21 (spec), A16–A20 (what
   Task 8's IT caught, with failure signatures).
5. `docs/done/2026-08-18-task8-handoff.md` — the IT mechanics + defects
   forensics (the "economics correction" and the five defects are told
   there better than anywhere else).
6. `docs/architecture/README.md` — design decisions.
7. Load the **`jenkins-plugin-operations` skill** (it carries the live
   per-core API findings, the Jelly forensics, and the Task 8 landing
   state — and is the one to patch when something new breaks).

## 9. Suggested first moves for Task 9 (TDD order)

1. Re-read §5 of this doc + the plan's Task 9 section.
2. Pure seam first: a unit-tested `buildOtpauthUri(label, accountId,
   base32Secret)` + `qrDataUri(uri)` (zxing) — TDD with documented BDD.
3. The two pure decision seams for `postEnroll`/`postEnrollConfirm`
   (seed validation + verify-before-commit), unit-pinned like
   `MfaController`'s existing seams.
4. Then the six `@WebMethod` endpoints, then `config.jelly` at the
   corrected path, then the IT cases in §5.4 — **the render-presence
   assertion (5.1) is cheap insurance against the silent failure; write
   it first, let it go red, then let the view fix it.**
5. Each endpoint lands with its `@WebMethod` + test + doc in the same
   commit. `mvn -o -B -ntp clean verify` before each commit. Commit
   message flags deviations. Push to `develop` (CI runs on push).
