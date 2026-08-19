# Task 8 handoff — MfaFilterIT (third write; two production defects found)

**Written by Sebastian, 2026-08-19.** Supersedes the second write (committed
`3b45151`) and the first (committed `53b1334`). Read top to bottom; the old
versions' seam tables are partly stale now (context path and endpoint paths
changed understanding mid-session).

**Where Task 8 stands in one line:** the IT is written, compiles clean, and
runs fast — and it has **caught two real production defects**. Defect A
(302 self-loop on every gated request) is **fixed in code**. Defect B (MFA
page 404s on any real local security realm — i.e. the live box) is
**diagnosed to the line, needs mads's ruling, then one bounded sweep**.
Nothing is committed; the tree below is the whole truth.

## The ruling mads owes before more work (answer this first)

**Defect B move the mount `securityRealm/mfa` → `mfa` (top-level, single
segment)?** Recommended: yes.

- The controller's `getUrlName()` = `securityRealm/mfa`, but on any
  **ModelObject-backed local security realm** (HPSR — the exact
  production shape of `jenkins.devcru.org`) the active realm is mounted by
  Stapler at the **top-level `securityRealm` node** and swallows the whole
  prefix. Decoded Stapler 404 body (captured this session):
  `No matching rule was found on hudson.security.HudsonPrivateSecurityRealm
  for "/mfa"`. On the live box, every enrolled user's gate bounce 404s.
- Tasks 1–7 stayed green only because those harnesses ran the default test
  realm (no ModelObject at that node). The IT finally matches production
  shape — this is the defect class Task 8 exists to catch.
- `mfa` is a free single segment: no core mount, no ModelObject can claim a
  bare segment, survives any realm.
- If mads prefers another segment, name it; the sweep is parameterised on
  the choice, nothing else changes.

The sweep after ruling (all mechanical, paths/lines below):
1. `MfaController.getUrlName()` (line 157) → `"mfa"`; class-doc lines
   30–36 + 66–70 (the "URL unchanged, stays as plan wants" deviation note
   becomes deviation #3 with the 404 evidence — honest red→green per
   AGENTS.md).
2. `MfaFilter.ALLOWED_PREFIXES` (lines 127–133): `"/securityRealm"` →
   `"/mfa"` (keep `/securityRealm` too only if core realm pages need
   post-auth navigation — check the 7 IT cases first; the gate only needs
   the MFA page itself plus auth-flow paths). Comment on 122–126 updates.
3. `MfaController.resolveRedirectTarget` / `isSecurityPath` (lines 733–759):
   add `mfa` to the first-segment set so a redirect *to* the MFA page
   degrades to root (else post-verify loops back into the gate). Class-doc
   360 + the `FilterLogicTest`/`MfaControllerTest` pins for this behaviour
   reference the old path (lines ~171, 209, 463 in `MfaControllerTest`;
   ~210–296, 426–534, 567 in `FilterLogicTest`).
4. `MfaFilter.redirect` line 436 (`ctx + "/securityRealm/mfa?"` →
   `ctx + "/mfa?"`) + its javadoc line 426 + the class-doc line 24.
5. `MfaFilterIT`: endpoint helper line 828 (`"securityRealm/mfa/" +
   endpoint` → `"mfa/" + endpoint`) + ~10 Location assertions containing
   `securityRealm/mfa` (lines ~192, 372, 447, 508, 519, 586, 645, 647 +
   doc blocks).
6. `MfaController/index.jelly` line 4 doc comment. (The page's JS POSTs to
   bare `postVerify`/`postResendEmail` with no `action` attribute, so it
   is relative-to-page — verify the `postForm` helper in `index.jelly`
   once at resume; no hardcoded paths expected anywhere else in the page.)

## Repo / tree state (verified 2026-08-19)

- Branch `develop` @ `3b45151` (`task8(WIP): MfaFilterIT draft +
  CaptureEmailSender + surefire IT include`). `master` untouched.
- **Uncommitted diff — exactly two files:**
  - `M src/main/java/org/sebcru/mfa/MfaFilter.java` — the Defect A fix
    (rewrite of `targetPath()`, lines ~389–415, with a "why not
    getServletPath()" javadoc) + the allow-list comment unchanged. NOTE:
    the `catch (RuntimeException)` block at ~lines 218–223 ended up with
    one less indent level than the surrounding style; run
    `git diff MfaFilter.java` at resume and tidy it to match neighbours
    before committing (cosmetic only; compiles clean).
  - `M src/test/java/org/sebcru/mfa/MfaFilterIT.java` — **fully rewritten**
    (~855 lines, supersedes the 793-line committed draft that didn't
    compile). Same 7 BDD cases, same package, same `@WithJenkins`
    method-parameter injection, `CaptureEmailSender` unchanged and in
    place. Compiles clean (`mvn -q -o test-compile` → 0 errors).
- No `TEMP-DIAG`/`MFADBG`/`ITDBG` markers remain anywhere (grepped clean).
- README + TECH_DEBT: **not yet updated for Task 8** (house rule: same
  commit as the IT landing).

## Canonical test state (the only run you should trust)

```
export PATH="$HOME/opt/jdk-21.0.12+8/bin:$HOME/opt/apache-maven-3.9.11/bin:$PATH"
cd /home/hunter/dev/devcru-jenkins-mfa
mvn -o -B -ntp test -Dtest=MfaFilterIT > /tmp/apidump/canonical.txt 2>&1
```

Result 2026-08-19: **Tests run: 7, Failures: 6, Errors: 0** — suite wall
clock ~16 s. All 6 failures are the *identical* assertion: `expected:
<302> but was: <404>` raised at `mfaPage`/raw-bounce — HtmlUnit follows
the (correct) 302 to the MFA page and the page 404s (Defect B). The 1
pass is the **API-token case**: Basic `user:apitoken` → 200 with no MFA
bounce; it never touches the MFA page, so it proves the Defect A fix
holds for the token branch and that the gate otherwise passes
authenticated traffic correctly. `api_json` is therefore your canary that
Defect A is fixed while B is pending.

Live filter trace captured this session (temp instrumentation, since
removed) showed the *correct* post-fix decisions:
`uri=[/jenkins/job/it-email-job/] d=REDIRECT`,
`uri=[/jenkins/securityRealm/mfa] d=PASS` — the filter side is done;
only the page mount 404s.

## Defect A — 302 self-loop (FIXED, verified)

- Symptom: first live IT run, 6/7 die with HtmlUnit `Too many redirects`;
  the job GET 302s to the MFA page, which 302s to itself forever.
- Root cause: `targetPath()` used `http.getServletPath()`, which
  **returns `""`** for gated requests on the 2.528.3 embedded-Jetty/Stapler
  chain (filter runs before dispatch). Every request therefore evaluated
  as `/` → never allowed → including the MFA page itself.
- Fix: `targetPath()` now computes the in-site path as
  `getRequestURI()` minus `getContextPath()` (spec decomposition,
  context-aware), folding the query string as before; null/odd URI still
  degrades to `/` (fail-closed). Javadoc documents why `getServletPath()`
  is wrong on this stack so nobody "simplifies" it back.
- Verified by live per-request trace (correct `d=` per URI) + the
  `api_json` case passing + the 404 now being the *page*, not the bounce.

## Defect B — mount collision (DIAGNOSED, RULING NEEDED)

- Symptom: after A was fixed, the redirect-follow 404s.
- Evidence: decoded Stapler route page in the 404 body —
  `No matching rule was found on hudson.security.HudsonPrivateSecurityRealm
  for "/mfa"` (request evaluated as `Hudson, "/securityRealm/mfa"` →
  `Hudson.getSecurityRealm(), "/mfa"`).
- Why it's production-blocking: the IT installs an HPSR realm (needed for
  real password users); HPSR implements `ModelObject` → Stapler mounts it
  at top-level `securityRealm` → owns the prefix. The live box runs a
  local realm; its bounce 404s for every enrolled user.
- Why it was invisible before: default test realm is not a ModelObject at
  that node; no earlier test hit the page over HTTP against a local realm.
- Fix: the mount move above (pending ruling). Post-fix expectation: all 7
  green; if new failures appear, they will be in the *page* domain
  (crumb/form/JSON), not the gate.

## Test-harness bugs found & fixed in the IT (so you don't re-derive them)

1. **Context path is `/jenkins/`**, not `""` (the old seam table's `ctx is
   "" in tests` is WRONG). `JenkinsRule` boots under `/jenkins/`
   (`Running on http://localhost:<port>/jenkins/`). Every URL must be
   built relative (`href`/`hostAbs` helpers) — `new URL(base, "/job/…")`
   drops the context and 404s at the server root (this was the whole
   first run, 6×404).
2. **Login:** use the harness's `c.login(user, pw)` — the hand-rolled
   `/login` POST never established a usable Jenkins session in this
   harness version.
3. **Enrolment** (old open question 3, now resolved): install
   `HudsonPrivateSecurityRealm` (HPSR; `Details.fromPlainPassword` is
   package-private so do not use it) and create the user via the realm's
   `createAccount` (the core descriptor route — `c`-driven or
   `Jenkins.get().getSecurityRealm()` cast). The IT's `enroll` helper
   does this and it works: login succeeds, the gate sees the user.
   (Re-check the helper at `MfaFilterIT` if anything is off, but it is
   proven green through login + bounce.)
4. **MFA page form:** declared by `id="verifyForm"`, not name —
   `page.getElementById("verifyForm")`; exactly one hidden input (the
   crumb); read its name into a field for the POSTs. The POST helper uses
   crumb + `loadWebResponse` (raw, no auto-follow) for JSON envelopes.
5. **Resend JSON field:** the cooldown field on the JSON is `cooldown` —
   verified this session (handoff #2 said "verify"; now verified).
6. `WebResponse` has **no `getUrl()`** — use `getWebRequest().getUrl()`.
   `FailingHttpStatusCodeException.getResponse()` (not
   `getWebResponse()`). `Cookie.getValue()` (not `getCookieValue()`).

## Economics correction (supersedes the old "be precious" guidance)

The old handoff warned "expect 5–10 min / boot". **False for this
harness:** each `@WithJenkins` method boots a fresh Jenkins in ~1–5 s and
the whole 7-case suite runs ~16 s. Iterating on the IT directly is cheap;
run single methods with `-Dtest='MfaFilterIT#<method>'` freely. Keep the
compile oracle (`mvn -q -o test-compile`) as the first check after edits.
This host still truncates long interactive output to roughly one visible
line — keep the redirect-to-`/tmp/apidump/*.txt` habit for anything
multi-line, but you no longer need to be precious about probe costs.

## Exact plan of work at resume (in order)

1. Get mads's ruling on the mount (top of this doc). Default if silence
   is not acceptable: do NOT guess the move — hold and ask once.
2. `git diff` both modified files; tidy the `MfaFilter` catch-block indent.
3. Execute the sweep (numbered list under the ruling block) in one pass;
   update the affected BDD doc blocks in `FilterLogicTest` /
   `MfaControllerTest` to the new path (they are pins of *path
   behaviour*, keep the semantics, change the string).
4. `mvn -q -o test-compile` clean → `mvn -o -B -ntp test -Dtest=MfaFilterIT`
   → 7/7 green (fix page-domain failures against reality if any).
5. `mvn clean verify` (mirrors CI incl. SpotBugs).
6. README "Practical usage" → status 0–8 complete + the honest note:
   first real-world MFA attempt now exercises the whole wire (the IT is
   the A5 pin). TECH_DEBT: close A5 (IT landed), add A15 (Bearer gap) per
   its ruling (still open from handoff #2), add the two defect rows
   (tentative A16 = getServletPath loop; A17 = securityRealm/mfa
   collision) each with red→green evidence. Same commit.
7. Commit (suggested: `fix(gate): targetPath via URI-ctxPath (no 302
   self-loop); move MFA mount to /mfa (HPSR collision); end-to-end IT
   green (A5)`) → push `develop` → report to mads → **WAIT**.

## Carried from the previous handoffs (still true, don't re-learn)

- **Process:** `develop` only; `master` advances on mads approval; no
  force-push; `mvn clean verify` locally (SpotBugs is verify-bound);
  README practical-usage + TECH_DEBT in the same commit; report → WAIT.
- **The loop incident:** the reliable oracle is the compiler, not javap
  probes; this host truncates interactive output to ~one line; redirect
  to files; one probe per question; when in doubt **write the handoff
  early** (this is the third compaction of Task 8's life).
- **BDD standard:** every test documents WHAT / GIVEN-WHEN-THEN /
  WHY-SOLVES (AGENTS.md); `TotpTest.java` reference, `FilterLogicTest`
  closer example; record red→green history honestly.
- **Anonymous NPE trap:** `MfaFilter` null-guards `prop` before
  `TrustStore.isTrusted`; keep any guard you touch.
- **Registration milestones:** `EXTENSIONS_AUGMENTED` (not `STARTED`) +
  plain `@Extension`; changing either → boot dies.
- **The OR at step 9 is signed-by-behaviour** (`sessionVerified ||
  trustLive`); case 6 of the IT is the pin.
- **`getOrCreate` writes config.xml** — product hot path stays read-only.
- **No Bearer on 2.528.3** — A15.
- **Open ruling from handoff #2 still on the table:** plan case 1
  ("fresh session → 302" post-verify) vs the signed OR (fresh login of a
  remembered user MUST pass). The IT pins the signed behaviour; ruling
  still owed if mads wants the literal plan line post-verify.
- **Toolchain (unchanged, exact):**
  `export PATH="$HOME/opt/jdk-21.0.12+8/bin:$HOME/opt/apache-maven-3.9.11/bin:$PATH"`
  (default PATH has no `jar`/`javap`); offline `-o` works; artifacts:
  jenkins-core 2.528.3, test-harness 2545.va_5c4d760c7ef,
  test-harness-htmlunit 228.v9cb_fe1b_5b_7da_ (shaded, `hidden.jth`);
  classpath dump regenerable via
  `mvn -q -o dependency:build-classpath -Dmdep.outputFile=/tmp/apidump/cp.txt -DincludeScope=test`.
- **`~/.m2/settings.xml` may contain credentials** — treat all values
  `[REDACTED]`, never echo.
- **Key seams (current, post-session):**
  - redirect: `302 Location: <ctx>/securityRealm/mfa?redirect=<validated>`
    (becomes `<ctx>/mfa?…` after the ruling) — `Location` is context-
    relative in the test JVM.
  - gate user resolution: `User.get2(Jenkins.getAuthentication2())`
    — the per-request security context, i.e. a real `/login` form session.
  - session flag: `MfaController.VERIFIED_ATTR = "org.sebcru.mfa.verified"`.
  - success JSON `{ok:true, rememberHours, redirect}`; failure
    `{ok:false, error, retrySeconds?}`; resend `{ok, resent, cooldown}`
    (field verified `cooldown`).
  - endpoints: `POST …/postVerify` (field `code`, `redirect` param),
    `POST …/postResendEmail` (no dest field — registered-mbox-only).
  - TOTP: `Totp.newBase32Secret()`, `decodeSecret`, `codeAt(key, ms)`.
  - sender injection: extension singleton + package-private
    `setSenderForTest`, **restore a fresh `JenkinsEmailSender` in test
    teardown** (the rewritten IT does — keep it).
  - config defaults: 24/30-day windows, 5 attempts / 15-min lockout,
    300 s TTL, 60 s cooldown; policy default REQUIRED.
