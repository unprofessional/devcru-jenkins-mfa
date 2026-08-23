# A22-b admin factor-management — implementation handoff (v2, 2026-08-23, pre-session-reset)

Written by Sebastian for Sebastian (next session). Everything below is the
**current on-disk state** at session end, verified by reads/greps this
session. Do not reset/overwrite the working tree — all A22-b work is
**uncommitted** on branch `a22b-spec` (last commit `01bd8e6`).

**Repo:** `/home/hunter/dev/devcru-jenkins-mfa`
**Binding spec:** `docs/todo/2026-08-23-A22b-admin-factor-management-spec.md`
**House rules:** `AGENTS.md` (BDD doc on every test, README practical-usage
updated in the same commit, local validation = `mvn clean verify` mirrors CI
incl. SpotBugs, no PR without mads, commit via `git commit -F <file>` then
read back, push `a22b-spec`).

Maven: `export PATH="$HOME/.local/bin:$PATH"`, always `-o` (offline).
JDK for javap: `export PATH="$HOME/opt/jdk-21.0.12+8/bin:$PATH"`.

---

## 0. Headline — two open defects, both diagnosed with hard evidence

`MfaAdminIT` is **5 legs, 3 red / 2 green**. The 2 green: carve-out 302
gate-bounce leg + self-strike pin (verified passing in run 3). The 3 red are
**both consequences of TWO root causes**, fully diagnosed, no guessing left:

### Defect 1 — admin page render 404s (`forward` has no rule to land on)

`MfaAdminController.doIndex` (admin path) does
`rsp.forward(this, "index.jelly", req)`. Stapler 2030's 404 dump (run 3,
surefire report, non-admin leg) lists **every** URL mapping on the action:
`doIndex` for `/index/...` and `/`, `postClearFactors` for `/clearFactors/...`,
`postRevokeTrust` for `/revokeTrust/...`, **`VIEW.groovy for url=/VIEW`**,
**`VIEW.jelly for url=/VIEW`**, plus BLOCKED getters. **There is NO
`index.jelly` mapping.** Forwarding to token `"index.jelly"` → "No matching
rule was found for /index.jelly" → 404. `sendRedirect2("index.jelly")`
(run 2's attempt) 302s to a URL token that likewise 404s.

**Why the sibling works:** `MfaController` has **no `doIndex`** at all —
Stapler auto-renders the class-dir view `org/sebcru/mfa/MfaController/index.jelly`
on the empty token. A `doIndex` *exists* on `MfaAdminController` precisely
because the page GET needs a permission gate, and its existence is what
disables the auto-view.

**Ranked fixes (next session picks after the one-line probe below):**
- **A (recommended, zero new machinery):** delete `doIndex` entirely; keep
  the permission gate where the spec puts the *real* enforcement (the verbs,
  already done) + add the page-level gate **in the jelly**: new controller
  model getter (e.g. `adminPageAllowed()` → the existing
  `adminManageAllowed(...)` seam with session/trust state), jelly top:
  `<j:if test="${!it.adminPageAllowed()}"><st:statusCode value="403"/>` + a
  minimal 403 body, `<j:else>` roster. `StatusCodeTag` is CONFIRMED present
  in stapler-jelly 2030 (`org/kohsuke/stapler/jelly/StatusCodeTag.class` in
  the jar). Non-admin GET → 403 ✓; unauth-enrolled GET → gate 302 first
  (unchanged) ✓; unauth-unenrolled GET → 403 via jelly ✓. IT body
  assertions on the page-403 need loosening from JSON-envelope to
  "403 + admin_permission_required OR core 403" — check spec case text for
  the exact pin; the verb 403s keep the JSON envelope (spec-pinned).
- **B:** keep `doIndex`; render the view server-side via the Jelly builder
  (need to verify the exact class in stapler-jelly 2030 — javap the jar;
  candidates `JellyBuilderT`, `CustomJellyContextTearOff`). More moving
  parts, keeps the 403 JSON shape on GET.
- **C (403 half only):** throw
  `org.springframework.security.access.AccessDeniedException` from
  `doIndex` for denials — Spring `ExceptionTranslationFilter` is CONFIRMED
  live in this stack (run-1 stack traces show it firing), core's
  `l:requiresPermission` idiom. But the admin-render path still needs a
  working view mechanism → must pair with A or B. Note `hudson.util.AccessDenied`
  does NOT exist in core 2.528.3 (javap found nothing) — do not import it.

**One-line probe to settle A vs recursion fear:** `forward(this, "", req)`
is NOT safe — the mapping list shows the empty token maps to `doIndex`
itself → infinite forward loop. Do not try it.

### Defect 2 — `User.hasPermission(ADMINISTER)` is NOT denied by the
custom SidACL (the non-admin leg tested a false world)

Run 3: the "lowly" user (logged in via HPSR local realm, authorized by
`LeastPrivilegeAdministerStrategy("admin-user")`) GET `/mfaAdmin` and the
404 trace shows dispatch went **`doIndex` → `forward`** — i.e.
`hasAdminister(actor)` returned **TRUE** for lowly. The seam is
`User.hasPermission(Jenkins.ADMINISTER)`
(`MfaAdminController.hasAdminister` is a one-liner over it).

Evidence: run-3 surefire report, `nonAdminIsDeniedTheAdminSurfaceAtTheWire`
failure — the 404 dispatch chain (quoted in full in §4). Under FCOL or a
matrix strategy this path is uncontested; under a hand-rolled
`AuthorizationStrategy` returning a `SidACL` from `getRootACL()`, the grant
is evidently bypassed.

**Diag… steps (cheap, in order):**
1. `javap -c -p hudson.model.User | sed -n '/getACL/,/areturn/p'` (and
   `getACL2`) on the core jar — which ACL object does a User consult?
   (If it's the enclosing `hudson.model.UserGroup`'s ACL, check whether
   that delegates to `Jenkins.get().getACL()` → `getRootACL()` — if not,
   my strategy's ACL is simply out of the path for User-level checks, and
   the strategy must be wired differently — e.g. also set
   `rule.jenkins.setSecurityRealm`/UserGroup ACLs, or use
   `ACL.SYSTEM2`-free plumbing.)
2. If the ACL path looks right, add a 5-line probe in the IT: after
   login, `System.err.println(User.get("lowly").get().hasPermission(Jenkins.ADMINISTER))`
   and the same under `ACL.SYSTEM2.hasPermission` — plus print
   `((Object)acl)` from `rule.jenkins.getACL()`.
   **Verify what `PrincipalSid.getPrincipal()` actually returns at
   runtime.** The FQCN `hudson.security.PrincipalSid` is verified
   (javap succeeded this session: `getPrincipal() :java.lang.Object`),
   BUT the return *semantics* are the open question: the Jenkins
   `Principal` javadoc says "Returns the principal, e.g. a UserDetails
   object". If it returns the `UserDetails` object rather than the
   username string, my grant table's `adminUser.equals(u)` can never
   match — which by itself would still deny lowly (fail-closed), so it
   does NOT explain Defect 2 alone. Combine this check with step 1's
   ACL-path check: the likely combined story is that the ACL being
   consulted is NOT my SidACL at all (something upstream granted
   ADMINISTER).

**Security-honesty note for the commit/report:** until Defect 2 is
understood, the non-admin leg proves *page 404s*, not *permission 403*.
The production seam (`hasAdminister` over `User.hasPermission`) is the
**correct** API for core strategy worlds (FCOL/matrix on the live box) —
the suspect wiring is in the TEST strategy, but prove it, don't assume.

---

## 1. What is DONE and green (verified this session)

**Main source (compiles: `mvn -o compile` EXIT=0):**
- `MfaFilter.java` — `/mfa` allow-list entry made **segment-precise**
  (bare page / `?query` / `/mfa/<endpoint>`), so `/mfaAdmin*` is NOT swept
  through the gate allow-list. The carve-out is ruling 1 + spec case 7
  ("the allow-list does not pass it" → 302). Filter decision applies to
  **every HTTP method** (verified by read, lines ~236-244): POSTs get the
  same 302. The spec's §4/§6 "zero filter changes" is a contradiction on a
  false premise (`startsWith("/mfa")` DOES match `"/mfaAdmin"`) — carve-out
  implemented as the signed intent says; documented in TECH_DEBT + spec-
  tension note.
- `MfaController.java` — `mfaadmin` added to the `isSecurityPath` degrade
  set (spec §6.3: post-verify redirect targets degrade to root).
- `VerifyOutcome.java` — new `ERR_ADMIN_PERMISSION =
  "admin_permission_required"` (distinct from the credential-axis
  `admin_verification_required`).
- `MfaAdminController.java`:
  - `doIndex(StaplerRequest, StaplerResponse)` (LEGACY javax stapler —
    distinct from the verbs' `StaplerRequest2/Response2`; the two are NOT
    in a subtype relationship in this stack, verified) — permission
    check → 403 JSON envelope `admin_permission_required`; admin path →
    **`rsp.forward(this, "index.jelly", req)`** ← DEFECT 1 (and the
    signature now declares `throws IOException,
    javax.servlet.ServletException` ← run-2 compile error fixed).
  - `postClearFactors` / `postRevokeTrust` — permission axis **FIRST**
    (`hasAdminister`), then the credential seam (`adminManageAllowed`),
    then confirm-match, then self-strike check. Denial order pins:
    non-admin+unenrolled → 403 `admin_permission_required`;
    admin+unenrolled → 403 `admin_verification_required` (Ruling-3 edge);
    self-target → **200** `admin_self_management_forbidden` (per-request
    denials ride 200 envelopes; auth denials ride 403 —
    `writeEnvelope` semantics verified by read).
  - `adminManageAllowed(administer, enrolled, sessionVerified, trustLive)`
    — 4-arg seam (permission axis added; was 3-arg pre-A22b).
  - `clearFactorState(UserProperty p)` — extracted single writer of fully-
    unenrolled state: TOTP secret, email code secret + registered email,
    trustedUntilMs, pending code hash, codeIssuedAt, lastResendAt, failed
    attempt streak. **Both** pending/secret fields take `hudson.util.Secret`
    (setters are `Secret`, getters return `Secret`) — got this wrong once
    in a unit-test fixture.
  - Audit logging: one loud line per mutation (actor → target, no
    secrets); SEVERE on persistence failure.
- `MfaAdminController/index.jelly` — **fixed real WIP bug**: line 180
  used undeclared XML entity `&rsquo;` → **the whole page 500'd on every
  render** (run-1 failures 1/2/3 root cause). Now a plain `'`. The
  handoff-v1's "jelly verified" verdict was WRONG; this is why the red→
  green story belongs in the commit (AGENTS.md: honest history).
- `DevcruMfaConfig/config.jelly` + `config.properties` — spec §6.4
  discoverability: a link entry "Factor recovery (locked-out users)" →
  `../mfaAdmin/`, with hint text. NOTE the file is
  `escape-by-default='true'` — the `<a href>` is a static anchor, safe.
  (An `st:out` attempt was tried and rejected: no `st` namespace there —
  do not re-introduce.)

**Tests — green, with counts (surefire-verified this session):**
- `FilterLogicTest` — **15/15** incl. the new both-direction carve-out pin
  (`/mfaAdmin*` all shapes → REDIRECT incl. query string and sub-paths;
  `/mfa`, `/mfa?redirect=…`, `/mfa/postVerify`, `/mfa/postResendEmail` →
  PASS).
- `AdminManageAllowedTest` (new file, plain-JVM, no Jenkins boot) —
  **6/6**: seam quadrilateral incl. both permission×credential axes,
  `clearFactorState` byte-for-byte pin, `AdminRow` masking + column
  contract (`maskEmail` — `mads@devcru.org` → `m***@devcru.org`, no
  registered mailbox → empty string + `hasEmail()` false, verified
  against the impl), unenrolled predicate. Fixture lesson recorded:
  `new MfaUserProperty()` is NOT bare — do not assume.

**Docs (done, same-commit set):**
- `docs/todo/TECH_DEBT.md` — A22 entry "Landed 2026-08-23" note (lists
  every landed piece + the spec §6 contradiction + the `mfaadmin`
  lowercase segment name); A22 moved to the Resolved table; new
  "Not in the code yet": **A24 — force-enrol view** (Ruling 4
  companion).
- `README.md` — "Known gap" paragraph → "Admin recovery path (A22-b,
  landed 2026-08-23)" behavioural paragraph; Practical-usage quote block
  updated ("not built" → "landed 2026-08-23"); recovery-path bullet now
  points at `/mfaAdmin` + the new paragraph.
- **Still pending (AGENTS.md gate):** final BDD pass on the IT legs
  (several already have full GIVEN/WHEN/THEN blocks written this session —
  verify all 5 against the TotpTest standard), and the red→green history
  note (jelly `&rsquo;` 500 + A19 redirect-following helper bug + the
  forward saga) — class-level on the IT file.

---

## 2. `MfaAdminIT` — current shape (5 legs) and status at session end

File: `src/test/java/org/sebcru/mfa/MfaAdminIT.java`. Run-3 state
(`/tmp/a22b-it-run3.log` + its surefire report, read together — see §4
stale-data warning): **Tests run: 5, Failures: 3, Errors: 0.** The three
failing legs, verbatim from the report:
`verifiedAdminClearsLockedOutVictimAndOwnFactorsSurvive` (page render →
404 = Defect 1), `unenrolledAdminCanReadRosterButNotMutate` (same =
Defect 1), `nonAdminIsDeniedTheAdminSurfaceAtTheWire` (404 not 403 =
Defects 1+2 compounded). By exclusion the two green legs are: the
carve-out 302 leg and the self-strike pin — both failed in run 1, both
passing in run 3, i.e. the jelly-500 + redirect-following fixes are
confirmed live.

Legs (names):
1. `enrolledPasswordOnlySessionIsBouncedByTheGateOffTheAdminSurface` —
   carve-out: enrolled password-only admin, POST clearFactors with valid
   crumb → **302** off the admin surface (rawPostAdmin, redirect-disabled),
   victim property unchanged. **GREEN run 3.**
2. `unenrolledAdminCanReadRosterButNotMutate` — Ruling-3 edge: unenrolled
   FCOL admin reads roster (200 + row), POST → **403**
   `admin_verification_required` JSON. RED only via Defect 1 (page 404).
3. (self-strike pin — verified-admin clears own id → **200**
   `admin_self_management_forbidden`; victim factors intact.) GREEN run 3.
4. `nonAdminIsDeniedTheAdminSurfaceAtTheWire` — least-privilege strategy
   ("lowly": READ only; "admin-user": ADMINISTER; anon nothing). Expect:
   non-admin GET → **403** `admin_permission_required`; non-admin POST →
   403 same error; elevated "admin-user" (unenrolled) → the credential-axis
   403 instead (proves PERMISSION IS CHECKED FIRST — the seam order pin).
   RED via Defects 1+2 (page 404; and the seam let "lowly" through).
5. `verifiedAdminClearsLockedOutVictimAndOwnFactorsSurvive` — full admin
   journey: verify TOTP → page 200 → clear locked-out victim → victim
   fully unenrolled (property byte-for-byte) → admin's own factors intact
   (the "no self-strike by accident" property). RED only via Defect 1.

**Helpers (all verified by read this session):**
- `rawGet(c, rule, token)` — GET with redirect disabled/restored.
- `rawPostAdmin(c, rule, endpoint, userId)` — POST clearFactors/revokeTrust
  shape (crumb + userId + confirmUserId), **redirect disabled + restored**
  (A19 lesson baked in — run 1's 200-instead-of-302 was this bug), returns
  `WebResponse` or the FailingHttpStatusCodeException's response.
- `postAdmin(...)` — expects-200 variant for the admin journey.
- `pageHtml(...)` — follows the chain and asserts 200 at the end (the
  "chain: … final 404" assertion site).
- `LeastPrivilegeAdministerStrategy` (nested, static final) —
  **`extends AuthorizationStrategy`** (in THIS core it is an abstract
  CLASS, not an interface — javap-verified; `implements` + `extends
  SidACL` does not compile), implements `getRootACL()` returning a fresh
  anonymous `SidACL` + `getGroups()` empty; holds a **programmatic
  Descriptor** (no `@Extension` — deliberately: test-scope annotation
  scanner risk, and nothing in the leg renders the descriptor).
  ACL grant table: `ADMINISTER` → only the named adminUser; `READ` (global)
  → every non-anonymous authenticated principal (baseline so the harness
  `login()` can complete — run 1 showed post-login `/` 403 kills the login
  helper itself); everything else → `null` → SidACL **fails closed**
  (bytecode-verified: unmatched Sid → `Boolean.FALSE`).
  **BUT see Defect 2 — its grants are evidently not the ACL the seam
  consults for `User` checks.**
- `ensureRealm(rule)` returns the `HudsonPrivateSecurityRealm` (users
  created programmatically with `HudsonPrivateSecurityRealm.OneTimeUsage`?
  — check the helper: passwords are `pw-<name>` style; realm is configured
  allow-signup-off, no captcha).

**Compile gate:** `mvn -o -q -ntp test-compile` EXIT=0 at the fix point;
run 3 proved main+test compile clean after the `throws` addition.

---

## 3. Verified API facts (do not re-discover; all javap/jar-verified
this session against the resolved classpath)

- **Stapler version actually on the build: 2030.v88a_855365981**
  (`dependency:build-classpath` → `/tmp/a22b-cp.txt`). A 2061 jar also
  exists in `.m2` but is NOT resolved. `StaplerResponse.forward(Object,
  String, StaplerRequest)` throws `javax.servlet.ServletException` +
  `IOException` (legacy world, despite the plugin's `jakarta` filter API —
  the two coexist; the verbs use `StaplerRequest2/Response2`, `doIndex`
  uses the legacy pair; they are NOT subtype-related here).
- Core jar: `~/.m2/repository/org/jenkins-ci/main/jenkins-core/2.528.3/
  jenkins-core-2.528.3.jar`. `hudson.security.AuthorizationStrategy` =
  **abstract class** (ctor `AuthorizationStrategy()`, methods `getACL`
  non-abstract, `getRootACL()` abstract, `getGroups()` abstract — confirm
  exact set if you touch the strategy). `hudson.security.SidACL` provides
  `hasPermission2`/`_hasPermission` (fail-CLOSED on `null` return —
  bytecode-verified). `hudson.security.PrincipalSid` present in core
  (FQCN re-verify per Defect 2 step 3). **`hudson.security.
  MatrixAuthorizationStrategy` is ABSENT** from this core (moved out;
  only FCOL/Legacy remain) — that is why the SidACL hand-roll exists.
  `hudson.util.AccessDenied` ABSENT. `Describable.getDescriptor()` is a
  default method.
- `stapler-jelly` (both versions) contain
  `org/kohsuke/stapler/jelly/StatusCodeTag` → `<st:statusCode>` is usable.
- Spring `ExceptionTranslationFilter` (spring-security-web 6.5.3) is on
  the classpath AND live in the request chain (run-1 stack traces).
- `User.hasPermission2` bytecode →
  `ACL.hasPermission2(Authentication, Permission)` via `getACL()` — see
  Defect 2 diag step 1 for the `getACL()` question.
- `MfaUserProperty` setters that take `hudson.util.Secret`, not String:
  `setTotpSecret`, `setEmailCodeSecret`, `setPendingCodeHash`. Getters
  return `Secret`. `maskEmail` shape verified. `hasEmailFactor()` /
  `hasTotpFactor()` / `isMfaEnabled()` / pending-state predicate are the
  factor seam's inputs (see `MfaUserProperty.java` ~line 100ff).
- `DevcruMfaConfig` default policy = `REQUIRED` (gate is active in all ITs
  by default; no explicit config in the ITs beyond the realm).

---

## 4. Run history (evidence trail, exact artifacts)

- `/tmp/a22b-it-run1.log` + surefire — 5 legs: **3 failures, 1 error**.
  Findings: (a) jelly `&rsquo;` → page 500 on every render (fixed — see
  §1); (b) `rawPostAdmin` followed the gate 302 → saw the MFA page 200
  (fixed, A19-idiom); (c) login 403 at `/` for a fully-fail-closed
  user (fixed: READ baseline grant — fixture shape, correct call).
- `/tmp/a22b-it-run2.log` — **compile failure** (not a test run):
  `MfaAdminController.java:[96,16] unreported exception
  javax.servlet.ServletException` from `doIndex` calling `forward`
  (fixed: `throws` added).
- `/tmp/a22b-it-run3.log` + surefire — 5 legs: **3 failures, 0 errors**.
  All 3 = the admin pages 404 (Defect 1; the non-admin one additionally
  proves Defect 2 — `doIndex` reached `forward` for "lowly", i.e. the
  permission check passed). The full non-admin 404 dispatch trace (with
  the URL-mapping list) is in the run-3 surefire report
  `target/surefire-reports/org.sebcru.mfa.MfaAdminIT.txt` — it is the
  primary evidence for Defect 1's fix choice.
- Earlier compiles: `/tmp/a22b-main-compile2.log` (`mvn -o -q -ntp compile`
  EXIT=0), `/tmp/a22b-compile3.log` (test-compile EXIT=0).
- **Stale-data warning:** surefire `.txt`/`.xml` under `target/` are
  per-run; a `mvn` failure at the compile phase does NOT refresh them.
  This session once read a stale report and nearly wrote it into the
  handoff — **always pair a surefire read with the matching run log's
  timestamp/`Tests run:` line.**

---

## 5. Exact next steps (in order)

1. `git status --short` — confirm the on-disk set (§1 files + the test
   files + docs) is the working tree's full delta; if anything unexpected,
   STOP and report to mads. (A "sibling subagent modified" warning fired
   during this session on `MfaAdminController.java` — likely a stale-
   write notice from my own backgrounded maven/patch interplay, but verify
   the file's tail matches §1's description before editing further.)
2. **Defect 2 diag first** (it decides the whole non-admin leg): run
   diag steps 1-3 from §0-Defect-2. Cheap: javap + one probe println (or
   a scratch `@Test` — delete after; do not leak debug state into the
   committed file).
3. Pick Defect-1 fix (A recommended) and implement. If A: remove
   `doIndex` (revert the `throws` line too), add the model getter +
   jelly gate, and adjust the page-403 assertions (IT legs 2/4: status 403
   + body token per spec case text; the 403-body shape for GET is a
   **test-authoring** choice, not spec-pinned — the spec pins the 403
   status and the verb JSON envelopes).
4. Re-run `MfaAdminIT` (single: `mvn -o -ntp test -Dtest=MfaAdminIT
   -DfailIfNoTests=false`), read the FRESH surefire + log together (§4
   warning). Target: 5/5.
5. Re-run the unit suites once more (`AdminManageAllowedTest,
   FilterLogicTest`) — cheap, catches doc-pass regressions.
6. **AGENTS.md gates before committing:** (a) BDD pass on all 5 IT legs
   against the TotpTest standard (WHAT / GIVEN-WHEN-THEN in `<pre>` /
   WHY-SOLVES; class-level red→green history note: jelly-500, A19
   helper, forward saga, Defect 2 finding); (b) README practical-usage
   re-read (done in §1 — re-verify after any behaviour change from step 3,
   e.g. if the page-403 body shape is user-visible); (c) `mvn -o -B
   clean verify` — mirrors CI, SpotBugs + enforcer + unit + IT + `.hpi`
   (SpotBugs has NOT run on A22-b code yet — expect possible nits on the
   new code; the `LeastPrivilegeAdministerStrategy` descriptor and the
   audit-log lines are the likely candidates).
7. Commit: `git commit -F <msgfile>` (write the message to a file first;
   include the red→green story + the spec-contradiction note + the
   Defect-2 finding if it changes the seam — it must not change the
   production seam without mads's sign-off: report and ask). Read the
   commit back (`git log -1`), push `git push origin a22b-spec`. **No PR.**
   Report to mads with: green tally, the two defects + fixes, the spec
   §6 contradiction (ruling), and the A24 deferral.

---

## 6. Standing instructions (unchanged, from mads)

- Branch `a22b-spec`; last commit `01bd8e6`; everything current is WIP.
- mads-approved-per-step on merges; **no PR** without explicit ask.
- Spec is the binding document; where spec and ruling 1 conflict on the
  gate (they do), the SIGNED ruling (carve-out, case 7: "the allow-list
  does not pass it") wins — documented as a spec-contradiction note, not
  silently resolved.
- Credentials never in commits/logs/doc; any seen are `[REDACTED]`
  (test-only local-realm passwords in `MfaAdminIT` are throwaway fixtures
  and acceptable, they are not real secrets).
- This handoff supersedes v1 (`docs/todo/2026-08-23-A22b-
  implementation-handoff.md` v1 content) where they conflict.
