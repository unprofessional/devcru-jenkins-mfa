# Task 7 handoff — MfaFilter (the gate) + DevcruMfaPlugin registration

**Written by Sebastian, 2026-08-18, after Task 6 landed as `f705ea3` on `develop` (CI green).**
Status: Tasks 0–6 complete, tested, pushed. mads's next "proceed" is for **Task 7**.
If you're reading this after a context reset: the repo is clean — start from the
plan, not from memory.

## The rule that governs this whole build (mads)

- Work on `develop`; `master` advances only when mads approves/merges. No force-push, ever.
- Each task: implement + TDD → `mvn clean verify` green (**NOT** `mvn test` — CI binds
  SpotBugs into verify) → update the README section **"Practical usage — what end users
  should expect"** in the SAME commit → push to `develop` → report → **WAIT** for
  mads's approval/merge before the next task.
- Every test documents its TDD as BDD (WHAT / GIVEN-WHEN-THEN / WHY-SOLVES) — house
  standard in root `AGENTS.md`, reference impl `TotpTest.java`.
- Security decisions are mads-signed in the plan — implement as written, don't re-litigate.
- If mads asks a question ("what's next?"), ANSWER IT BEFORE doing work. (Got corrected
  for this once — it mattered to him.)

## Where we are

- Branch `develop` at `825c3a3` (`feat(controller): lazy-mint per-user
  email-code HMAC key (closes A2 gap)`), CI green. Repo clean.
- Plan (in-repo): [`docs/plans/2026-08-17-jenkins-mfa-plugin.md`](../plans/2026-08-17-jenkins-mfa-plugin.md)
  — **Task 7 section ≈ lines 531–565**. Read it first thing.
- **Tech-debt / audit list: [`docs/todo/TECH_DEBT.md`](TECH_DEBT.md)** — the 2026-08-18
  top-to-bottom audit findings (A1–A14). **Rulings recorded 2026-08-18** and
  binding for this task: **A1** (`current()` authoritative for all runtime
  reads — filter AND controller; `get()` is only the null-safe fallback;
  reconcile the `DevcruMfaConfig` javadoc in the same commit), **A3**
  (`?redirect=` query parameter is canonical over `Referer`; one pure
  `resolveRedirectTarget` for both), **A5** (the Task 8 IT must assert the
  end-to-end pre-login redirect, not just a safe target). **A2 is LANDED**
  (controller lazy-mint, commit `825c3a3`); only its Task 9 half (enrolment-UI
  minting) remains — the filter does not touch it. **A7/A8 ruled**: Task 9
  consumes the telemetry and the clear-path resets the streak.
- Architecture record: [`docs/architecture/README.md`](../architecture/README.md) —
  the audit companion (abstractions, state-management domains, §3 end-to-end
  flow, §7 integration surface, §9 recorded deviations). Read §2 + §7 before
  wiring the filter.
- Tasks landed so far (all in `git log` on develop): 0 scaffold · 1 `Totp` (RFC 6238) ·
  2 `MfaUserProperty` · 3 `EmailCodeIssuer`+`EmailSender` · 4 `TrustStore`+`RateLimiter`
  · 5 `DevcruMfaConfig` (GlobalConfiguration + admin jelly) · 6 `MfaController` (login
  page at `/securityRealm/mfa`, `postVerify`, `postResendEmail`, pure seams:
  `resolveRedirectTarget`, `classifyFactor`, `maskEmail`, `ensureEmailCodeSecret`,
  `VerifyOutcome`) + `JenkinsEmailSender` (Mailer plugin) + `index.jelly` ·
  A2 lazy-mint pass (the first email use mints and persists each user's HMAC key).
  53 tests, SpotBugs clean.
- Task 6's two deviations are **settled** (recorded in commit `f705ea3` + README):
  (1) controller mounts as `hudson.model.RootAction` because `jenkins.model.GlobalAction`
  does not exist in core 2.528.3; (2) `postResendEmail` takes no `dest` parameter —
  registered mailbox only, so it can't be an open relay.

## Task 7 target (from plan)

**Files:**
- Create: `src/main/java/org/sebcru/mfa/MfaFilter.java`
- Replace: `src/main/java/org/sebcru/mfa/DevcruMfaPlugin.java` (currently a 10-line
  `@Extension` stub from Task 0)

**Decision chain (exact order, per plan lines 550–560; A1 ruling applied —
all runtime config reads go through `current()`, not `get()`):**
0. `off()` → pass (kill switch: `"1".equals(System.getenv("DEVCRU_MFA_OFF"))`
   OR `DevcruMfaConfig.current().getPolicy() == Policy.OFF`) — checked FIRST.
1. Not an `HttpServletRequest` → pass.
2. API-token request → pass (see verified detection below — plan's `JenkinsUtil`
   idiom is wrong for this core).
3. No authenticated user → pass (core login flow owns it).
4. Path allow-list (prefixes): `/login`, `/logout`, `/securityRealm`, `/static/`,
   `/images/`, `/adjuncts/` (and the usual static-resource paths) — note the
   allow-list is per the plan text at line 555; `/securityRealm` prefix already
   covers the MFA page, so don't add a redundant `/securityRealm/mfa` entry.
5. `policy == OFF` → pass (belt-and-braces with 0).
6. User exempt (`config.isUserExempt(name)`) → pass.
7. Has `MfaUserProperty` **and** `isMfaEnabled() == false` → pass (unenrolled users
   are NOT hard-locked — mads-signed security decision).
8. Session attribute `org.sebcru.mfa.verified` == `Boolean.TRUE` **and**
   `TrustStore.isTrusted(p, cfg, now)` → pass. **Document in a comment: the session
   attr alone is sufficient — a live session that logged in is trusted for its
   lifetime; `trustedUntilMs` governs *future* logins. Do NOT "fix" this into
   per-request expiry of active sessions — that was the exact UX sin of the old
   plugin (mads-signed).**
9. Otherwise: 302 to `<contextPath>/securityRealm/mfa?redirect=<target>`.

**DevcruMfaPlugin shape (plan line 562):**
`@Extension` class, `@Initializer(after = STARTED)` →
`PluginServletFilter.addFilter(new MfaFilter())`; `@Terminator` →
`PluginServletFilter.removeFilter(new MfaFilter())`.

**Commit:** `feat(filter): MFA gate with API-token + exemption + trust bypass`

## CRITICAL API findings VERIFIED against 2.528.3 this session (2026-08-18)

The plan sketch (written before this core was resolved) contains **three** wrong
idioms. Verified with `javap`/`jar tf` against
`$HOME/.m2/repository/org/jenkins-ci/main/jenkins-core/2.528.3/jenkins-core-2.528.3.jar`:

1. **No `JenkinsUtil` class exists in jenkins-core 2.528.3** (any package —
   `jar tf | grep JenkinsUtil` returns nothing). The plan's
   `JenkinsUtil.getCurrentUser()` (line 554) is unimplementable as written.
   Current-user idioms that DO exist: `hudson.model.User.current()` (returns null
   for anonymous — confirm null-vs-system semantics when writing step 3) and
   `jenkins.model.Jenkins.getAuthentication2()` (non-null Spring `Authentication`;
   `getPrincipal() == org.acegisecurity… / UserDetails.NOAUTHENTICATION`-style
   check for anonymous). Task 6 used `User.get2(Jenkins.getAuthentication2())` in
   `MfaController.currentUser()` — reuse that exact seam.
2. **API-token detection:** the class is `jenkins.security.BasicHeaderApiTokenAuthenticator`
   (NOT `hudson.security.*` — core moved these packages in this LTS line). It sets a
   **request attribute keyed by its own class name
   (`BasicHeaderApiTokenAuthenticator.class.getName()`) with a `Boolean` value** —
   verified via `javap -c` (ldc of the class object at the `setAttribute` site). So
   step 2 = `Boolean.TRUE.equals(req.getAttribute(
   jenkins.security.BasicHeaderApiTokenAuthenticator.class.getName()))`.
   (Cross-check the value type against the constant-pool when wiring; the plan's
   "is Boolean true" matches.)
3. **`hudson.util.PluginServletFilter` exists in core** with
   `addFilter(jakarta.servlet.Filter)` / `removeFilter(jakarta.servlet.Filter)`
   (both jakarta and javax overloads exist; **2.528 is jakarta-servlet** — implement
   `jakarta.servlet.Filter`, not `javax` — `javax.sse`-era imports will not
   compile).

Also verified in Task 6 (still true): `User.current()`, `User.get2(Authentication)`,
`CrumbIssuer.getCrumb(ServletRequest)`, Stapler 2 (`StaplerRequest2`/`StaplerResponse2`
/`Stapler.getCurrentRequest2()`), core `net.sf.json.JSONObject`.

## Toolchain (this host)

- JDK: `$HOME/opt/jdk-21.0.12+8/bin` · Maven: `$HOME/opt/apache-maven-3.9.11/bin`
- `export PATH="$HOME/opt/jdk-21.0.12+8/bin:$HOME/opt/apache-maven-3.9.11/bin:$PATH"`
  then `mvn -B -ntp clean verify`
- API probes: `javap -cp <jenkins-core-2.528.3.jar> <FQCN>` (Stapler classes live in
  the stapler jar, NOT core). "Does class X exist": `jar tf <core jar> | grep X`.
- CI: `.github/workflows/ci.yml` fires on every develop push; `mvn clean verify` on
  JDK 21. Watch: `curl -s https://api.github.com/repos/unprofessional/devcru-jenkins-mfa/actions/runs?per_page=5`
  until the head-sha run is `completed success`.
- GitHub: no `gh`/token on this host (can't open PRs); pushes go straight to
  `develop` per mads. Repo has its own `core.sshCommand` (git config) — **do NOT
  override with `GIT_SSH_COMMAND` env**, the default push works.

## Existing APIs Task 7 builds on (all on develop, all unit-tested; signatures verified 2026-08-18)

- `org.sebcru.mfa.MfaController` — `RootAction`, urlName `securityRealm/mfa`.
  The session attr it sets on success is
  `org.sebcru.mfa.verified` = **`Boolean.TRUE`**, and the key lives on as
  `MfaController.VERIFIED_ATTR` (package-private `static final String`) —
  **reference that constant from `MfaFilter`**, do not re-spell the literal, or
  the gate and the page silently drift. `postVerify` sets it on the
  (regenerated) session before it 302s back out. Pure seams
  (`resolveRedirectTarget`, `classifyFactor`, `maskEmail`) are package-private
  statics you may reference for the `?redirect=` contract.
- `org.sebcru.mfa.MfaUserProperty` — `User.getProperty(MfaUserProperty.class)`
  for "has property" checks (do NOT call `getOrCreate` in the filter hot path —
  it writes config.xml); `isMfaEnabled()`, `hasTotpFactor()`, `hasEmailFactor()`.
- `org.sebcru.mfa.gate.TrustStore` — instance methods: `isTrusted(p, cfg, now)`,
  `trust(p, cfg, now)`, `revoke(p)`, `effectiveTrustHours(cfg)`. (NOT static —
  Task 6 instantiated one; filter needs its own instance or a package constant.)
- `org.sebcru.mfa.gate.RateLimiter` — `isLocked/retrySeconds/recordFailure/clear/
  recentFailures` (all instance + `name, cfg, now` args).
- `org.sebcru.mfa.DevcruMfaConfig` — **A1 ruling (2026-08-18): `current()` is
  authoritative for ALL runtime reads** (filter and controller); `get()` is
  only the null-safe fallback `current()` already uses when the descriptor
  is absent (tests/pre-startup). Do NOT wire the filter on `get()` — that
  was the pre-ruling note and it would reintroduce the config-instance
  duality the ruling kills. **While wiring, reconcile the
  `DevcruMfaConfig` class javadoc in the same commit** (house rule: an
  enforcement layer landing must fix stale "single source of truth" claims
  that contradict the enforced behaviour). `Policy.OFF/REQUIRED`,
  `getPolicy()`, `isUserExempt(name)`.
- `org.sebcru.mfa.email.*` — not needed by the filter.
- `DevcruMfaPlugin.java` — 10-line `@Extension` stub; replace entirely.

## Decisions already made upstream (don't re-open without mads)

- Package `org.sebcru.mfa` STAYS — mads: "definitely staying in there as tribute".
- **No per-request expiry of active sessions** (openmfa's sin) — step 8 semantics
  above, documented in a comment.
- Kill switch: `DEVCRU_MFA_OFF=1` env OR `Policy.OFF` — checked FIRST (step 0).
- Server-managed state is never form data-bound; secrets are `hudson.util.Secret`.
- `@Symbol` dropped in Task 5 (`io.jenkins.plugins.Symbol` not on classpath).
  Do NOT add it back unasked.
- `RootAction` (not GlobalAction) + no `dest` on resend — settled in Task 6.

## Task 7 execution order (proposed; adjust on plan re-read)

1. Re-read plan Task 7 (lines ~531–565) — this note compresses, it doesn't replace.
2. Verify the two load-bearing seams with one `javap` call each: (a) the
   `BasicHeaderApiTokenAuthenticator` request-attr key/value, (b) anonymous-user
   detection idiom (`User.current()` null-semantics vs `getAuthentication2()`
   principal check). Pick one and document it in the filter class Javadoc.
3. Write `MfaFilter` (decision chain 0–9 exactly, jakarta servlet) + replace
   `DevcruMfaPlugin` with the `@Initializer`/`@Terminator` registration.
4. Tests: the decision chain is a pure function of (config policy, exempt list,
   has-property, isMfaEnabled, session-verified, trust, path, api-token flag).
   Extract it as a package-private static `decision(...)` returning an enum
   (`PASS`/`REDIRECT`) and unit-test the full table in plain JVM (BDD blocks per
   AGENTS.md); the `doFilter` glue (302 write, path/attr extraction) is covered
   by Task 8's `MfaFilterIT`. Kill-switch env seam: tested-by-construction +
   a `setForTest`/method-level seam per plan line 581 (no JVM env in unit tests).
5. `mvn -B -ntp clean verify` → all green + SpotBugs clean.
6. README practical-usage: status line → "Tasks 0–7"; end-user note: the gate is
   now actually enforced on a live install — enrolled users get bounced to the MFA
   page after password login; exempt users, API tokens, and unenrolled users are
   unaffected. Keep the honest "enrollment UI (Task 9) not landed" caveat.
7. Commit `feat(filter): MFA gate with API-token + exemption + trust bypass`;
   push develop; watch CI to green; report to mads (flag the 3 sketch-idiom
   corrections: no JenkinsUtil, `jenkins.security.*` package, jakarta-only
   filter). **STOP. Wait for approval.**

Next after Task 7 (don't start it): Task 8 `MfaFilterIT` — Jenkins-in-JVM
integration test (first real boot; 5–10 min; long timeout); it exercises the
filter glue Task 7 deliberately left to it.
