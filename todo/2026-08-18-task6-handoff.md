# Task 6 handoff — MFA login page + verify/resend endpoints

**Written by Sebastian, 2026-08-18. Status: Task 5 APPROVED & MERGED. Task 6 NOT STARTED (no files written, nothing committed).**
If you're reading this after a context reset: Tasks 0–5 are done, tested, and merged. mads's next "proceed" is for Task 6. Everything below is verified against the repo and the 2.528.3 core, not memory.

## The rule that governs this whole build (mads)

- Work on `develop`; `master` advances only when mads approves/merges. No force-push, ever.
- Each task: implement + TDD → `mvn clean verify` green (NOT `mvn test` — CI binds SpotBugs into verify) → update the README section **"Practical usage — what end users should expect"** in the SAME commit → push to `develop` → report → WAIT for mads's approval/merge before the next task.
- Every test documents its TDD as BDD (WHAT / GIVEN-WHEN-THEN / WHY-SOLVES) — house standard in root `AGENTS.md`, reference impl `TotpTest.java`.
- Security decisions are mads-signed in the plan — implement as written, don't re-litigate.
- If mads asks a question ("what's next?"), ANSWER IT BEFORE doing work. (I got corrected for this once — it mattered to him.)

## Where we are

- Branch `develop` at `7bebb6e` (`feat(config): DevcruMfaConfig global configuration + admin UI`), CI green. Repo clean.
- Plan: `/home/hunter/docs/plans/2026-08-17-jenkins-mfa-plugin.md` — **Task 6 section ≈ lines 489–527**. Read it first thing.
- Tasks landed so far (all in repo history via git log on develop): 0 scaffold · 1 `Totp` (RFC 6238) · 2 `MfaUserProperty` · 3 `EmailCodeIssuer`+`EmailSender` · 4 `TrustStore`+`RateLimiter` · 5 `DevcruMfaConfig` (GlobalConfiguration + admin jelly).

## Task 6 target (from plan)

- `src/main/java/org/sebcru/mfa/MfaController.java` + `src/main/resources/org/sebcru/mfa/MfaController/index.jelly`
- `postVerify(code)`: rate-limit check first (locked → `{ok:false,error:"locked",retrySeconds}`) → try TOTP (`config.totpWindow`) → fall back to email code verify → on success: `TrustStore.trust` + session regenerate + `setAttribute("org.sebcru.mfa.verified", true)` → `{ok:true, rememberHours}`.
- `postResendEmail()`: cooldown check → `EmailCodeIssuer.resend` via real `EmailSender` (Jenkins' mailer) → `{ok:true, cooldown}`.
- `index.jelly`: one form — 6-digit code input; "Use email code instead" link reveals masked registered email + send button with JS cooldown countdown; on success 302 to Referer **only if in-site and non-login**, else `/` (the "no dead redirect / no black page" fix). Inline CSS only.
- Plan says "Test: exercised in Task 8 integration" — BUT AGENTS.md demands BDD-documented tests for anything we test. Plan: extract the pure logic (referer validation, JSON body building, factor-attempt ordering) into small static/package-private methods and unit-test THOSE in plain JVM; leave the endpoint glue to Task 8's Jenkins harness.
- JSON via core `net.sf.json.JSONObject` + `rsp.getWriter()` — no new deps (this is why Task 6 stays dep-free; see below).

## CRITICAL API finding from pre-work (verify cost = 1 command, finding cost me an hour)

**`jenkins.model.GlobalAction` DOES NOT EXIST in this build's jenkins-core 2.528.3** (verified: sha1 `150bcc…be6d` matches the `.sha1` file — it's the genuine artifact; `javac` against `mvn -q dependency:build-classpath -Dmdep.outputFile=/tmp/cp.txt` classpath fails with "cannot find symbol"; full-classpath jar scan finds no such class). The plan sketch `MfaController implements GlobalAction` predates this core layout.

The in-core idiom for top-level actions in this core (confirmed by `IdentityRootAction` in jenkins-core being `@Extension implements hudson.model.UnprotectedRootAction`):
- **`hudson.model.RootAction`** (extends `hudson.model.Action` + `hudson.ExtensionPoint`) — mount at Jenkins root, appears in root action list (hide by returning `getIconFileName() == null`).
- `hudson.model.UnprotectedRootAction` — same but reachable WITHOUT auth (NOT what we want).

**Intended deviation for Task 6 (decide & document at commit time, flag to mads in the report):** implement `RootAction` (not the non-existent `GlobalAction`). `getUrlName()` stays `securityRealm/mfa` per plan — a `RootAction`'s urlName is the full path under Jenkins root, so the URL is exactly `…/<root>/securityRealm/mfa` as the plan wants ("stable, current-core path"). Session + security checks still apply (RootAction is NOT Unprotected). Record it in the commit message + class Javadoc like Task 5's deviations (jenkins.model.* not hudson.security.*, getCategory() shape).

Also for Task 6: the plan's `postVerify(...FilePath return)` is sketch debris — end points should return `void`/`HttpResponse`; use `void` + write JSON to the response stream (Task 5 set the precedent: plan sketch → verify against real API → document deviation).

## Toolchain (this host)

- JDK: `$HOME/opt/jdk-21.0.12+8/bin` · Maven: `$HOME/opt/apache-maven-3.9.11/bin`
- `export PATH="$HOME/opt/jdk-21.0.12+8/bin:$HOME/opt/apache-maven-3.9.11/bin:$PATH"` then `mvn -B -ntp clean verify -DskipITs`
- API probes: `javap -cp $HOME/.m2/repository/org/jenkins-ci/main/jenkins-core/2.528.3/jenkins-core-2.528.3.jar <FQCN>` (Stapler classes live in the stapler jar, NOT core — `StaplerResponse2`, `QueryParameter`, `HttpResponse` confirmed present on the maven classpath)
- `jar tf <jenkins-core jar>` for "does X exist"; full classpath via `mvn -q dependency:build-classpath -Dmdep.outputFile=/tmp/cp.txt` (worked when NOT offline; `-o` prefix-resolution failed)
- CI: `.github/workflows/ci.yml` fires on every develop push; `mvn clean verify` on JDK 21. Watch: `curl -s https://api.github.com/repos/unprofessional/devcru-jenkins-mfa/actions/runs?per_page=5` until the head-sha run is `completed success`.
- GitHub: no `gh`/token on this host (can't open PRs); pushes go straight to `develop` per mads.

## Existing APIs Task 6 builds on (all on develop, all unit-tested)

- `org.sebcru.mfa.crypto.Totp` — `verify(secret, code, window, now)` / `generateSecret()` (constant-time compare; window = ± steps)
- `org.sebcru.mfa.MfaUserProperty` — `getOrCreate(User)`, `getTotpSecret()`, `getRegisteredEmail()`, `getPendingCodeHash()`, `getCodeIssuedAt()`, `isMfaEnabled()` (enabled = has TOTP secret OR registered email)
- `org.sebcru.mfa.email.EmailCodeIssuer` — `issue(user, userSecret, now, ttl, sender)` → code sent; `verify(user, userSecret, submitted, now, ttl)` → `CONSUMED|NO_PENDING|WRONG_CODE|EXPIRED`; `resend(user, userSecret, now, cooldown, ttl, sender)` → cooldown string or null
- `org.sebcru.mfa.email.EmailSender` — interface; Task 6 supplies the Jenkins-mail implementation (Jenkins SMTP config)
- `org.sebcru.mfa.gate.TrustStore` — `trust(user, cfg, now)` grants `max(rememberForHours, trustMinHours)`; `effectiveTrustHours(cfg)` is THE number for the "remembered for N hours" response (don't re-derive)
- `org.sebcru.mfa.gate.RateLimiter` — `isLocked(name, cfg, now)`, `retrySeconds(name, cfg, now)`, `recordFailure(name, cfg, now)` (trips at 5th failure, lockout 15 min, no-extend), `reset(name)` — clear on success
- `org.sebcru.mfa.DevcruMfaConfig` — `current()` = persisted instance (null-safe; never returns null), `Policy.OFF/REQUIRED`, `getTotpWindow()`, `getEmailCodeTtlSeconds()`, `getEmailResendCooldownSeconds()`, `isUserExempt(name)` (Task 7 filters it, NOT Task 6), `exemptUserList()`

## Decisions already made upstream (don't re-open without mads)

- Package `org.sebcru.mfa` STAYS — mads: "definitely staying in there as tribute" (2026-08-18).
- No per-request expiry of active sessions (openmfa's sin); the filter (Task 7) reads only session attribute `org.sebcru.mfa.verified`.
- Server-managed state is never form data-bound into Jenkins objects; secrets are `hudson.util.Secret`.
- `@Symbol` was dropped in Task 5: `io.jenkins.plugins.Symbol` (plugin-util-api) is not on the classpath; descriptor discovery by class name suffices. Do NOT add it back unasked.
- Kill switch: `DEVCRU_MFA_OFF=1` env OR `Policy.OFF` — Task 7 checks it FIRST.

## Task 6 execution order (proposed; adjust on plan re-read)

1. Re-read plan Task 6 (lines ~489–527) — this note compresses, it doesn't replace.
2. Implement `RootAction` decision above; write `MfaController` with endpoint methods; extract pure logic into a testable seam (e.g. `static String redirectTarget(StaplerRequest2 req)` validation + a small `VerifyOutcome` record/JSON builder).
3. Plain-JVM unit tests for the pure seam (BDD blocks per AGENTS.md; honest red→green notes only).
4. `index.jelly` (well-formed XML — validate by parsing, as Task 5 did) + `config.properties`-style strings if copy lives there.
5. `mvn -B -ntp clean verify -DskipITs` → expect all-green + SpotBugs clean.
6. README practical-usage: status line → "Tasks 0–6", add what the end user experiences of the login page (code → success → back to where you were; email-code path; the honest "not yet: nothing is enforced yet — the gate filter is Task 7").
7. Commit `feat(ui): MFA login page + verify/resend endpoints`; push develop; watch CI to green; report to mads with the RootAction deviation flagged. STOP. Wait for approval.

Next after Task 6 (don't start it): Task 7 `MfaFilter` + `DevcruMfaPlugin` (replace the stub) — the actual gate.
