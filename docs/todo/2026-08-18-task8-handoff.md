# Task 8 handoff — MfaFilterIT (end-to-end, Jenkins in-JVM)

**Written by Sebastian, 2026-08-18, after Task 7 landed as `fe17f12` on
`develop` (pushed; CI green).**
Status: Tasks 0–7 complete, tested, pushed. mads's next "proceed" is for
**Task 8** (the integration test). If you're reading this after a context
reset: the repo is clean — start from the plan, not from memory.

## The rule that governs this whole build (mads)

- Work on `develop`; `master` advances only when mads approves/merges. No
  force-push, ever.
- Each task: implement + TDD → `mvn clean verify` green (**NOT** `mvn test` —
  CI binds SpotBugs into verify) → update the README section **"Practical
  usage — what end users should expect"** in the SAME commit → push to
  `develop` → report → **WAIT** for mads's approval/merge before the next task.
- Every test documents its TDD as BDD (WHAT / GIVEN-WHEN-THEN / WHY-SOLVES) —
  house standard in root `AGENTS.md`, reference impl `TotpTest.java`.
  (Task 7's `FilterLogicTest` is a more recent example of the same shape.)
- Security decisions are mads-signed in the plan — implement as written; the
  ONE flagged exception is recorded below (Bearer, test case 3) and needs a
  ruling if the IT hits it.
- If mads asks a question ("what's next?"), ANSWER IT BEFORE doing work.

## Where we are

- Branch `develop` at `fe17f12` (`feat(gate): Task 7 — MFA gate filter + live
  registration; A1/A3/A5/A14 landed`), pushed, CI green. Repo clean.
- Plan (in-repo): [`docs/plans/2026-08-17-jenkins-mfa-plugin.md`](../plans/2026-08-17-jenkins-mfa-plugin.md)
  — **Task 8 section = lines 568–586**. Read it first thing.
- Tech-debt: [`docs/todo/TECH_DEBT.md`](TECH_DEBT.md). Task 7 closed **A1,
  A3 (plumbing), A5 (plumbing), A14** (rows in the Resolved table). **A5's IT
  half is owed to THIS task**: assert the full pre-login-URL round trip, not
  merely that a safe target comes back. A2's lazy-mint is in; its *second*
  minting path (enrolment UI) is Task 9. A7/A8 telemetry: Task 9.
- Architecture record: [`docs/architecture/README.md`](../architecture/README.md).
  §6.1 = the filter registration as it actually is (incl. the two documented
  deviations, §9.7/§9.8). §5 "Trust semantics" = the mads-signed session-flag
  vs `trustedUntilMs` disjunction the IT exercises.
- Task 7 handoff (now historical): [`docs/done/2026-08-18-task7-handoff.md`](../done/2026-08-18-task7-handoff.md).

## The seams Task 8 actually uses (verified against disk + jenkins-core 2.528.3)

The filter is **already registered live** — `InjectedTest`'s Jenkins-in-JVM
boot runs with it. So `MfaFilterIT` (a `JenkinsRule` test in the same
`src/test` tree — surefire picks it up like `InjectedTest`; there is no
failsafe plugin in this pom) hits a booted Jenkins that already has the gate.

| Seam | Exact value |
|---|---|
| Session flag the filter reads | `MfaController.VERIFIED_ATTR` = `"org.sebcru.mfa.verified"` (package-private constant — the IT is same-package, so reference it directly) |
| Filter's redirect param | `MfaFilter.REDIRECT_PARAM` = `"redirect"` (package-private, same-package IT can use it) |
| Success JSON from `postVerify` | `{ok:true, rememberHours:<long>, redirect:"<validated path>"}` — `VerifyOutcome.ok(rememberHours, redirect)` |
| Failure JSON | `{ok:false, error:"<code>"}` — codes in `VerifyOutcome`: `ERR_LOCKED`="locked" (carries `retrySeconds`), `ERR_WRONG_CODE`="wrong_code", `ERR_NO_PENDING`, `ERR_EXPIRED`, `ERR_COOLDOWN`="resend_cooldown", `ERR_NOT_ENROLLED`, `ERR_NOT_AUTHENTICATED`, `ERR_SERVER` |
| Resend JSON | `{ok:true, resent:true, cooldownSeconds:<long>}` — `VerifyOutcome.resent(cooldown)` |
| Endpoints | `POST /securityRealm/mfa/postVerify` (fields `code`, + `redirect` carried by the page JS; the IT can also pass `redirect` itself to pin A5), `POST /securityRealm/mfa/postResendEmail` |
| TOTP API | `Totp.newBase32Secret()`, `Totp.decodeSecret(String)→byte[]`, `Totp.codeAt(key, epochMillis)`, `Totp.verify(key, input, now, window)` — pure statics, no Jenkins |
| User setup | `User.get2(authentication)` + `MfaUserProperty.getOrCreate(u)` (throws IOException) + `setTotpSecret(Secret)`, `setRegisteredEmail(String)`, `setEmailCodeSecret(Secret)`; persist with `u.save()` |
| Sender injection (email_flow) | `MfaController` is an `@Extension` singleton: `MfaController.all().get(0)` (or find it from the action) then the **package-private `setSenderForTest(EmailSender)`** — Task 7 built it explicitly for this task (javadoc says "Task 8 injects a CaptureEmailSender"). There is NO `CaptureEmailSender` in the tree yet — write it (implements `EmailSender`, records to a `List`) in `src/test/java/org/sebcru/mfa/email/`. Reset the singleton to a fresh `JenkinsEmailSender` in `@AfterEach` so `InjectedTest` can't be poisoned. |
| Config for the IT | `DevcruMfaConfig.currentSafe()` returns the descriptor instance in a booted Jenkins; policy defaults to REQUIRED with the plan defaults (24/30-day windows, 5 attempts/15 min lockout, 300 s code TTL, 60 s resend cooldown). If a case needs different knobs, mutate the descriptor instance and `save()` it, then restore in `@AfterEach`. |
| Crumbs/cookies | `JenkinsRule.WebClient` handles crumbs + cookies (plan line 583). For the raw `j_acegi_securityCheck` POST use `client.getPage(...)` with the form filled, or `client.submit(...)`. |

## Task 8 target (plan lines 576–586, with the Task 7 add-ins)

**Files:**
- Create `src/test/java/org/sebcru/mfa/MfaFilterIT.java`
- Create `src/test/java/org/sebcru/mfa/email/CaptureEmailSender.java`
- README "Practical usage" + "Status" in the SAME commit (house rule) —
  bump the status line to **Tasks 0–8 complete**; "end-to-end mail round
  trips" moves out of the "still lands per the plan" sentence (the IT proves
  the round trip; the *live-box* cutover is still Task 10).

**Test cases (the plan's five, plus two Task 7 pins this task owns):**
1. **totp_flow** — create user, `MfaUserProperty` TOTP secret; password login
   via the real flow → **assert the 302 lands on
   `/securityRealm/mfa?redirect=<original target>`** (the A3 carrier is on the
   wire, not just in the unit tests); `postVerify` with
   `Totp.codeAt(key, now)` and the same `redirect` param → JSON
   `{ok, rememberHours, redirect:<original>}` — **A5's IT pin: the redirect
   is the pre-login URL, not the MFA page, not just "some safe target"**;
   next `GET` of a protected path in the same session → 200; a fresh session
   for the same user → 302 again. Also assert **session id changed** at
   verify time (anti-fixation — the flag exists on the NEW session).
2. **email_flow** — `CaptureEmailSender` in; `postResendEmail` → JSON
   `resent:true` AND the captured mail body contains the 8-char code AND the
   mail went to `getRegisteredEmail()` (registered-mailbox-only is a signed
   decision); `postVerify` with the captured code → trusted.
3. **api_token_exempt — RULING NEEDED, see the red flag below.** Plan line
   579 writes `Authorization: Bearer` against `/api/json` → 200 without MFA.
   **Verified in core 2.528.3: there is no Bearer authenticator** (mads
   checked the core auth-filter setup 2026-08-18; only `BasicHeader*`
   token-auth classes exist). The filter's exemption is **attribute-based**
   (`jenkins.security.BasicHeaderApiTokenAuthenticator.class.getName()` →
   `Boolean.TRUE`), which is what core actually sets for a *basic-auth*
   API-token request. So: pin the IT on the **Basic** header (`username:apitoken`,
   what core 2.528.3 supports — assert the attribute is present AND the
   request passes the gate un-challenged) and leave Bearer as a **named gap**
   in TECH_DEBT (new row A15, status RULING-NEEDED) for mads: either core
   gains Bearer in a future LTS and the seam follows, or Bearer simply does
   not exist on 2.528.3 and CI on this box uses Basic. The attribute check is
   already the right shape for either outcome — nothing in the filter changes
   if the ruling is "attribute is the contract."
4. **lockout** — 5 wrong TOTP codes → the 6th request returns
   `{ok:false, error:"locked", retrySeconds>0}` and the gate still 302s
   (lockout is enforced inside `postVerify`'s first check, BEFORE touching the
   code — the user cannot probe a locked account).
5. **kill-switch** — `off()` logic stays unit-pinned (Task 7 did it in
   `FilterLogicTest`); what the IT adds: flip the descriptor policy to OFF
   (`save()`), and a fully enrolled, unverified user now gets **200, not
   302**, on a protected path with no MFA page in between — the "a setting,
   not an uninstall" line, end-to-end. Restore the policy in `@AfterEach`.
6. **(Task 7 pin) error-dispatch pass** — GET a deliberately 404ing protected
   URL as an enrolled unverified user → the response is the **404**, not a
   302 to the MFA page (recursion guard, plan deviation recorded in §9).
   (If JenkinsRule makes a raw ERROR-dispatch assertion awkward, a
   `HttpServletRequest.getDispatcherType()==ERROR` stub pin in
   `FilterLogicTest`'s shape is acceptable — but the 404 case is worth one
   honest try in the IT first.)

**Run:** `mvn test -Dtest=MfaFilterIT` for iteration (5–10 min is normal —
first booted-Jenkins test after the ~7 s `InjectedTest`); **commit gate is
still `mvn clean verify`** (mirrors CI — SpotBugs + everything, ~15 min).
**Commit:** `test(it): end-to-end TOTP/email/token/lockout/kill-switch/404
flows (A5 round-trip pin)`

## Known hazards (learned the hard way in Task 7; do not re-learn)

- **Anonymous NPE trap:** `MfaFilter` null-guards `prop` before the trust
  check (`TrustStore.isTrusted` dereferences the property). If you touch the
  decision inputs, keep the guard — an anonymous request with `prop==null`
  used to NPE, and the fail-closed catch masked it as a "Too many redirects"
  loop in `InjectedTest`.
- **Do NOT add state to `MfaFilter`.** `PluginServletFilter.removeFilter`
  matches by **identity**; `DevcruMfaPlugin` keeps one instance for add AND
  remove. A second instance = a filter that is registered forever.
- **Registration milestones are load-bearing.** `EXTENSIONS_AUGMENTED` (not
  `STARTED`) + plain `@Extension` (not `hudson.Plugin` subclass), both
  documented in architecture §9.7/§9.8 with the exact failing boot error.
  Changing either is NOT a nit — the boot dies with
  `IllegalStateException: Unable to inject class`.
- **The OR at step 9 is signed-by-behaviour, not by-sentence.** Plan line
  559's `sessionVerified AND isTrusted` was implemented as
  `sessionVerified || trustLive` (justified in `MfaFilter`'s class doc +
  architecture §5). The IT's totp_flow *fresh-session* step is the test that
  would break under the literal AND — it is the pin for the judgment call.
- **`getOrCreate` writes to disk.** The filter is read-only by design (audit
  §5 Domain-1); the IT's *assertions* may call `getOrCreate`, the product
  code must not (hot path).
- **No Bearer.** If anything in the IT or a follow-up assumes
   `Authorization: Bearer` works on 2.528.3, that is the A15 gap — check
   TECH_DEBT before wiring it.

## Suggested execution order

1. `CaptureEmailSender` (trivial; compiles against `EmailSender`).
2. The IT skeleton with **case 3 (token)** first — it is the cheapest, and
   it is the one with the ruling question: write it for **Basic**, run it,
   and if green, stop and **ask mads the Bearer question** (A15) before the
   rest is written, so the doc/README wording is settled once.
3. Case 1 (totp_flow) — the longest; it carries the A5 pin.
4. Cases 2, 4, 5, 6.
5. README (status → 0–8, practical-usage sentence moved) + TECH_DEBT (A15
   row with whatever mads ruled; A5 → RESOLVED fully, not just the plumbing
   half) in the same commit.
6. `mvn clean verify` → commit → push `develop` → report → WAIT.

## Open questions for mads (answer before/during, not after)

1. **A15 (Bearer):** IT pins Basic (the only token header 2.528.3 supports);
   Bearer recorded as a gap. Confirm, or rule "no gap, attribute is the
   contract, delete the plan's Bearer line."
2. **IT naming:** plan calls the file `MfaFilterIT.java` but there is no
   failsafe plugin — it runs as a regular surefire test (like `InjectedTest`).
   Fine to keep the IT name, or rename to `MfaFilterEndpointTest`. Cosmetic —
   mads picks.
