# A22-b Implementation Handoff — admin factor management (session reset, 2026-08-23)

> **Audience:** me (Sebastian), resuming after a hard session reset. Everything in
> this file is disk-verified or explicitly flagged UNVERIFIED. The code on disk is
> **mid-implementation**: the guard chain is written but the tree does NOT compile
> (one known defect, §5) and nothing has been re-run green since the guard landed.
>
> **Spec (binding):** [`2026-08-23-A22b-admin-factor-management-spec.md`](2026-08-23-A22b-admin-factor-management-spec.md) — §9 carries all five rulings.
> **Repo rules (binding):** `AGENTS.md` at repo root — BDD-documented tests, `mvn clean verify` locally (NOT `mvn test`), README "Practical usage" updated in the landing commit, `develop` is the work branch, no force-push.

## 1. Branch & git state (snapshot at reset)

- Branch: **`a22b-spec`** (off `develop` @ `e671384`).
- `develop == origin/develop @ e671384` (verified current at task start).
- Commits on `a22b-spec`:
  - `9b2708f` — `docs: A22-b spec …` — **pushed** (was the push point when this branch was shared).
  - `da5ae2b` — `docs: A22-b rulings received from mads 2026-08-23 (shape A, two verbs for now, unenrolled-admin denied, enrolled-only roster provisional, typed-id confirmation)` — **UNVERIFIED: likely still local-only.** Check `git log --oneline origin/a22b-spec..a22b-spec` before pushing.
- `git status --short` at reset:
  ```
  M  src/main/java/org/sebcru/mfa/VerifyOutcome.java      (3 new ERR_ constants, committed-elsewhere? NO — working tree)
  ?? src/main/java/org/sebcru/mfa/MfaAdminController.java  (NEW, 439 lines)
  ?? src/main/resources/org/sebcru/mfa/MfaAdminController/ (index.jelly, 241 lines)
  ?? src/main/webapp/mfa-admin.js                          (165 lines)
  ?? src/test/java/org/sebcru/mfa/MfaAdminIT.java          (322 lines)
  ```
  i.e. **nothing of the implementation is committed.**

## 2. The five rulings (mads, 2026-08-23 — recorded in spec §9)

1. **Shape (A): new page.** `MfaAdminController` (`RootAction`) at `<root>/mfaAdmin`. NOT a parametrisation of the six self-service `/mfa` endpoints.
2. **Verbs for now: exactly two** — `clearFactors` (clear ALL factors on a named user = the README's documented lockout recovery) and `revokeTrust` (force the named user to re-verify: trust → 0, factors stay). The follow-up "force-enrol" third verb is **tracked as A24**, deliberately not built.
3. **Unenrolled-admin edge: DENY on destructive ops.** Verbatim ruling: an admin who is an ADMINISTER holder but has NOT enrolled MFA "sees the page, sees the roster, but cannot clear/revoke — must be a verified+enrolled admin" (an unenrolled user by definition holds no second factor; "you must be able to hold a credential to clear credentials").
4. **Roster scope: enrolled-only, "FOR NOW."** The A24 force-enrolment view reuses the same row list (that's the "third verb" mads foreshadowed in question 2).
5. **Destructive ops: 100% typed user-id confirmation** — client dialog that demands typing the user id verbatim AND server-side `confirmUserId == userId` re-check. Client = UX; server = the control.

**Plus the session-reset correction (verbatim, binding for the red proof):**
> "a hole that "mutates no state" can't be proven exploitable. In the naive iteration, a complete mutation has to be executed: that's precisely the point of case 3 (it works, and for anyone)."

## 3. What is on disk now (the implementation)

### `MfaAdminController.java` (NEW)
- `@Extension`, `RootAction`, `getUrlName()="mfaAdmin"`, `getIconFileName()=null`, `getDisplayName()="MFA administration"`.
- `doIndex` → `rsp.sendRedirect2("index.jelly")`.
- **Both verbs** — `@RequirePOST @WebMethod(name="clearFactors"|"revokeTrust")`, void `(StaplerRequest2, StaplerResponse2)`, house JSON-writer style (manual `PrintWriter`, `no-store` + `nosniff`). Chain order (load-bearing, every check before any mutation):
  1. `answerAdminDeniedIfUnverified` → **403** `{ok:false, error:"admin_verification_required"}` (the A23 403 shape — a 200-from-a-denied-request is the bug that pins the class).
  2. `denyOrConfirmError` → 200 envelopes: blank target → `admin_confirm_required`; **self-management FIRST** → `admin_self_management_forbidden`; confirm≠target → `admin_confirm_required`.
  3. target enrolled check → 200 `{ok:false, error:"not_enrolled"}` (**idempotent, not an error** — spec §8).
  4. mutate + `target.save()`; save-throw → 200 `{ok:false, error:"persistence_error"}` (honest persistence, never `ok:true`).
  - `clearFactors` mutation: `setTotpSecret(null); setEmailCodeSecret(null); setRegisteredEmail(null); setTrustedUntilMs(0)`.
  - `revokeTrust` mutation: `setTrustedUntilMs(0)` only.
- **The pure seam (unit-pinnable, A23-shape):**
  ```java
  static boolean adminManageAllowed(boolean enrolled, boolean sessionVerified, boolean trustLive) {
    if (!enrolled) return false;   // ruling 3
    return sessionVerified || trustLive;
  }
  ```
  The 403 glue reads the SAME instruments the gate reads: `VERIFIED_ATTR` (set only by a successful `postVerify`) + ONE `TrustStore.isTrusted(prop, cfg, now)` (written only by a successful verify). `TrustStore` is **instance-based** — the controller holds `new TrustStore()` (its own 1-second-granularity clock instance; same arithmetic as the filter's).
- **`AdminRow`** bean: `userId, displayName, maskedMail, isTotp(), isEmail(), isTrustLive()`. `getRosterRows()` = enrolled-only (ruling 4), sorted by id, get-only (never `getOrCreate`), mailbox **masked at source** via `MfaController.maskEmail` (package-private, same package; A16 — plaintext never enters the DOM).
- View getters: `isAdmin()` (ADMINISTER), `getMfaAdminBaseUrl()` (`Jenkins.getRootUrl()` else context-relative — house pattern), `getCrumbField()/getCrumbValue()`, `getAdminScriptUrl()` → `"plugin/devcru-mfa/mfa-admin.js"`.

### `VerifyOutcome.java` (MODIFIED — working tree)
Added after `ERR_VERIFICATION_REQUIRED`:
- `ERR_ADMIN_VERIFICATION_REQUIRED = "admin_verification_required"`
- `ERR_ADMIN_SELF_MANAGEMENT = "admin_self_management_forbidden"`
- `ERR_ADMIN_CONFIRM = "admin_confirm_required"`

### `MfaAdminController/index.jelly` (NEW, 241 lines)
Self-contained dark-theme document (same shape as the next-door `MfaController/index.jelly` — own Content-Type, nosniff, robots noindex, static JS not inline per the 2026-08-22 CSP round 2). Dumb view: `j:forEach` over `${it.rosterRows}` binding `userId/displayName/maskedMail/isTotp/isEmail/isTrustLive`, two buttons per row, JS wired by static script. **UNVERIFIED: the script binding line references a jelly property name — check it matches `adminScriptUrl` on the controller (a binding mismatch would 500 the page or drop the script).**

### `src/main/webapp/mfa-admin.js` (NEW, 165 lines)
`mfa-admin-init` + `mfa-admin-do-op` (IIFE, `defer`, DOM-ready), `confirmTyped` dialog (type the user id verbatim; mismatch reopens), single-flight `disabled` guard, fetch POST with `credentials:'same-origin'`, hidden-input sourced base url + crumb. **UNVERIFIED: I fixed one mangled double-POST expression after writing it — re-read the `post` function before trusting.**

### `src/test/java/org/sebcru/mfa/MfaAdminIT.java` (NEW, 322 lines — JUnit5, `@WithJenkins`, rule injected per method, house shape)
- `ensureRealm` — HPSR + **`FullControlOnceLoggedInAuthorizationStrategy`** (the Task 8/Task 9/A23 harness: every logged-in user has ADMINISTER, so the cases exercise the CREDENTIAL axis, not the permission axis).
- **Case 1 `passwordOnlySessionCannotClearOtherUsersFactors`** (spec case 3 / the A23-analogue): victim enrolled (TOTP `JBSWY3DPEHPK3PXP` + registered email `victim.example`); attacker enrolled (TOTP only), logs in, NOT verified; POSTs both verbs → expects **403** + `admin_verification_required` + victim state byte-identical.
- **Case 2 `verifiedAdminClearsLockedOutVictimAndOwnFactorsSurvive`** (spec case 2): verified admin GETs the page (roster contains both, **no plaintext mailboxes in DOM**), clears victim → `ok:true` + factors gone; victim re-logs in and reaches the dashboard 200; second clear → `not_enrolled`; admin's own factors survive; `revokeTrust` on the cleared user → `not_enrolled`.
- Helpers: `enroll`, `verifyTotp` (POSTs `mfa/postVerify` with a computed TOTP code — `Totp.decodeSecret/codeAt`), `mfaCrumb` (crumb sourced from the `/mfa` page — renders for EVERY session shape, which is exactly what lets case 1's attacker carry a crumb), `postAdmin` (**5-arg: `rule, c, endpoint, userId, int expectedStatus`**), `pageHtml`, `rawGet` (context-relative — leading slash stripped; see §6 pitfall), `hostAbs` (absolute Location resolution at host authority).

## 4. The red→green proof (honest state)

- **RED IS PROVEN (this is the real, load-bearing result):** against the first naive iteration of the two verbs (mutations present, authorization absent), case 1's exact IT answered **`ok:true` on `clearFactors` and the victim's TOTP seed + registered mailbox were wiped in two requests** — "it works, and for anyone", per the correction. That red is what makes the seam load-bearing instead of decorative.
- **GREEN IS NOT YET PROVEN.** After the guard chain landed, the IT was left with a compile error (§5) and no `mvn test-compile`/`test` run has completed since. Do not claim green.
- `/tmp/a22b-red*.log` (red1–red6) may still exist — worth a glance at resume for the raw red output. If gone, the red is reconstructible by `git stash`-ing nothing (nothing is committed) — instead: temporarily comment the `answerAdminDeniedIfUnverified` call, run case 1, observe the wipe, restore. Only do that if mads wants a fresh red capture.

## 5. Known compile defect (fix at resume, first step)

`MfaAdminIT` call sites still use the OLD 4-arg `postAdmin` signature; the helper is now 5-arg:
- line ~162: `postAdmin(rule, c, "clearFactors", victim.getId())` → add `, 200`
- line ~179: `postAdmin(rule, c, "clearFactors", victim.getId())` → add `, 200`
- line ~192: `postAdmin(rule, c, "revokeTrust", victim.getId())` → add `, 200`

(case 1's calls at ~106/~111 already pass `403`.)

## 6. The security finding still OPEN — the gate's `/mfa` prefix sweeps `/mfaAdmin/*`

**Status: found, analyzed, NOT yet patched.** This is the top open item.

`MfaFilter.ALLOWED_PREFIXES` contains the bare `"/mfa"` and `isAllowedPath` is `startsWith` — so **`/mfaAdmin/clearFactors` matches the allow-list** (`/mfaAdmin/...`.startsWith(`/mfa`) is true). That is the SAME defect class as A23's original bug (an allow-listed sibling path doing a factor-destroying mutation without requiring a verified actor) — the spec explicitly says `/mfaAdmin` is NOT on the allow-list (ruling 1) and "A23's decision chain stays byte-identical".

**Interaction with the IT (reasoned out here so it isn't re-litigated at resume):**
- The controller's 403 seam is **gate-independent by design**: it reads `VERIFIED_ATTR` + trust directly. It remains the authoritative mutation authorization even when the gate is inert (policy `OFF`, or the `DEVCRU_MFA_OFF=1` env kill-switch — the gate is explicitly an "off-able" layer; the admin mutation guard must survive that off-state). That is the layer case 1's IT pins.
- The gate carve-out is the PRIMARY reachability layer when the gate is ON (policy REQUIRED): unverified sessions 302 away from `/mfaAdmin` before any controller code runs. Pin it where the house pins pure decisions — **`FilterLogicTest`** (pure `decision(...)` input `/mfaAdmin/clearFactors` → `REDIRECT` under REQUIRED, while `/mfa` and `/mfa/postVerify` stay `PASS`) — rather than as another IT, unless the policy-default question below says otherwise.
- **UNVERIFIED: `DevcruMfaConfig`'s default policy in a fresh test Jenkins.** If the default is `OFF`, the gate is inert inside the ITs and case 1 tests the controller layer directly (consistent with the §4 red). If a REQUIRED-policy harness is wanted for a gate-leg IT, `MfaFilterIT` has the house pattern (check how it switches policy).
- Patch sketch (decide the shape at resume, both defensible): (a) tighten the prefix `"/mfa"` → still keep the bare segment but special-case in `decision()` a `securityPath` set (`/mfaAdmin`) that is checked BEFORE step 5 and forces `REDIRECT` under REQUIRED; or (b) change the prefix to a segment-exact match. Option (a) mirrors the A23 "securityPath first" structure the postmortem names — prefer it, and pin it in `FilterLogicTest`.

## 7. Remaining work, ordered (at resume)

1. `cd /home/hunter/dev/devcru-jenkins-mfa && git status --short` — confirm tree matches §1 (if different, the reset left something; reconcile before proceeding).
2. Fix the three `postAdmin` call sites (§5). `mvn -o -q -ntp test-compile` — must be clean.
3. Read `index.jelly`'s script-binding line and `mfa-admin.js`'s `post` function end-to-end (§3 UNVERIFIED items).
4. **Gate carve-out + `FilterLogicTest` pin** (§6). Check `DevcruMfaConfig` default policy first.
5. **Write `AdminManageAllowedTest`** — the controller's class Javadoc already references it (A23-shape pure-seam unit test: the ruling-3 unenrolled-quadrilateral — unenrolled→false even verified; unenrolled+unverified→false; enrolled+unverified+untrusted→false; enrolled+sessionVerified→true; enrolled+trustLive→true; enrolled+both→true). House reference for the pin style: `MfaControllerManagementTest` (the A23 seam's unit test). **Per-test BDD blocks are MANDATORY here (AGENTS.md).**
6. **Audit `MfaAdminIT` for AGENTS.md compliance** — class-level BDD is present; verify/fill the per-method WHAT / GIVEN-WHEN-THEN `<pre>` / WHY blocks for both cases (TotpTest is the reference shape), plus the honest red→green history in the class Javadoc (the red in §4 IS real — record it, don't embellish).
7. **Spec §7 unit legs**: the spec's case list implies the seam quadrilateral (now #5) — check §7 for any other named unit ITs (self-management pin, confirm-mismatch pin, persistence-error pin) and write them — as unit tests for the seam/`denyOrConfirmError` where pure, ITs where they need the booted harness. (`denyOrConfirmError` is private static — test via the booted IT or relax visibility deliberately; decide consciously.)
8. **Green run**: `mvn -o test -Dtest='MfaAdminIT'` (the CI-mirroring `mvn clean verify` comes after ITs pass — SpotBugs runs at `verify`).
9. **README "Practical usage — what end users should expect"** — update in the SAME commit as the landing (AGENTS.md rule): the lockout-recovery path is now real user-facing behaviour ("an admin clears the user's factor state" — previously only manual config surgery).
10. `mvn clean verify` (JDK 21 host toolchain) — full CI mirror.
11. Commit on `a22b-spec` (message style: house convention `feat: …` / `test: …`), push. Then mads decides `develop` merge / PR — do NOT merge to `develop` without approval.
12. Acceptance walk-through per the post-rollout report's discipline (AGENTS.md): the IT journey IS the browser journey for this surface (login → verify → roster → clear → re-login as victim), and both response shapes (200 envelope / 403 envelope) are asserted — but note the honest gap: no real-browser pass on the jelly/JS has happened; the static-JS wiring is compile-unverified. If mads wants the full acceptance, that's a live-server step.

## 8. Environment & tool quirks (learned this session — do not re-learn)

- **Host terminal truncates some output to a single line** (seen repeatedly with grep/version commands). Reliable pattern: write to a file, then `read_file`/`sed -n 'A,Bp'`, or use the `read_file` tool for sources. `mvn` runs: `> /tmp/x.log 2>&1` then inspect `target/surefire-reports/<class>.txt` for failures.
- `execute_code` was reported blocked in the prior window — re-verify if relied on; `terminal`/`read_file`/`patch`/`write_file` all worked.
- `search_files` with `\(` in the pattern failed (`grep: Unmatched ( or \(`) — avoid unescaped parens in that tool's regex.
- `mvn surefire:test` (CLI goal) **skips test-compile** — use `mvn test -Dtest='…'` or `verify`; for compile-oracle speed use `mvn -o -q -ntp test-compile`.
- `-o` (offline) works — the repo's test deps are cached.
- House facts verified this session:
  - JUnit5 ITs: method takes `JenkinsRule rule` injected; `rule.jenkins` field; **`rule.getURL()`** (NOT `getUrl()`) — confirmed against `MfaFilterIT`.
  - `JenkinsRule.WebClient c` is an inner class; `c.login(user, pw)` is the house login.
  - Stapler in this parent: NO `HttpResponses.json` (symbol missing) — house JSON is void endpoint + `StaplerResponse2` + manual `PrintWriter` (pattern: `MfaController.postVerify` / `postVerifyAllowlisted`).
  - `TrustStore.isTrusted(MfaUserProperty, DevcruMfaConfig, long)` — INSTANCE method, needs config; the filter's instance is a private static in `MfaFilter` (not reusable).
  - `MfaController.maskEmail` is package-private static; `MfaController.VERIFIED_ATTR` is a public static String constant.
  - `MfaUserProperty.getOrCreate(User)` throws IOException; field-setter + `user.save()` is the write path used everywhere (incl. A23's destroy path).
  - `Totp.decodeSecret(String)`, `Totp.codeAt(byte[], long)` exist for IT code generation.
- The A23 history (context for why this exists): `/securityRealm/postVerifyAllowListed` was an MfaFilter-allowed path that wiped the current user's TOTP seed from an unverified session with trust still set. Fix: (a) `managementAllowed` seam requiring verified/trusted actor, (b) move factor-destroy off the allowed sibling. The A23 IT proves both legs. **A22-b re-proves the same shape on the admin surface so "unverified session can't destroy factor state" holds endpoint-for-endpoint, and adds the actor-state quadrilateral the A23 IT can't express (cross-user mutation).**

## 9. Decisions already made (do not re-litigate, but these are MINE not mads's — mads can overrule)

- Separate controller (ruling 1) keeps A23's six-endpoint decision chain byte-identical (spec §4).
- 403 (not 200+ok:false) for the credential denial = A23's house shape; the IT asserts the STATUS.
- Self-management check ordered BEFORE the typed-confirm check (the load-bearing rule is the first post-credential gate).
- `not_enrolled` is an idempotent 200-envelope outcome, not an HTTP error (spec §8).
- `trustLive` passes the admin seam (remembered device already proved a factor — symmetry with the gate's trust clause).
- The admin surface is NOT added to `MfaFilter.ALLOWED_PREFIXES` — but because the existing bare `/mfa` prefix already sweeps it (see §6), the "not on the allow-list" requirement is only truly satisfied once the carve-out lands. Until then the spec's invariant is aspirational, not real.
- A24 naming for the follow-up force-enrolment verb/view.

## 10. What NOT to do

- Do not merge to `develop`/`master` or open a PR without mads.
- Do not commit anything yet (tree is dirty on purpose; the compile is broken).
- Do not describe the `/mfaAdmin` surface as gated "as of now" — it is currently swept by the `/mfa` prefix until §6 lands.
- Do not claim the IT is green; the last completed run was RED (by design, against the naive surface), and the tree since then has not compiled.
- No plaintext registered mailboxes in ANY new assertion message either (A16 — the IT's own output is consumer-visible; note the existing case-2 assertions print the page HTML on failure, which only contains masked mail — safe, but don't "help" by adding raw ones).
