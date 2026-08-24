# A22-b admin factor-management — implementation handoff (v3, 2026-08-23, POST-REVIEW)

Written for Sebastian (next session). **The implementation is DONE, committed,
pushed, and externally reviewed: APPROVED.** This handoff now exists to hand
you ONE remaining task (§1). Read §0 (status) and §1 (what to do next) first.
§2–§4 are reference you may need; §5 is the resolved-defect audit trail —
**do not re-do any of §5.**

**Repo:** `/home/hunter/dev/devcru-jenkins-mfa`
**Binding spec:** `docs/todo/2026-08-23-A22b-admin-factor-management-spec.md`
**House rules:** `AGENTS.md` (BDD doc on every test, README practical-usage
updated in the same commit, local validation = `mvn clean verify` mirrors CI
incl. SpotBugs, no PR without mads, commit via `git commit -F <file>` then
read back, push `a22b-spec`).

Maven: `export PATH="$HOME/.local/bin:$PATH"`, always `-o` (offline).
JDK for javap: `export PATH="$HOME/opt/jdk-21.0.12+8/bin:$PATH"`.

---

## 0. Status — IMPLEMENTED, RESTART-PROVEN, REAL-BROWSER ACCEPTED

- Branch `a22b-spec`; restart-survival work is committed/pushed through
  `05ebb43`. The current acceptance/fix commit sits on top and is pending its
  final `clean verify` + commit/push gate. **No PR** (per ruling).
- Booted-Jenkins coverage is six `MfaAdminIT` legs, including the
  restart-survival round trip. The real-browser walk then booted the branch
  through `hpi:run` under the real `/jenkins` context and drove a second
  headful Chromium on Xvfb — not HtmlUnit and not the collector browser.
- **Browser finding and fix:** the roster rendered, but both action buttons
  were dead because `getAdminScriptUrl()` emitted relative
  `plugin/devcru-mfa/mfa-admin.js`; Chromium resolved it beneath
  `/jenkins/mfaAdmin/`. `MfaAdminIT` was made red on the rendered script URL,
  then `getAdminScriptUrl()` was fixed to root the resource at Stapler's
  current context (`/jenkins/plugin/...` live). The same leg is green 6/6.
- **Full journey passed in real Chromium:** admin password login → live TOTP
  verification → enrolled-only roster (`admin`, `sac`) with no raw mailbox in
  the DOM → dark and light media renders → typed-id confirmation disabled on
  mismatch/enabled on exact `sac` → clear succeeds and removes `sac` from the
  roster → `sac` reaches the dashboard password-only → generates a fresh QR
  and seed on Security → confirms a live TOTP → passes the immediate MFA gate
  → appears enrolled again.
- **Restart/browser persistence passed:** after restarting the actual
  `hpi:run` JVM, remembered trust survived; each user revoked it through the
  Security UI, then admin's original TOTP and `sac`'s newly-enrolled TOTP both
  verified. The admin roster reloaded as `admin,sac`; least-privilege
  `reader` reloaded and received 403 `admin_permission_required` on
  `/mfaAdmin/`.
- Executable, non-secret CDP journeys and the sandbox fixture live under
  `scripts/acceptance/a22b/`. Generated credentials, browser profile, logs,
  candidate seeds and screenshots remain ignored under `.scratch/`; none
  enter Git.

## 1. Restart-survival leg (spec §7 case 3, §10) — COMPLETE

`MfaAdminIT.clearedVictimSurvivesRestartAndRecoveryCompletes` proves leg 5's
clear flow → on-disk `config.xml` anti-vacuity anchor → `rule.restart()` →
(a) victim reloaded still cleared, (b) a fresh password-only victim session
reaches the dashboard, (c) victim re-enrols end to end, and (d) the admin's
own factors survive byte-for-byte and remain live. No persistence defect was
found. The real-browser walk above independently exercised the same consumer
journey against the actual `hpi:run` process and a second real Chromium.

### §10 breadth-of-consideration ledger

1. **Host:** `hpi:run` served Jenkins 2.528.3 at the non-root `/jenkins`
   context. Probe found the relative static-script URL defect; context-rooted
   URL fixed and pinned in `MfaAdminIT`.
2. **Runtime envelope:** second headful snap Chromium ran on isolated CDP 9333
   under Xvfb `:99`; the collector browser/CDP 9222 was not touched. Jenkins
   CSP loaded the corrected same-origin static script.
3. **External consumer:** real Chromium completed login, TOTP, roster,
   typed-confirmation mutation, password-only recovery, QR/manual-seed
   re-enrolment, and post-restart verification. HtmlUnit alone was not treated
   as acceptance.
4. **Environments:** standalone admin page captured under emulated dark and
   light `prefers-color-scheme`; controls remained present and legible.
5. **Privilege:** sandbox-only one-admin `SidACL` granted ADMINISTER only to
   `admin`, READ to authenticated users. `reader` reached the dashboard but
   `/mfaAdmin/` answered 403 `admin_permission_required`, including after
   restart.
6. **Time/order:** confirmation began disabled, remained non-operative until
   exact target id `sac`, then single-flight clear completed. Newly enrolling
   `sac` was immediately gated and had to verify the new factor before return.
7. **Restart:** actual `hpi:run` JVM restarted. Admin factor, newly-enrolled
   victim factor, remembered trust, roster, and least-privilege denial all
   survived; trust was revoked through each user's UI before proving both
   TOTP factors live again.

**Acceptance result:** §10's both-theme and real-browser items are complete.
The final repository gate remains `mvn -o -B clean verify`, then commit/readback
and push to `a22b-spec`; no PR.

## 2. IT shape + helpers (reference for the restart leg)

File: `src/test/java/org/sebcru/mfa/MfaAdminIT.java`. **5 legs, all green at
commit** (the v2 red legs are fixed):

1. `enrolledPasswordOnlySessionIsBouncedByTheGateOffTheAdminSurface` — carve-out
   302 leg.
2. `unenrolledAdminCanReadRosterButNotMutate` — Ruling-3 edge.
3. self-strike pin — verified admin clears own id → 200
   `admin_self_management_forbidden`, victim factors intact.
4. `nonAdminIsDeniedTheAdminSurfaceAtTheWire` — least-privilege strategy;
   includes the **(d) verified-non-admin order probe** (the Defect-2
   discriminator: a proven-credential non-admin is denied on the PERMISSION
   axis, not credential). **Your new restart leg is leg 6.**
5. `verifiedAdminClearsLockedOutVictimAndOwnFactorsSurvive` — the admin journey
   (your base to extend).

Helpers (verified by read; reuse, don't rewrite): `rawGet`, `rawPostAdmin`
(redirect disabled + restored — the A19 idiom), `postAdmin` (expects-200),
`pageHtml`, `enroll`, `verifyTotp`, `ensureRealm`. The nested
`LeastPrivilegeAdministerStrategy` (extends the abstract
`AuthorizationStrategy`, returns a fail-closed `SidACL` from `getRootACL()`) is
only needed for leg 4 — your restart leg can use the default FCOL world.

## 3. Verified API facts (do not re-discover — javap/jar-verified)

- Stapler on the build: 2030.v88a_855365981. The verbs use
  `StaplerRequest2/Response2`. `doIndex` was REMOVED (Defect-1 fix): the
  class-dir view `MfaAdminController/index.jelly` auto-renders on the empty
  token (the `MfaController` sibling proves the shape); the page READ gate is
  `adminPageAllowed()` in the jelly (`<j:when test="${!it.adminPageAllowed()}">`
  → `<st:statusCode value="403"/>`).
- **The two roster cells that 404'd** used `j:out` as an attribute on `<td>`
  (invalid XML → `JellyFacet#buildIndexDispatchers` dropped the view). They are
  now standalone `<j:out value="..."/>` elements (lines ~231-232). Do not
  reintroduce attribute-form `j:out`.
- Core jar: `jenkins-core-2.528.3`. `AuthorizationStrategy` = abstract class.
  `MatrixAuthorizationStrategy` ABSENT offline (why the SidACL hand-roll exists).
  `SidACL` fails closed on null. `hudson.util.AccessDenied` ABSENT.
- **The Defect-2 seam (the approved production form):**
  `Jenkins.get().getACL().hasPermission2(auth, Jenkins.ADMINISTER)`,
  fail-closed on null / `AnonymousAuthenticationToken` / ANONYMOUS_USERNAME.
  NOT `User.hasPermission(...)` (self-granting no-op — see §5).
- `MfaUserProperty` setters taking `hudson.util.Secret` (not String):
  `setTotpSecret`, `setEmailCodeSecret`, `setPendingCodeHash`; getters return
  `Secret`. `clearFactorState(p)` is the single writer of the fully-unenrolled
  state.
- `UserProperty` persistence: `target.save()` writes the user's config.xml;
  `rule.restart()` reloads from disk — that round-trip is exactly what your
  restart leg asserts.

## 4. Run history (evidence trail, condensed)

Run logs under `/tmp/a22b-*.log` (run1 jelly-500 + redirect-following + login-
403 fixture; run2 compile-fail on missing `throws`; run3 the two-defect red;
run4 the `j:out` SAXParseException discovery; run5 a self-inflicted HtmlUnit
cast bug in leg 5(c); run6 final green). **Stale-data warning:** surefire
reports under `target/` are per-run — always pair a surefire read with the
matching run log's `Tests run:` line.

## 5. Resolved-defect record (v2 §0 — audit trail, DO NOT RE-DO)

- **Defect 1 (admin page never rendered / 404).** Root cause was two stacked
  bugs: the `doIndex` forward had no rule to land on, and the view itself had
  never been load-tested (two roster cells used `j:out` as an attribute →
  invalid XML → view dropped at facet build → silent 404). Fix: remove
  `doIndex`, rewrite the cells as standalone `<j:out/>`, put the 403 read gate
  in the jelly. The v1/v2 "jelly verified" verdict was a static read, not a
  render — recorded in the IT's red→green history.
- **Defect 2 (the permission seam was a no-op).** Bytecode-proven on core
  2.528.3: `User.getACL()` wraps the strategy ACL in a delegate that
  self-grants TRUE when the principal matches the user's own id, BEFORE
  consulting the strategy — so `actor.hasPermission(ADMINISTER)` was true for
  every authenticated actor. Fix: check the current session against the Jenkins
  ROOT ACL (`getAuthorizationStrategy().getRootACL()` verbatim, no self-grant
  wrapper). **This seam change is mads-approved (2026-08-23); do not alter it
  further without sign-off.**
- **Filter carve-out (spec §6 contradiction, resolved as the signed ruling).**
  `MfaFilter` allow-list now matches `/mfa` segment-precisely (bare / `?query`
  / `/mfa/<endpoint>`) so `/mfaAdmin/*` is NOT swept through the gate
  allow-list (the A23 sibling-sweep class, 2nd instance). Pinned both
  directions in `FilterLogicTest`.

## 6. Standing instructions (from mads) + process note

- Branch `a22b-spec`; implementation committed `d2a9008`; your restart leg will
  be a NEW commit on top.
- mads-approved-per-step on merges; **no PR** without explicit ask.
- Spec is the binding document. Where spec and ruling conflict, the SIGNED
  ruling wins, documented as a contradiction note — not silently resolved.
- Credentials never in commits/logs/doc; test-only local-realm passwords are
  throwaway fixtures, not real secrets.
- **Process note from the review (the one miss worth not repeating):** the
  Defect-2 seam change was made on disk BEFORE mads signed off; mads had to
  pull the thread. The guardrail's substance survived (it stayed
  uncommitted/reversible and got sign-off), but the sequence didn't. Going
  forward: when implementation surfaces a decision that needs mads — a seam
  change, a spec contradiction, a defect that moves the security model — STOP
  and report-and-ask. Don't fold it into the flow. That keeps a clean gate
  instead of a mid-flow trip.
- This handoff (v3) supersedes v1 and v2 where they conflict.
