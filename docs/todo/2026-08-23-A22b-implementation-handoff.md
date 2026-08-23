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

## 0. Status — IMPLEMENTED, COMMITTED `d2a9008`, PUSHED, REVIEWED: APPROVED

- Branch `a22b-spec` @ `d2a9008` (pushed to `origin/a22b-spec`). **No PR**
  (per ruling). The two v2 defects are RESOLVED — full story in the `d2a9008`
  commit message and in §5 below.
- **All gates green at commit:** `MfaAdminIT` 5/5 (booted Jenkins, FCOL +
  hand-rolled least-privilege SidACL), `AdminManageAllowedTest` 6/6,
  `FilterLogicTest` 15/15, `MfaFilterIT` 9/9, `TotpTest` 5/5. SpotBugs clean,
  `devcru-mfa.hpi` builds, `mvn -o -B clean verify` BUILD SUCCESS.
- **External review (Moldy, 2026-08-23): APPROVED.** She independently re-ran
  `mvn -o -B clean verify` from a clean checkout (224 tests, 0 fail, SpotBugs
  clean, hpi builds) and reviewed the seam, the filter carve-out, and the IT.
  Her verdict: the Defect-2 seam fix is correct and "the whole show"; leg 4(d)
  is the genuine red→green discriminator. **One open item** — see §1.
- TECH_DEBT: A22-b is in the Resolved table (the code shipped). The §1
  acceptance item is tracked under "Not in the code yet."

## 1. YOUR NEXT TASK — the restart-survival leg (spec §7 case 3, §10)

This is the one thing the review found standing between "merged" and
"live-ready." The spec set a higher done-bar than the branch cleared.

**Why.** Spec §7 case 3 called the restart leg "not negotiable for a
credential-clearing op," and §10 item 2 requires it. Right now the clear's
persistence is proven only at the seam level (`clearFactorState` byte-for-byte
in `AdminManageAllowedTest`) and `target.save()` is called — but nothing yet
proves the persisted clear **survives a Jenkins restart**. For an op that
destroys credentials, that's the leg that has to exist.

**What to build.** One new `@Test` leg in `MfaAdminIT.java`, extending leg 5's
setup (`verifiedAdminClearsLockedOutVictimAndOwnFactorsSurvive`):

1. Verified admin clears a locked-out victim (reuse leg 5's enroll/verify/clear
   flow — the victim ends fully unenrolled, `target.save()` persisted).
2. `rule.restart()` — restart the Jenkins instance (reloads from disk).
3. **After restart**, assert:
   - the victim's `MfaUserProperty` is still cleared (unenrolled) — i.e. the
     clear persisted to disk and reloaded, NOT resurrected;
   - the gate now passes the victim (unenrolled = exempt) — they can log in
     with password only;
   - the victim can re-enrol (the README's documented recovery path, end to
     end);
   - the ADMIN's own factors also survived the restart (no collateral loss).
4. The leg is the postmortem's restart lesson applied to A22-b: "what survives
   / what breaks across a restart" must be asserted, not assumed.

**Definition of done for THIS task:**
1. New leg written first and proven meaningful (it asserts real post-restart
   state, not a tautology). If it exposes a persistence bug, that's the point —
   fix it, record the red→green honestly.
2. BDD-documented per AGENTS.md (WHAT / GIVEN-WHEN-THEN in `<pre>` /
   WHY-SOLVES), and the class-level red→green history note updated with this leg.
3. README practical-usage re-checked (the recovery paragraph should already
   describe this; verify it matches what the leg proves).
4. `mvn -o -B clean verify` green (SpotBugs + enforcer + unit + IT + `.hpi`).
5. Commit via `git commit -F <msgfile>`, read back (`git log -1`), push
   `git push origin a22b-spec`. **No PR.**
6. Report to mads: green tally + what the leg asserts + any persistence finding.

**Out of scope unless mads says otherwise:** spec §10 also lists a both-themes
render of the admin page and a real-browser walk on the dev instance. Do the
restart leg FIRST; then ask mads whether those gate this task or wait. Do not
bundle them in silently.

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
