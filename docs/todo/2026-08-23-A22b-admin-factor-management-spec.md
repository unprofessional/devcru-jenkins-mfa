# A22-b spec — Admin management of other users' factors

> **Status: RULINGS RECEIVED (mads, 2026-08-23) — implementing in this
> branch. §9 resolved as below.**
> **Branch:** `a22b-spec` (off `develop` @ `e671384`)
> **Debt entry:** `docs/todo/TECH_DEBT.md` § "A22" (A22-b) + "Not in the code yet"
> **Named because:** the README's documented lockout-recovery path ("an admin
> clears the user's stored factor state; the user re-enrolls") currently has
> **no UI to do it**. This is also the last user-visible functional gap called
> out by the publishing research
> (`docs/2026-08-23-publishing-to-jenkins-update-center.md`).

## 1. The problem, precisely

A user who has lost every factor device (phone *and* mailbox) is locked out
until the admin clears their `MfaUserProperty` factor state. Today that means:

- no page, no endpoint — the only writer of factor-clearing state is the
  victim's own self-service endpoints, which by the A23 guard
  (`managementAllowed`) require the *victim* to have a verified session or
  live trust — exactly what a fully locked-out user cannot produce;
- the workaround is raw `config.xml` surgery on a live box: stop Jenkins,
  hand-edit the victim's user XML, restart. Undocumented in the UI, and
  dangerous to do with the plugin's encrypted-at-rest `Secret` values on
  disk.

A22-b closes that with a small, admin-gated surface.

## 2. Design decision — the two shapes from the debt note

The debt note sketches **option (B)**: admin-targeted overrides on the
existing six `/mfa` profile endpoints (a `user=` parameter; the endpoint acts
on the target when the caller ≠ target, behind `ADMINISTER`).

**This spec recommends option (A): a separate admin page — `MfaAdminController`
at mount `/mfaAdmin`, `RootAction` (same pattern as `MfaController`) — with a
read-only roster + a small number of admin operations.** Rationale:

1. **The `/mfa` allow-list is a liability, not an asset, for admin writes.**
   The gate allow-lists the bare `/mfa` prefix *precisely so a
   password-only, pre-verify session can reach the two verify endpoints*
   (the A23 hole was the cost of that). Putting a target parameter on
   existing `/mfa` endpoints means every future reviewer must ask "does the
   allow-list now pass an admin mutation to a pre-verify session?" Option (A)
   mounts on a **new prefix that is NOT allow-listed**: admin operations are
   only reachable from a verified-or-trusted session by construction, and
   the A23 invariant ("nothing under `/mfa` mutates pre-verify, except the
   two verify endpoints") stays exactly as pinned by the attack-chain IT.
2. **The self-service contract on the six endpoints is intentional (A22-a:
   "acts on `currentUser()` only").** Option (B) makes every one of the six
   endpoints a two-user function: "who is this button acting on" becomes a
   per-request question. A22's own verification note warns this is a
   guaranteed-confusion surface. Option (A) leaves all six endpoints and
   their tests untouched.
3. **Option (B) cannot do the roster anyway.** Recovery needs a list of
   enrolled users; that is a page, so (B) needs a page too — at which point
   the page's own endpoints *are* option (A), with (B)'s parameterised
   endpoints as a redundant second route to the same mutations (two writers
   of factor state = the state-and-failure rule's "different names, different
   writers" smell).
4. **Blast radius.** Option (A) adds code; it changes none of the live
   system's existing decision chains (gate, six endpoints, trust, rate
   limit). Option (B) rewrites authorization on six live prod endpoints —
   on a box that is LIVE (2026-08-22 cutover) — for a feature whose
   recovery-path users are a handful of humans.

Option (B) remains on the table if mads prefers it; §8 lists the delta.
**Everything below assumes (A) until ruled otherwise.**

## 3. What the admin page is

A single page at `<ctx>/mfaAdmin` (new segment; no core mount, no realm can
squat it — the same property that made `/mfa` safe in A17), reachable only
by holders of **Overall/Administer** (core's own `Jenkins.ADMINISTER`,
checked on *both* the GET and every POST — the gate is not the protection,
per A23's lesson).

**The roster (GET, read-only):** a table of all users with an
`MfaUserProperty` where `isMfaEnabled()` is true:

| Column | Source | Note |
|---|---|---|
| User id | `User.getId()` | |
| Mailbox | `MfaUserProperty.getMaskedRegisteredEmail()` | **Masked, never full** — same rule as the login page (`maskEmail`): an admin investigating a lockout can confirm "that's the right mailbox" without the roster becoming a PII directory. Full address stays on the target user's own security tab. |
| TOTP | `hasTotpFactor()` | yes/— |
| Email codes | `hasEmailFactor()` | yes/— |
| remembered device live | `TrustStore.isTrusted(p, cfg, now)` | yes/expired/— |
| lockout | `RateLimiter.isLocked(id, cfg, now)` | "locked out (Ns remain)" / — |
| Last verified factor | `getLastVerifiedFactor()` (0=TOTP/1=email) | the A8 telemetry field, finally displayed |

Non-enrolled users do not appear (a lockout only exists for enrolled users;
listing the unenrolled would make the page a user-directory).

**Per-row operations (POST):**

1. **Clear factor state** — the recovery operation. Clears
   `totpSecret`, `registeredEmail`, `emailCodeSecret`, `trustedUntilMs`,
   `pendingCodeHash`, `codeIssuedAt`, `lastResendAt`, and
   `failedAttemptStreak` on the target's property, one `target.save()`, on
   one `@WebMethod` endpoint (`postClearFactors`?token=clearFactors` —
   naming follows the six endpoints: `@RequirePOST` +
   `@WebMethod(name = "clearFactors")`, `userId` request parameter).
   The user is now unenrolled: the gate passes them (unenrolled = exempt),
   they log in with password only and re-enroll. Exactly the recovery path
   the README describes — now with buttons. (RateLimiter state is
   process-memory and outlives the property; because the user is unenrolled
   the limiter is moot, so no limiter mutation is sent — the lockout column
   goes blank on the next render because the gate skips unenrolled users
   before consulting it. This is reasoned from the gate's decision-chain
   order, *not yet probed* — it is probe #1 of the implementation.)
2. **Revoke remembered devices** — `postRevokeTrust`/`revokeTrust?userId=`:
   the *other* half of lockout support (a user whose *own* account is fine
   but whose remembered browser was stolen, or who simply wants forced
   re-verification at their next login on all browsers — without the full
   factor-clear which also kills their working phone). Reuses the existing
   `TrustStore.revoke(p)` seam; does **not** touch factors.
   Deliberately NOT a third "disable email only" / "disable totp only"
   admin op: factor surgery on one factor only is self-service territory,
   and the recovery path per the signed plan decision 7 is the *whole*
   clear. Keep the surface two verbs.

Both verbs: the confirmation is a browser JS `confirm()` dialog (the
static-asset rule: the page's script lives at
`plugin/devcru-mfa/mfa-admin.js`, **not** inline — CSP is
`script-src 'self'`, the 2026-08-22 round-4 lesson), the response is the
same 200+JSON contract as the six endpoints (`{ok:true}` /
`{ok:false, error:"…"}`, `Cache-Control: no-store`, nosniff).

**Admin audit line:** every successful mutation logs
`WARNING MFA admin <actor-id> cleared factor state / revoked trust for user
<target-id>` (the same loud-not-silent landmine standard as the post-rollout
fixes). No new audit store — Jenkins' log is the audit.

## 4. Authorization — the seam (pure, unit-pinned like A23's)

New static seam on the admin controller, same shape as
`managementAllowed` so the house pattern holds:

```
adminAllowed(actorPresent, isAdminister, targetExists, isSelf, sessionVerified, trustLive)
```

- `!actorPresent` → 401-equivalent `{ok:false, error:"not_authenticated"}`
- `!isAdminister` → **403** `admin_permission_required`
  (`actor.hasPermission(Jenkins.ADMINISTER)` — checked in Java on every
  endpoint AND on the page GET; core already 403s the page for
  non-ADMINISTER, this is the endpoint-side backstop so the page render
  gate and the wire gate cannot drift)
- `targetExists` false → `{ok:false, error:"user_not_found"}` (no 500, no
  oracle difference between "exists but unenrolled" and "does not exist" —
  an unenrolled target gets `not_enrolled`, a missing one `user_not_found`;
  both exist, neither leaks)
- `isSelf` (target id == actor id) → **403** `self_management_forbidden`.
  **This is the load-bearing rule for A22-b's security case:** without it,
  a password-only admin session (no verify, no trust) could POST
  `clearFactors(userId=self)` and strip *their own* factors — the A23
  factor-strike chain, one endpoint to the left. Self-management stays
  exclusively on the six self-service endpoints with their A23 guard.
- `!(sessionVerified || trustLive)` — evaluated against the **actor's**
  property/session — → 403 `verification_required` (same string as A23,
  same meaning: an admin who has not proved a second factor this login and
  holds no live trust cannot manage *anyone else's* credentials. The
  admin's own trust/verify state is what's demanded; the target's state is
  irrelevant to the guard, by design.)

Ordering is fixed (permission → user → self → verify) so every failure has
one stable string; a denied request writes **nothing** (deny-before-
mutation, the A23 invariant, now on the admin path too).

The gate's interaction, stated as fact for review:

- `/mfaAdmin` is **not** in `MfaFilter.ALLOWED_PREFIXES`. An enrolled admin
  with a password-only, unverified session is 302'd to `/mfa` and must
  verify before reaching the roster — exactly the "freshly proven to touch
  credentials" posture above, enforced by the existing decision chain with
  **zero filter changes**. (The allow-list entry added is none; the only
  filter-adjacent change is to the *controller-side* `isSecurityPath` set
  — see §6, item 2.)
- Unenrolled admins (the admin account itself is currently enrolled in
  reality, but the install allows an unenrolled admin): the gate passes
  them through (unenrolled = exempt), the `isAdminister` check is the
  protection for the roster's GET read, and the two POSTs 403 on
  `verification_required` for an unenrolled actor (an unenrolled admin's
  session never carries `VERIFIED_ATTR` and has no trust — so an
  unenrolled admin can *see* the roster but *cannot clear* anyone. That
  is a consequence of the signed trust semantics, and it is the right
  one: you should not be able to clear credentials you yourself have not
  proven you can hold. Flagging it as a **ruling needed** in §9 — it is
  the one behaviour a reviewer might want to soften.)

## 5. Persistence honesty (landmine standard)

- Both mutations modify the target's in-memory property **then**
  `target.save()` on the target `User`. If `save()` throws: the mutation
  remains in memory (the running box works), but the response is
  `{ok:false, error:"persistence_error"}` + a `SEVERE` log with the actor
  and target ids — never `ok:true` over an unpersisted clear (the
  post-rollout landmine rule: answering success while data is unpersisted
  is lying with a status code, and here the lie is especially bad: the
  victim "re-enrolls", the box restarts, their factors come back, and the
  admin's clear was a fiction).
- The admin page is rendered from the live in-memory properties, not from
  disk: no cache, no stale roster after a clear (re-render on the next
  request reflects the mutation immediately).

## 6. Surface inventory (what touches what)

1. **New file** `MfaAdminController.java` (`RootAction`, mount
   `mfaAdmin`, `getIconFileName()` null — no action-bar icon; the page is
   findable by URL, and the admin settings page §-below links it).
   - GET model: the roster rows (§3) + crumb field/value (same
     `Functions` delegation as the other two pages) + base URLs.
   - `clearFactors` / `revokeTrust` endpoints with the §4 seam.
2. **New file** `MfaAdminController/index.jelly` (the roster table,
   static script tag to `mfa-admin.js`, `j:out` for any dynamic text —
   A18: not `x:out`) and `mfa-admin.js` (confirm dialogs + the two fetch
   POSTs, mirroring `mfa-section.js`'s shape).
3. **`MfaFilter` — one-line-ish change:** add `"mfaadmin"` to the
   `isSecurityPath` first-segment set, so a post-verify redirect *to* the
   admin page degrades to root instead of looping back into the gate
   (the exact reason `mfa` is in that set post-A17). No allow-list
   change, no decision-chain change.
4. **`DevcruMfaConfig/config.jelly` — one line:** a link to
   `/mfaAdmin` from the admin MFA settings page, so the surface is
   discoverable (no second navigation tree; the settings page is the
   admin's MFA front door).
5. **`README.md`, "Practical usage" § "Who can open that section" + the
   known-gap paragraph:** the "Known gap" (TECH_DEBT A22-b) paragraph at
   the top of the README becomes the implemented description of the admin
   recovery path (house rule: same commit as the landing task).
6. **`docs/todo/TECH_DEBT.md`:** A22 entry gains an A22-b "Landed" note;
   item moves to the Resolved table with the commit; the "Not in the code
   yet" bullet is removed.
7. **Tests** (§7). **Nothing changes** in: `MfaFilter`'s decision chain,
   `MfaController`'s six endpoints, `managementAllowed`,
   `MfaUserProperty`, `TrustStore`, `RateLimiter`, the existing
   allow-list entries.

## 7. Test plan (BDD-documented per AGENTS.md; red→green where genuine)

**Unit (plain JVM, no boot) — `MfaAdminControllerTest` or the existing
seam test file, house pattern `MfaProfileSeamTest`:**

1. `adminAllowed` across the full quadrilateral: admin+verified,
   admin+trust, admin+neither (denied), non-admin+verified (denied),
   self-target (denied, permission present), missing target. Every
   quadrilateral's THEN is the stable error string, not just boolean.
2. The roster row model (masked email — a raw address must not appear in
   *any* output field; TOTP/email/trust/lockout columns from a fixture
   property; an unenrolled user produces no row).

**Integration (booted Jenkins, `JenkinsRule`, HPSR shape as the live box) —
new `MfaAdminControllerIT`, reusing `MfaFilterIT`'s helpers verbatim
(context path, `c.login`, captured-mail, `rawGet` with
`setRedirectEnabled(false)` — A19's lesson applies to every new raw-status
assert here):**

3. **The recovery journey (the acceptance case):** admin (ADMINISTER +
   enrolled, verified via a real TOTP code) → victim (enrolled TOTP,
   simulated total lockout: wrong-code ×5 to trip the lockout, then no
   further attempts) → admin's session GETs `/mfaAdmin` → roster shows the
   victim's row (masked mailbox, TOTP=yes, locked-out) → POST
   `clearFactors?userId=victim` with confirm → JSON ok → **victim's property
   is fully clear of factors, trust, and pending state** (the IT asserts
   each field, byte-wise where the type allows) → victim logs in with
   password only → **no MFA bounce** (gate sees unenrolled) → victim
   re-enrolls a fresh TOTP (self-service, the six endpoints) → victim
   verifies → the full round trip closes the recovery. This is the
   consumer journey as an executable, committed script.
4. **The A23-analogue on the admin path:** password-only admin session
   (enrolled, unverified, no trust) → POST `clearFactors?userId=<someone>`
   → 403 `verification_required`, target's property **byte-identical
   before/after** (the IT fabricates a known pending-code state and asserts
   it survived). Same shape as the A23 attack-chain IT, same honesty
   standard: this test is written *first* and must be run against the
   endpoint before the seam exists, so the red phase is on record.
5. **The self-strike pin:** admin, verified, POSTs
   `clearFactors?userId=<self>` → 403 `self_management_forbidden`, admin's
   own factors untouched. (Without this pin, the §4 "load-bearing" rule is
   a comment.)
6. **Non-admin denied at the wire:** a user without ADMINISTER (the IT's
   authz strategy grants the admin everything; the victim has no
   ADMINISTER) → GET `/mfaAdmin` → 403; POST `clearFactors?userId=…` →
   403 `admin_permission_required`. (The privilege slot of the
   breadth list: the elevated probe is not the subordinate probe.)
7. **The gate interaction pin:** enrolled admin, password-only session →
   GET `/mfaAdmin` → **302 to `/mfa`** (the allow-list does *not* pass it —
   the §4 invariant, pinned at the wire while we're here).
8. **Persistence honesty is not IT-able cheaply** (kill the disk mid-save
   in a JenkinsRule is overreach); the `persistence_error` branch is
   covered at the unit level of the glue with a seam that throws, and the
   branch is named so a live failure is greppable. Recorded as the one
   deliberately-not-booted branch, the same standard the A23 IT set.

**CI:** `mvn clean verify` green (SpotBugs `check` + enforcer + all tests),
JDK 21 — the build gate, not the acceptance gate.

## 8. Breadth-of-consideration enumeration (required work product)

Filled at spec time with the probes available on this repo; slots marked
*deferred* become hard pre-landing probes in the implementation.

| Slot | Concrete reality | Probe | Result / status |
|---|---|---|---|
| Host | Jenkins 2.528.3 Stapler dispatch, `RootAction` mount, crumb filter, `Jenkins.ADMINISTER` | Read `MfaController` (same pattern, live prod), `MfaFilter`'s dispatch facts, A17's mount-collision forensics; the IT boots the production realm shape | `/mfaAdmin` is a free segment (no core mount at that node in any realm shape the IT covers — **verify against the booted HPSR in case 3, as A17 taught**, not just by string search); crumb + `@RequirePOST` + `@WebMethod` trio is the house pattern (A20). Green at spec. |
| Runtime envelope | Jenkins CSP `script-src 'self'` (round-4 2026-08-22), SpotBugs `check` + enforcer, access-modifier-checker (A21's AMC lesson) | Read the postmortem; the existing `mfa-gate.js` / `mfa-section.js` static-asset pattern | JS must be a static file, same-origin URL built from the root URL; AMC: page model uses only public core API (`User.getById`, `hasPermission`, property getters) — A21's `User.impersonate2` detour is **not** needed because the admin path never impersonates a target, it writes the target's property directly via `User.save()` (public). Green at spec. |
| External consumer | A human admin, in a browser, on a stress call at 2am, clearing a colleague's factors without breaking the colleague's working phone | IT case 3 (the journey); the `confirm()` dialog; the roster's locked-out/expired columns; the two verbs being distinct | Journey scripted as an IT (case 3). Dialog and columns designed above. **Deferred:** real-browser walk of the admin page on the dev instance post-landing (the postmortem discipline: the IT is the harness; the walk is the acceptance — see §10). |
| Environments | Dark + light theme (both themes broke the login page in post-rollout round 5); Jenkins 2.528.3 baseline; the plugin directory's existing CSS | The login page's theme-aware fix (commit history); the new page uses the same class names / `j:out` tags as the two live pages | The admin page deliberately reuses the two live pages' visual vocabulary (no new CSS palette) so theme risk inherits their proven fix. **Deferred:** both-theme render check in the acceptance walk. |
| Privilege | Least-privileged consumer: a user with *no* ADMINISTER; and the enrolled-but-unenrolled-admin edge (§4) | IT case 6 (no-ADMINISTER 403 at wire + page); the seam quadrilateral | Spec'd; **deferred to landing:** the unenrolled-admin-reads-only-cannot-write behaviour is a *ruling* (§9) before case 6's second half is pinned. |
| Time | Best case (one click), worst case (the admin clears the wrong user — the roster must be unambiguous: user id + masked mailbox + which factors are present, all in the row next to the button), impatient (double-click clears) | Roster layout above; the JS POSTs are single-flight (button disabled during flight, the six-endpoints' JS already does this) | Designed; the double-click idempotency is a free consequence of the JSON contract (a second clear on an already-cleared user is `not_enrolled`, not an error state — the IT asserts that shape in case 3's tail). |
| Restart | What survives: the target's cleared property (persisted by `target.save()`); the admin's trust (untouched — the admin keeps their session + their browser trust; clearing a *victim* never touches the admin); what breaks: nothing by design (the one destructive op is persisted or it says so, §5) | IT case 3's post-clear victim re-login (the box keeps running; the property is on disk); the §5 honesty rule | Green at spec at the seam level; the full restart leg (clear → `rule.restart()` → victim login → re-enroll) **joins IT case 3 before landing** — the postmortem's restart lesson is not negotiable for a credential-clearing op. |

## 9. Rulings (mads, 2026-08-23) — received and binding

1. **Shape: (A) new page** — "new page for sure". Implemented as specified:
   `MfaAdminController` at mount `/mfaAdmin`, separate surface, six profile
   endpoints untouched.
2. **Verb set: clear-all + revoke-trust only — "yes, for now"**, explicitly
   provisional (see ruling 4: a third verb — force-enrol — is the follow-up
   that reuses this page, plus a first-time-login MFA setup screen; both
   deferred by mads).
3. **The unenrolled-admin edge: DENY.** An admin account with no enrolled
   factor can read the roster (ADMINISTER) but cannot clear/revoke — the
   spec's "you must be able to hold a credential to clear credentials" line
   holds. Pinned by the seam quadrilateral + an IT.
4. **Roster scope: enrolled-only — FOR NOW**, because the *next* item reuses
   this roster as the force-enrolment surface (a checkbox + save that enrols
   a factor for an unenrolled user — a THIRD verb beyond ruling 2 — plus a
   first-time-login MFA setup screen). Two design consequences for THIS
   landing, chosen so the follow-up does not force a rework:
   - the roster render model is a pure row-list built from the live users,
     so the third verb can add checkbox state/columns without a new page;
   - the endpoints take `userId` + operation, not a row-index, so per-row
     future actions map to the same wire shape.
   The follow-up is tracked in TECH_DEBT as a successor item (A24), not
   implemented here.
5. **Destructive-verb UX: 100% typed user-id confirmation** — mads: "100%
   user typed confirmation". The `clearFactors` form requires typing the
   target user's exact id before the POST fires, and **the endpoint
   re-checks the typed value matches the target server-side** (typed-id is
   not just UX — a client-side-only check is bypassable). `revokeTrust` takes
   the same typed-id confirmation: one rule for the whole surface, no
   lighter confirmation hiding behind a "less destructive" label.

The five original questions this resolved remain recoverable from git history
(this file's first revision); the rulings above are the binding record.

## 10. Acceptance (definition of done, per the postmortem discipline)

Landing is not the IT being green. Done =

1. `mvn clean verify` CI-green (the precondition);
2. IT case 3 (recovery journey incl. the `rule.restart()` leg) green;
3. the full admin journey walked in a **real browser on the dev instance**:
   log in as admin → verify → open `/mfaAdmin` (both themes) → clear the
   sacrificial test user's factors → that user logs in with password only →
   re-enrolls → restart → both paths survive; plus the least-privilege leg:
   a non-ADMINISTER account is refused the page and the wire;
4. README's known-gap paragraph replaced with the shipped description,
   same commit;
5. TECH_DEBT A22 resolved with the commit stamped;
6. every test BDD-documented per AGENTS.md; the §7 case 4 red phase is on
   record (written first, run red, then fixed).

The external-review gate (Moldy's pass over the A22-b diff) is assumed at
the same standard as A23's review: it found the A23-class hole in *this
exact endpoint family*; an admin surface that mutates another user's
credential state is the last place a shape like CRITICAL-1 hides.
