# A24 spec delta — force-enrol view + third verb + first-time MFA setup

> **Status: APPROVED — all 16 §9 decisions ruled AS RECOMMENDED (mads, 2026-08-25). Implementation authorized.**
> **Branch:** `a24-spec-delta` (off `develop`, post-A22-b/§1-D)
> **Debt entry:** `docs/todo/TECH_DEBT.md` § "Not in the code yet" — **A24**
> **Named because:** A22-b Ruling 4 scoped the roster **enrolled-only — FOR
> NOW**, explicitly because this follow-up reuses that roster as the
> force-enrolment surface. The handoff (§1-C) is binding on process:
> spec + mads's rulings BEFORE any implementation, and the real-browser
> acceptance MUST run on `qwen3.8:27b-mtp-q8_0` and state that exact model.
> This document is a **delta**: everything in
> `2026-08-23-A22b-admin-factor-management-spec.md` not modified here stands.

## 1. The problem, precisely

Three gaps, all downstream of fleet-wide enforcement (`Policy.REQUIRED`):

1. **The empty-roster problem.** Under REQUIRED the whole point is that
   *everyone* should be enrolled — but `/mfaAdmin` lists only enrolled
   users, so on a compliant box the admin's recovery page renders empty,
   and on a partially-compliant box the admin has **no view of who is
   still unenrolled** — the exact population they need to act on. The debt
   entry calls this out by name: the empty-roster state is expected, not a
   defect, but expected-and-useless is still useless.
2. **No way to enrol anyone but themselves.** Enrolment today is strictly
   self-service (the six `/mfa` profile endpoints, `currentUser()` only).
   An admin who wants a specific user enrolled — onboarded contractor,
   service account owner who keeps forgetting, someone on a stress deadline
   — can only nag them in chat.
3. **First-time setup under enforcement has no designed entry.** When a
   user becomes enrolled *without having done the enrolment themselves*
   (verb 3 below), their next login must land them somewhere that walks
   them through completing setup — without ever letting them reach the rest
   of Jenkins unverified, and without the admin's action being readable as
   "the admin verified me".

## 2. Scope decision inherited from Ruling 4's shaping

Ruling 4 chose the row-list render model and the `userId`+operation wire
shape **specifically so this delta needs no new page and no wire-shape
rework**. Honoured here:

- One admin surface: `MfaAdminController` at `/mfaAdmin`. No second admin
  controller or roster model. `mfaadmin` is already in the
  `isSecurityPath` carve-out; any first-time setup routing/filter delta is
  specified separately in §6 and must remain token/segment precise.
- Third verb rides the existing POST contract: `@RequirePOST` +
  `@WebMethod(name = "forceEnrol")`, parameters `userId` +
  `confirmUserId` (typed-id confirmation, Ruling 5 applies verbatim —
  one rule for the whole surface, no lighter confirmation hiding behind a
  "less destructive" label).
- The existing actor-authorization seam stays unchanged; the new endpoint
  adds a pure target-state decision after the existing permission,
  credential, self-target, and typed-confirm checks (§4.3).

## 3. The complement view (fixing the empty roster)

When `DevcruMfaConfig.current().getPolicy() == REQUIRED`, the same pure row
list exposes three explicit rollout states (sections or filter views, per D9):

- **Enrolled** — `isMfaEnabled()` true and `forcedSetupPending` false; the
  existing recovery verbs remain.
- **Setup pending** — `forcedSetupPending` true. Under the recommended email
  design these rows already have an email factor, so `isMfaEnabled()` alone
  would misleadingly call them complete; they stay separately visible until
  the target actually verifies.
- **Not enrolled** — no live factor and no pending marker: the true complement
  that carries the force-enrol control.

All rows keep exact id, display name, masked mailbox-or-"(none)", explicit
factor indicators (TOTP/email/none), **rollout state** (enrolled/setup
pending/not enrolled), and **account state** (active/disabled/unknown).
Factor reality, rollout obligation, and account status must be separate labels
so an admin can see why a row is actionable. Visible counts and honest
zero-state copy for all three prevent an empty table from looking like a read
failure.

Under `Policy.OFF` the not-enrolled complement is hidden by the recommended
D9 ruling: with the gate killed, it is a directory rather than an enforcement
worklist. Already-enrolled rows remain the recovery roster, and a pending
marker remains visibly labelled there even though OFF does not block its user.

The same read-plane rules apply: `User.getAll()`, get-only, no
`getOrCreate`, masked mailboxes, stable sort, safe-degradation to empty on
bootstrap-time RuntimeExceptions.

## 4. The third verb — force-enrol

### 4.1 What the verb does (and deliberately does not do)

`POST /mfaAdmin/forceEnrol` with crumb-bearing form fields
`userId=<u>`, `confirmUserId=<u>`, and `email=<mailbox>`. This reuses the
existing request shape and 200 JSON success envelope:

```json
{"ok":true,"op":"forceEnrol"}
```

The existing 403 `admin_permission_required` /
`admin_verification_required` and 200 JSON business-denial conventions remain
unchanged. The mutation then:

- Writes `registeredEmail` plus a non-secret `forcedSetupPending` marker on
  the target's property (creating the property if absent — the one sanctioned
  `getOrCreate`, inside the same single-writer endpoint), then one
  `target.save()`.
- Effect: `isMfaEnabled()` flips true (email factor present), the marker
  distinguishes admin-forced setup from ordinary enrolled state, and the
  target has **no live trust and no verified session** — their very next
  request is bounced to `/mfa` for first-time setup (§6).
- It does NOT: generate or set any secret, touch `totpSecret`,
  `pendingCodeHash`, `trustedUntilMs`, or any session attribute; mark the
  user verified; grant trust. The marker clears only after successful factor
  verification persists, or through the ruled rollback path.
  **Force-enrol creates an obligation to verify; it can never create a proof
  of verification.** The admin's
  action is unreadable as "the admin vouched for this session" — the
  target still has to produce a real factor check before anything else
  happens. This is the load-bearing security line of the whole feature.

Why email-only enrolment: TOTP enrolment requires the *user's* authenticator
scan — an admin-generated TOTP secret the user never scanned into a device
is a lockout generator, not an enrolment. Email enrolment uses the mailbox
the admin supplies and the user proves control of at first verification.
TOTP remains available (and encouraged) as self-service add-on afterwards.

### 4.2 Admin UX

On each complement-row: a mailbox field + button. Confirm dialog states the
consequence plainly ("<id> will be required to complete MFA setup at their
next login"). Typed-id confirmation required, server-rechecked (Ruling 5).
On success the row moves from `Not enrolled` to `Setup pending`, counts
update, and reload derives the same result from persisted state. Audit line,
loud-not-silent:
`WARNING MFA admin <actor> force-enrolled user <target> (email factor)`.

### 4.3 Guard and target-state extension

The existing actor seam remains
`adminManageAllowed(administer, enrolled, sessionVerified, trustLive)`.
The endpoint follows today's order: `answerAdminDenied` (permission then
credential) → `denyOrConfirmError` (self-target then exact typed id) →
non-creating target lookup → target-state decision → mutation/save. Target
state must not be folded into the actor-authorization seam.

- Self-target is denied exactly as today
  (`admin_self_management_forbidden`) — an admin enrols themselves through
  their own profile tab like everyone else.
- An ordinarily enrolled target returns `{ok:false,
  error:"already_enrolled"}`. A target already carrying
  `forcedSetupPending` follows the D5 idempotence/correction ruling.
- Mailbox validation is an A24 endpoint contract (the current property
  setter normalizes blank state but is not an address validator): syntactically
  invalid → `invalid_email`; blank → refused (blank would silently un-enrol,
  which is `clearFactors`' job, single-writer rule). Address ownership is
  proved only when the target enters the code delivered to that registered
  mailbox; the admin's POST proves no mailbox control.

## 5. Edge cases

| Case | Behaviour |
|---|---|
| Already-pending user (`forcedSetupPending` true) | Same address short-circuits idempotently; a different address is an explicit **pending-enrolment correction**: replace `registeredEmail`, keep the marker true, clear any pending email-code state tied to the old mailbox, save once, and audit the update. Rationale: fixing a typo must neither require factor-clear first nor leave an old-address code live. **Ruling needed — D5.** |
| Disabled/deleted user | `user_not_found` for missing. Recommended pending D6: a positively disabled realm user remains visible with a Disabled indicator but force-enrol is refused; unknown realm status is labelled honestly and cannot 500 the roster. |
| Target mid-session when force-enrolled | Their current session carries no VERIFIED_ATTR and no trust (they were unenrolled, so they could never earn either). Next request → gate bounces to `/mfa`. No session invalidation is sent and none is needed — the gate does the work per-request. Pinned in IT (leg 3 tail): a live pre-existing session of the target is bounced, not waved through. |
| Actor persistence failure | §5 of the parent spec verbatim: `{ok:false, error:"persistence_failed"}` + SEVERE log. Never `ok:true` over an unpersisted enrolment — worse here than in recovery: the admin believes the user is covered, the user believes they're exempt, both wrong. |
| Valid setup code but marker-clear save fails | Recommended pending D16: return `persistence_failed`, leave setup pending, issue no trust/verified-session success, and log loudly without the code/address. This deliberately tightens the current ordinary-verify save-failure behavior for the forced setup branch so "setup complete" survives restart or is not claimed. |
| Rollback / off switch | Per-user, recommended D8: `clearFactors` also clears `forcedSetupPending` in the same save. Fleet-wide, `Policy.OFF` is the immediate gate kill switch and hides the complement view (§3); it does not delete factors or markers. |
| Unenrolled-admin actor | Ruling 3 (A22-b) binds unchanged: reads yes, mutates no — `admin_verification_required`. |

## 6. First-time MFA setup flow (post-enforcement)

Entry point: the **existing** gate bounce. An enrolled-but-never-verified
session hitting anything lands on `/mfa` exactly as a locked-out user does
— no new URL, no allow-list change, no new decision chain. What's missing
today is presentation, not mechanics: `/mfa` currently assumes "you have a
factor, prove it".

Delta: when the arriving session's property carries
`forcedSetupPending`, `MfaController` renders the **setup variant**. Do not
infer first-time state from `lastVerifiedFactor`: the current field is a
factor enum (`0 = TOTP`, `1 = email`) whose default `0` is indistinguishable
from a real prior TOTP verification; expired trust likewise does not mean
"never verified." The explicit marker is the honest signal:

1. Explains the state in one sentence: your administrator enabled MFA for
   your account; finish setup to continue.
2. Step 1: request + enter an email code (existing endpoints, untouched
   semantics — issue-code and verify run exactly as today).
3. Step 2 (nudge, not wall): after email verification succeeds, offer TOTP
   enrolment inline ("add an authenticator now"); skippable — the user is
   legitimately enrolled on email alone. Skipped-TOTP is recorded nowhere;
   no nag-state field is added.
4. On success the existing verify path clears `forcedSetupPending`, grants
   trust, and persists those changes together before it regenerates/marks the
   session verified exactly as any other verification. Nothing about setup
   bypasses verification because setup IS verification — the variant is copy
   plus step order, not new authorization.

Security pins carried explicitly:

- Setup variant renders only for the session's OWN property (self-service
  endpoints, unchanged guard).
- No admin/setup endpoint may flip `lastVerifiedFactor` or issue trust;
  successful `postVerify` remains the single verification writer (the A23
  attack-chain IT family stays authoritative).
- Rate limiter, crumb, nosniff/no-store: untouched, inherited.

## 7. Acceptance criteria sketch

CI: `mvn clean verify` green (SpotBugs `check`, enforcer, JDK 21).

Unit (seam + models):

1. Extended `adminAllowed` quadrilateral×enrolment-state matrix — every
   THEN is the stable error string (`already_enrolled`,
   `admin_self_management_forbidden`,
   `admin_verification_required`, …).
2. Roster-state model: never-enrolled, setup-pending, and completed users
   each land in exactly one view; pending cannot be miscounted as completed
   merely because the forced email makes `isMfaEnabled()` true; under OFF the
   not-enrolled view is hidden without erasing pending state.
3. First-time-state derivation: `forcedSetupPending` alone selects setup;
   default/TOTP-valued `lastVerifiedFactor` and expired trust cannot
   impersonate or suppress that marker; marker clearing is pinned per D10.

Integration (`MfaAdminIT` legs added, red-first where genuine):

4. **Force-enrol journey:** verified admin force-enrols an unenrolled user
   with a mailbox → property shows email-only enrolment persisted
   (`rule.restart()` leg included, per the non-negotiable restart
   discipline) → target's pre-existing live session is bounced to `/mfa`
   on next request → setup variant renders → email code issued/captured/
   verified → target reaches root → `lastVerifiedFactor` set by the verify
   endpoint alone.
5. **Guard pins:** self-target refused with the existing 200 JSON envelope;
   already-enrolled target envelope; password-only admin 403
   `admin_verification_required` with the target's bytes
   identical before/after; non-admin 403 at the wire; typed-confirm mismatch
   refused server-side.
6. **Setup-does-not-bypass pin:** the setup variant's rendered page offers
   no link/form reaching authenticated root content; a direct fetch of a
   protected URL from the half-set-up session is still gated.
7. **Pending/idempotence:** same-address repeat is unchanged; corrected
   address invalidates the old pending code; two admin requests never mint a
   credential or clear the setup marker.
8. **Failure honesty:** wrong/expired email code, expired session, and
   marker-clear persistence failure do not release the user; successful
   verification clears the marker and survives `rule.restart()`.
9. **Policy/identity edges:** OFF, exempt, disabled, unknown-realm, and
   deleted-between-render-and-POST behavior matches §9 rulings and cannot
   create a user record on lookup.
10. **Regression:** existing clear/revoke, A23 management guards, safe
    redirect, non-root context, API-token exemption, and admin-factor survival
    stay green.

Real-browser acceptance (handoff §1-C, binding): walked on the dev instance
**on `qwen3.8:27b-mtp-q8_0`, stated exactly in the report** — confirm the
active model before and after the walk; then cover both themes, force-enrol
click-through incl. typed confirm, target's first-login setup walk end-to-end in
headful Chromium, OFF-switch hiding the complement, context-rooted script
URL check under a non-root context path.

Docs: README known-gap/A24 paragraph replaced in the landing commit;
TECH_DEBT A24 moves to Resolved with the commit stamped.

## 8. Implementation sequence after rulings

This is a sequencing sketch, not authorization to implement:

1. Record every §9 ruling in this file and reconcile the body before code.
2. Add red pure tests for roster/state derivation and the expanded admin
   decision seam, including stable errors and deny-before-mutation.
3. Add the ruled persisted setup state and extend the existing
   `AdminRow`/`getRosterRows()` model into enrolled and complement views; do
   not create a second user index or mutate on GET.
4. Add the `forceEnrol` endpoint using the existing `userId` +
   `confirmUserId` wire, authorization order, persistence honesty, and audit
   pattern.
5. Add the first-time `/mfa` presentation/state branch without weakening A23
   guards or broadening the allow-list; reuse verification single-writers.
6. Add JenkinsRule journey/restart/session/off-switch coverage, then run the
   full offline CI mirror: `mvn -o -B clean verify`.
7. Update README practical usage and TECH_DEBT in the same user-facing
   implementation landing, per `AGENTS.md`.
8. Perform the §7 real-browser walk on `qwen3.8:27b-mtp-q8_0`, with before/
   after model confirmation and evidence in the report. No deployment, push,
   or PR without mads's normal explicit approval.

## 9. **DECISIONS — MADS'S RULINGS REQUIRED; IMPLEMENTATION BLOCKED**

Each item has a recommended default, not an answer-by-silence. Record an
explicit ruling for every item here before implementation begins.

1. **What force-enrol provisions. RECOMMEND: provision an email factor from
   an admin-entered mailbox plus a non-secret `forcedSetupPending` marker,
   but no TOTP seed; the target proves mailbox control with the delivered
   code before reaching Jenkins.** Alternative A: persist only an
   `enrolmentRequired` marker and make the user scan/prove a user-generated
   TOTP candidate. Alternative B: generate or accept a TOTP seed server-side/
   admin-side (not recommended: the admin now handles a credential and the
   user can be locked behind a seed they never scanned).

2. **Who chooses/proves the email address. RECOMMEND: the verified admin
   enters it, the server never echoes it unmasked after the POST, and the
   target proves ownership by receiving the code; the admin action itself is
   not verification.** Alternative: derive the mailbox from Jenkins' mailer
   property (needs a precedence/missing-address rule). If mads chooses the
   marker/TOTP design in D1, this decision becomes not applicable.

3. **Where first-time setup lives. RECOMMEND: the existing `/mfa` GET with a
   controller-selected setup variant and existing exact POST routes; no new
   mount and no broad `/mfa/*` allow-list.** Alternative: dedicated
   `/mfaSetup/` entry with its own exact allow-list and redirect-loop tests.

4. **Users who never complete setup / grace period. RECOMMEND: no grace
   period in A24.** Under REQUIRED they remain at `/mfa` until they verify,
   the admin clears factors, they are exempted/disabled, or policy switches
   OFF. If grace is wanted, mads must rule its duration, start event (admin
   POST or first login), warnings, expiry behavior, persistence, and who may
   extend it.

5. **Already-pending/re-force behavior. RECOMMEND: same mailbox returns an
   idempotent unchanged result; a different mailbox is an explicit audited
   correction that replaces `registeredEmail`, keeps `forcedSetupPending`,
   and invalidates any pending code for the old address.** Alternative:
   refuse every already-enrolled target and require `clearFactors` first. If
   D1 chooses a requirement-only marker, recommend repeated force returns
   unchanged and never generates a second candidate.

6. **Disabled/deleted/unknown-realm users. RECOMMEND: deleted-at-POST is
   `user_not_found`; positively disabled users remain visible with a
   `Disabled` indicator but cannot be force-enrolled; realm status that
   cannot be resolved is `Unknown`, not guessed active.** mads must identify
   the authoritative disabled signal on the deployed security realm or rule
   that disabled status remains out of scope. One failed realm lookup must
   never 500 the whole roster.

7. **Session/trust result. RECOMMEND: force-enrol does not invalidate a live
   target session itself; the gate catches its next request. Successful code
   verification uses the existing session-regeneration, VERIFIED_ATTR, and
   normal remember-browser behavior, so setup does not demand the same code
   twice.** Alternative: verify the session but suppress remembered trust on
   the first setup.

8. **Rollback/off switch. RECOMMEND: global `Policy.OFF` bypasses the gate
   immediately without deleting factors/markers; per-user `clearFactors`
   clears both the forced email factor and `forcedSetupPending`, and
   `exemptUsers` is the emergency exception.** Alternative: add a distinct
   cancel-pending operation. Rule an already-open setup page under OFF;
   recommended: it becomes optional (the user can leave for Jenkins), while
   a voluntarily submitted valid code may still complete normal verification.

9. **Complement visibility. RECOMMEND: under `REQUIRED`, show explicit
   Enrolled / Setup pending / Not enrolled views and counts; under OFF, hide
   only Not enrolled while retaining recovery rows and pending labels.**
   Alternative: show all three under OFF and REQUIRED. Under either choice,
   factors, rollout state, and account active/disabled/unknown are separate
   indicators, not one overloaded badge.

10. **How the setup variant is identified. RECOMMEND: persisted
    `forcedSetupPending`, cleared only by successful verification or the
    ruled admin rollback.** Existing `lastVerifiedFactor` cannot encode
    "never": `0` means TOTP and is also the Java default, while trust may
    simply have expired. Alternative: a broader persisted `everVerified` +
    enrolment-origin model (more state than A24 needs).

11. **Whether TOTP is mandatory after email verification. RECOMMEND: no;
    email is already a valid factor under `hasEmailFactor()`, so TOTP is a
    prominent but skippable post-verification nudge.** Alternative: require a
    user-scanned and code-proved TOTP before release, which makes setup a
    two-factor-provisioning policy and needs recovery rules.

12. **Exempt, service, and API-only identities. RECOMMEND: exempt users stay
    visible and labelled but their force action is disabled; preserve current
    API-token gate exemptions, so A24 governs interactive browser access and
    says so honestly.** Alternative: force-enrol overrides exemptions or
    blocks API tokens (larger compatibility/revocation scope). Decide whether
    historical/API-only `User.getAll()` records count toward compliance.

13. **Bulk rollout. RECOMMEND: no `Force all` in the first A24 landing;
    accurate complement visibility plus deliberate per-row writes first.** If
    bulk is required, rule eligible scope, preview, exclusions, confirmation
    phrase, partial-failure reporting, per-target audit, and rollback.

14. **Blank-mailbox roster rows. RECOMMEND: include every unenrolled
    `User.getAll()` record, including absent property/blank mailbox, rendered
    as `(no mailbox)` with the admin field available only when otherwise
    eligible.** Alternative: hide records that cannot be email-enrolled; not
    recommended because it recreates the empty-roster blind spot.

15. **Wire verb and confirmation. RECOMMEND: `forceEnrol`, with existing
    `userId` + exact `confirmUserId` + crumb and A22-b's typed-id dialog.**
    Alternative name: `enrolUser`. Do not weaken confirmation merely because
    no factor is deleted; the action can still lock an account behind setup.

16. **Valid verification but persistence failure. RECOMMEND: the forced
    setup branch returns `persistence_failed`, does not mark/regenerate the
    session as verified, and leaves `forcedSetupPending` true until a retry
    persists marker-clear + trust.** Alternative: preserve ordinary
    `postVerify` behavior (let the current session through and log the failed
    save), accepting that restart can present "first-time setup" again after
    the page claimed completion.

---
*Ruling record received 2026-08-25 (mads, Discord channel 1539025444295413770):
"ALL decisions approved AS RECOMMENDED." D1–D16 stand exactly as written above;
the recommended defaults are the binding rulings. No alternatives selected.*
