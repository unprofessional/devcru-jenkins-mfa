# A24 spec delta — force-enrol view + third verb + first-time MFA setup

> **Status: DRAFT — rulings needed (§8). Spec-first; nothing implemented.**
> **Branch:** `a24-spec-delta` (off `develop`, post-A22-b/§1-D)
> **Debt entry:** `docs/todo/TECH_DEBT.md` § "Not in the code yet" — **A24**
> **Named because:** A22-b Ruling 4 scoped the roster **enrolled-only — FOR
> NOW**, explicitly because this follow-up reuses that roster as the
> force-enrolment surface. The handoff (§1-C) is binding on process:
> spec + mads's rulings BEFORE any implementation, and the real-browser
> acceptance MUST run on qwen3.8:27b and state so.
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

- One surface: `MfaAdminController` at `/mfaAdmin`. No new controller, no
  new mount, no filter changes beyond nothing — `mfaadmin` is already in
  the `isSecurityPath` carve-out.
- Third verb rides the existing POST contract: `@RequirePOST` +
  `@WebMethod(name = "forceEnrol")`, parameters `userId` +
  `confirmUserId` (typed-id confirmation, Ruling 5 applies verbatim —
  one rule for the whole surface, no lighter confirmation hiding behind a
  "less destructive" label).
- The §4 seam grows one guard input, not a new seam (§5).

## 3. The complement view (fixing the empty roster)

When `DevcruMfaConfig.current().getPolicy() == REQUIRED`, the page renders
**two rosters**:

- **Enrolled** — the existing `AdminRow` list, unchanged (recovery verbs).
- **Not enrolled** — the complement: users carrying either no
  `MfaUserProperty` or one where `isMfaEnabled()` is false. Row model is
  `AdminRow` narrowed (id, display name, masked mailbox-or-"(none)",
  factor columns all "—") plus one new column: **enrolment state**
  ("never enrolled" vs "pending setup" — see §4).

Under `Policy.OFF` the complement section is hidden entirely: with the gate
killed, "who isn't enrolled" is a compliance question, not a security one,
and rendering it would make the page a user-directory for no protective
purpose. (This preserves the A22-b rationale for enrolled-only scope under
OFF; REQUIRED is what turns the complement from directory into duty.)

The same read-plane rules apply: `User.getAll()`, get-only, no
`getOrCreate`, masked mailboxes, stable sort, safe-degradation to empty on
bootstrap-time RuntimeExceptions.

## 4. The third verb — force-enrol

### 4.1 What the verb does (and deliberately does not do)

`POST /mfaAdmin/forceEnrol?userId=<u>&confirmUserId=<u>&email=<mailbox>`:

- Writes ONLY `registeredEmail` on the target's property (creating the
  property if absent — the one sanctioned `getOrCreate`, inside the same
  single-writer endpoint), then `target.save()`.
- Effect: `isMfaEnabled()` flips true (email factor present), the gate now
  treats the target as enrolled, and the target has **no live trust and no
  verified session** — their very next request is bounced to `/mfa` for
  first-time setup (§6).
- It does NOT: generate or set any secret, touch `totpSecret`,
  `pendingCodeHash`, `trustedUntilMs`, or any session attribute; mark the
  user verified; grant trust. **Force-enrol creates an obligation to
  verify; it can never create a proof of verification.** The admin's
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
Audit line, loud-not-silent:
`WARNING MFA admin <actor> force-enrolled user <target> (email factor)`.

### 4.3 Guard extension

Existing ordering (permission → user → self → verify) gains one branch;
the seam signature becomes
`adminAllowed(..., isSelf, sessionVerified, trustLive, targetAlreadyEnrolled)`:

- `isSelf` → denied exactly as today (`self_management_forbidden`) — an
  admin enrols themselves through their own profile tab like everyone else.
- `targetAlreadyEnrolled` → `{ok:false, error:"already_enrolled"}` — the
  double-click/idempotency shape mirrors `not_enrolled` on clearFactors.
- Mailbox validation: same mask/format rule as the self-service save path;
  invalid → `invalid_email`; blank → refused (blank would silently
  un-enrol, which is clearFactors' job, single-writer rule).

## 5. Edge cases

| Case | Behaviour |
|---|---|
| Already-pending user (property exists, `registeredEmail` set, never verified) | Force-enrol with the SAME address → idempotent `already_enrolled` ok-envelope? No — treated as a **re-enrol update**: a different address replaces `registeredEmail` (single field write, `save()`), audit-logged as an update; the same address short-circuits `already_enrolled`. Rationale: the admin fixing a typo'd mailbox must not have to clear the user's whole state first. **Ruling needed — D3.** |
| Disabled/deleted user | `user_not_found` for missing; a disabled-in-realm user gets the same treatment as any existing user (the gate handles disabled accounts upstream; the admin surface does not duplicate realm policy). No oracle difference beyond the existing strings. |
| Target mid-session when force-enrolled | Their current session carries no VERIFIED_ATTR and no trust (they were unenrolled, so they could never earn either). Next request → gate bounces to `/mfa`. No session invalidation is sent and none is needed — the gate does the work per-request. Pinned in IT (leg 3 tail): a live pre-existing session of the target is bounced, not waved through. |
| Actor persistence failure | §5 of the parent spec verbatim: `{ok:false, error:"persistence_error"}` + SEVERE log. Never `ok:true` over an unpersisted enrolment — worse here than in recovery: the admin believes the user is covered, the user believes they're exempt, both wrong. |
| Rollback / off switch | Two levels, both existing seams: per-user, the admin runs `clearFactors` (A22-b verb 1) — force-enrol leaves no residue it doesn't share with normal enrolment; fleet-wide, `Policy.OFF` is the kill-switch path and hides the complement view (§3). No new undo machinery. |
| Unenrolled-admin actor | Ruling 3 (A22-b) binds unchanged: reads yes, mutates no — `verification_required`. |

## 6. First-time MFA setup flow (post-enforcement)

Entry point: the **existing** gate bounce. An enrolled-but-never-verified
session hitting anything lands on `/mfa` exactly as a locked-out user does
— no new URL, no allow-list change, no new decision chain. What's missing
today is presentation, not mechanics: `/mfa` currently assumes "you have a
factor, prove it".

Delta: when the arriving session's property has a registered mailbox but
zero completed verifications ever (`lastVerifiedFactor` unset AND no live
trust — a cheap, honest "first time" signal derived from existing fields),
`MfaController`'s page renders the **setup variant**:

1. Explains the state in one sentence: your administrator enabled MFA for
   your account; finish setup to continue.
2. Step 1: request + enter an email code (existing endpoints, untouched
   semantics — issue-code and verify run exactly as today).
3. Step 2 (nudge, not wall): after email verification succeeds, offer TOTP
   enrolment inline ("add an authenticator now"); skippable — the user is
   legitimately enrolled on email alone. Skipped-TOTP is recorded nowhere;
   no nag-state field is added.
4. On success the existing verify path sets VERIFIED_ATTR / issues trust
   exactly as any other verification. Nothing about setup bypasses
   verification because setup IS verification — the variant is copy plus
   step order, not new authorization.

Security pins carried explicitly:

- Setup variant renders only for the session's OWN property (self-service
  endpoints, unchanged guard).
- No endpoint may flip `lastVerifiedFactor` or issue trust except the two
  existing verify endpoints (single-writer invariant restated; the A23
  attack-chain IT family stays authoritative).
- Rate limiter, crumb, nosniff/no-store: untouched, inherited.

## 7. Acceptance criteria sketch

CI: `mvn clean verify` green (SpotBugs `check`, enforcer, JDK 21).

Unit (seam + models):

1. Extended `adminAllowed` quadrilateral×enrolment-state matrix — every
   THEN is the stable error string (`already_enrolled`,
   `self_management_forbidden`, `verification_required`, …).
2. Complement-row model: unenrolled user produces exactly one row with
   factor columns false and "(no mailbox)" masking; enrolled user appears
   in enrolled roster only; under OFF the complement getter returns empty.
3. First-time-signal derivation: mailbox+never-verified → true;
   previously-verified (even now cleared?) — pinned per D4 ruling.

Integration (`MfaAdminIT` legs added, red-first where genuine):

4. **Force-enrol journey:** verified admin force-enrols an unenrolled user
   with a mailbox → property shows email-only enrolment persisted
   (`rule.restart()` leg included, per the non-negotiable restart
   discipline) → target's pre-existing live session is bounced to `/mfa`
   on next request → setup variant renders → email code issued/captured/
   verified → target reaches root → `lastVerifiedFactor` set by the verify
   endpoint alone.
5. **Guard pins:** self-target 403; already-enrolled target envelope;
   password-only admin 403 `verification_required` with the target's bytes
   identical before/after; non-admin 403 at the wire; typed-confirm mismatch
   refused server-side.
6. **Setup-does-not-bypass pin:** the setup variant's rendered page offers
   no link/form reaching authenticated root content; a direct fetch of a
   protected URL from the half-set-up session is still gated.

Real-browser acceptance (handoff §1-C, binding): walked on the dev instance
**on qwen3.8:27b, stated in the report** — both themes, force-enrol click-
through incl. typed confirm, target's first-login setup walk end-to-end in
headful Chromium, OFF-switch hiding the complement, context-rooted script
URL check under a non-root context path.

Docs: README known-gap/A24 paragraph replaced in the landing commit;
TECH_DEBT A24 moves to Resolved with the commit stamped.

## 8. DECISIONS — rulings needed from mads

Each with recommended default; silence-on-review takes the default per house
process.

1. **Complement-view visibility:** show the not-enrolled roster only under
   `Policy.REQUIRED` (recommended: yes — under OFF it's a user-directory
   with no protective purpose; preserves the A22-b enrolled-only rationale
   in the OFF case). Alternative: always show both rosters.
2. **Force-enrol writes email factor only** (recommended: yes — TOTP
   admin-side is a lockout generator; TOTP stays self-service). Alternative:
   allow admin-paste TOTP secret (rejected in design; would need ruling).
3. **Re-force-enrol with a different mailbox updates the address** rather
   than demanding clear-first (recommended: yes — typo-fix ergonomics;
   audit-logged as an update). Same-address repeat returns
   `already_enrolled`.
4. **"First time" signal definition** for the setup variant: mailbox set +
   `lastVerifiedFactor` unset + no live trust (recommended). Note the odd
   corner it implies: a user whose factors were admin-cleared AFTER a prior
   verification will NOT see the setup variant (they've seen `/mfa` before)
   — acceptable; alternative is a persistent `everVerified` flag, which adds
   a schema field for cosmetics.
5. **Skip-TOTP-after-email-setup is allowed** (recommended: yes — email
   alone is legitimate enrolment per `hasEmailFactor()`; TOTP push stays a
   nudge). Alternative: make TOTP mandatory at setup (a policy question
   larger than A24).
6. **Complement roster includes users with a property-but-blank-mailbox
   rows showing "(no mailbox)"** (recommended: yes — they're exactly the
   users needing enrolment; the admin fills the mailbox in the form).
7. **Verb name on the wire: `forceEnrol`** (recommended; matches house
   naming, unambiguous in audit lines). Alternative: `enrolUser`.

---
*Ruling record goes here once received, A22-b §9 style.*
