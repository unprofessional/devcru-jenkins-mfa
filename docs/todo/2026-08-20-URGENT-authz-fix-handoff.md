# 🚨 URGENT — authorization fix handoff (blocks Task 10)

**Written 2026-08-20 by Moldy** (external security review, mads-directed).
**Priority: URGENT. Nothing else — including Task 10 — proceeds until this
fix lands and is green.**

**Read first:** `AGENTS.md` (repo rules), then this doc top to bottom. It is
self-contained: findings, evidence with file:line, the exact fix shape, and
the test contract are all here.

---

## 0. Why this exists

Moldy reviewed the plugin end-to-end on 2026-08-19 (every security-critical
file, plus jenkins-core 2.528.3 bytecode, plus an independent
`mvn -o clean verify` — 94/94 green, exit 0). Verdict: crypto, session
handling, redirect validation, rate limiting, and the gate mechanics are all
sound. **One critical authorization flaw found** (two attack variants, one
root cause). Tracked as **A23** in `TECH_DEBT.md`.

## 1. Root cause

`MfaFilter.ALLOWED_PREFIXES` (MfaFilter.java:130–137) contains the bare
prefix `"/mfa"`, and `isAllowedPath` (MfaFilter.java:349–363) matches with
`startsWith`. That exemption exists so gated-unverified sessions can reach
the verify page and `postVerify` — but it passes **every** path under `/mfa`,
including all six Task 9 management endpoints:

`postEnroll` · `postEnrollConfirm` · `postEmailTestCode` ·
`postDisableTotp` · `postDisableEmail` · `postRevokeTrust`

None of the six checks whether the session has passed MFA. `/crumbIssuer`
is also allow-listed, so a gated-unverified session can obtain a CSRF crumb.

**The code believes it is protected and is wrong:** the
`postDisableTotp`/`postDisableEmail` javadoc claims "an enrolled, gated,
unverified session cannot reach these endpoints at all." That is false.
Worse, `MfaProfileIT.allSixProfileEndpointsAreRoutedNot404` logs in as an
enrolled user, skips TOTP verification entirely, and successfully POSTs all
six endpoints with 200s — the test suite pins the hole as intended behavior.

## 2. Attack chains

**CRITICAL-1 — factor stripping (no brute force, two requests):**
attacker holds the victim's password (the exact threat MFA exists for) →
logs in → gate 302s to `/mfa` → attacker POSTs `/mfa/postDisableTotp` and
`/mfa/postDisableEmail` (crumb from `/crumbIssuer`) → both factors wiped →
`isMfaEnabled()` is false → gate passes the session through. Full account
access. MFA defeated entirely. This also contradicts the README's stated
design ("no self-service 'reset everything,' by design").

**CRITICAL-2 — seed-swap brute force (same root cause):**
`postEnrollConfirm` is reachable pre-verify and has **no rate limiting**
(`RateLimiter` only guards `postVerify`). An attacker submits their OWN
candidate seed plus guessed 6-digit codes; when a guess matches the
attacker's seed, `confirmEnrollDecision` commits it — replacing the
victim's TOTP factor with attacker-controlled material. With window ±1,
≈3 valid codes per 10⁶ → ~333K attempts expected for 50% success (≈1 hour
at 100 req/s). Outcome: persistent access; the victim's authenticator
silently stops working. The code comment justifying the missing throttle
("only wastes the presenter's own patience") is the wrong frame: the
presenter is not necessarily the account owner.

(`postEmailTestCode` and `postRevokeTrust` pre-verify are nuisance-only:
inbox spam at one mail/minute and trust revocation. Same fix covers them.)

## 3. The fix (required shape)

One guard, applied at the top of all six management endpoints, BEFORE any
state mutation:

```java
// 403 unless this session has already proven a factor (postVerify sets
// VERIFIED_ATTR) OR holds live device trust (trust was granted by a prior
// successful verification — an attacker with only the password has neither).
if (isMfaEnrolled(user)
    && !Boolean.TRUE.equals(request.getSession(false) == null ? null
        : request.getSession(false).getAttribute(VERIFIED_ATTR))
    && !trustLive(prop, now)) {
  return 403 {ok:false, error:"verification_required"};
}
```

Why this exact shape:

- **`isMfaEnrolled(user)` first** — unenrolled users are passed by the gate
  and must keep self-enrollment access; their sessions never carry
  `VERIFIED_ATTR`, so the guard must let them through.
- **`VERIFIED_ATTR`** (`"org.sebcru.mfa.verified"`, MfaController.java:145)
  is the same attribute the gate reads (MfaFilter.java:391) — one source of
  truth, no new session state.
- **`trustLive(prop, now)`** (property `trustedUntilMs` vs now, same logic
  the gate uses) — trusted-device sessions already proved a factor within
  the trust window; without this clause the guard would break the legitimate
  disable/re-enroll flow from a remembered browser. An attacker with only
  the password cannot have trust: `trustedUntilMs` is only written by
  `postVerify` success.
- Factor write endpoints (`postDisableTotp`, `postDisableEmail`) MAY
  additionally require strict `VERIFIED_ATTR` (no trust clause) if mads
  prefers a harder line there — the default shape above is the minimum
  correct fix; ask before hardening beyond it.

Implementation notes:

- Extract the guard as a **pure seam** (e.g.
  `managementAllowed(prop, sessionVerified, trustLive)` → boolean) so it is
  unit-pinned without a booted Jenkins, per the repo's seam discipline
  (`MfaProfileSeamTest` is the pattern).
- **Fix the false javadoc** on `postDisableTotp`/`postDisableEmail` in the
  same commit — document the actual guard.
- `postVerify` and `postResendEmail` stay reachable pre-verify (that is the
  point of the allow-list). Do not touch them.
- **Optional same-commit hardening (recommended, one line):** remove the
  `@DataBoundSetter` from `MfaUserProperty.setTotpSecret` so `configSubmit`
  can never bind a seed — restores the documented invariant "the seed is
  committed only via `postEnrollConfirm`" (the config.jelly form does not
  bind it; nothing legitimate is lost).

## 4. Test contract (red→green, house rule)

1. **New IT first (must be RED before the fix):** an enrolled, gated,
   unverified session gets **403** from each of the six endpoints and the
   victim's factor state is byte-identical afterward (attack-chain pin —
   post `postDisableTotp` + `postDisableEmail`, assert `hasTotpFactor()` /
   `hasEmailFactor()` unchanged).
2. **Rework `allSixProfileEndpointsAreRoutedNot404`:** the routing pin stays,
   but from a **verified** session (prove the factor first, per §4.3 of the
   BLOCKED task-10 handoff). Its current pre-verify shape pins the hole and
   must not survive unchanged.
3. **Unit-pin the seam** (`MfaProfileSeamTest` style): enrolled+unverified+
   untrusted → deny; enrolled+verified → allow; enrolled+unverified+
   trust-live → allow; unenrolled → allow.
4. Full gate: `mvn -o -B -ntp clean verify` — all tests green AND SpotBugs
   clean (linter is a separate gate; see BLOCKED handoff §4.6).

## 5. Same-commit rule (non-negotiable here)

Code + tests + docs land together. In the fixing commit, also update:
- `TECH_DEBT.md` A23 → RESOLVED with the landed note (commit hash, what the
  guard checks, which ITs pin it).
- README security claims if any sentence is touched by the new behavior
  (the "no self-service reset" line becomes true — make sure it says so).
- This handoff: stamp it LANDED/RESOLVED at the top and move it to
  `docs/done/`.

## 6. Explicitly OUT of scope (do not bundle)

Minor findings from the same review — real, but not part of this fix;
mads rules on them separately:

- `setTotpWindow` has no clamp (negative value = total TOTP lockout;
  admin footgun, admin-only surface).
- `RateLimiter` javadoc "fresh burst after lockout expiry" is inaccurate
  (behavior is MORE restrictive than documented — safer, just wrong docs).
- `EmailCodeIssuer` EXPIRED-path comment/code discrepancy (cosmetic).
- `registeredEmail` binds from the security tab without mailbox
  verification (user picks their own delivery address; no access gain).

## 7. Definition of done

1. Guard seam implemented + unit-pinned; all six endpoints guarded.
2. Attack-chain IT green (was red first — honest red→green in the commit
   message, house rule).
3. `mvn -o -B -ntp clean verify` fully green, SpotBugs 0.
4. False javadoc fixed; TECH_DEBT A23 resolved; this handoff stamped and
   moved to `docs/done/`.
5. **Then** — and only then — pick up
   `docs/todo/2026-08-19-task10-handoff-BLOCKED.md` for the deploy.

---

*The full review record (everything verified sound, the bytecode-level
BearerTokenFilter check, the independent build run) lives in Moldy's
workspace: `reviews/jenkins-mfa/REVIEW-2026-08-19.md`. This handoff carries
everything needed to fix; the review carries everything needed to trust the
rest of the codebase.*
