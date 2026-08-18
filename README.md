# devcru-mfa — Devcru Jenkins MFA plugin

Self-hosted MFA for Jenkins: **TOTP** (RFC 6238, Authy/Google Authenticator-compatible) and
**email one-time codes**, with **long remembered devices** (default 30 days, hard floor 24h),
no subscription, no third-party redirects.

Replaces the SaaS-branded 2FA plugin (email-only free tier, short trust, broken redirects,
paywalled UI) on `jenkins.devcru.org` (Jenkins 2.577, Local Security Realm).

## Status

Tasks 0–4 complete: toolchain + scaffold, RFC 6238 TOTP core (TDD against
RFC 4226/6238 vectors), per-user factor state, the email-code factor
(generation, hashing, single-use, expiry, resend throttle), and the two
gate brains — the remembered-device trust (24 h policy floor) and the
per-user rate limiter / lockout (sliding 30-minute failure window, 5
attempts, 15-minute lockout that cannot be extended by retries). The login
gate, enrolment/management UI, and mail delivery wiring land per the plan
(`docs/plans/2026-08-17-jenkins-mfa-plugin.md`).

## Practical usage — what end users should expect

> The TOTP engine, per-user state, and the email-code factor
> (generation, hashing, single-use, expiry, resend) are implemented and
> tested. The login gate, enrolment/management UI, and the mail delivery
> wiring land per the plan. Descriptions of login flow are the committed
> behaviour contract, not yet-shipped screenshots.

### Enrolling

- **TOTP:** the user scans a QR (or manually enters the 20-character secret)
  into *any* RFC 6238 authenticator — Google Authenticator, Authy, 1Password.
  No specific app, cloud account, or subscription is required.
- **Email codes:** the user registers one mailbox; no authenticator app
  needed. Codes are 8 characters from an unambiguous alphabet (no `0`/`O`,
  no `1`/`I`), so a code read off a phone at a busy desk is a code that
  verifies. Codes are single-use and valid for 5 minutes; a resend is
  available, throttled to one per minute.
- **At least one factor is required once enrolled; having both is allowed.** A
  TOTP-only user and an email-only user get identical gate protection.

### Day-to-day login

- Enrolled users enter their password, then a 6-digit code (TOTP rotates
  every 30 seconds) or an 8-character email-delivered one-time code.
- **Codes are always mailed to the registered mailbox on the account** —
  never to an address an attacker can point them at.
- **Remembered devices:** a successful MFA keeps the browser trusted for the
  configured window (default 30 days, never shorter than 24 h), so the code
  is not re-demanded on every visit. API tokens are exempt — CI keeps working.

### Corner cases, and how they are handled

- **Clock-skewed phone.** TOTP verification accepts the current step plus one
  adjacent step on each side. A device whose clock is off by up to ~30 s
  still verifies — old phones and NTP-less managed devices don't produce
  "wrong code" noise. The window is fixed, so an attacker does not collect
  extra valid codes by waiting.
- **Copy-pasted codes.** Surrounding and embedded whitespace is stripped
  before comparison; pasting ` 284 361` from a clipboard still works. Email
  codes match case-insensitively — a mail client that folds to lowercase (or
  a phone's autocorrect doing it) does not produce a wrong code.
- **Wrong, short, or garbled input.** Rejected cleanly as a wrong code —
  never a stack trace or a 500 on the login path. (Verification compares in
  constant time; there is no timing side channel to probe.) The rate limit
  counts *dense* bursts, not bad days: 5 wrong codes inside any rolling
  30-minute window lock the user out for 15 minutes, with a live
  "try again in N seconds" countdown. The window slides — failures from an
  hour ago don't count — so a genuinely clumsy user is not punished hours
  later, and a slow drip that never exceeds 5 per 30 minutes is never
  locked (acceptable: each single wrong-code attempt is a 1-in-a-million
  TOTP guess, and the lockout exists to make dense automated brute force
  uneconomical, which it does).
- **A locked-out user is not held hostage.** The 15-minute lockout runs
  from the moment it trips and cannot be extended by further wrong
  attempts — an attacker who knows your username cannot keep your lockout
  rolling forever by re-submitting codes during the countdown. The
  countdown always ends.
- **A code sits in someone's inbox.** That is exactly the threat model: an
  email can be forwarded, spoofed back, or typed from a shared family
  mailbox. So every email code is **single-use** — the first successful
  verification kills it, and replaying the email's code gets nothing.
- **A code outlives the moment it was needed.** Codes expire 5 minutes after
  issue; an expired code is not "old but valid" — the pending state is
  cleared, so resubmitting the old email's code cannot succeed. The remedy
  is one resend (cooldown permitting).
- **Resend button as a spoofer's mail bomb.** A failed-login attacker who
  wants to harass the real user by hammering "resend code" is throttled: at
  most one fresh code per minute, and each resend retires the previous code
  — an attacker can never keep several live codes in play.
- **Stealing codes off the server.** Email codes are never stored; what is
  kept is a per-user-keyed hash (`sha256(HmacSHA256(code, key))`), so
  filesystem or `config.xml` access yields no usable codes, and one user's
  state cannot be cross-checked against another user's.
- **Empty or whitespace-only forms.** A submit with blank TOTP/secret/email
  fields is treated as *not enrolled*, not as enrolled-with-nothing — forms
  cannot lock a user out by accident, and a whitespace email address is
  never treated as a delivery target.
- **Unenrolled users and service accounts.** MFA is mandatory only for users
  who have enrolled at least one factor (plus an exemption list for service
  accounts). Nobody is hard-locked before they've opted in, and headless
  automation on API tokens is unaffected.
- **Forging trust or resetting counters.** The trust expiry, failure
  counters, and pending-code state are server-managed; they are
  deliberately *not* bindable from the user's security-profile form. A
  crafted profile submit cannot grant itself a 30-day trust, zero out a
  lockout streak, or submit a crafted pending code.
- **Lost everything (lost phone and mailbox).** Documented admin recovery
  path clears the user's stored factor state; the user re-enrolls. No
  self-service reset, by design.

### Storage and privacy

- The TOTP seed, the per-user email-code HMAC key, and the pending-code
  hash are stored **encrypted at rest** with the Jenkins master key — not
  readable from `config.xml` even by someone with filesystem access.
  Email codes themselves never touch disk.
- The registered mailbox is stored in plain text on purpose: it is a
  delivery address, not a credential, and an admin investigating a lockout
  should be able to see it.
- Everything stays on this host. No SaaS backend, no third-party redirect,
  no telemetry, no phone home.

### What users will never see

- No paywalled features (the paid-search/filter UI of the plugin it replaces
  is just… there).
- No SMS, no WebAuthn/passkeys, no hardware keys — deliberately out of scope.
- No "re-auth every few hours" churn: the trust window is days, floored at
  24 h, configurable.
- No broken post-login redirect: MFA completion returns to the requested
  page, built from the live context path and crumb.

## Build

Java 21 + Maven 3.9+:

```bash
mvn package        # → target/devcru-mfa.hpi
```

## Workflow

All development on `develop`; `master` advanced only on explicit mads approval per step.

**Testing standard: required BDD documentation for every test** — see [AGENTS.md](AGENTS.md).
