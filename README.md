# devcru-mfa — Devcru Jenkins MFA plugin

Self-hosted MFA for Jenkins: **TOTP** (RFC 6238, Authy/Google Authenticator-compatible) and
**email one-time codes**, with **long remembered devices** (default 30 days, hard floor 24h),
no subscription, no third-party redirects.

Replaces the SaaS-branded 2FA plugin (email-only free tier, short trust, broken redirects,
paywalled UI) on `jenkins.devcru.org` (Jenkins 2.577, Local Security Realm).

## Status

Tasks 0–2 complete: toolchain + scaffold, RFC 6238 TOTP core (TDD against
RFC 4226/6238 vectors), and per-user factor state. The login gate,
enrolment/management UI, and email-code factor land per the plan
(`docs/plans/2026-08-17-jenkins-mfa-plugin.md`).

## Practical usage — what end users should expect

> The TOTP engine and per-user state below are implemented and tested; the
> gate, UI, and email-code pieces are in progress. Descriptions of login
> flow are the committed behaviour contract, not yet-shipped screenshots.

### Enrolling

- **TOTP:** the user scans a QR (or manually enters the 20-character secret)
  into *any* RFC 6238 authenticator — Google Authenticator, Authy, 1Password.
  No specific app, cloud account, or subscription is required.
- **Email codes:** the user registers one mailbox; no authenticator app
  needed.
- **At least one factor is required once enrolled; having both is allowed.** A
  TOTP-only user and an email-only user get identical gate protection.

### Day-to-day login

- Enrolled users enter their password, then a 6-digit code (TOTP rotates
  every 30 seconds) or an email-delivered one-time code.
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
  before comparison; pasting ` 284 361` from a clipboard still works.
- **Wrong, short, or garbled input.** Rejected cleanly as a wrong code —
  never a stack trace or a 500 on the login path. (Verification compares in
  constant time; there is no timing side channel to probe.) Failed attempts
  will count toward per-user rate limiting and temporary lockout
  (5 attempts / 15 min by default) — landing with Task 4.
- **Empty or whitespace-only forms.** A submit with blank TOTP/secret/email
  fields is treated as *not enrolled*, not as enrolled-with-nothing — forms
  cannot lock a user out by accident, and a whitespace email address is
  never treated as a delivery target.
- **Unenrolled users and service accounts.** MFA is mandatory only for users
  who have enrolled at least one factor (plus an exemption list for service
  accounts). Nobody is hard-locked before they've opted in, and headless
  automation on API tokens is unaffected.
- **Forging trust or resetting counters.** The trust expiry and failure
  counters are server-managed state; they are deliberately *not* bindable
  from the user's security-profile form. A crafted profile submit cannot
  grant itself a 30-day trust or zero out a lockout streak.
- **Lost everything (lost phone and mailbox).** Documented admin recovery
  path clears the user's stored factor state; the user re-enrolls. No
  self-service reset, by design.

### Storage and privacy

- The TOTP seed and the per-user email-code HMAC key are stored
  **encrypted at rest** with the Jenkins master key — not readable from
  `config.xml` even by someone with filesystem access.
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
