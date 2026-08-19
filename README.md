# devcru-mfa — Devcru Jenkins MFA plugin

Self-hosted MFA for Jenkins: **TOTP** (RFC 6238, Authy/Google Authenticator-compatible) and
**email one-time codes**, with **long remembered devices** (default 30 days, hard floor 24h),
no subscription, no third-party redirects.

Replaces the SaaS-branded 2FA plugin (email-only free tier, short trust, broken redirects,
paywalled UI) on `jenkins.devcru.org` (Jenkins 2.577, Local Security Realm).

## Status

Tasks 0–8 complete: toolchain + scaffold, RFC 6238 TOTP core (TDD against
RFC 4226/6238 vectors), per-user factor state, the email-code factor
(generation, hashing, single-use, expiry, resend throttle), the two gate
brains — the remembered-device trust (24 h policy floor) and the per-user
rate limiter / lockout (sliding 30-minute failure window, 5 attempts,
15-minute lockout that cannot be extended by retries) — the admin
configuration surface (Manage Jenkins → Security: policy, issuer, trust
windows, rate-limit knobs, exempt users), the MFA controller (the login
screen at the plugin's MFA page — `/mfa` on the live box, with its two POST
endpoints — TOTP or email
code verification, and email-code resend via Jenkins' standard Mailer — the
shape-based factor router, the open-redirect-safe "back to where you were"
redirect resolver, and session fix-up on success), and the MFA gate filter
itself: the request path the login flow actually takes, registered at
startup, that enforces the whole policy (kill switch, API-token exemption,
auth-flow/static allow-list, exemption list, unenrolled pass-through,
verified-session-OR-remembered-trust) and bounces everyone else to the MFA
page with their real destination carried in the URL. The gate's decision
table is unit-tested branch-by-branch; the filter's live-registration and
302 wiring are exercised by the plugin's own `InjectedTest` Jenkins-in-JVM
boot, which now runs with the filter active. Only the enrolment/management
UI (Task 9) remains outstanding per the plan in this repo ([`docs/plans/2026-08-17-jenkins-mfa-plugin.md`](docs/plans/2026-08-17-jenkins-mfa-plugin.md)).

Two Task 6 deviations from the plan sketch, both flagged in the commit and
in the code (a third, the mount move `securityRealm/mfa` → `/mfa`, is
recorded with Task 8 above): (1) the controller mounts as a
`hudson.model.RootAction` because `jenkins.model.GlobalAction` does not
exist in the resolved 2.528.3 core (its path was subsequently moved by
mads's Task 8 ruling — see above), and (2) `postResendEmail` takes no
destination parameter — codes go to the account's registered mailbox and
only there, so the resend button cannot be turned into an open mail relay.

**Task 7 (the gate):** registered as a servlet filter at startup, it enforces the gate on every request. The full decision chain (kill switch → API token → anonymous → core error pages → auth-flow/static allow-list → policy → exemption list → unenrolled → verified-session-OR-remembered-trust) is unit-tested branch-by-branch, and the plugin's own `InjectedTest` harness now boots a real Jenkins on every build with the filter live (Task 8's dedicated end-to-end IT builds on that). Landing Task 7 surfaced three corrections to the plan sketch (no `JenkinsUtil` in core 2.528.3 — current-user detection is via `User.get2(Jenkins.getAuthentication2())`; the api-token request-marker class sits in `jenkins.security.*`, not `hudson.security.*`; the filter must be `jakarta.servlet.Filter`, not `javax`), plus one deliberate extension: core error-page dispatches (404/500) are passed through so a broken URL is never turned into an MFA challenge loop.

**Task 8 (end-to-end IT of the live gate):** `MfaFilterIT` boots a real Jenkins (in-JVM, HPSR local realm with real password users — the production shape) and drives the *whole wire*: password login → gate 302 → MFA page → form POST → verified session → the protected page, plus a captured-mail round trip to the registered mailbox. It fired on **five defects while doing so**, all fixed (TECH_DEBT A16/A17/A18/A20 in the plugin, A19 in the harness itself): (1) *A16* — every request was evaluating its path as `/` — `getServletPath()` is empty in this filter position on 2.528.3 — a silent infinite-302 loop for every enrolled user, fixed with a `getRequestURI()` − context-path decomposition; (2) *A17* — the MFA page's mount `securityRealm/mfa` was **swallowed by the live local realm's own `ModelObject` mount** — a 404 for every enrolled user's gate bounce on any local-realm deployment (i.e. this one) — fixed by moving the mount to the single free segment **`/mfa`**, per mads's ruling of 2026-08-19 (controller, allow-list, redirect validator, unit pins, IT, and page all moved with it); (3) *A18* — the page emitted `<x:out>`, a tag that does not exist on this runtime's Jelly, and 500'd on render — now `j:out` (`jelly:core`, the escape tag core's own views use); (4) *A19* — the IT's own `rawGet` helper was silently following the bounce's 302, so four rounds of "the gate 404/500s" were actually the *destination* page's status — the gate's 302 was correct throughout; (5) *A20* — `postVerify`/`postResendEmail` had **no dispatch token at all** (Stapler auto-maps only get/is/do-prefixed methods, and `@RequirePOST` is policy, not routing), so the verify/resend buttons would have been dead for every user — now `@WebMethod`-declared with the exact tokens the page's JS already posts. The suite is green 7/7: TOTP flow with the `?redirect=` round trip (A5's booted assertion), the email-code flow to the registered mailbox only, the API-token attribute re-pin (A15's Bearer gap is documented in the case), the 5-wrong-code lockout, the policy-OFF kill switch, the remembered-device fresh login, and the error-dispatch no-loop guard.

## Project documentation (in this repo)

All project docs live under [`docs/`](docs/): `docs/plans/` holds
implementation plans, `docs/todo/` active work notes, `docs/done/` stale
docs with historical reference, and
[`docs/architecture/`](docs/architecture/README.md) the
architecture & design-decision record used to audit the code.

| File | What it is |
|---|---|
| [`docs/plans/2026-08-17-jenkins-mfa-plugin.md`](docs/plans/2026-08-17-jenkins-mfa-plugin.md) | The master implementation plan: tasks 0–10, the security-model decisions (mads-signed), and the per-task acceptance criteria. Read this before touching any task. |
| [`docs/done/2026-08-18-task7-handoff.md`](docs/done/2026-08-18-task7-handoff.md) | Landed Task 7's handoff note (gate filter): the re-verified 2.528.3-core API findings (incl. three corrections to the plan sketch — no `JenkinsUtil`, `jenkins.security.*` package, jakarta-only filter), the seams it used, the execution order, and the two registration deviations it turned into (`EXTENSIONS_AUGMENTED` not `STARTED`; plain `@Extension` not `hudson.Plugin`) — moved to `done/` when Task 7 landed. |
| [`docs/architecture/`](docs/architecture/README.md) | Architecture & design-decision record (abstractions, state-management boundaries, Jenkins integration surface, auth/security seams). The audit companion. |
| [`docs/todo/TECH_DEBT.md`](docs/todo/TECH_DEBT.md) | Working technical-debt list from the 2026-08-18 top-to-bottom audit (A1–A20, with status/owner per item). Rulings from mads: 2026-08-18 (`current()` is authoritative — A1; both minting paths for `emailCodeSecret` — A2; `?redirect=` canonical over `Referer` — A3; Task 9 consumes-and-resets the telemetry fields — A7/A8) and 2026-08-19 (mount move `securityRealm/mfa` → `mfa` — A17). Task 8 also added A15 (Bearer gap, open for ruling) and the booted-IT defects A16 (getServletPath 302 loop), A17 (realm mount collision), A18 (`<x:out>` render 500), A19 (IT `rawGet` followed redirects), A20 (endpoints had no dispatch token). |
| [`docs/done/2026-08-18-task8-handoff.md`](docs/done/2026-08-18-task8-handoff.md) | Landed Task 8's handoff note (end-to-end IT of the live gate): the two production defects it caught (A16 the getServletPath 302 self-loop, A17 the HPSR `securityRealm/mfa` mount collision — ruled 2026-08-19 to move to `/mfa`), the verified IT mechanics (context path, `c.login`, HPSR enrolment, form-by-id, JSON envelopes), the economics correction (~5 s per case, not minutes), and the A5/A15 corrections — moved to `done/` when Task 8 landed. |


## Practical usage — what end users should expect

> The TOTP engine, per-user state, the email-code factor (generation,
> hashing, single-use, expiry, resend, and auto-provisioned per-user HMAC
> key), the two gate brains, the admin settings, the MFA login screen
> with its verify/resend endpoints, and the automatic login gate (Task 7)
> that enforces all of it on a live install are implemented and tested;
> mail codes are delivered through the standard Jenkins Mailer (global SMTP
> config) once that plugin — preinstalled on any real instance — is present.
> The gate is real and is verified end to end on a booted Jenkins (Task 8's
> IT): on a live instance an enrolled user is bounced to the MFA page after
> their password login until the second factor is proven, and the whole wire
> — password login, the 302, the MFA page, the verify/resend POSTs, the
> mail round trip to the registered mailbox, the session rotation, and the
> "back to where you were" round trip — is asserted green, while API tokens,
> exempt service accounts, and unenrolled users are unaffected, and the kill
> switch is a setting, not an uninstall. Only the self-service
> enrollment/management UI (Task 9) is not a shipped screen yet — a user who
> has no factors enrolled cannot lock themselves in or out
> (there is nothing to gate them with), and the flow described below is the
> committed behaviour contract end to end.

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
- **Remembered devices:** a successful MFA keeps *this login* trusted for the
  session's lifetime (no per-request re-verification — the code is not
  re-demanded on every page load), and it *remembers the browser* for the
  configured window (default 30 days, never shorter than 24 h): a *future*
  login from that browser inside the window skips the code. Logging out ends
  the first; the window expiring ends the second. API tokens are exempt —
  CI keeps working.

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
- **Every knob an admin touches is clamped, not trusted.** The settings
  page enforces floors at save time: the trust floor can never be stored
  below 24 h even if a lower number is typed in, and tuning knobs (window,
  lockout, code TTL, resend cooldown, attempt limit) cannot be stored as 0 —
  a zero would silently disable the protection that field provides
  ("0-second code lifetime" = "no email code ever works"). The 24 h trust
  floor is enforced twice — here at the knob, and again at grant time in
  the trust store — so the guarantee holds on the normal admin path and
  cannot be weakened by a single mis-entered value.
- **Disabling the whole gate is a setting, not an uninstall.** The policy
  select on the same page offers OFF as a kill switch: the filter goes
  inert, nobody is gated, and the plugin stays installed and configured
  for the fix-forward (plus the `DEVCRU_MFA_OFF=1` env var for incidents
  where even the config page is unreachable).

### Storage and privacy

- The TOTP seed, the per-user email-code HMAC key, and the pending-code
  hash are stored **encrypted at rest** with the Jenkins master key — not
  readable from `config.xml` even by someone with filesystem access.  The
  per-user HMAC key is auto-provisioned on first email use when it does not
  yet exist (a fresh 128-bit random value, minted once and never reused), so
  every account hashes its codes under its own key rather than a shared
  default. Email codes themselves never touch disk.
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
