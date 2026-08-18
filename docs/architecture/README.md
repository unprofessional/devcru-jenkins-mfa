# Architecture & Design Decisions — devcru-mfa

> **Purpose.** This is the audit companion for the code. Read it before
> reviewing any class: it records *what each abstraction is, where the
> boundaries are, and why each design decision was made*, with the load-bearing
> seams pinned visually. Security-model decisions are mads-signed in the plan
> ([`docs/plans/2026-08-17-jenkins-mfa-plugin.md`](../plans/2026-08-17-jenkins-mfa-plugin.md))
> and are recorded here as settled, not re-litigated.
>
> **Status: Tasks 0–7 landed (`develop`, CI green). Task 7 (the gate filter)
> landed 2026-08-18 — see the Task 7 entries in §2, §5, §6.1 and the
> registration deviation in §9.8.** Where a section covers Task 8–9 material
> it is marked *(planned)*.
>
> **Audit findings** live in [`docs/todo/TECH_DEBT.md`](../todo/TECH_DEBT.md)
> (working list with statuses/owners; §10 here is the pointer). The 2026-08-18
> top-to-bottom read produced them; they are *observations for mads's audit*,
> not committed decisions (unless noted).

---

## 1. The plugin in one picture

Self-hosted MFA for Jenkins: **TOTP** (RFC 6238, Authy-compatible) and
**email one-time codes**, long remembered devices (default 30 d, floor 24 h),
no SaaS backend, no paywall. It replaces the openmfa-style SaaS plugin on
`jenkins.devcru.org` (Jenkins 2.577, Local Security Realm) because that plugin
is email-only on the free tier, has short trust, and dead-ends post-MFA
redirects.

The system is a *gate*: after the core handles password authentication, a
servlet filter *(Task 7)* checks whether the session is MFA-verified and, if
not, bounces the user to a self-contained login page that proves the second
factor.

```
                       JENKINS REQUEST PIPELINE
┌──────────────────────────────────────────────────────────────────────────────────┐
│  client ──HTTP──> core filters (CSRF crumb, authn) ──> [ MFA GATE ] (Task 7)     │
│                                                              │                   │
│          ├── PASS (verified session · trust live · API token · exempt ·          │
│          │        unenrolled · anonymous) ────────────> Stapler ──> app pages    │
│          │                                                                       │
│          └── NO ── 302 ──> <root>/securityRealm/mfa?redirect=…  (in-site target) │
└──────────────────────────────────────────────────────────────────────────────────┘
                                                        │ 302
                                                        ▼
┌───────────────────────────────────────┐      ┌─────────────────────────────────────┐
│ MFA PAGE (Jelly, self-contained HTML  │      │ MfaController (RootAction)          │
│ document; inline CSS/JS, zero assets) │ ◄────► │ GET → page model (issuer, crumb,    │
│ index.jelly — form + XHR client JS    │ ◄────► │     masked email, factor flags)     │
│ navigates ONLY to the server-         │ ◄────► │ POST postVerify     → VerifyOutcome │
│ validated redirect field in the       │ ◄────► │ POST postResendEmail→ VerifyOutcome │
│ VerifyOutcome JSON response           │      │ (delegated to the pure brains)      │
└───────────────────────────────────────┘      └─────────────────────────────────────┘

                                        ▼
┌───────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Totp (RFC 6238, pure JDK)        EmailCodeIssuer (hash / TTL / single-use /                       │
│                                  cooldown)                TrustStore (trust math)                 │
│                                                      RateLimiter (sliding-window lockout, in-mem) │
└───────────────────────────────────────────────────────────────────────────────────────────────────┘
                                        │ reads / writes
                                        ▼
┌────────────────────────────┐   ┌─────────────────────────────────┐
│ MfaUserProperty (per-user) │   │ DevcruMfaConfig (global)        │
│ user/<id>/config.xml       │   │ GlobalConfiguration + admin UI  │
│ secret fields master-key   │   │ clamped at save; exemption list │
│ encrypted at rest          │   │ policy / knobs / issuer         │
└────────────────────────────┘   └─────────────────────────────────┘```

---

## 2. Abstraction inventory

Nine production classes, seven test classes. The package tree mirrors the
layers:

```
src/main/java/org/sebcru/mfa/
├── DevcruMfaPlugin.java      # @Extension; @Initializer(EXTENSIONS_AUGMENTED)-static
│                             # registers MfaFilter, @Terminator removes it (Task 7)
├── MfaFilter.java            # the gate: pure decision() + jakarta Filter glue (Task 7)
├── MfaController.java        # RootAction: page + postVerify/postResendEmail
├── MfaUserProperty.java      # per-user factor state (UserProperty) + nested DescriptorImpl
├── DevcruMfaConfig.java      # admin knobs (GlobalConfiguration)
├── VerifyOutcome.java        # JSON outcome value type (endpoints → page JS)
├── crypto/
│   └── Totp.java             # RFC 6238, pure JDK crypto, static
├── email/
│   ├── EmailCodeIssuer.java  # code lifecycle (stateful-free brain)
│   ├── EmailSender.java      # delivery BOUNDARY (interface)
│   └── JenkinsEmailSender.java # Mailer-plugin implementation of the boundary
└── gate/
    ├── TrustStore.java       # remembered-device arithmetic
    └── RateLimiter.java      # sliding-window failure lockout (in-memory)
```

| Class | Layer | Role | State held |
|---|---|---|---|
| `Totp` | crypto brain | generate/verify codes, constant-time compare | none (static) |
| `EmailCodeIssuer` | factor brain | code gen, hash, TTL, single-use consume, cooldown | none (state lives on the user property) |
| `TrustStore` | gate brain | trust grant/revoke/expires | none (writes `trustedUntilMs` onto the property) |
| `RateLimiter` | gate brain | per-username failure window + lockout | **in-memory maps** (see §5) |
| `MfaUserProperty` | state | the user's MFA posture (factors, trust expiry, pending-code hash, telemetry) | persisted via `User.save()` |
| `DevcruMfaConfig` | policy | the knobs every brain reads | persisted via descriptor `save()` |
| `MfaFilter` | gate / glue | the decision chain (pure `decision()`) + the 302 (Task 7) | none (stateless; reads config/user/session per request) |
| `MfaController` | HTTP surface | page model + the two POST endpoints + session fix-up | singleton: one `RateLimiter`, `TrustStore`, `EmailCodeIssuer`, `EmailSender` |
| `VerifyOutcome` | contract value | the exact JSON the endpoints write and the JS parses | none |
| `JenkinsEmailSender` | I/O adapter | deliver code via Jenkins Mailer (SMTP) | none |
| `DevcruMfaPlugin` | lifecycle | registers/unregisters the gate filter (Task 7; see §6.1 + §9.8) | the one process-wide `MfaFilter` instance |

**Dependency direction (house rule).** The brains depend on *data* (a
`DevcruMfaConfig` POJO, an `MfaUserProperty` instance, an explicit `now`
millisecond instant) — never on Jenkins singletons. That is what keeps
Tasks 1–6 plain-JUnit-testable with no Jenkins VM. Only the *glue*
(`MfaController` endpoints, `JenkinsEmailSender`) touches `Jenkins.get()`,
`Mailer`, sessions, or the wall clock.

```
            PURE (plain-JVM tested)              GLUE (Task 8 tested)
   ┌──────────────────────────────────┐   ┌──────────────────────────────┐
   │ Totp · EmailCodeIssuer ·         │   │ MfaController endpoints ·    │
   │ TrustStore · RateLimiter ·       │   │ regenerateVerified ·         │
   │ classifyFactor ·                 │   │ JenkinsEmailSender ·         │
   │ resolveRedirectTarget ·          │   │ page-model getters ·         │
   │ MfaFilter.decision/.off/         │   │ MfaFilter.doFilter glue      │
   │ resolveTarget ·                  │   │ (registration happy paths    │
   │ maskEmail · VerifyOutcome        │   │ exercised by InjectedTest)   │
   └──────────────▲───────────────────┘   └──────────────┬───────────────┘
                  │  reads cfg (POJO), prop (POJO), now   │
                  └───────────────────────────────────────┘
                          cfg = DevcruMfaConfig instance
                          prop = MfaUserProperty instance
```

---

## 3. The verification flow (Task 6 behaviour)

```
 browser                          MfaController                    brains
    │                                │                                │
    │ GET /securityRealm/mfa         │                                │
    ├───────────────────────────────>│ page model: issuer, masked     │
    │<───────────────────────────────│ email, factor flags, crumb     │
    │                                │                                │
    │ POST postVerify {code, crumb}  │                                │
    ├───────────────────────────────>│ 1. isLocked? ─────────────────>│ RateLimiter
    │                                │    yes → {locked, retrySeconds}│
    │                                │ 2. classifyFactor(code)        │ (pure)
    │                                │    6 digits → TOTP             │
    │                                │    8 email-alphabet → EMAIL    │
    │                                │ 3. verify primary factor       ├──────────> Totp.verify
    │                                │    fallback: other enrolled    ├──────────> Issuer.verify
    │                                │                                │
  ┌── verified ─────────────────────────────────────────────────────────┴─┐
  │ 4a. TrustStore.trust(prop, cfg, now)      (floor applied inside)      │
  │     u.save()   (persistence hiccup swallowed — user still verified)   │
  │ 5a. RateLimiter.clear(name)                                                  │
  │ 6a. session regenerate + VERIFIED_ATTR=TRUE  (fixation defence)         │
  │ 7a. resolveRedirectTarget(Referer, host, port, ctx)  (pure, pinned)    │
  │     → 200 {ok, rememberHours, redirect}   ── browser navigates ONLY   │
  │                                                 to res.redirect        │
  └────────────────────────────────────────────────────────────────────────┘
  ┌── failed ───────────────────────────────────────────────────────────────────┐
  │ 4b. RateLimiter.recordFailure(name, cfg, now)   (may trip lockout)         │
  │     prop.setFailedAttemptStreak(…+1); u.save()   (telemetry only)          │
  │     → 200 {ok:false, error:"wrong_code" | …}     (never a 500)             │
  └─────────────────────────────────────────────────────────────────────────────┘
```

`postResendEmail` is the same shape minus the verify: checks email enrolment,
checks the resend cooldown against `lastResendAt`, then
`Issuer.resend → JenkinsEmailSender.send(registered mailbox)`.

**The redirect contract.** `redirect` in the JSON is the *already-validated*
target. The client JS (`index.jelly`) navigates only to that field, never to
the raw `Referer` — that single seam is what makes "no dead redirect / no open
redirect" hold end to end. `resolveRedirectTarget` accepts only: same-origin
absolute `http(s)` URLs (host + explicit port must match), or server-relative
`/…` paths; it rejects protocol-relative `//…`, foreign paths, and
login/security first-segments; everything else → site root. Pinned by
`MfaControllerTest`.

**Session regeneration (anti-fixation).** On success, *all* existing session
attributes are snapshotted, `invalidate()` is called, a fresh session is created
and the snapshot is restored, then `org.sebcru.mfa.verified = Boolean.TRUE` is
set. Spring Security's login context survives because it lives in the session
under `SPRING_SECURITY_CONTEXT_KEY` — copied as an ordinary attribute. The
session id changes; authentication does not.

---

## 4. Factor engines and their guarantees

### 4.1 TOTP (`crypto/Totp`)

- RFC 6238: 30 s step, 6 digits, HMAC-SHA1 (the Authy/Google shape).
- Secret: 128 bits from `SecureRandom`, stored unpadded Base32.
- `verify` tries `step ± window` (default ±1 ⇒ ±30 s clock skew tolerated —
  no "wrong code" noise from NTP-less phones) and stops at the first match.
- **Constant-time compare** (`MessageDigest.isEqual`, pinned to US-ASCII
  bytes — a SpotBugs-caught default-charset bug, see commit `8203d85`).
- Input whitespace is stripped before length check (`" 284 361"` works).
- 1-in-a-1,000,000 per-attempt guess space; the *rate limiter* (not the
  alphabet) is what bounds brute force.

### 4.2 Email one-time codes (`email/EmailCodeIssuer`)

- 8 chars from `A–Z0–9` minus `0 O 1 I` — unambiguous on paper/phone;
  32⁸ ≈ 1.1×10¹² candidates.
- **Confidentiality model** (security decision 2): the plaintext code exists
  only in the `issue`/`resend` return value, the mail body, and a local
  variable during `verify`. What is *persisted* is
  `sha256(HmacSHA256(code, perUserCodeSecret))` (Base64, stored as `Secret`).
  A stolen `config.xml` yields no usable codes; two users' states cannot be
  correlated. Comparison is over hashed forms ⇒ no timing signal on a wrong
  code.
- **Per-user key provenance (A2, landed 2026-08-18):** `perUserCodeSecret`
  is auto-provisioned by `MfaController.ensureEmailCodeSecret` — a pure,
  idempotent seam that mints a 128-bit random key on first email use behind
  `hasEmailFactor()` and returns the stored key thereafter. The original
  blank-string fallback is gone; the Task 9 enrolment UI adds the second,
  at-enrolment minting path.
- **Single-use:** on a matching hash the pending state is cleared *before*
  the TTL is consulted (expired-match also clears), so replay is impossible —
  including by the same user, and a retried POST cannot double-consume.
- **TTL:** 300 s default; `NO_PENDING` (never issued / consumed) is reported
  distinctly from `EXPIRED` internally, but externally both are just a failed
  attempt plus a rate-limit count.
- **Resend cooldown:** 60 s default; while live, `resend` returns null and
  touches no state. A fresh issue overwrites the pending hash, so at most one
  code is ever live per user (mail-bomb ceiling: one mail/minute).
- Delivery is the `EmailSender` **boundary** (§6.2); the issuer is
  delivery-agnostic, which is what lets `RecordingSender` test doubles pin the
  crypto without an SMTP round trip. `JenkinsEmailSender` enforces the
  no-address fail-closed rule and puts the code in the body only, never the
  subject, never logged.

---

## 5. State management and boundaries ★

This is the section the audit is about. Every piece of state, where it lives,
how long it survives, and *who may write it*:

| State | Where | Format | Lifetime | Writers | Readers |
|---|---|---|---|---|---|
| TOTP seed `totpSecret` | `~JENKINSUSER/config/user/<id>/config.xml` | XStream `Secret`, **master-key encrypted** | until changed | user profile only (Task 9 UI) | `MfaController` (verify) |
| Email HMAC key `emailCodeSecret` | same file | `Secret`, encrypted | until changed | server (Task 3/9) | `EmailCodeIssuer` via controller |
| Registered mailbox `registeredEmail` | same file | **plaintext** (delivery address, admin-grep-able deliberately) | until changed | user profile only | page (masked), issuer (target) |
| Trust expiry `trustedUntilMs` | same file | epoch ms, plain | until re-granted | `TrustStore.trust` / `.revoke` only | gate (`MfaFilter.decision`, step 9) |
| Pending code hash + `codeIssuedAt` + `lastResendAt` | same file | `Secret` + epoch ms | 300 s / per-issue | `EmailCodeIssuer` only | `EmailCodeIssuer`, controller |
| `failedAttemptStreak` | same file | int, plain | grows forever (see A8) | controller only (telemetry) | *(nothing yet)* |
| `lastVerifiedFactor` | same file | long, plain | — | *(nothing yet — A9)* | *(nothing yet)* |
| Policy knobs | `~JENKINSUSER/config/…/DevcruMfaConfig.xml` | descriptor XML | until saved | admin form only, **clamped in `configure()`** | every brain, via `DevcruMfaConfig.get()` |
| MFA-verified flag | **`HttpSession`** (`org.sebcru.mfa.verified`) | `Boolean` | browser session (id regenerated on success) | controller only, on success | gate (`MfaFilter`, step 9) |
| Failure timestamps + lockouts | **heap** (`RateLimiter` maps, inside the controller singleton) | `ConcurrentHashMap<name, List<Long>>` + `Map<name, Long lockoutUntil>` | **Jenkins restart wipes it** *(plan security decision 5)* | `recordFailure`/`clear`, under one monitor | controller (`isLocked`, first check in `postVerify`) |
| Code plaintext | **nowhere persistent** — mail body + one JVM local | — | one SMTP send | `EmailCodeIssuer` | `EmailSender` |

### The four state domains and their boundaries

```
 ┌ DOMAIN 1 · PER-USER (JENKINS-OWNED PERSISTENCE) ────────────────────────┐
 │  MfaUserProperty ──XStream──> user/<id>/config.xml                       │
 │  Boundary: the @DataBoundSetter FENCE.                                   │
 │    form-bindable (user may own these):                                   │
 │      setTotpSecret, setRegisteredEmail                                    │
 │    server-managed (NOT form-bindable):                                    │
 │      trustedUntilMs, failedAttemptStreak, lastVerifiedFactor,             │
 │      emailCodeSecret, pendingCodeHash, codeIssuedAt, lastResendAt         │
 │  A crafted security-profile submit cannot forge a 30-day trust, zero a   │
 │  streak, or inject a pending hash. Secret fields are master-key          │
 │  encrypted at rest; plaintext code material never touches the disk.       │
 │  Save discipline: MfaUserProperty.getOrCreate() WRITES config.xml —      │
 │  the hot path (page render, and the Task 7 filter) must use              │
 │  u.getProperty(...) (read-only), never getOrCreate().                    │
 └──────────────────────────────────────────────────────────────────────────┘
 ┌ DOMAIN 2 · GLOBAL (JENKINS-OWNED PERSISTENCE) ──────────────────────────┐
 │  DevcruMfaConfig extends jenkins.model.GlobalConfiguration:              │
 │  descriptor save()/load() ⇄ config/DevcruMfaConfig.xml.                  │
 │  Boundary: configure() clamps at SAVE time (trustMinHours ≥ 24; knobs    │
 │  ≥ 1), and TrustStore re-clamps at GRANT time (max(remember, floor)).    │
 │  ⚠ AUDIT A1: two instances exist — the descriptor instance and a static  │
 │  process-default (get()/setForTest()). See §7 and §10.                   │
 └──────────────────────────────────────────────────────────────────────────┘
 ┌ DOMAIN 3 · PROCESS MEMORY (WIPES ON RESTART — SIGNED TRADE-OFF) ────────┐
 │  RateLimiter maps inside the MfaController @Extension singleton.         │
 │  Plan security decision 5: deliberately in-memory like openmfa;          │
 │  a restart clears all lockouts (restart = impersonation reset; accepted) │
 │  in exchange for zero disk I/O on the request path. No persistence, no   │
 │  background threads; lazy sweep on every mutating call caps state (      │
 │  100 timestamps/user, expired lockouts dropped).                         │
 └──────────────────────────────────────────────────────────────────────────┘
 ┌ DOMAIN 4 · BROWSER SESSION (JENKINS-OWNED, SERVER-SIDE SESSION STORE) ──┐
 │  org.sebcru.mfa.verified = Boolean.TRUE, set only after a successful     │
 │  verification, on a REGENERATED session id. No client-supplied trust     │
 │  token exists (security decision 6) — the flag cannot be forged from     │
 │  outside the session.                                                     │
 └───────────────────────────────────────────────────────────────────────────┘
```

### Trust semantics — the subtle, mads-signed part

`trustedUntilMs` and the session flag are **different instruments** and it is
easy to conflate them:

```
  session  VERIFIED flag ──► authorises THIS browser session, for its lifetime
                              (the gate's primary pass, MfaFilter.decision
                              step 9 — first operand of the disjunction).
                              A live session that logged in is trusted.

                              ⚠ There is deliberately NO per-request expiry of
                                an active session — "re-auth every N hours"
                                churn was the exact UX sin of the replaced
                                plugin. mads-signed; do not "fix" it.

  trustedUntilMs          ──► governs FUTURE logins only: when the user next
                              opens a new session, if this instant is still in
                              the future the browser is remembered (the gate's
                              TrustStore.isTrusted check — second operand of
                              step 9's disjunction). Expiry is strict `>`:
                              trustedUntilMs == now is already expired.
```

The session-flag pass and the trust pass are a *disjunction* in
`MfaFilter.decision` (step 9: `sessionVerified || trustLive`), and the
disjunction is deliberate — the plan sketch's step 8 is written
`sessionVerified AND isTrusted`, which would (a) re-prompt a live, verified
session in the moment its 30-day trust expired mid-session — the exact
"re-auth churn" sin the session-flag semantics remove — and (b) make the
remembered-device path impossible, since a fresh session by definition has no
session flag yet. Each operand covers a different moment: the flag covers
the session the user is *in*; `trustedUntilMs` covers the sessions they
*haven't started yet*. (Recorded as a deliberate reading of the sketch, not a
deviation from a mads-signed decision — the signed decision is the *two
instruments and their separate lifetimes* (mads, 2026-08-17); the OR that
makes both work at once is the implementation of that decision. Pinned by
`FilterLogicTest.step9IsADisjunction`.)

The README's end-user line "keeps the browser trusted for the configured
window" describes this second instrument; the session flag is what actually
keeps *this* window open. (Noted in the audit, A6.)

### Lockout arithmetic (the pins that matter)

```
  failures in sliding window <maxAttempts>  ──►  recordFailure appends now
  failures + this one == maxAttempts        ──►  TRIP: lockoutUntil = now + lockout
                                                 (the trip failure is NOT appended)
  attempt while a lockout is live           ──►  controller short-circuits
                                                 (isLocked checked FIRST in
                                                 postVerify); even if one slipped
                                                 through, recordFailure will NOT
                                                 extend a live lockout
  success                                   ──►  clear() removes failures AND lockout

  Consequences (each a red→green pin in RateLimiterTest):
   · lockout trips exactly on the 5th in-window failure, not the 6th
   · the trip starts at TRIP time, so "try again in N" is bounded and true
   · an attacker cannot roll a victim's lockout forever by retrying
   · null-config fallbacks use the same value*UNIT_MS arithmetic as the
     non-null path (a bare `30L`-ms fallback once pruned the window so a
     null config could never lock anyone out)
```

---

## 6. Jenkins integration surface (the attack/audit surface)

### 6.1 Extension registration (what the plugin plugs into)

| Registration | Class | Effect |
|---|---|---|
| `RootAction` @Extension | `MfaController` | mounts the page at `<root>/securityRealm/mfa` *(not* a `GlobalAction` — that type does not exist in core 2.528.3; Task 6 deviation 1) |
| `GlobalConfiguration` @Extension | `DevcruMfaConfig` (+ nested descriptor via inheritance) | Manage Jenkins → Security form (`config.jelly`), persisted `DevcruMfaConfig.xml` |
| `UserPropertyDescriptor` @Extension (nested `DescriptorImpl`) | `MfaUserProperty` | user security-profile section; the data-binding entry point for the user-owned fields |
| **`@Extension` (plain class, NOT a `hudson.Plugin` subclass)** | `DevcruMfaPlugin (Task 7)` | the gate's **filter registration**: `static @Initializer(after=EXTENSIONS_AUGMENTED) → PluginServletFilter.addFilter(filter)` + `@Terminator → removeFilter(filter)`; one shared `MfaFilter` instance (see §9.8 for why not `hudson.Plugin`, and §9.7 for why not `after=STARTED`) |

### 6.2 Mail delivery (the only outbound I/O)

```
 EmailCodeIssuer ──(EmailSender boundary)──> JenkinsEmailSender
                                                │ Mailer.descriptor().createSession()
                                                │ (Jenkins' global SMTP config —
                                                │  the same one that mails build results)
                                                ▼
                                        jakarta.mail MimeMessage
                                        subject: "Your Jenkins MFA code"
                                        body:    code, TTL, anti-phish hint
                                        → SMTP → registered mailbox ONLY
```

- `mailer` is a **BOM-managed** compile dependency (no version tag — the
  bom-2.528.x import resolves it; it pre-installs on any real instance, so it
  is existing infra, not new baggage). `jakarta.mail` does *not* ship in
  jenkins-core (verified by `jar tf`, 0 hits) — the repo comment that claimed
  it did was wrong and is corrected.
- Delivery failure must not 500 the login page: `JenkinsEmailSender` throws a
  typed `IllegalStateException`, the endpoint contract is
  "the user's remedy is a resend (cooldown permitting)."
- **No `dest` parameter on resend (Task 6 deviation 2).** The plan sketch's
  `postResendEmail(String dest, …)` would be an open mail relay; resend always
  targets `getRegisteredEmail()`.

### 6.3 Core APIs the code leans on (verified against jenkins-core 2.528.3)

| Use | API | Note |
|---|---|---|
| Current user | `Jenkins.getAuthentication2()` + `User.get2(Auth)` | contractually non-null authn; `MfaController.currentUser()` wraps in try/catch → anonymous on bootstrap |
| CSRF crumb | `hudson.Functions.getCrumbRequestField()` / `getCrumb(StaplerRequest2)` | resolved via `Stapler.getCurrentRequest2()` because the page is *not* wrapped in `<l:view>` (no `h` taglib binding); the hidden field is model-supplied, policy stays in core |
| JSON | `net.sf.json.JSONObject` (json-lib, in core) | omits nulls — `VerifyOutcome` relies on that for field-presence semantics |
| Response hardening | `@RequirePOST` (Stapler interceptor) + core CSRF crumb filter | belt-and-suspenders: policy is the crumb, `@RequirePOST` is method discipline |
| Persistence | `User.save()`, descriptor `save()/load()`, `Secret` master-key wrap | `Secret` plaintext is in-JVM only; XStream encryption at `save()` time |
| Token exemption *(Task 7)* | `jenkins.security.BasicHeaderApiTokenAuthenticator.class.getName()` request attribute (`Boolean.TRUE`) | verified via `javap -c` on the constant pool; **no `JenkinsUtil` exists in this core** |
| Filter registration *(Task 7)* | `hudson.util.PluginServletFilter.addFilter(jakarta.servlet.Filter)` | jakarta-only (2.528 is post-javax) |

### 6.4 Self-contained page constraint

`MfaController/index.jelly` emits a **complete standalone HTML document**
(no `<l:view>` wrapper, inline CSS/JS, no external assets). That makes it
strict XML with four recurring gotchas (all hit, all pinned in the skill
pitfall list): single root `<j:jelly>` with everything nested inside; every
boolean attribute needs a value (`novalidate="novalidate"`); inline
`<script>` with `<`/`&` must be `//<![CDATA[ … //]]>`-fenced; and
`escape-by-default='false'` on the page means the `<x:out>` bindings
(masked email, issuer) are the *only* escaping left — keep the bound-set
minimal and non-user-settable.

---

## 7. The config-instance duality (read this before touching `DevcruMfaConfig`)

`DevcruMfaConfig` has **two ways to obtain an instance**, and they are *not
the same object*:

```
  Admin saves form
        │  configure() clamps, then descriptor.save()
        ▼
  ┌─────────────────────────────┐     GlobalConfiguration.all()
  │ descriptor instance         │ ◄─── current()  (iterates, casts)
  │ (the persisted one Jenkins  │
  │  serves, loaded from XML)   │        │ not found (pre-startup / unit test)
  └─────────────────────────────┘        ▼
                                  ┌─────────────────────────────┐
                                  │ static 'instance'           │
                                  │ (process default; fresh     │
                                  │  DevcruMfaConfig() fields = │
                                  │  plan defaults)             │
                                  └─────────────────────────────┘
                                                 ▲
                     runtime callers use get() ──┤  (MfaController today;
                     which returns the static,   │   Task 7 filter planned)
                     NOT the descriptor          └────────────
```

The split was deliberate and documented *as a testability seam*: `get()`
returns a null-safe process-default so the gate brains and their plain-JVM
tests never require a running descriptor. `setForTest()` swaps it for tests.
**RESOLVED (Task 7, per mads's A1 ruling):** in a live Jenkins the
callers that matter — the gate filter AND the controller — now use
`currentSafe()` (the descriptor instance, `get()` only as the documented
no-descriptor fallback), so an admin save is visible to the gate in the same
request it is made in. `MfaController` migrated its three runtime read sites
(issuer label, verify trust-window, resend cooldown) in the same commit, and
`MfaController.currentUser()` now delegates to the filter's shared
`MfaFilter.findCurrentUser()` — one config object, one user definition.

The two-layer clamp must stay consistent with the duality: `configure()`
clamps the *saved* copy; `TrustStore` re-clamps at grant time from whatever
config instance was passed. If the two instances ever hold different values
(the live situation today), grant-time arithmetic runs on the *defaults*
instance's values.

---

## 8. Security model — settled decisions and their code locations

mads-signed in the plan §"Security model decisions"; each mapped to where the
code enforces it (as of Tasks 0–7):

| # | Decision | Enforced by |
|---|---|---|
| 1 | **API tokens are exempt** — gating them breaks CI | `MfaFilter.decision` step 2 (request-attribute check on `jenkins.security.BasicHeaderApiTokenAuthenticator.class.getName()`; the IT re-pin is Task 8) |
| 2 | **Email codes never stored in plaintext** — store `HmacSHA256(code, perUserKey)` | `EmailCodeIssuer.hashOf`, §4.2 |
| 3 | **Session regenerated on successful verify** (fixation defence) | `MfaController.regenerateVerified`, §3 |
| 4 | **TOTP compare is constant-time** (`MessageDigest.isEqual`) | `Totp.constEq` (US-ASCII bytes) |
| 5 | **Rate limiting per-username, in-memory, sweep-on-expiry; restart clears it — acceptable** | `RateLimiter`, §5 Domain 3 |
| 6 | **Trust is server-side session state only; no client-supplied trust token** | session attribute + `trustedUntilMs`, §5 |
| 7 | **Recovery: admin clears the user's property, re-enroll; no self-service reset** | *(Task 9 page + plan's recovery note; `TrustStore.revoke` already exists)* |
| — | **Unenrolled users are not hard-locked** (policy REQUIRED = mandatory once enrolled) | `MfaUserProperty.isMfaEnabled()` → `MfaFilter.decision` step 8 (`notEnrolled` → PASS) |
| — | **Trust floor ≥ 24 h, enforced twice** (save-time knob clamp + grant-time `max`) | `DevcruMfaConfig.configure()` + `TrustStore.trust` |
| — | **Server state is never form-bindable** | `@DataBoundSetter` fence, §5 Domain 1 |
| — | **Codes only to the registered mailbox** (resend has no `dest`) | `postResendEmail`, §6.2 |
| — | **No open redirect** (redirect = server-validated target, else root) | `resolveRedirectTarget` (the single validator for both the gate's `?redirect=` parameter AND the `Referer` fallback), §3 + §5 |
| — | **Kill switch**: `DEVCRU_MFA_OFF=1` env or `Policy.OFF` — a setting, not an uninstall | `MfaFilter.decision` step 0 (both halves — `MfaFilter.off()`); a live-admin toggle, no uninstall required |

Non-goals (YAGNI, signed): WebAuthn/passkeys, SMS, hardware keys,
LDAP/SSO (realm stays `LocalSecurityRealm`), per-job MFA.

---

## 9. Deviations of the code from the plan sketch (all flagged, all settled)

Recorded here so the audit does not re-raise them as open issues:

1. **`RootAction`, not `GlobalAction`** (Task 6). `jenkins.model.GlobalAction`
   absent from core 2.528.3; `RootAction` (not `UnprotectedRootAction`, so it
   stays behind authn) gives the identical URL. Flagged in commit `f705ea3` +
   `MfaController` class doc.
2. **`postResendEmail` has no `dest`** (Task 6). Closed the open-mail-relay
   hole the sketch left open.
3. **`configure()`, not `configure(req, json)`-only shape, clamps at save**
   (Task 5). The sketch's "single source of truth for the 24 h floor" claim
   became **two** layers when the save-time clamp was added — the
   `TrustStore` javadoc was rewritten in the same task to say so.
4. **`@Symbol("devcruMfa")` dropped** (Task 5). `io.jenkins.plugins.Symbol`
   needs `plugin-util-api`, absent from the offline `~/.m2`; descriptor
   discovery is by class name anyway, so the symbol removed zero functionality.
   Do **not** add it back unasked.
5. **`endpoints return void + JSON writer`, not the sketch's `FilePath`**
   (Task 6).
6. **`get()` instead of `current()` in the controller** (pre-Task 7). *Resolved
   by the A1 ruling, landed in Task 7 (same commit as the filter): the
   controller's runtime readers now use `currentSafe()` like the gate does —
   see §7. No longer an open item.*
7. **`EXTENSIONS_AUGMENTED`, not `STARTED`, for the filter registration**
   (Task 7). The plan sketch says `@Initializer(after=STARTED)`. On core
   2.528.3 an `@Initializer` on a class is instantiated through
   `TaskMethodFinder.lookUp` → `Jenkins.getInjector().getInstance(…)` **before
   the milestone fires**; at `STARTED` the Guice injector does not exist
   yet, so the boot dies with
   `IllegalStateException: Unable to inject class
   org.sebcru.mfa.DevcruMfaPlugin` (from `TaskMethodFinder.lookUp`) and
   `InjectedTest`'s Jenkins-in-JVM boot fails. At `EXTENSIONS_AUGMENTED` the
   injector is live and the same annotation works unchanged — this is the
   milestone core's own JENKINS-60118 idiom ("register a servlet filter from
   a plugin") uses. Also made the method `static` for the same class of
   reason: core `@Initializer` methods on `@Extension` singletons are
   instance-bound, which works, but `static` removes the dependency on the
   extension's own lifecycle ordering and matches core's usage
   (`hudson.model.UserLanguages`). Both choices are pinned by the
   filter actually booting in `InjectedTest` under `mvn clean verify`.
8. **`DevcruMfaPlugin` is a plain `@Extension` class, not a `hudson.Plugin`
   subclass** (Task 7). The plan sketch shows `class DevcruMfaPlugin extends
   hudson.Plugin`; a `hudson.Plugin` instance is created and held by its
   `PluginWrapper` and is *not* in Guice's object graph, so
   `TaskMethodFinder`'s `injector.getInstance(DevcruMfaPlugin.class)` fails
   with the same "Unable to inject class" boot error (reproduced before
   deciding). A `hudson.Plugin` main class is optional in a Jenkins plugin —
   the `@Extension`s (this class + `MfaController` + `DevcruMfaConfig` +
   `MfaUserProperty.DescriptorImpl`) are what make it a plugin. The plan's
   `@Extension @NoArgsConstructor class DevcruMfaPlugin { @Initializer…
   @Terminator… }` note (Task 7 section, line ~562) is exactly this shape
   and was followed; the `extends hudson.Plugin` in the sketch's code block
   is the part that does not build.
9. **Package `org.sebcru.mfa` is a tribute, not a typo** (mads). Never
   propose renaming to `org.devcru.mfa`.

---

## 10. Audit findings → [`docs/todo/TECH_DEBT.md`](../todo/TECH_DEBT.md)

Split out of this record on 2026-08-18 (commit following the 2026-08-18
audit) into a **working** list with statuses (mads rulings recorded
2026-08-18: `RULING-RECORDED` / `OPEN` / `CTX`), owners by task, and a
Resolved table. The findings keep their A1–A14 numbers, so every
cross-reference in this file, the plan, and the Task 7 handoff still lands.

**Task 7 status (landed 2026-08-18):** the gate filter (`MfaFilter`) and its
registration (`DevcruMfaPlugin`) landed with the A1 ruling implemented
(`currentSafe()` authoritative for filter AND controller readers) and the
A3/A5 plumbing implemented (the `?redirect=` parameter is canonical over the
POST's `Referer`; both flow through the one `resolveRedirectTarget`
validator). **A1, A3, A5 (plumbing half) and A14 are RESOLVED** in
`docs/todo/TECH_DEBT.md`. Still open from that list: **A5's IT half** (the
booted-Jenkins round-trip assertion), plus A2's Task 9 enrolment-UI minting
path, A7/A8's Task 9 telemetry consumer + reset wiring — all Task 8/9 work.


---

## 11. Conventions the code obeys (keep them when you touch things)

1. **Explicit `now`/`nowMs` in every brain method.** No `System.currentTime-
  Millis()` in crypto/gate classes. Production callers (the controller)
   pass the real clock; tests pin it. Zero wall-clock flake by construction.
2. **Depend on config *data*, not Jenkins singletons.** Brains take a
   `DevcruMfaConfig` instance (and survive `cfg == null` with their own
   plan-default fallbacks — same `value * UNIT_MS` shape as the non-null path,
   never a bare unit-less literal).
3. **Pure seams are package-private statics** (`classifyFactor`,
   `resolveRedirectTarget`, `maskEmail`) — pinned by `MfaControllerTest` in
   a plain JVM. Glue is *glue for Task 8* (session regen, endpoint wiring)
   and deliberately not unit-tested.
4. **Fail-closed, never a 500, on the verification path.** Wrong/blank/
   garbage input → structured `VerifyOutcome.fail(…)`; the page maps every
   error code to a friendly string; a stack trace on the login path is a
   contract violation.
5. **Secrets are `hudson.util.Secret`**; the registered email is plaintext on
   purpose (delivery address, not credential).
6. **Server state is never `@DataBoundSetter`.** User-ownership fence:
   `setTotpSecret`, `setRegisteredEmail` only.
7. **BDD-documented TDD per `AGENTS.md`** (WHAT / GIVEN-WHEN-THEN /
   WHY-SOLVES per test; red→green history in the class doc). Reference:
   `TotpTest.java`.
8. **Local validation mirrors CI: `mvn clean verify -DskipITs`** (SpotBugs
   + enforcer bind to `verify`; `mvn test` silently skips the linter).
9. **The README's "Practical usage" section updates in the same commit as
   any task that lands.** Honest "implemented vs. in progress" note stays
   current.
10. **When adding a second enforcement layer for a guarantee, re-search for
    the old "single source of truth" claim and rewrite it in the same commit**
    (the 24 h floor had exactly this happen in Task 5).

---

*Maintained by Sebastian. Update this file whenever a decision changes —
stale architecture docs are worse than none, because the next reader audits
against them. When a section describes superseded behaviour, move the section
to `docs/done/` with a date, don't delete history.*
