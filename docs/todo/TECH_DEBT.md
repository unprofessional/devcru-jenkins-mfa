# TECH_DEBT — devcru-mfa

> **Provenance.** 2026-08-18 top-to-bottom code audit (Tasks 0–6 landed,
> `develop` at `f705ea3`, before Task 7). Originally §10 of
> [`docs/architecture/README.md`](../architecture/README.md); split out here
> on 2026-08-18 so the findings are a **working list with statuses**, not a
> read-only appendix. **Rulings received from mads 2026-08-18 (see
> "Rulings recorded" below), 2026-08-19 (Task 8's Defect B mount move —
> see A17); fixes land in their owner tasks.**
>
> **How this file works.**
> - Each item keeps its audit number (A1–A14) so cross-references in the
>   architecture record, and the task handoffs stay valid (A15 added from the
>   Task 8 IT's named Bearer gap; A16/A17 are Task 8's two production
>   defects, added 2026-08-19).
> - **Status:** `RULING-RECORDED` (mads has decided; fix lands in the named
>   owner task / commit) · `OPEN` (needs a decision or code change, no
>   ruling yet) · `CTX` (no action — context for the next reviewer) ·
>   `RESOLVED` (in the table below).
> - **Owner task** names where the fix belongs when it belongs to a task;
>   otherwise the fix is a standalone commit on `develop`.
> - When an item is resolved: set status, link the fixing commit, append the
>   item to the Resolved table (don't delete — the audit trail is the point).

---

## Rulings recorded (mads, 2026-08-18) — awaiting the code fix

### A1 — `DevcruMfaConfig` instance duality: the gate runs on a defaults instance
**Status: RESOLVED (Task 7).** **Owner: Task 7 (filter) + controller
migration, same commit.**

`MfaController` reads policy via `get()` — the static process-default
instance — while admin form saves land on the descriptor instance
(`current()`'s domain). A fresh `DevcruMfaConfig` is constructed once at
class-init with the plan defaults and is *never* updated by form saves.
Consequence: the gate currently runs on defaults; admin-visible tuning
(windows, exemptions, policy) only reaches it once a `current()` path is
wired.

> **Ruling (mads, 2026-08-18):** `current()` is authoritative for **all
> runtime readers — the filter and the controller**. `get()` is kept only as
> the null-safe fallback `current()` already provides when no descriptor
> exists (tests / pre-startup). Reconcile the `DevcruMfaConfig` class
> javadoc in the same commit (house rule: a second enforcement layer must
> update stale "single source of truth" claims).

> **Landed (Task 7):** `MfaFilter` reads the gate policy from
> `DevcruMfaConfig.currentSafe()` — the descriptor instance (with the
> documented `get()` fallback when no descriptor is loaded yet) — and
> `MfaController`'s three runtime read sites (`getIssuer`, the verify
> trust-window, the resend cooldown) migrated to the same authoritative
> instance in the same commit; `MfaController.currentUser()` now delegates
> to the filter's shared `MfaFilter.findCurrentUser()`, so the gate and the
> page it sends users to agree on the same user. The `DevcruMfaConfig` class
> javadoc was reconciled: its "single source of truth" framing now makes the
> descriptor instance the one authoritative reader and `get()` the
> documented fallback. Pinned by the filter landing under `InjectedTest`'s
> live-Jenkins boot (a boot where the filter and the descriptor read the
> same object with the filter live).

### A2 — `emailCodeSecret` never minted; codes hash under a blank-string key
**Status: RULING-RECORDED — lazy-mint path LANDED; Task 9 enrolment-UI path outstanding.** **Owner: controller lazy-mint (this commit) + Task 9 (enrolment UI minting). Both.**

*Originally:* the controller fed
`p.getEmailCodeSecret() == null ? "" : …` — a **blank-string HMAC key** — to
`EmailCodeIssuer`, because nothing anywhere minted the per-user key. The
mechanics worked (single-use, TTL, replay-proof), but the mads-signed
confidentiality story — per-user HMAC key, master-key encrypted at rest,
"two users' states cannot be correlated" — was not implemented: every
account hashed under the same empty key.

> **Ruling (mads, 2026-08-18):** **both** paths — the Task 9 enrolment UI
> mints the key at first email enrolment, *and* the controller lazy-mints on
> first email issue — so there is no gap between now and Task 9. README's
> "per-user-keyed" sentence becomes true once the lazy-mint lands.

> **Landed (this commit):** `MfaController.ensureEmailCodeSecret(p)` — a
> pure, idempotent seam. First email use behind `hasEmailFactor()` mints a
> fresh 128-bit random key (`Totp.newBase32Secret()`, stored as a
> master-key-encrypted `Secret`), persisted on the next `u.save()`; every
> later call returns the stored key unchanged. Both call sites
> (`verifyEmail`, `postResendEmail`) now route through it, and the
> blank-string fallback is gone. Pinned by
> `MfaControllerTest.lazilyMintsPerUserEmailCodeHmacKeyExactlyOnce`
> (mint-once, idempotent, never-clobbers). TOTP-only users are never
> handed a key. **Outstanding:** the Task 9 enrolment UI still owns the
> *second* minting path (mint at enrolment, before first login).

### A3 — `?redirect=` query parameter vs `Referer`: two redirect contracts
**Status: RESOLVED (plumbing, Task 7); Task 8 IT assertion remains (see A5).** **Owner: Task 7 (filter plumbing) + Task 8 (IT assertion, see A5).**

The filter spec (Task 7 handoff) 302s to `/securityRealm/mfa?redirect=<target>`;
`MfaController.postVerify` never looks at `redirect` and feeds
`resolveRedirectTarget` from `req.getHeader("Referer")` — two inputs, two
shaped validators, drift risk.

> **Ruling (mads, 2026-08-18):** **the `?redirect=` query parameter is
> canonical over `Referer`.** Implementation: read the parameter first;
> fall back to the `Referer` header only when the parameter is absent; both
> flows through the single existing pure `resolveRedirectTarget`.

> **Landed (Task 7):** `MfaFilter` bounces to
> `/securityRealm/mfa?redirect=<target>` — the `target` is the ONE
> validator (`MfaFilter.resolveTarget` →
> `MfaController.resolveRedirectTarget`, host-checked) — and
> `MfaController.postVerify` now reads that `?redirect=` parameter first,
> falling back to `Referer` only when it is absent, and resolves through the
> same seam, so the two contracts share one validator. The MFA page's JS
> carries the parameter across both POSTs
> (`postVerify`, `postResendEmail`) so it survives the form round trip.
> Pinned unit-side by `FilterLogicTest` (canonical-parameter over Referer,
> blank-parameter fallback, forged-off-site parameter refuses) and the
> `postVerify` composition pin in `MfaControllerTest`. **Outstanding:**
> Task 8 asserts the end-to-end pre-login URL round-trips against a booted
> Jenkins (A5's IT half).

### A7 — `failedAttemptStreak` write-only and unbounded
**Status: RULING-RECORDED.** **Owner: Task 9 (consumer + reset wiring).**

`postVerify` increments and persists it on every failure; `RateLimiter.clear`
(success / lockout) does *not* reset it; nothing reads it yet. Grows
monotonically per user forever.

> **Ruling (mads, 2026-08-18):** option **(a)** — *Task 9 consumes it and
> the clear-path resets it.* Concretely for Task 9: the enrolment UI reads
> the streak (e.g. "recent failed attempts" hint or reset context) **and**
> the success/clear path (`RateLimiter.clear` callers) resets the streak on
> the property before `u.save()`. Until Task 9 lands, the field stays
> write-only but bounded-in-effect by the lockout window's practical rate.

### A8 — `lastVerifiedFactor` documented telemetry with no writer
**Status: RULING-RECORDED.** **Owner: same commit as A7's Task 9 work.**

Javadoc says "0 = totp, 1 = email. Telemetry only." — but nothing writes it;
every property carries `0` (implies TOTP) even for email-only users.

> **Ruling (mads, 2026-08-18):** option **(a)** — *Task 9 consumes it.*
> Concretely: `postVerify` (or Task 9's factor-UI companion) writes the
> factor index on success, and the Task 9 UI displays the last-verified
> factor. Same commit as the A7 fix. Note: "the clear-path resets it"
> applies to the streak (A7); a last-factor has no reset — it is overwritten
> by the next success by design.

## OPEN — no ruling yet

### A5 — "Back to where you were" resolves to the MFA page, not the pre-login page
**Status: RESOLVED (Task 8 — the IT assertion landed green).** **Owner: Task 7 (plumbing) + Task 8 (IT assertion).**

A same-origin POST carries the *MFA page's own URL* as its `Referer`
(`/securityRealm/mfa` is the page issuing the form POST). So the
`Referer`-only `resolveRedirectTarget` send-back lands the user on the MFA
page itself in the normal browser path — not where they were headed. The A3
ruling (`?redirect=` canonical) settled the *direction*; Task 7 did the
plumbing.

> **Landed (Task 7):** the gate's 302 now carries the pre-login destination
> in `?redirect=` (validated by the single `MfaController.
> resolveRedirectTarget` — a forged parameter is refused exactly as a forged
> Referer is); the MFA page's JS reads it from `window.location.search` and
> re-attaches it to every XHR POST, and `postVerify` consumes the parameter
> first with `Referer` as the fallback (covering the parameter-less entry,
> e.g. a bookmarked MFA page). The open-redirect guarantee now holds
> end-to-end through both carriers.
>
> **Landed (Task 8):** `MfaFilterIT.totpFlowEndToEndWithRedirectRoundTrip`
> asserts the full round trip against a booted Jenkins: no-carrier bounce
> falls back to the context root (never a dead path); an in-site
> `?redirect=` parameter carries EXACTLY that job path through the 302
> Location → MFA page form → `postVerify` JSON `redirect` (A3 — the
> parameter is canonical on the wire); the session id rotates on success
> (anti-fixation) and the verified session reaches the protected path with
> no re-prompt. The signed contract is narrower than "pre-login URL
> preservation" (see the Task 8 handoff's A5 correction — with no carrier,
> core owns the pre-login destination, and the gate's contract is the root
> fallback).

### A15 — API-token exemption: plan's `Bearer` case has no core authenticator on 2.528.3
**Status: RESOLVED BY RULING (mads, 2026-08-19) — implementation owed as a
standalone task (A21).** **Owner: the Bearer task (no filter change on the
gate side; the gate already exempts the request attribute).**

The plan's Task 8 IT case 3 specified re-pinning the API-token exemption
against a real security chain with `Authorization: <api-token> jenkins-core
2.528.3 has **no Bearer token authenticator** (verified against the resolved
artifact — only the `BasicHeader*` token classes exist; a full-string search
of the jar finds no Bearer at all). The IT therefore
pins the **Basic** `user:token` header end to end
(`MfaFilterIT.apiTokenExemptFromGate` — 200, no gate bounce), and the
exemption itself is the in-chain request attribute
`jenkins.security.BasicHeaderApiTokenAuthenticator` — which works for
whatever authenticator sets it.

**Ruling (mads, 2026-08-19):** implement Bearer — but *not* as a bet on
core gaining it (A15 option (a) was rejected in spirit) and *not* by
pulling a third-party dependency. Spring Security 6.5.3 is in the
dependency tree only as a `provided` *transitive* of jenkins-core, and
Jenkins does not run Spring Security's web filter chain (the Spring jars
serve the type system only: `Authentication`, `GrantedAuthority`) — so
"built-in" is the wrong frame. The implementation, tracked as A21, is a
small `jakarta.servlet.Filter` registered earliest (ahead of the gate):
read `Authorization: <api-token> strip the `Bearer ` prefix, resolve the user's
`ApiTokenProperty.matchesPassword(…)` (the same core primitive
`BasicHeaderApiTokenAuthenticator` uses under `Basic`), and on success
set the request auth + the same api-token request attribute the gate
already exempts — so no gate change is required on either outcome, as
A15's original note promised.

### A16 — `MfaFilter.targetPath()` evaluated every request as `/` (302 self-loop)
**Status: RESOLVED (Task 8).** **Owner: Task 8 (IT exposed, filter fixed, same
commit).**

Task 8's end-to-end IT — the first test to drive the real gate over HTTP
against a booted Jenkins — fired on a silent infinite-302 loop: every request
(the MFA page included) 302'd to itself until HtmlUnit threw "Too many
redirects". Root cause: `targetPath()` was built on
`HttpServletRequest.getServletPath()`, which returns `""` at the
`PluginServletFilter` position on the 2.528.3 embedded-Jetty/Stapler chain
(filter runs before dispatch — live trace: `sp=[] ctx=[/jenkins]` on every
gated request). Every request therefore evaluated as `/` → allow-list never
matched. The unit suite (pure `decision()` over string paths) can structurally
never catch this class — it pins the path the *filter computes*, not the
computation.

> **Red→green:** IT run 1, 6/7 red on "Too many redirects" + per-request
> `TEMP-DIAG` trace capturing `uri`/`decision` per request → fix: in-site
> path = `getRequestURI()` − `getContextPath()` (spec decomposition),
> query folded, null/odd → `/` fail-closed; `MfaFilter`'s javadoc now carries
> the "why not getServletPath()" so nobody simplifies it back. Green: 7/7.

### A17 — MFA page mount `securityRealm/mfa` squatted by the live realm (404)
**Status: RESOLVED (Task 8 — mads-ruled 2026-08-19).** **Owner: Task 8.**

After A16, the IT's redirect-follow 404'd. Decoded Stapler route page in the
404 body: `No matching rule was found on
hudson.security.HudsonPrivateSecurityRealm for "/mfa"` — the *active realm*
is a `ModelObject`, and Stapler mounts it at the top-level `securityRealm`
node, which owns the whole prefix. On any local-realm deployment — the
production shape of `jenkins.devcru.org` — every enrolled user's gate bounce
404s. Invisible in Tasks 1–7 because every earlier harness used the default
test realm (no ModelObject at that node); the IT matched production shape
and exposed it.

> **Ruling (mads, 2026-08-19):** agreed with the recommendation — move the
> mount `securityRealm/mfa` → `mfa` ("I agree with your recommendation.
> Proceed."). `mfa` is a free single segment: no core mount, nothing a realm
> can squat, survives any realm shape.

> **Landed (Task 8, this commit):** the full 6-point sweep —
> `MfaController.getUrlName()` → `"mfa"` (+ deviation #3 with the 404
> evidence); allow-list entry `/securityRealm` → `/mfa` (the seven IT cases
> verified no IT case needs the realm's own mount tree post-auth; anonymous
> reach of realm pages is already owned by step 3); `isSecurityPath` first-
> segment set +`mfa` (a redirect *to* the MFA page degrades to root, else
> post-verify loops back into the gate); the gate's 302 Location; the IT's
> endpoint helper + Location pins; the jelly doc line. Unit pins
> (`FilterLogicTest`/`MfaControllerTest`) moved with the path, semantics
> kept. Green: 7/7.

### A18 — MFA page 500'd on render: `<x:out>` is not a tag on this runtime
**Status: RESOLVED (Task 8 — mads-ruled 2026-08-19).** **Owner: Task 8.**

Once Defect B was fixed, every test that reached the MFA page over HTTP hit
a 500: `JellyException: index.jelly:105 <x:out> This tag does not understand
the 'value' attribute`. The Jelly on the 2.528.3 classpath
(`org.jenkins-ci:commons-jelly` fork + `commons-jelly-tags-xml`) defines no
`out` tag — there is no `org/apache/commons/jelly/tags/xml/OutTag.class`.
The escape-output tag is `j:out` under `jelly:core` (the same tag core's own
views use); `x:` is `jelly:xml`, its element set (`element`, `attribute`,
`doctype`, `transform`) never included `out`. Invisible in Tasks 1–7 because
`InjectedTest`'s Jelly-parse check validates structure, not serve-time
execution — the page was served over HTTP for the first time in this IT.

> **Landed (Task 8, this commit):** the page's two dynamic TEXT values
> (issuer, masked email) moved from `<x:out value="…"/>` to
> `<j:out value="…"/>`; the crumb attribute is interpolated raw, exactly as
> core's own crumb-bearing views (`signup.jelly`,
> `authenticate-security-token.jelly`) do — the default crumb token is
> base62, never XML-special, and an attribute value cannot itself contain a
> nested tag. With `escape-by-default='false'` on the page, the `j:out`
> text positions are the one remaining XML-escape surface, so they are
> deliberately core's tag. The doc comment names the failure signature so
> nobody "restores" the x: prefix.

### A19 — `MfaFilterIT`'s `rawGet` followed redirects despite its contract
**Status: RESOLVED (Task 8).** **Owner: Task 8 (test-harness defect, not a
filter defect).**

`rawGet`'s Javadoc said "no redirect following", but
`c.loadWebResponse(req)` follows 302s by default. For four consecutive
failure rounds the "gate returns 404/500" readings were in fact the
*destination* page's status (the MFA page's own 404, then its own 500) —
the gate's 302 had been correct the whole time, and the page defects
(A17/A18) were still genuine but were mis-attributed to the filter for two
rounds. Fixed by explicitly toggling `setRedirectEnabled(false)` around
`loadWebResponse` on the same client (a second client would have lost the
session/cookies). Lesson pinned in the helper's Javadoc: in this harness a
raw-status assertion must switch the client's redirect behaviour, there is
no "raw by default".

### A20 — MFA endpoints not URL-routable: `postVerify`/`postResendEmail` 404
**Status: RESOLVED (Task 8).** **Owner: Task 8 (IT exposed, controller
fixed, same commit).**

Once A17–A19 were fixed, the IT's first ever *executed* verify POST 404'd.
The booted 404 body is unambiguous: Stapler resolved `/mfa` to the
`MfaController` and then reported `No matching rule was found on
…MfaController for "/postVerify"`, listing its URL mappings — only the
`getX` accessors. Stapler's dynamic-method dispatch auto-maps only
get/is/do-prefixed methods (plus explicit `@WebMethod`); a method named
bare `postVerify` exposes **no dispatch token at all**, and
`@RequirePOST` is a *policy* guard (rejects non-POST) — it does not
declare a URL. Production impact: with the page now reachable, **every
user's verify and resend would have been a dead button** (the JS POSTs to
relative `postVerify`/`postResendEmail`) — the IT caught it before
ship. Invisible through Tasks 1–7 because this endpoint glue was
deliberately left to Task 8's IT (`MfaController` class doc) and the page's
bounce itself had been 404/500 all along, so no POST had ever reached the
controller.

> **Landed (Task 8, this commit):** both endpoints are annotated
> `@WebMethod(name = "postVerify" | "postResendEmail")` — the only
> attribute this Stapler's `WebMethod` has (verified against the resolved
> artifact: `public abstract String[] name()`) — declaring the exact
> tokens the page's JS and the plan's contract already use, so no
> client-side change was needed; `@RequirePOST` stays for the method-level
> guard. The class comment names the failure signature so nobody strips
> the annotation as "unused".

### A21 — Bearer `Authorization: <api-token> authenticator (home-grown, no dependency)
**Status: LANDED (2026-08-19) — `org.sebcru.mfa.BearerTokenFilter` +
`BearerTokenFilterTest` (8 parse cases) + `MfaFilterIT#bearerTokenExemptFromGate`
(booted IT, positive + no-oracle negative); CI full-green 83 tests / 0 failures
on `clean verify`.**
**Owner: landed this session; no action remaining.**

The A15 resolution, as a buildable unit — a new `jakarta.servlet.Filter`
(registered earliest in `DevcruMfaPlugin`, ahead of the gate): (1) reads
`Authorization: <api-token> on requests that carry it; (2) strips the `Bearer `
prefix (case-insensitive scheme match); (3) **resolves the caller's identity
from a companion header, not the token** — a Jenkins API token is an opaque
40-hex random value with no embedded identity (verified against
`ApiTokenProperty`; unlike GitHub-style tokens you cannot parse a user out of
it), so the client also sends `X-Jenkins-User: <id>` (an explicit, documented
client contract of our making — the only way to know *which* user's token to
check without an O(N) scan of every user, which we refuse to do per request);
(4) checks
`User.getById(x, false).getProperty(ApiTokenProperty.class).matchesPassword(bearerValue)`;
(5) on success, sets the request authentication (the
`SecurityContextHolder`'s `Authentication`, via the public
`User.impersonate2()` seam — the one step Spring's absent Bearer filter would
do) and the **api-token request attribute the gate already exempts** — so the
gate path is unchanged and the exemption contract is identical for Basic and
Bearer; (6) on *any* mismatch or runtime exception — header missing, unknown
user, wrong token, empty token, a property that fails to resolve — pass
through untouched (anonymous / gate apply exactly as today; no silent 401, no
500, no oracle: a wrong Bearer is byte-for-byte indistinguishable from no
token).

**Landed design note (AMC constraint):** a first draft that delegated the token
check to core's internal `jenkins.security.BasicApiTokenHelper` — or the
`User.impersonate(UserDetails)` overload — failed
`access-modifier-checker:enforce` ("must not be used"): a Jenkins plugin may
only call core's approved public API surface. The landed build uses the public
`ApiTokenProperty.matchesPassword` path (the same primitive Basic's
authenticator relies on under the hood, reached through the public door) and
`User.impersonate2()` (the public 0-arg Spring-flavoured impersonation seam —
no current-user permission assertion) — same effective behaviour, no
dependency on internal seams that could shift across core versions.

**Non-goals (per the ruling):** no new dependency (rejected — see A15);
no change to the gate's decision chain (it still reads the same api-token
attribute; it has zero code changes for Bearer); no change to the Basic path.

**Acceptance met:** (a) unit test — `BearerTokenFilter.parseBearing` is pure
string logic and unit-tested in a plain JVM (`BearerTokenFilterTest`, 7 cases:
well-formed, scheme case-insensitivity, Basic-adjacent, blank token, absent
companion header, blank companion header, absent `Authorization` header, raw
user-id pass-through). The token-check half is not a plain-JVM test —
`ApiTokenProperty.matchesPassword` only dereferences a real `tokenStore` once
it has been populated by a token minted for a saved user, so that half is
live-tested as (b); (b) IT — `MfaFilterIT#bearerTokenExemptFromGate` mirrors
`apiTokenExemptFromGate` but with `Authorization: <api-token> (case: `bearer`) +
`X-Jenkins-User`, real `rule.createApiToken` token, booted Jenkins: 200 with
**no** `/mfa` bounce. The same IT carries the no-oracle negative — a Bearer
token presented for the wrong caller id must return the same status +
Location as a bare no-token baseline (200 in this harness, because anonymous
has read access to the job API; the assertion compares the two rather than
asserting a hardcoded status, so it keeps pinning itself if the anonymous
access model ever changes). Existing Basic and anonymous cases remain green.

## CLOSED-ON-WATCH — no action, context for the next reader

### A4 — `DevcruMfaConfig.current()` scans `GlobalConfiguration.all()` per call
**Status: CTX.** Fine at endpoint call rates, but the Task 7 filter invokes
it on *every* request (the A1 ruling makes `current()` the per-request read).
The cast-scan is O(n-plugin-configs); acceptable at this scale. If filter
latency is ever profiled, this is the line to look at. No change now.

### A9 — `MfaUserProperty.isMfaEnabled()` — no defect, but fragile
**Status: CTX.** Calls `totpSecret.getPlainText()` under a `!= null` guard
before the empty check — safe today (same shape as `hasTotpFactor()`).
Recorded because the guard is one "simplification" away from a real NPE on a
non-null-but-blank secret. A unit test pinning the blank-secret shape would
make the fragility structural rather than documentary; welcome in a Task 9
commit, not required.

### A10 — Stale pending-code hash lingers after expiry
**Status: CTX.** `verify` clears pending state only on a *hash match*
(`CONSUMED` and `EXPIRED` branches); a wrong-code attempt against an expired
pending code leaves the dead hash in place until a later match or a fresh
issue overwrites it. An expired hash authorises nothing. Noted so a reader
expecting an eager TTL sweep doesn't flag it as a bug.

### A12 — `RateLimiter`'s global monitor serializes failure recording
**Status: CTX.** `synchronized(this)` across all users' failure paths — a
few map ops per *failed* attempt; success path is a `remove`, reads
(`isLocked`) stay lock-free. Correct and cheap enough for a delay measure.
Context for anyone tempted to make it lock-free; don't, without a reason.

### A14 — `DevcruMfaPlugin` is still the Task 0 stub
**Status: RESOLVED (Task 7).** The stub is replaced by the
`@Initializer`/`@Terminator` filter registration in
`org.sebcru.mfa.DevcruMfaPlugin` — a plain `@Extension` singleton (NOT a
`hudson.Plugin` subclass, which is not Guice-creatable and breaks
`TaskMethodFinder`'s instantiation, and NOT `hudson.Plugin`'s own
lifecycle), a static initializer registered at `EXTENSIONS_AUGMENTED`
(the plan sketch's `STARTED` fires before the Guice injector is built,
which is the milestone this class's javadoc documents with the exact
failure signature), and a `@Terminator` that calls `removeFilter` with an
identity-equal instance. See the architecture record's Task 7 note for
the full deviation record.

## Not in the code yet (planned work, not debt)

Task 9's enrolment/management UI (+ A2's *second* minting path and A7/A8's
telemetry consumer + reset wiring). Task 10's live-box cutover (the plan's
backup/rollback section).

---

## Resolved

| Item | Resolved by | Commit | Note |
|------|-------------|--------|------|
| A1 — gate ran on a config defaults instance | `DevcruMfaConfig.currentSafe()` becomes the single authoritative runtime reader; `MfaFilter` and all three `MfaController` read sites use it; `MfaController.currentUser()` delegates to the filter's `findCurrentUser()`; class javadoc reconciled (see "Landed" note in A1). | this commit (Task 7) | The A1 ruling, code-complete: one config object, one user definition, shared by gate and page. |
| A3 — two redirect contracts (parameter vs. Referer) | `MfaFilter` 302s with `?redirect=<validated>`; `postVerify` reads the parameter first, `Referer` fallback only when absent; both carry the same host-checked validator; MFA page JS carries the parameter across both POSTs (see "Landed" note in A3). | this commit (Task 7) | The A3 ruling, code-complete; the live end-to-end round-trip assertion is Task 8's A5 IT. |
| A5 — send-back resolved to the MFA page itself | Plumbing (this commit, Task 7): the gate carries the pre-login destination in `?redirect=` (forged parameters refused by the same validator as forged Referers); the page JS and `postVerify` consume it. Full resolution (Task 8, 2026-08-19): `MfaFilterIT.totpFlowEndToEndWithRedirectRoundTrip` — no-carrier → context root; in-site parameter round-trips verbatim through Location → page → JSON; session id rotates on success. | Task 7 commit + this commit (Task 8) | Code-complete end to end; see A5's "Landed (Task 8)" note for the signed-contract scope. |
| A14 — plugin class still the Task 0 stub | Replaced by the `@Extension` + `@Initializer(EXTENSIONS_AUGMENTED, static)` + `@Terminator` registration with one shared filter instance (see A14 note and the architecture record's Task 7 deviation record). | this commit (Task 7) | Deviation from the plan's `hudson.Plugin`/`STARTED` sketch, documented in `DevcruMfaPlugin`'s javadoc with the exact failure signature. |
| A6 — README conflated the two trust instruments | One-sentence rewrite of "Remembered devices" in README "Practical usage": session trust (this login, no per-request re-check) vs. browser memory (future logins, the configured window) split into distinct sentences. | this commit (rulings, 2026-08-18) | End-user contract now matches §5 "Trust semantics" of the architecture record. |
| A11 — `postVerify` comment drift on crumb embedding | Rewrote the endpoint-block comment in `MfaController`: the page gets the crumb from the Java model (`getCrumbField()`/`getCrumbValue()`), not via the `h` taglib (unbound — no `<l:view>`), and the model calls the same core static (`Functions.getCrumb`) so policy stays in core. | this commit (rulings, 2026-08-18) | Comment-only change. |
| A13 — `resolveRedirectTarget`'s one-directional port check left unexplained | Expanded the `@param port` javadoc: a port-less referer is accepted on host match alone, and why that is benign for single-origin Jenkins (browsers only emit a port when non-default). | this commit (rulings, 2026-08-18) | Comment-only change; if Task 7's A3 plumbing touches this function, tighten the check to the same comment's argument. |

*Move items here with their fixing commit when closed. Keep the resolved
text intact — this file is the audit trail.*
