# TECH_DEBT — devcru-mfa

> **Provenance.** 2026-08-18 top-to-bottom code audit (Tasks 0–6 landed,
> `develop` at `f705ea3`, before Task 7). Originally §10 of
> [`docs/architecture/README.md`](../architecture/README.md); split out here
> on 2026-08-18 so the findings are a **working list with statuses**, not a
> read-only appendix. **Rulings received from mads 2026-08-18 (see
> "Rulings recorded" below); fixes land in their owner tasks.**
>
> **How this file works.**
> - Each item keeps its audit number (A1–A14) so cross-references in the
>   architecture record, the plan, and the Task 7 handoff stay valid.
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
**Status: RESOLVED (plumbing, Task 7); Task 8 IT assertion still owed (see
below).** **Owner: Task 7 (plumbing) + Task 8 (IT assertion).**

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
> end-to-end through both carriers. **Still owed (Task 8):** the
> integration test asserting the full pre-login-URL round trip against a
> booted Jenkins — the unit pins cover the input selection and the
> validator, not the live boot path (session flag + JS + POST + 302).

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

Task 8's integration test (the `InjectedTest` boot already exercises the
filter's registration and happy paths live; Task 8 adds the dedicated IT:
session regeneration on success, a live-mail round trip, A5's full
pre-login-URL round-trip assertion against a booted Jenkins, and the
re-pin of the API-token request attribute against a real security chain).
Task 9's enrolment/management UI (+ A2's *second* minting path and A7/A8's
telemetry consumer + reset wiring). Task 10's live-box cutover (the plan's
backup/rollback section).

---

## Resolved

| Item | Resolved by | Commit | Note |
|------|-------------|--------|------|
| A1 — gate ran on a config defaults instance | `DevcruMfaConfig.currentSafe()` becomes the single authoritative runtime reader; `MfaFilter` and all three `MfaController` read sites use it; `MfaController.currentUser()` delegates to the filter's `findCurrentUser()`; class javadoc reconciled (see "Landed" note in A1). | this commit (Task 7) | The A1 ruling, code-complete: one config object, one user definition, shared by gate and page. |
| A3 — two redirect contracts (parameter vs. Referer) | `MfaFilter` 302s with `?redirect=<validated>`; `postVerify` reads the parameter first, `Referer` fallback only when absent; both carry the same host-checked validator; MFA page JS carries the parameter across both POSTs (see "Landed" note in A3). | this commit (Task 7) | The A3 ruling, code-complete; the live end-to-end round-trip assertion is Task 8's A5 IT. |
| A5 — send-back resolved to the MFA page itself | The gate now carries the pre-login destination in `?redirect=` (forged parameters refused by the same validator as forged Referers); the page JS and `postVerify` consume it (see "Landed" note in A5). | this commit (Task 7) | Plumbing landed; the booted-Jenkins round-trip IT assertion is what Task 8 still owes. |
| A14 — plugin class still the Task 0 stub | Replaced by the `@Extension` + `@Initializer(EXTENSIONS_AUGMENTED, static)` + `@Terminator` registration with one shared filter instance (see A14 note and the architecture record's Task 7 deviation record). | this commit (Task 7) | Deviation from the plan's `hudson.Plugin`/`STARTED` sketch, documented in `DevcruMfaPlugin`'s javadoc with the exact failure signature. |
| A6 — README conflated the two trust instruments | One-sentence rewrite of "Remembered devices" in README "Practical usage": session trust (this login, no per-request re-check) vs. browser memory (future logins, the configured window) split into distinct sentences. | this commit (rulings, 2026-08-18) | End-user contract now matches §5 "Trust semantics" of the architecture record. |
| A11 — `postVerify` comment drift on crumb embedding | Rewrote the endpoint-block comment in `MfaController`: the page gets the crumb from the Java model (`getCrumbField()`/`getCrumbValue()`), not via the `h` taglib (unbound — no `<l:view>`), and the model calls the same core static (`Functions.getCrumb`) so policy stays in core. | this commit (rulings, 2026-08-18) | Comment-only change. |
| A13 — `resolveRedirectTarget`'s one-directional port check left unexplained | Expanded the `@param port` javadoc: a port-less referer is accepted on host match alone, and why that is benign for single-origin Jenkins (browsers only emit a port when non-default). | this commit (rulings, 2026-08-18) | Comment-only change; if Task 7's A3 plumbing touches this function, tighten the check to the same comment's argument. |

*Move items here with their fixing commit when closed. Keep the resolved
text intact — this file is the audit trail.*
