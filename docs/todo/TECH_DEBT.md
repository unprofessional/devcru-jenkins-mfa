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
**Status: RULING-RECORDED.** **Owner: Task 7 (filter) + controller migration
in the same pass.**

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

### A2 — `emailCodeSecret` never minted; codes hash under a blank-string key
**Status: RULING-RECORDED.** **Owner: standalone commit (controller
lazy-mint) + Task 9 (enrolment UI minting). Both.**

`MfaUserProperty.setEmailCodeSecret` is documented as "set by Task 3 when the
email factor is first enrolled", but Task 3 (`EmailCodeIssuer`) never writes
it, and the controller passes
`p.getEmailCodeSecret() == null ? "" : …` — a **blank-string HMAC key**. The
mechanics still work (single-use, TTL, replay-proof), but the mads-signed
confidentiality story — per-user HMAC key, master-key encrypted at rest,
"two users' states cannot be correlated" — is not actually implemented.

> **Ruling (mads, 2026-08-18):** **both** paths — the Task 9 enrolment UI
> mints the key at first email enrolment, *and* the controller lazy-mints on
> first email issue — so there is no gap between now and Task 9. The
> lazy-mint is a standalone commit (Sebastian); the enrolment-side minting
> lands with Task 9. README's "per-user-keyed" sentence becomes true once
> the lazy-mint lands.

### A3 — `?redirect=` query parameter vs `Referer`: two redirect contracts
**Status: RULING-RECORDED.** **Owner: Task 7 (filter plumbing) + Task 8 (IT
assertion, see A5).**

The filter spec (Task 7 handoff) 302s to `/securityRealm/mfa?redirect=<target>`;
`MfaController.postVerify` never looks at `redirect` and feeds
`resolveRedirectTarget` from `req.getHeader("Referer")` — two inputs, two
shaped validators, drift risk.

> **Ruling (mads, 2026-08-18):** **the `?redirect=` query parameter is
> canonical over `Referer`.** Implementation: read the parameter first;
> fall back to the `Referer` header only when the parameter is absent; both
> flows through the single existing pure `resolveRedirectTarget`.

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
**Status: OPEN (direction settled by the A3 ruling).** **Owner: Task 7
(plumbing) + Task 8 (IT assertion).**

A same-origin POST carries the *MFA page's own URL* as its `Referer`
(`/securityRealm/mfa` is the page issuing the form POST). So the current
`Referer`-based `resolveRedirectTarget` send-back lands the user on the MFA
page itself in the normal browser path — not where they were headed. The A3
ruling (`?redirect=` canonical) settles the *direction*; what remains is
Task 7 plumbing the parameter through to `postVerify`'s target resolution,
and **Task 8's integration test asserting the end-to-end pre-login URL
round-trips**, not merely that *a* safe target is returned.

(Residual: if `postVerify` receives `?redirect=` on the POST itself it is in
the query string directly; if the browser POSTs to a bare URL, the controller
falls back to the POST's `Referer` — which for a same-origin form POST is
the MFA page. Task 8 decides the final plumbing detail and pins it in the
IT. Flagged so the Task 7/8 implementation doesn't half-implement it.)

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
**Status: CTX (closes with Task 7).** By design — the stub is replaced by the
`@Initializer`/`@Terminator` filter registration. Noted so the audit doesn't
re-flag it as an oversight.

## Not in the code yet (planned work, not debt)

The Task 7 gate filter + decision chain (A1/A3/A5 concentrate there), the
A2 controller lazy-mint (standalone, next step), the Task 9 enrolment UI
(+ A2's key minting and A7/A8's telemetry consumer), the Task 8 integration
test (session regeneration + live-mail round trip + A5's redirect assertion),
and the Task 10 live-box cutover (plan's backup/rollback section).

---

## Resolved

| Item | Resolved by | Commit | Note |
|------|-------------|--------|------|
| A6 — README conflated the two trust instruments | One-sentence rewrite of "Remembered devices" in README "Practical usage": session trust (this login, no per-request re-check) vs. browser memory (future logins, the configured window) split into distinct sentences. | this commit (rulings, 2026-08-18) | End-user contract now matches §5 "Trust semantics" of the architecture record. |
| A11 — `postVerify` comment drift on crumb embedding | Rewrote the endpoint-block comment in `MfaController`: the page gets the crumb from the Java model (`getCrumbField()`/`getCrumbValue()`), not via the `h` taglib (unbound — no `<l:view>`), and the model calls the same core static (`Functions.getCrumb`) so policy stays in core. | this commit (rulings, 2026-08-18) | Comment-only change. |
| A13 — `resolveRedirectTarget`'s one-directional port check left unexplained | Expanded the `@param port` javadoc: a port-less referer is accepted on host match alone, and why that is benign for single-origin Jenkins (browsers only emit a port when non-default). | this commit (rulings, 2026-08-18) | Comment-only change; if Task 7's A3 plumbing touches this function, tighten the check to the same comment's argument. |

*Move items here with their fixing commit when closed. Keep the resolved
text intact — this file is the audit trail.*
