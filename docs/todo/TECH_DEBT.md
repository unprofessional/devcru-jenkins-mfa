# TECH_DEBT — devcru-mfa

> **Provenance.** 2026-08-18 top-to-bottom code audit (Tasks 0–6 landed,
> `develop` at `f705ea3`, before Task 7). Originally §10 of
> [`docs/architecture/README.md`](../architecture/README.md); split out here
> on 2026-08-18 so the findings are a **working list with statuses**, not a
> read-only appendix.
>
> **How this file works.**
> - Each item keeps its audit number (A1–A14) so cross-references in the
>   architecture record, the plan, and the Task 7 handoff stay valid.
> - **Status:** `OPEN` (needs a decision or code change) ·
>   `DECIDE` (mads ruling required, code blocked or at risk on it) ·
>   `CTX` (no action — context for the next reviewer) · `CLOSED` (moved to
>   `docs/done/` only when the parent task doc is archived).
> - **Owner task** names where the fix belongs when it belongs to a task;
>   otherwise the fix is a standalone commit on `develop`.
> - When an item is resolved: set status, link the fixing commit, move the
>   item to the Resolved table at the bottom (don't delete — the audit trail
>   is the point).

---

## OPEN — rulings needed from mads

### A1 — `DevcruMfaConfig` instance duality: the gate runs on a defaults instance
**Status: DECIDE.** **Owner task: Task 7 (+ Task 8 for the controller).**

`MfaController` reads policy via `get()` — the static process-default
instance — while admin form saves land on the descriptor instance
(`current()`'s domain). A fresh `DevcruMfaConfig` is constructed once at
class-init with the plan defaults and is *never* updated by form saves.

Consequence: the gate currently runs on defaults; admin-visible tuning
(windows, exemptions, policy) only reaches it once a `current()` path is
wired. The class doc says "callers use `get()`"; the Task 7 handoff mandates
`current()` for the filter. Two different claims about the same seam.

**Ruling required:** which instance is authoritative for runtime policy?
Recommended: `current()` for all runtime readers (filter *and* controller),
with `get()` kept only as the null-safe fallback `current()` already
provides when no descriptor exists (tests/pre-startup). Then reconcile the
class javadoc in the same commit (house rule: a second enforcement layer
must update stale "single source of truth" claims).

### A2 — `emailCodeSecret` is never minted; codes hash under a blank-string key
**Status: DECIDE.** **Owner task: confirm — Task 9 enrolment UI, or
a controller lazy-mint now.**

`MfaUserProperty.setEmailCodeSecret` is documented as "set by Task 3 when the
email factor is first enrolled", but Task 3 (`EmailCodeIssuer`) never writes
it, and the controller passes
`p.getEmailCodeSecret() == null ? "" : …` — a **blank-string HMAC key**. The
mechanics still work (single-use, TTL, replay-proof), but the mads-signed
confidentiality story — per-user HMAC key, master-key encrypted at rest,
"two users' states cannot be correlated" — is not actually implemented:
every user's pending codes would hash under the same empty key.

**Ruling required:** Task 9's enrolment UI mints the key (parallel to TOTP
seeding via `Totp.newBase32Secret()`-style material, stored
`Secret.fromString`), or the controller lazy-mints on first email issue.
Recommend the latter *additionally* — it's three lines and closes the gap
before any enrol UI exists. README's "per-user-keyed" sentence is then true
rather than aspirational.

### A3 — `?redirect=` query parameter vs `Referer`: two redirect contracts
**Status: OPEN.** **Owner task: Task 7.**

The filter spec (Task 7 handoff) 302s to
`/securityRealm/mfa?redirect=<target>`; `MfaController.postVerify` never
looks at `redirect` and feeds `resolveRedirectTarget` from
`req.getHeader("Referer")`. Both are server-validated, in different shapes —
and a contract with two inputs is two contracts that can drift.

**Fix when Task 7 lands:** `?redirect=` (present in the URL the user arrived
with) is the authoritative in; `Referer` becomes the fallback (e.g. direct
hits that carry no parameter). One pure function, one home, both paths through
it.

## OPEN — code/doc work with a clear owner

### A5 — "Back to where you were" resolves to the MFA page, not the pre-login page
**Status: OPEN.** **Owner task: Task 7 (plumbing) + Task 8 (IT assertion).**
Companion to A3.

A same-origin POST carries the *MFA page's own URL* as its `Referer`
(`/securityRealm/mfa` is the page issuing the form POST). So the current
`Referer`-based `resolveRedirectTarget` send-back lands the user on the MFA
page itself in the normal browser path — not where they were headed. The
`?redirect=` parameter is almost certainly the intended primary source
(reinforcing A3).

**Task 8's integration test must assert the end-to-end pre-login URL
round-trips**, not merely that *a* safe target is returned.

### A7 — `failedAttemptStreak` is write-only and unbounded
**Status: OPEN.** **Owner task: decide before Task 9.**

`postVerify` increments and persists it on every failure; `RateLimiter.clear`
(success / lockout) does *not* reset it; nothing reads it (Task 9's UI hint
is the planned consumer). It grows monotonically per user forever.

**Fix options:** (a) Task 9 consumes it *and* the clear-path resets it;
(b) stop persisting a counter nothing reads. One decision, same commit as
the choice.

### A8 — `lastVerifiedFactor` is documented telemetry with no writer
**Status: OPEN.** **Owner task: same commit as A7's decision.**

Javadoc says "0 = totp, 1 = email. Telemetry only." — but `postVerify` never
sets it, so every user's property carries `0` (implies TOTP) even for
email-only users. Same family as A7: either the controller/Task 9 writes it,
or the field is dead and should go.

### A6 — README conflates the two trust instruments
**Status: OPEN.** **Owner task: any task landing before Task 10 —
practical-usage pass.**

"Keeps the browser trusted for the configured window" blurs
`org.sebcru.mfa.verified` (this session, indefinite — signed: no per-request
expiry) with `trustedUntilMs` (*future* logins). See the architecture record
§5 "Trust semantics". One sentence fix; land it with the Task 8 or 9 README
pass so the end-user contract is exact before cutover.

### A11 — `postVerify` Javadoc drift on crumb embedding
**Status: OPEN.** **Owner task: piggyback on the A3/A5 Task 7 commit.**

The method Javadoc says the page embeds the crumb "via core's `h` taglib";
the page actually receives it from the Java model (`getCrumbField()` /
`getCrumbValue()`) — by design, precisely because the page skips `<l:view>`.
The class-level doc gets it right; the method comment does not.

### A13 — `resolveRedirectTarget`'s port comparison is one-directional
**Status: OPEN.** **Owner task: same commit as A3 (or a one-line comment).**

The explicit-port `Integer.parseInt(port)` comparison only runs when the
referer carries a port; a port-less referer matches the site's port
regardless (including non-default). Benign for single-origin Jenkins
(browsers send the real port when non-default), but it's an implicit
assumption with no comment. Add the comment at minimum; tighten if the same
commit is touching the function for A3.

## CLOSED-ON-WATCH — no action, context for the next reader

### A4 — `DevcruMfaConfig.current()` scans `GlobalConfiguration.all()` per call
**Status: CTX.** Fine at endpoint call rates, but the Task 7 filter invokes
it on *every* request. The cast-scan is O(n-plugin-configs); acceptable.
If filter latency is ever profiled, this is the line to look at. No change.

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
Task 9 enrolment UI (+ A2's key minting and A7/A8's telemetry consumer), the
Task 8 integration test (session regeneration + live-mail round trip + A5's
redirect assertion), and the Task 10 live-box cutover (plan's
backup/rollback section).

---

## Resolved

| Item | Resolved by | Commit | Note |
|------|-------------|--------|------|
| —    | —           | —      | —    |

*Move items here with their fixing commit when closed. Keep the resolved
text intact — this file is the audit trail.*
