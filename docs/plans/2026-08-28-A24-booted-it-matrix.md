# A24 §7 booted IT matrix — plan + breadth enumeration (2026-08-28)

> **STATUS — LANDED 2026-08-28 (supersedes the open framing below).**
> Executed as planned: `MfaAdminA24IT` (5 legs, 1,432 lines, BDD-documented)
> GREEN — `mvn -o -B test -Dtest=MfaAdminA24IT` 5/5, 36.0s
> (`/tmp/a24it-full3.log`, Finished 2026-08-28T20:05:54-04:00); full
> CI-mirror `mvn -o -B clean verify` 149/149 green
> (`/tmp/a24it-final-verify.log`, Finished 2026-08-28T20:09:35-04:00).
> One red→green escalation, per this file's red→green policy: leg 4 (D16)
> found a genuine product defect — `postVerify`'s forced-setup branch
> cleared the marker + granted trust in memory BEFORE `u.save()` with no
> rollback; fixed in the same commit (catch branch restores
> marker/trust/streak/proven-factor before answering
> `persistence_failed`). Committed `f631503` (matrix + fix) and `63ce631`
> (docs), branch `a24-it-matrix` pushed to origin (head `63ce631`);
> `develop` untouched, **no PR filed — awaiting mads's merge decision**.
> Breadth slot 2's "Result: pending" below now reads: verified — logs
> above. The "No production-code changes planned" sentence is superseded
> by the D16 fix (the only production change; reported to mads, accepted
> in-channel 2026-08-28).

**Branch:** `a24-it-matrix` off `develop` (`7b8d7a3`). **Binding spec:**
`docs/done/2026-08-25-A24-force-enrol-spec-delta.md` §7 items 4–10 (all
rulings AS RECOMMENDED, 2026-08-25). **Model for the work + report:**
`qwen3.8:27b-mtp-q8_0`.

## Scope

The A24 implementation (PR #28) is seam-pinned (`A24ForceEnrolSeamTest`,
10 pins) with one booted leg (`MfaAdminIT` leg 7, setup-pending recovery).
This plan executes the remaining spec §7 booted integration legs —
Stapler dispatch, the two authorization chains at the wire, the gate's
bounce, `target.save()` persistence, and `rule.restart()` round-trips — as
`MfaAdminA24IT`, self-contained (house shape per `MfaAdminIT`/
`MfaProfileIT`), one commit per leg cluster. **No production-code changes
planned.** If a leg goes red on a genuine product defect: red→green,
separate commit pair, reported to mads before proceeding (AGENTS.md:
security seams do not move without sign-off).

## Leg → spec mapping

| Commit (branch) | Spec §7 | Test method(s) |
| --- | --- | --- |
| 1 journey | 4 + 10 (partial) | `forceEnrolJourneyWithRestartCompletesSetupEndToEnd` — admin force-enrols (typed-confirm wire shape) → email-only property + marker ON DISK → target's LIVE pre-existing session bounces to `/mfa?redirect` on next request → setup variant renders (real title, no escape links) → `postResendEmail` issues to the REGISTERED mailbox only (CaptureEmailSender) → `postVerify` with the captured 8-char code → marker clear + trust + `lastVerifiedFactor=1` (EMAIL, set by the endpoint alone) → target reaches root 200 → `rule.restart()` → target's FRESH password session passes the gate on live trust (marker-clear+trust survived) → admin page slices settled (enrolled +1, pending 0, complement shrank) → admin's own factors intact (regression within the leg) |
| 2 guards | 5 + 10 | guard pins at the wire: (a) self-target `forceEnrol` → 200 `admin_self_management_forbidden` (200-envelope per spec, target untouched); (b) already-enrolled target → 200 `already_enrolled` with factor state byte-identical; (c) `confirmUserId` mismatch/absent → 200 `admin_confirm_required`, no mutation; (d) password-only admin (enrolled, unverified, no trust) → 403 `admin_verification_required`, target byte-identical; (e) under least-privilege strategy: unenrolled non-admin POST → 403 `admin_permission_required` (checked FIRST); (f) verified non-admin (enrolled + TOTP-verified, no ADMINISTER) → ALSO `admin_permission_required` — the Defect-2 check-order probe on the A24 verb |
| 3 setup+idempotence | 6 + 7 | (a) **setup-does-not-bypass:** the rendered setup variant (real HTTP, half-set-up session) offers exactly the verify form and crumb — no link/form to authenticated root content; a direct GET of a protected path (root) from that session → 302 gate bounce; (b) **idempotence:** same-address repeat `forceEnrol` → 200 UNCHANGED, exactly ONE mail ever, no second audit-relevant write (pending-code state identical); (c) **correction:** different address → CORRECT — new address live, marker still pending, the OLD address's pending code does not verify (invalidated at D5); (d) two admin requests never mint a credential (no `emailCodeSecret`, no trust) nor clear the marker; (e) roster state at the wire: pending row is NOT in the enrolled slice (marker outranks `isMfaEnabled()`) |
| 4 failure honesty | 8 | (a) wrong 8-char code → 200 `wrong_code`, pending state preserved (a correct code still verifies after the miss — no single-use on a miss); (b) expired code → `expired` (TTL 1s set via `DevcruMfaConfig` test seam — the wire proof that expiry is REAL, not comment drift, the A23-review minor's class); (c) resend within cooldown → `resend_cooldown` with retry seconds; (d) **D16 persistence failure:** target's user dir made read-only before the verify → `persistence_failed`, session NOT verified (root still bounces), marker STILL pending → dir restored → re-issued code verifies → completion persists (the "setup complete either survives restart or is not claimed" pin, at the wire). N/A note: the plain (non-forced) persistence branch is already pin-shaped by leg 6 of `MfaAdminIT`; this leg is the FORCED branch only |
| 5 edges | 9 | (a) policy OFF: gated users no longer bounce (root 200 unverified), the complement view is HIDDEN on the admin page (D9: directory ≠ worklist) while the pending slice STAYS visible (obligation honesty) and the enrolled slice remains; (b) exempt user: `forceEnrol` → 200 `user_exempt` and the gate passes them (exempt list works end-to-end); (c) unknown realm (no HPSR Details property): the row renders with an `unknown` account label and `forceEnrol` IS allowed (D6: unknown ≠ disabled — refusal is positive-signal only); (d) deleted-between-render-and-POST: a user present at render time, deleted before the POST (in-JVM `User.getById(id,false).delete()` between two requests) → 200 `user_not_found`, and `User.getById(id,false)` stays null — NO record created on lookup |
| 6 regression net | 10 | full `mvn -o -B clean verify` (CI mirror) — the existing A22-b/A23/A21 suites plus all matrix legs. README check: no end-user behaviour change (tests-only); the "implemented vs in progress" note touched only if it materially improves honesty |

## Breadth enumeration (required work product — slots, probes, results)

1. **The host (Jenkins 2.528.3 / Stapler 2030).** Dispatch facts used:
   `@WebMethod(name="forceEnrol")` is the only routing token (A20 lesson);
   POST-only via `@RequirePOST`; root action mounted `mfaAdmin`. *Probe:*
   every leg POSTs the real wire shape (crumb from the real MFA page +
   `userId` + `confirmUserId` [+ `email`]); the 404/405 class is caught by
   the same routing the verbs were built on. *Result:* verified against
   the merged `postForceEnrol` source (line 231–303) + `MfaProfileIT`'s
   A20 routing precedent before writing.
2. **The runtime envelope.** Offline maven (`mvn -o -B`), JDK 21
   (`/opt/jdk-21.0.12+8`), SpotBugs at `verify`, no network. Collector
   Chromium `:9222` untouched; this matrix is HTMLUnit-based (no headful
   browser) — the real-browser layer is the already-accepted A24 walk
   (mads override, 2026-08-28). *Probe:* each leg's first run; the full
   matrix's last run is the CI-mirror verify. *Result:* verified —
   `/tmp/a24it-full3.log` (5/5, 36.0s) + `/tmp/a24it-final-verify.log`
   (149/149 clean verify, SpotBugs `check` + enforcer passed).
3. **External consumers.** The wire JSON envelopes
   (`{ok,error:{stable strings}}` / `{ok,op:"forceEnrol"}`) are parsed by
   `mfa-admin.js` — the strictest consumer. *Probe:* legs assert the
   EXACT stable strings from `VerifyOutcome` (the JS's switch on them),
   e.g. `already_enrolled` vs `user_not_found` are distinct; the 403
   bodies carry `no-store`+`nosniff` (asserted in the guard leg). The
   second consumer is the EMAIL: `CaptureEmailSender` records
   destination+code+TTL; the leg pins "registered mailbox only" (the
   signed no-open-relay decision) and that the body's code is the one
   that verifies.
4. **Environments.** Gate policies REQUIRED (default, most legs) and OFF
   (edge leg: bounce gone, complement hidden, pending slice stays).
   Themes/locales N/A for the wire legs (render-presence is the
   A22-b/§1-D walk's proven ground; this matrix asserts behaviour, and
   the setup-variant title string IS asserted in the rendered HTML —
   one theme-neutral content probe, both schemes already proven at the
   A22-b real-browser layer with mads's accepted A24 override).
   `DEVCRU_MFA_OFF` env var: N/A — the policy-OFF half of the kill
   switch is the same `off()` seam, unit-pinned (no JVM env in ITs,
   plan line 581).
5. **Privilege.** The elevated AND subordinate probes: verified-ADMIN
   admin (journey), PASSWORD-ONLY admin (credential axis, 403
   `admin_verification_required`), unenrolled NON-admin and
   TOTP-verified NON-admin under the least-privilege strategy
   (permission axis FIRST, the Defect-2 check-order probe), and the
   UNENROLLED target who starts exempt and becomes enforced. The admin
   surface's `adminPageAllowed()` (READ, ADMINISTER-only) vs the verb's
   two-axis chain is exercised by having the unenrolled admin READ the
   page (200, slices) in the guard leg while being denied the verb.
6. **Time.** TOTP: fresh `codeAt(now)` per attempt (no stale 30s window
   edges). Email: TTL 1s for the expiry arm (real clock sleep ~1.5s —
   the IT may take its time; the pin is the `expired` string, not the
   sleep), 60s cooldown asserted WITHOUT sleeping (the
   `resend_cooldown` + retry-seconds envelope is the time proof — the
   first resend in the leg is free, the immediate second hits cooldown
   by construction of `lastResendAt`). Lockout: 5 wrong codes would
   trip a 15-min lockout — the wrong-code arm uses ONE miss so the
   subsequent correct-code assertions are not confounded (streak reset
   on success is leg-5-of-MfaAdminIT's ground).
7. **Restart.** `rule.restart()` in the journey leg: disk anchors
   asserted BEFORE the restart (marker ON DISK via the user
   `config.xml` probe, the `userDir`/XML-regex helper copied from
   `MfaAdminIT`) so the post-restart state reads round-trip truth;
   after restart: marker-clear+trust survived (fresh session passes the
   gate), admin factors byte-identical. The D16 leg proves the
   CONVERSE: an unpersisted marker-clear must NOT be claimed (no
   verified session), then the retry persists — "works in this session"
   is refused as "works" at the wire.

## Red→green policy

AGENTS.md: record the red→green story only where it genuinely mattered.
Expected-greens are recorded as honest greens with the first-run log
path; any red gets a defect entry (symptom → root cause → fix commit)
in THIS file before proceeding, and security-seam changes escalate to
mads first.

## Standing rules (inherited, restated for the branch)

Work branch `develop`; `master` advances only on explicit per-step
approval; no force-push ever; NO PR unless mads asks. Commits: message
in a file, `git commit -F`, read back via `git log`. BDD doc (WHAT /
BDD GIVEN-WHEN-THEN / WHY-SOLVES) on every test per `TotpTest` house
standard — a test commit without its docs blocks review. One commit per
leg cluster; README touched in the same commit only for user-facing
change (none planned — tests only; the "implemented vs in progress"
honesty note checked at the end). Credentials in chat/logs:
`[REDACTED]`. No PII in group channels; progress messages on this
multi-step job; #showcase is watching.
