# A24 §7 booted IT matrix — session-reset handoff (2026-08-28, v1)

**To:** the next Sebastian session. **From:** the session that executed the
matrix. **Supersedes:** nothing (first v for this task); it *indexes* the
plan doc (now stamped LANDED) and the spec of record.

## 1. Headline — verified state (pair every claim with its artifact)

- **Task COMPLETE on code** — the branch is ready for mads's merge
  decision. Nothing is left to execute; what remains is a MERGE DECISION
  (mads) + a PR (file on request) + optional follow-ups (§7 below).
- **Branch `a24-it-matrix`, head `63ce631`, pushed to origin** —
  `git ls-remote --heads origin a24-it-matrix` returns
  `63ce631d8f570a31b31fdbe8112a4746bf915903`; local `git status -sb` reads
  `## a24-it-matrix...origin/a24-it-matrix` (clean, in sync).
  `develop` was **not** touched. **No PR filed** (standing rule: file only
  on explicit mads request).
- **Tally (corrected):** full CI-mirror `mvn -o -B clean verify` =
  **149/149 green**, 0 F/E/S —
  `/tmp/a24it-final-verify.log`, Finished **2026-08-28T20:09:35-04:00**.
  `MfaAdminA24IT` alone = **5/5 in 36.0s** —
  `/tmp/a24it-full3.log`, Finished **2026-08-28T20:05:54-04:00**.
  ⚠ **Honesty note (do not re-quote the old number):** earlier
  in-session reports and one commit message said "298/298". That was a
  double-count (per-class lines + phase summary). The *strict-anchored*
  Results summary is 149; per-class sum is 149; **there is no failsafe
  plugin — surefire explicitly includes `**/*IT.java`** (pom.xml
  surefire `<includes>`). 298 is wrong; TECH_DEBT has been corrected to
  149 (uncommitted fix in this handoff's commit). The commit message of
  `f631503` still contains "298" in one line; correcting an already-pushed
  commit message would need history rewrite — NOT worth it; this handoff
  is the correction of record. Verify by `git log -1 f631503 | grep 298`.
- **Open defects: NONE.** The only red that reached a verdict as
  product-side (D16) is fixed + pinned + regression-netted. All other
  reds were test-side, classified empirically (§4 red→green history).
- **The product change is exactly one place:** `src/main/java/org/
  sebcru/mfa/MfaController.java`, the forced-setup catch branch in
  `postVerify` (+9 net lines, in `f631503`). Diff:
  `git --no-pager show f631503 -- src/main/java/org/sebcru/mfa/MfaController.java`.

## 2. What is DONE and green

Per-file, from the committed diff (`git --no-pager diff --stat
develop..HEAD` = 6 files, +1587/-8):

| File | Status | Proof |
| --- | --- | --- |
| `src/test/java/org/sebcru/mfa/MfaAdminA24IT.java` | NEW, 1,432 lines, 5 legs + nested least-privilege strategy, BDD-documented per `TotpTest` house standard | 5/5 green, `/tmp/a24it-full3.log` |
| `src/main/java/org/sebcru/mfa/MfaController.java` | D16 rollback fix (see §3) | leg 4 red→green + full net 149/149 |
| `docs/plans/2026-08-28-A24-booted-it-matrix.md` | plan + breadth enumeration, **now stamped LANDED** (stamping itself in this handoff's commit; the file shipped at `f631503` pre-stamp) | `git diff develop..HEAD -- <file>` |
| `README.md` | A24 D16 honesty note in the Practical-usage behaviour contract (per AGENTS.md same-commit rule) | in `63ce631` |
| `docs/todo/TECH_DEBT.md` | both A24 entries (open + resolved row) record the matrix landing + D16; **tally corrected 298→149 in this commit** | in `63ce631` + uncommitted fix now committed |
| `docs/done/2026-08-25-A24-force-enrol-spec-delta.md` | spec-of-record header: "§7 matrix remains unimplemented" → LANDED line | in `63ce631` |

The 5 legs, each verified GREEN from a FRESH run (not a stale report):

1. `forceEnrolJourneyWithRestartCompletesSetupEndToEnd` — wire verb →
   email-only property + `forcedSetupPending` **on disk** → live-session
   gate bounce → closed setup variant → captured code → trust → root 200 →
   `rule.restart()` → fresh session passes on **persisted** trust → roster
   slices settle → admin factors intact.
2. `guardPinsDenyTheForceEnrolVerbAtTheWire` — self/confirm/
   already-enrolled 200-envelopes; (d1) enrolled password-only admin gets
   the **gate 302** (surface not allow-listed) vs (d2) unenrolled admin
   reads roster 200 but verb POST → **403** `admin_verification_required`;
   no-store/nosniff; deny-before-mutation "no MFA material" invariant;
   least-privilege nested strategy (permission axis FIRST).
3. `setupVariantIsClosedAndThePendingStateMachineHoldsAtTheWire` — one
   form / zero escape links, direct-fetch bounced; D5 idempotence (one
   mail total); correction invalidates the stale code (`no_pending`).
4. `failureHonestyRefusesToClaimSetupOverUnpersistedState` — wrong code
   survives; real 1s TTL expiry; cooldown `retrySeconds`; **D16 arm**
   (chmod'd user dir → `persistence_failed` → *bounce stands: no session,
   no in-memory trust, disk obligation intact* → restore → retry
   completes).
5. `policyAndIdentityEdgesBehavePerRulings` — OFF: no bounce, complement
   hidden, pending slice stays; exempt refuses + passes; unknown realm
   enrollable + `acct-unknown` (D6); deleted-between-render-and-POST
   `user_not_found`, lookup read-only.

## 3. In-flight object — NONE; state of the one product fix

`MfaController.postVerify`, forced-setup (`wasForcedSetup`) success→
save-failure path. BEFORE: success branch ran
`p.setForcedSetupPending(false)` + `TrustStore.trust(...)` + streak reset +
`setLastVerifiedFactor(1)` **in memory, before** `u.save()`; on `IOException`
it answered `persistence_failed` but never undid those mutations.
`MfaFilter` gate step 9 admits on `sessionVerified || trustLive`, and
`trustLive` reads the **in-memory** property → a `persistence_failed` user
kept a working session the disk did not back (fail-open; violated the
binding D16 ruling in the spec-of-record §10). AFTER: the catch branch
restores the four captured pre-state values (`preVerifyTrustUntil`,
`preVerifyFactor`, `preFailureStreak`, and re-sets
`forcedSetupPending(true)`) before answering. Pinned by leg 4's composite
gate check (no session AND no trust; disk file untouched). Regression
net: the whole verify path is exercised by the full suite; 149/149 green.

## 4. Run history (log ⇒ what it proved) — red→green, honest

| Log | Result | Proved |
| --- | --- | --- |
| `/tmp/a24it-journey1.log` / `journey2.log` | FAIL (compile) | My test-code errors (missing import; malformed helper sites) — test-side, mine |
| `/tmp/a24it-journey3.log` | GREEN 1/1, 13.9s | Leg 1 first-run green |
| `/tmp/a24it-guard1.log` | FAIL assert "denied op must not create target property" | RESOLVED: `User.getProperty(class)` auto-instantiates descriptor-backed properties, so `assertNull` is unobservable — probe `/tmp/a24it-probe.log` showed the target property `PRESENT, pristine` at fixture time and byte-identical after both denied ops. Test-side. Invariant re-written as "no MFA material" |
| `/tmp/a24it-guard2.log` | FAIL pin (d) 200 | RESOLVED: reused admin carried a persisted 720h remember-trust — product CORRECT, fixture wrong. Test-side |
| `/tmp/a24it-guard3..5.log` | FAIL pin (d) 302 | RESOLVED: single pin conflated gate control with controller seam. Split into (d1) gate-302 / (d2) 403; roster GET must **follow Stapler 302 forwards** (bare rawGet unfaithful). Test-side |
| `/tmp/a24it-guard6.log` | GREEN 1/1 | Leg 2 green at wire |
| `/tmp/a24it-l34.log` | FAIL leg 3 | RESOLVED: jelly renders button attributes on separate lines; single-space `contains` could never match. Test-side |
| `/tmp/a24it-l34.log` | FAIL leg 4 | **PRODUCT DEFECT (D16)** — the one that mattered. Fix in `MfaController` (see §3) |
| `/tmp/a24it-l34b.log` | FAIL (compile) | My over-engineered session-reading helper used absent harness APIs (`rule.getWebServer()`, `org.htmlunit.Cookie`). Removed; composite gate pin replaced it |
| `/tmp/a24it-l34c.log` | GREEN 2/2 | Legs 3+4 green with the fix |
| `/tmp/a24it-full2.log` | FAIL leg 5 | RESOLVED: my row anchor assumed `<tr data-user-id=` first; rendered order is `data-display` then `data-user-id` (probe5 page dump confirmed). Test-side — and note I deleted two throwaway probes (`Leg2ProbeIT`, `Leg5ProbeIT`) after use |
| **`/tmp/a24it-full3.log`** | **GREEN 5/5, 36.02s** | **Matrix green** |
| **`/tmp/a24it-final-verify.log`** | **GREEN 149/149** (SpotBugs `check` + enforcer at `verify`) | **Regression net held with the product change; CI mirror** |

## 5. Verified API / environment facts (do NOT re-discover)

- **Test harness:** `mvn -o -B` (offline), `JAVA_HOME=/opt/jdk-21.0.12+8`,
  PATH prepend `$HOME/.local/bin`. **No failsafe** — surefire runs
  `**/*Test.java` + `**/*IT.java` together; so "full verify" = one 149-test
  run. `mvn test` silently skips SpotBugs — always `mvn clean verify`
  (AGENTS.md).
- **Stapler:** roster/mfaAdmin page uses forwards/redirects — a faithful
  booted GET must follow 302s (house `MfaAdminIT.pageHtml` pattern); a
  bare no-redirect `rawGet` is WRONG for the page, fine for asserting the
  first redirect itself.
- **`User.getProperty(MfaUserProperty.class)`**: auto-instantiates
  descriptor-backed user properties; "absent" MFA state is observed as a
  *pristine* property (no seed/mailbox/secrets/marker/trust), never `null`.
- **jelly rendering:** button/tr attributes render one-per-line
  (`data-op` newline `data-user-id`); row attribute order is
  `data-display` THEN `data-user-id`. String-match asserts must be
  line-break tolerant (the `sliceBetween`/substring helpers in
  `MfaAdminA24IT` are the working pattern).
- **Gate seam:** `MfaFilter` step 9 admits on `sessionVerified ||
  trustLive`; `trustLive` = in-memory property `trustedUntilMs > now`.
  This is why D16 required the in-memory rollback, not just the honest
  error string.
- **`postForceEnrol` 200-envelope errors** have STABLE strings from
  `VerifyOutcome` — the strict consumer is `mfa-admin.js`; pin the exact
  strings.
- **D16 test seam:** make the target's user dir unreadable
  (`setWritable(false)`) around the `postVerify` POST, restore in `finally`;
  the obligation file's *absence/creation* is the disk anchor (helper
  pattern from house `MfaAdminIT`).
- **TTL/cooldown seams:** `DevcruMfaConfig` descriptor/test setters for
  TTL (1s expiry arm, real sleep) and resend cooldown; the 60s cooldown is
  asserted without sleeping (first resend free, second hits
  `resend_cooldown` by construction).
- Host has NO `/usr/bin/unzip` (use Python `zipfile`); `javap` only at
  `/opt/jdk-21.0.12+8/bin/javap`.
- **Email capture:** `CaptureEmailSender` +
  `EmailCodeIssuer.setSenderForTest` (save/restore the static).

## 6. Exact next steps (execution order)

1. **If mads says "open the PR":** file `a24-it-matrix` → `develop`
   (push-via-SSH is the route; no `gh` token on this host; GitHub new-PR
   URL pattern `https://github.com/<owner>/devcru-jenkins-mfa/new/pull/
   develop…a24-it-matrix` — the repo `origin` is
   `github.com:unprofessional/devcru-jenkins-mfa.git`). CI
   (`.github/workflows/ci.yml`) runs `mvn clean verify` on PR open; the
   expectation is green (149/149 here, ~4 min locally).
2. **On merge:** squash/merge per mads's standing flow; after the merge,
   the two A24 TECH_DEBT entries can be re-stamped with the merge SHA and
   the plan doc can move `docs/plans/` → (house convention varies; the A22-b
   analogs live in `docs/done/` — move + `STAMPED DONE` if the house does
   it for plans).
3. **Deploy check (needs mads):** the live instance check 401'd (MFA
   enforced per the rollout — expected, NOT a defect; never bypass MFA).
   Post-merge, an authorized (mads-supplied, e.g. API-token) smoke of the
   force-enrol journey on the live host is the acceptance walk per
   AGENTS.md; credentials `[REDACTED]` always.
4. **Optional tracked debt (separate task, needs its own plan+ruling):**
   `DevcruMfaConfig.setTotpWindow` stores the raw value — a negative
   window is unclamped (lockout-flavour edge). Open since the §1-D
   review; do not bundle it into this PR.
5. **Nothing else is blocked or owed.** The "298" correction (TECH_DEBT)
   is committed with this handoff; the stale `298` inside `f631503`'s
   message body is accepted as-is (no history rewrite).

## 7. Standing instructions (verbatim, bind the next session)

- Work branch `develop`; **`master` advances only on explicit per-step
  mads approval; NO force-push.** **NO PR unless mads asks.**
- BDD doc per `TotpTest` on ANY test touched (WHAT / GIVEN-WHEN-THEN /
  WHY-SOLVES); a test commit without it blocks review. Red→green history
  recorded only where it genuinely happened.
- Local validation **must mirror CI**: `mvn clean verify` (not `test`).
- Every landing touches the README's "Practical usage" behaviour contract
  in the commit (done for this one — the D16 honesty note).
- Credentials: `[REDACTED]`, never in chat/logs/commits. No PII in group
  channels. #showcase ambient — progress messages on multi-step jobs.
- The A24 browser-walk model deviation is **OVERRIDE-ACCEPTED by mads
  2026-08-28** (walk ran `ox-alpha via OpenClaw subagent`; no qwen
  re-walk). This is closed history — do not re-litigate.
- Security rulings (spec §10, D1–D16) stand as signed; a diff that moves a
  ruled seam escalates to mads before proceeding (the D16 fix followed
  exactly this path: red → spec read → fix → mads report → acceptance).
- Handoff hygiene: keep this file <~30KB; if the task re-opens, bump to
  v2 OVER this filename and stamp the supersession.
