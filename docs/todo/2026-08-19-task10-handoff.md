# Task 10 handoff — written for a Sebastian with wiped context

**Written 2026-08-19, by Sebastian, at mads's direction (session reset
immediately follows).** Everything below is verified state as of this
moment — commit hashes, API shapes, failure modes, and rulings are
factual, not aspirational. Read top to bottom; it is self-contained by
design, but the "read these first" list at the bottom is still required
bedside reading.

**Context in one line:** Task 9 (the user-facing factor-management UI on
*Manage account → Security*) **LANDED with the commit that adds this doc
(one commit ahead of `57fcccc`)**. This handoff is therefore (a) the
**Task 9 landing record** — what shipped, what deviated, what is pinned
where — and (b) the **Task 10 (deploy to `jenkins.devcru.org`) kickoff**.
There is **no more development work** between this doc and the live-box
cutover, unless mads rules on the documented A22-b follow-up.

---

## 1. One-paragraph status

`devcru-mfa` (repo `/home/hunter/dev/devcru-jenkins-mfa`, branch
**`develop`**, remote `github.com:unprofessional/devcru-jenkins-mfa.git`)
sits one commit ahead of `57fcccc` (the commit that made the Task 9 prep
handoff reset-ready). **Tasks 0–9 are complete**; Tasks 0–8 plus A21 were
already pushed and CI-green before the Task 9 session. Task 9's landing
commit adds: the six `/mfa` profile endpoints (`postEnroll`,
`postEnrollConfirm`, `postEmailTestCode`, `postDisableTotp`,
`postDisableEmail`, `postRevokeTrust`), the security-tab section view
(`src/main/resources/org/sebcru/mfa/MfaUserProperty/config.jelly`,
descriptor-relative path — a wrong path fails *silently*, see §4.1), the
`zxing:javase` dependency, A7's streak reset + A8's proven-factor writer in
`postVerify`, `MfaProfileSeamTest` (6 unit) and `MfaProfileIT` (4 booted),
plus the same-commit docs (TECH_DEBT A2/A7/A8 resolved + **A22** new,
README practical usage, plan LANDED stamp). At the moment of writing:
**`mvn -o -B -ntp clean verify` is BUILD SUCCESS — 94/94 tests, SpotBugs
0 bugs, `.hpi` produced** (the earlier red — `REC_CATCH_EXCEPTION` in
`qrDataUri`, fixed by narrowing `catch (Exception)` to
`catch (com.google.zxing.WriterException | java.io.IOException)` — is
closed and pinned by the linter itself). CI on the devcru GitHub instance
will re-run `mvn clean verify` on push; local `clean verify` mirrors it.
**Next: Task 10 (deploy to `jenkins.devcru.org`)** — see §9 and the plan's
Backup & rollback section; no new code is expected unless mads rules on
A22-b (§6).

## 2. Operating environment (exact commands)

```bash
# The ONLY toolchain on this host that works — no system Java/Maven exists:
export PATH="$HOME/opt/jdk-21.0.12+8/bin:$HOME/opt/apache-maven-3.9.11/bin:$PATH"
cd /home/hunter/dev/devcru-jenkins-mfa

# Offline Maven is the norm (no network in the build):
mvn -o -B -ntp test-compile                     # fast syntax/compile gate
mvn -o -B -ntp test -Dtest=MfaProfileIT         # the Task 9 IT (~20 s)
mvn -o -B -ntp clean verify                     # CI-mirror: the ONLY full validation
```

Rules (from `AGENTS.md` — read it, it is required-reading):
- **`mvn clean verify`, never bare `mvn test`** — the parent POM binds
  SpotBugs + enforcer into `verify`. Task 9 itself was caught by this:
  94/94 tests + `.hpi` green, yet `verify` was red on one SpotBugs bug.
- Tests must be **BDD-documented** (WHAT / GIVEN-WHEN-THEN / WHY) —
  `TotpTest` is the reference; `MfaProfileSeamTest` and `MfaProfileIT`
  follow it and are fine new examples.
- **Same-commit rule:** code + tests + docs + `TECH_DEBT.md` + README
  practical usage land together. Task 9's landing commit obeyed it.
- Commit identity: `Sebastian <sebastian@devcru.org>`. Push: plain
  `git push origin develop` (SSH works; no `gh`, no token). No
  force-push; `master` advances only on mads's per-step approval.
- Long commit messages: `git commit -F <file>` (never inline `-m`), read
  the message back before pushing (`git log -1 | head -15`).
- `rg` is not installed — use `grep -rn`. This host truncates long
  terminal output to a line — redirect long output to a file first, then
  inspect surgically.

## 3. What Task 9 shipped (verified inventory)

**`MfaController` (six new endpoints, all under the existing `/mfa`
RootAction mount — `getUrlName()="mfa"`):**

| endpoint | body params | commits | returns |
|---|---|---|---|
| `postEnroll` | — | **nothing** (seed is one-time, returned for the round trip) | `{ok, seed, otpauthUri, dataUriPng}` |
| `postEnrollConfirm` | `seed`, `code` | `otpauthUri` secret ONLY when `Totp.verify` passes; never clobbers a working factor on failure | `{ok}` or `{ok:false, error: wrong_code|invalid_seed|totp_already_enabled}` |
| `postEmailTestCode` | — | mints through the SAME `ensureEmailCodeSecret(p)` seam (A2's second minting path) then mails | `{ok}` or `{ok:false, error: resend_cooldown, retrySeconds}` / `email_unconfigured` |
| `postDisableTotp` | — | clears `totpSecret` | `{ok}` |
| `postDisableEmail` | — | clears `registeredEmail` **and retires `emailCodeSecret`** (a re-enrolled account re-mints cleanly) | `{ok}` |
| `postRevokeTrust` | — | `trustedUntilMs := 0` (touch-only, idempotent) | `{ok}` |

All six: `@RequirePOST` **and** `@WebMethod(name = …)` — the A20 lesson
(bare `@RequirePOST` 404s; `@WebMethod` is what routes). All act on
`currentUser()` (strict self-service — A22, §6). JSON via `writeProfileJson`
/ `okJson` (net.sf.json `JSONObject.put` returns `Object` — discrete `put`
calls, no chaining).

**Pure seams (unit-pinned by `MfaProfileSeamTest`, 6 tests):**
`buildOtpauthUri(issuer, account, seed)` (canonical `otpauth://otp/…`
shape, percent-encoding of hostile chars via the `HEX` table; NOT
`URLEncoder`), `qrDataUri(uri)` (zxing 300×300 PNG → `data:image/png;base64,…`;
blank input → `""`; render failure → `""` — a QR is a convenience, manual
entry is the fallback, a 500 would hide both), `confirmEnrollDecision(
prop, seed, code, now, window)` (the verify-before-commit rule),
`percentEncode` (unreserved set + `:` `,` stay plain).

**A7 + A8 in `postVerify` (not new endpoints — the success path):**
a `proven` local tracks **which factor actually PASSED** (not the shape
submitted — a TOTP-shaped input the gate fell through to email records
EMAIL); on success the same `u.save()` that grants trust also does
`p.setFailedAttemptStreak(0)` (A7 reset) and
`p.setLastVerifiedFactor(proven == EMAIL ? 1 : 0)` (A8 writer). No extra
round trip. Wire-pinned in `MfaProfileIT` case c (§3 below).

**`MfaUserProperty`:** only NEW addition is `getMaskedRegisteredEmail()`
(null-safe, returns `""`). **The request-scoped section helpers
(`mfaCrumbField` / `mfaCrumbValue` / `mfaBaseUrl`) deliberately live on
`DescriptorImpl`, NOT the property** — the core security-page include binds
`it` = the descriptor (always non-null) and `instance` = the property
(**null for a fresh user**); and crumb/base are per-request state, not
persisted state. Note: `jenkins.model.Jenkins` (not `hudson.model.Jenkins`).

**The section view** — `src/main/resources/org/sebcru/mfa/MfaUserProperty/
config.jelly` (exact descriptor-relative path; §4.1 for why). No nested
`<f:form>` (the tab supplies ONE form → `configSubmit`); `f:invisibleEntry`
dummy keeps the `f:rowSet` non-empty; the ONLY form-bound field is
`registeredEmail` via `f:textbox` `field=` binding; everything else (the
section's ids: `mfaSection`, `mfaTotpGenerate`, `mfaTotpConfirm`,
`mfaTotpDisable`, `mfaEmail*`, `mfaRevokeTrust`) is presentation + a small
XHR block posting to the descriptor's ABSOLUTE `mfaBaseUrl` with the
descriptor-sourced crumb.

**`pom.xml`:** `com.google.zxing:javase:${zxing.version}` (3.5.3) added
beside existing `core` — `core` has `QRCodeWriter`/`BitMatrix`/the
**reader** classes; `javase` has `MatrixToImageWriter` (PNG bytes) and
`BufferedImageLuminanceSource` (decode-back for the round-trip test).
Both artifacts are primed in `~/.m2`, so `mvn -o` resolves them offline.

**Tests (all BDD-documented per `AGENTS.md`):**
- `MfaProfileSeamTest` — 6 plain-JVM unit tests over the four pure seams
  (otpauth URI incl. hostile chars; QR PNG **decodes back to exactly the
  input URI** — a truncating render is a loud red, not "your QR never
  works"; verify-before-commit; no-commit-on-failure; no-clobber).
- `MfaProfileIT` — 4 booted-Jenkins ITs (the shapes below).
- Unchanged suite: `MfaFilterIT` 8, `MfaControllerTest` 9,
  `MfaUserPropertyTest` 5, config/gate/totp/email suites — total **94**.

**`MfaProfileIT` cases (4, ~20 s total):**
1. `sectionRendersOnTheSecurityPageForEnrolledAndFreshUsers` — the 5.1
   silent-failure guard: `id="mfaSection"` present on the **LIVE**
   security page for (a) an enrolled user (who is verified first to pass
   the gate — §4.3) showing `mfaTotpDisable` not Generate, and (b) a fresh
   user (ungated; no factor → `hasTotpFactor()==false` — NOT a property
   nullity assertion, §4.5) showing `mfaTotpGenerate` not Disable.
2. `enrollConfirmRoundTripCommitsOnlyOnACorrectCode` — `postEnroll`
   commits nothing (seed in response, property untouched); correct
   `Totp.codeAt` → property `getTotpSecret().getPlainText() == seed` and
   `hasTotpFactor()`; a wrong code for a *second* candidate →
   `wrong_code` + the working seed byte-identical + still verifying.
3. `disableAndRevokeEndpointsFlipExactlyTheRightFlags` — now ALSO pins the
   A7/A8 wire contract (session-extended): wrong `postVerify` code →
   `failedAttemptStreak == 1`; successful TOTP verify → streak
   `== 0` (A7) AND `lastVerifiedFactor == 0` (A8) **over a fabricated
   `1`** (email), proving the writer records the PROVEN factor; then each
   of the three disable/revoke endpoints flips exactly its own persisted
   flag (incl. email-key retirement).
4. `allSixProfileEndpointsAreRoutedNot404` — the A20 boot guard: every
   endpoint answers **200** with a JSON `ok` key (a bare `@RequirePOST`
   method would 404 — the one thing that proves `@WebMethod` routing on a
   live Stapler).

## 4. The traps (verified against 2.528.3 + the red rounds — do not rediscover)

### 4.1 The view path fails *silently* — so the IT asserts the render
The section must live at `org/sebcru/mfa/MfaUserProperty/config.jelly`
(descriptor-relative: `Descriptor.getConfigPage()` defaults to
`"config"`; the core Security action does `st:include from="${d}"
page="${d.configPage}"`). The plan's ORIGINAL path
(`views/MfaUserProperty.jelly`) fails with **no 500, no parse error,
empty section, green build** — the "MFA never works, no error anywhere"
mode. IT case 1 is the only cheap guard: it asserts the rendered marker
on a booted page. Moving the file breaks case 1.

### 4.2 The security tab's crumb does not exist (on the security page)
Core's `f:form` around `configSubmit` carries **NO crumb hidden input**
(verified by dumping the rendered page). The only form on the box with a
crumb input is the hand-written MFA page's `verifyForm`. Therefore:
**source the crumb from `<ctx>/mfa/`** — it is allow-listed (the gate
never bounces it), renders for ANY logged-in user (enrolled or fresh),
and embeds `<input name="Jenkins-Crumb" type="hidden" value="…"/>`.
Deterministic recipe (in `MfaProfileIT.mfaCrumb`): raw GET **site-relative
`/mfa`** (never `/ctx/mfa` into `href()` — it appends under a base that
already carries the context → double context → 404), collapse
`\s+→" "`, then
`<input\s+name="([^"]*[Cc]rumb[^"]*)"\s+[^>]*?value="([^"]*)"` — the
non-greedy middle is load-bearing: Jelly emits `name …` **`type="hidden"`
…** `value …` in that order.

### 4.3 The gate bounces the security page for enrolled-unverified users
`/mfa` is allow-listed, but `/user/<id>/security/` is NOT — an enrolled
user who hasn't proven a factor 302s to `/mfa` like anywhere else. An IT
that follows that redirect lands on the **login page** (which HAS a crumb
and NO section) and fails with confusing "no crumb / no mfaSection"
messages. Correct order (the natural human flow): **login → `postVerify`
with a real `Totp.codeAt(key, now)` → then GET the security page**. Fresh
users are not gated (unenrolled pass) and reach the page directly.

### 4.4 The section's model split: descriptor vs instance
The action's include binds `it`=descriptor, `instance`=property
(**null for a fresh user** — any `instance.x` reference NPEs at render).
Presentation getters are on the property **only when null-safe**;
request-scoped state (crumb, absolute base URL) is on `DescriptorImpl`.
The base URL must be **absolute** (`Jenkins.get().getRootUrl() + "mfa/"`)
— the page lives at `/user/<id>/security/` and any relative endpoint URL
resolves against it (404 city).

### 4.5 Core databinding materializes an empty property on render
`f:textbox field="registeredEmail"` on a fresh user causes core to create
an **empty** `MfaUserProperty` — so "precondition: the property is null"
is false after the first page GET. Assert **factor state**
(`hasTotpFactor()`), never property existence/nullity.

### 4.6 SpotBugs `REC_CATCH_EXCEPTION` on web-layer seams
`qrDataUri`'s `catch (Exception e)` was the one red that broke
Task 9's final `verify` (all tests green, `.hpi` built — the linter is a
SEPARATE gate). The zxing chain throws exactly
`WriterException` (checked, `QRCodeWriter.encode`) and `IOException`
(checked, `MatrixToImageWriter.writeToStream`): narrow the catch to those
two and document why the broad catch is forbidden.

### 4.7 `userProperty${i}` rowSet scoping (why only email binds)
`doConfigSubmit` reads `optJSONObject("userProperty" + i)` per category
descriptor and feeds `reconfigure(rowSet)` / `newInstance(targetUser,
rowSet)` to that descriptor — binding happens through `@DataBoundSetter`s
ONLY. `MfaUserProperty` exposes exactly one: `registeredEmail` (a String).
The TOTP seed, mail HMAC key, trust expiry, streak, and pending-code
state are plain accessors → **a crafted profile submit cannot mint or
overwrite a factor or grant trust** (the A11-style "forged submit" corner
case in the README is this fence). All the real factor writes go over the
six JSON endpoints (crumb-guarded, `currentUser()`-scoped).

## 5. What to do on deploy (Task 10 — the only remaining work)

1. **Stage, don't guess:** `mvn hpi:run` locally; walk the acceptance
   checklist against the throwaway instance (enrol a TOTP via the NEW
   section, gate, verify, disable, re-enroll — the section is the one
   surface that never ran outside the IT).
2. **Snapshot before upload** (mandatory, plan's Backup & rollback):
   stop Jenkins, tar jobs/users/credentials/identity/secret files +
   config/plugin XML, sha256 `CHECKSUMS.txt`, off-host, keep-latest-2.
   **No snapshot, no deploy.**
3. **Cutover order:** upload the new `.hpi` (from `target/`, produced by
   `clean verify`) → mads re-enrolls (Authy TOTP + email — the section
   makes this a 90-second exercise; the old plugin's paywalled UI is what
   we're replacing) → remove the old plugin → acceptance checklist.
4. **Kill switch first rung:** `DEVCRU_MFA_OFF=1` (or policy
   OFF on the settings page) unblocks everyone without removing the
   plugin.
5. Live box facts: `jenkins.devcru.org`, **Jenkins 2.577** (NOT 2.528 —
   the build targets 2.528.3; the plugin is forward-compatible but the
   section path + admin-gate findings were verified on 2.528.3: BEFORE
   the cutover, open the Security tab on the live box and confirm the
   section renders — a 50 s check that covers any 2.528→2.577 drift in
   the include contract), Local Security Realm (which is why the `/mfa`
   mount move matters — HPSR squats `securityRealm`), agent `yharnam` on
   this host.
6. Full procedure: plan's **Backup & rollback** section + the
   `jenkins-plugin-operations` skill (its `references/
   cutover-and-rollback.md`).

## 6. Standing rulings & deviations (do not re-litigate)

- **A22 (Task 9, 2026-08-19 — the big deviation, fully specced in
  `TECH_DEBT.md`):** verified against core 2.528.3 (bytecode + jelly, not
  assumed): the Security tab's page wraps in
  `<l:layout permission="${app.ADMINISTER}">` and `doConfigSubmit` opens
  with `targetUser.checkPermission(Jenkins.ADMINISTER)`; `User.getACL()`
  delegates to `AuthorizationStrategy.getACL(targetUser)`, so the answer
  is per-install. **Consequences:** (a) under the IT's
  `FullControlOnceLoggedInAuthorizationStrategy` every user is admin →
  the self-service flow renders and passes, but the IT does **not** prove
  a non-admin path; (b) on a prod box with a matrix-ish strategy a
  non-admin likely cannot open the tab at all → enrolment there is an
  admin action (for the ONE-admin target install this is the intended
  shape, and the README says so). **Decision taken (A22-a):** endpoints
  act on `currentUser()` only — deliberately NOT `targetUser`-wired,
  because an admin opening someone else's tab would otherwise get a split
  (the bound email commits to the target; the buttons hit the admin's own
  factors). **Not built (A22-b):** admin-manages-others' factors
  (`instance`'s user when ≠ `currentUser()`, ADMINISTER-gated) — needs a
  mads ruling before implementation; it changes whose profile the button
  touches, so it is a security surface, not a convenience.
- **A7 scope note (honest deviation from the ruling):** the "reset on the
  clear path" half LANDED (wire-pinned); the "UI reads the streak" half
  (a "recent failed attempts" hint) did NOT — the section shows the live
  lockout state, not the raw number. It's a two-line jelly addition if
  ever wanted; the field is no longer unbounded either way.
- **A8:** wire-pinned; note the email-proven branch (records `1`) rides
  the same `proven` ternary and is NOT exercised in the profile IT (no
  mailbox capture there — that's the filter IT's email-path territory).
- **A2:** second minting path (`postEmailTestCode`) routes through the
  same `ensureEmailCodeSecret(p)` seam; `postDisableEmail` retires the
  key. One mint implementation, ever.
- **The mads-signed security-model decisions** live in the plan
  ("Security model decisions") — implement as written; re-litigating in a
  diff is out of scope (standing rule).
- **The `org.sebcru.mfa` package name is a deliberate tribute — do not
  propose or make a rename commit** (skill pitfall; mads has said it's
  staying).

## 7. Recurring pitfalls (short list — the skill has the full canon)

- `mvn test` ≠ `mvn clean verify` (SpotBugs + enforcer only run in
  `verify`); `mvn test` also skips nothing you care about — it just stops
  early. Both are true; use `verify`.
- One-line terminal truncation → redirect long output to a file, inspect
  surgically; `mvn test-compile` is the compile oracle.
- `patch` (fuzzy) tool mangles code-in-markdown and JS — re-read the
  touched region on disk after every doc/code patch.
- Display redaction renders token-shaped text as `***` — do not edit or
  conclude based on it; ground-truth with `od -c` / `base64`.
- HtmlUnit fork: `WebRequest` has `setAdditionalHeader` (no `addHeader`);
  `page.getUri()` does not exist; DOM lookups are flaky where raw-HTML
  regex is not; `loadWebResponse` + disables-redirects vs
  `getPage`/`c.getPage` redirect-following — pick ONE path per read.
- `net.sf.json.JSONObject.put` returns `Object` (no chaining).
- `Jenkins` is in `jenkins.model`, not `hudson.model`.
- Commit messages via `git commit -F file` + read-back before push;
  flag plan deviations IN the message.

## 8. Read these first (in this order, before touching code)

1. `AGENTS.md` (repo root) — the binding rules (BDD test docs,
   same-commit rule, `clean verify`).
2. `docs/plans/2026-08-17-jenkins-mfa-plugin.md` — **Task 9 section**
   (LANDED 2026-08-19 stamp at the top) for what was required; **Task 10
   section + Backup & rollback** for what's next; the **AMENDMENTS block**
   (plan-header) for the mads rulings (`/mfa` mount, Bearer, corrected
   view path).
3. `docs/todo/TECH_DEBT.md` — **A22** (the deviation, full spec), the
   A2/A7/A8 "Landed (Task 9, 2026-08-19)" notes, and the Resolved table
   rows for A2/A7/A8.
4. **This doc.**
5. `docs/architecture/README.md` — the design-decision record the code
   audited against (§10 points here from TECH_DEBT).
6. `docs/done/2026-08-19-task9-handoff.md` — the Task 9 PREP handoff
   (moved to `done/` with this commit): still accurate for the IT
   mechanics it was written to protect; this doc supersedes it for
   current state.
7. The `jenkins-plugin-operations` skill (`skill_view`) — host build
   env, deploy/rollback discipline, CI forensics, and its
   `references/task9-profile-ui-defects.md` (the red→green forensics of
   THIS session's IT rounds + working helper recipes).

## 9. Suggested first moves (Task 10, in order — no TDD; the code is done)

1. `export PATH=…` + `mvn -o -B -ntp clean verify` — confirm the box
   still builds exactly like the landing commit (30 s to fail early).
2. `mvn -o -B -ntp hpi:run` (background) — walk the full acceptance flow
   on the throwaway instance: enrol a TOTP **via the new section** (QR +
   confirm), hit the gate, verify, disable + re-enroll, revoke trust,
   email-code round trip with the Mailer plugin present. The section is
   the one surface with zero production traffic.
3. Live box: §5 step 2 (snapshot, checksums, off-host) — then cutover in
   the plan's order. After upload, the first manual check on the live
   box: open *Manage account → Security* and confirm `mfaSection` renders
   (covers 2.528→2.577 include-contract drift in one look).
4. If and only if mads wants admin-manages-others' factors: re-read the
   A22 note, rule A22-b, then a small isolated delta on the six endpoints
   (target `instance`'s user when it differs from `currentUser()`,
   ADMINISTER-gated) — TDD it with a second IT user.

---

*If something in this doc contradicts the code, the code wins and this
doc should be patched in the same commit that fixes it (house rule: a
handoff that lies is worse than none — it was written against verified
state on 2026-08-19).*
