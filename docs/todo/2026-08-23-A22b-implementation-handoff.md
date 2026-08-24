# A22-b admin factor-management — handoff (v5, 2026-08-24, PRODUCTION FEEDBACK ROUND)

> **§1 progress:** §1-A DONE (`14dc5d2`), §1-B DONE (`e5e68da`, theming fix +
> `MfaAdminIndexThemeTest` pin + browser proof). Both merged to `develop` as
> PR #20 (`26c1e7d`) and **DEPLOYED to production `jenkins.devcru.org`
> 2026-08-24 ~01:10 ET** (smoke green; deploy record in Moldy's memory, not
> here). **Next: §1-D — the production feedback round from mads's live walk.
> §1-C (A24) stays last** — separate spec-first PR awaiting mads's rulings.

Written for Sebastian (next session). **A22-b is APPROVED and is being merged
to `develop` by mads.** This handoff now hands you the POST-MERGE next steps
(§1), including cleanup from this PR. Read §0 (status + one correction you must
know) and §1 (what to do next) first. §2–§5 are reference; §6 is standing
instructions. **Do not re-do the resolved-defect record (§5).**

**Repo:** `/home/hunter/dev/devcru-jenkins-mfa`
**Binding spec:** `docs/todo/2026-08-23-A22b-admin-factor-management-spec.md`
**House rules:** `AGENTS.md` (BDD doc on every test, README practical-usage
updated in the same commit, local validation = `mvn clean verify` mirrors CI
incl. SpotBugs, no PR without mads, commit via `git commit -F <file>` then
read back).

Maven: `export PATH="$HOME/.local/bin:$PATH"`, always `-o` (offline).
JDK for javap: `export PATH="$HOME/opt/jdk-21.0.12+8/bin:$PATH"`.

---

## 0. Status + one correction you must internalize

**Status:** A22-b (admin roster + `clearFactors`/`revokeTrust`, the restart-
survival leg, the context-safe script-URL fix, the dual-theme fix) is green,
reviewed, APPROVED. MERGED 2026-08-24 as PR #20 (`a22b-1a-cleanup` →
`develop`, merge commit `26c1e7d`) and **DEPLOYED live to `jenkins.devcru.org`
(LAN-only, `http://192.168.7.35:8080`)** with a pre-deploy off-host snapshot.
mads then walked the live surface and filed the feedback round in §1-D. All
next work branches from `develop` (new branch).

**Correction 1 — model attribution (read this).** The real-browser acceptance
walk in this PR did NOT all run on you (qwen3.8:27b). Hermes logs show the
restart-survival leg ran on qwen, but mid-task mads ran `/model gptsol` in
another channel (for an unrelated Gmail cron), and Hermes' bare `/model`
PERSISTS GLOBALLY by default, so the browser navigation, screenshots, the
script-URL defect find/fix, and the final commit actually ran on
`gpt-5.6-sol`. config.default has now been reset to `qwen3.8:27b-mtp-q8_0`.
**Lesson: before AND after any real-browser (or any) work, confirm the active
model is the intended one** — check the Hermes status card / log, and state it
in your report. Don't let a silent model swap misattribute your work again.

**Correction 2 — the theme claim was overstated.** v3 §0/§10 said "dark and
light renders" were captured. The dark and light screenshots are
**byte-identical (same md5)** because `index.jelly` is a hardcoded dark-theme
page with NO light styling — emulating `prefers-color-scheme: light` renders
the identical dark page. So "both themes verified" was not true; there is no
light theme yet. That is task §1-B below. Do not repeat the overclaim.

## 1. NEXT TASKS (post-merge, branch from `develop`)

Do these in order. Each is its own commit; no PR without mads.

### §1-A — Cleanup from this PR (do this first) — ~~open~~ DONE 2026-08-23 (branch `a22b-1a-cleanup`)

Executed 2026-08-23: deleted all listed ephemeral state (cookie jars,
`sandbox-credentials`, `sac-reenrol-seed`, `fixture-seed-result.txt`,
HTML/JSON captures, `script-url-*`/`final-*` logs, `classpath.txt`,
`__pycache__`/`pycache`, temp `TmpWalkIT.java` + `WalkAuthorizationStrategy.java`
copy, scratch seeders and walk scripts). **Decision: `.scratch/screenshots/`
KEPT** — they are the acceptance record for this PR; they remain ignored via
`.gitignore` (`.scratch/`). Verified afterwards: `git status --short` clean,
no listeners on `:8081`/`:9333`, no cookie/seed/credential material in the
repo tree or in `/tmp` (name-pattern sweep). The reusable CDP journeys +
fixture under `scripts/acceptance/a22b/` are untouched and still the only
tracked fixture material.

The reusable CDP journeys + fixture already live (committed) under
`scripts/acceptance/a22b/`. Everything else from the walk is ephemeral runtime
state under ignored `.scratch/` and should be cleaned now that acceptance is
done — especially anything credential-shaped:

- Delete `.scratch/` runtime state: `sandbox-credentials`, `sac-reenrol-seed`,
  `fixture-seed-result.txt`, all `*.cookies`, the `whoami*.json` /
  `fixture-crumb.json`, the `script-url-*.log` / `final-*.log` captures, the
  `__pycache__` + `pycache/` trees, `classpath.txt`, the HTML captures, and the
  temp `TmpWalkIT.java` + `src/.../WalkAuthorizationStrategy.java` copies (the
  durable strategy lives in `scripts/acceptance/a22b/fixture-src/`).
- Keep or drop the `.scratch/screenshots/` evidence deliberately (they are the
  acceptance record; if kept, leave them ignored; if dropped, note it).
- Then confirm: `git status --short` clean, no listeners left on `:8081`/`:9333`,
  no credential/seed/cookie material sitting on disk. Never leave throwaway
  credentials on disk after the run that needed them.

### §1-B — Fix the admin page theming (the real light/dark gap) — ~~open~~ DONE 2026-08-23 (branch `a22b-1a-cleanup`, same branch as §1-A)

Executed 2026-08-23, per the house ruling above (Jenkins' own pages follow the
user's theme): `MfaAdminController/index.jelly` is now genuinely dual-theme —
the base rules are the dark theme and a `@media (prefers-color-scheme: light)`
block re-paints EVERY painted surface, using the house light palette already
established in `MfaUserProperty/config.jelly` (`#1f2328` text, `#f8f9fa`
buttons, `#d0d7de` borders, `#1e7e34`/`#b3261e` success/error). The 403
denial arm got its own dual-theme stylesheet too, so the denial page is not a
dark hole in a light UI.

Pinned by `src/test/java/org/sebcru/mfa/MfaAdminIndexThemeTest`
(BDD per the house rule, `TotpTest` shape): both-scheme `color-scheme`
declaration, per-surface light coverage (no inherited dark islands),
light-vs-dark body background actually different (the source-level form of
the screenshot-md5 acceptance), and theme-aware 403 arm. Honest red phase:
written against the dark-only page first — the light-block and 403 pins
failed with `expected: not <null>` / `expected: <true> but was: <false>`,
then went green on the fix.

**Acceptance met — real-browser walk, on qwen3.8:27b-mtp-q8_0 (Correction 1
honoured: the model in this report is Qwen 3.8 27B MTP Q8_0 running under the
Hermes harness; all pixels below were inspected natively by it).** `hpi:run`
on :8081, headful Chromium 151 under `:99`, real admin login + TOTP verify to
the roster, and the denial arm reached as an ANONYMOUS visitor (the
`actor == null` branch of `answerAdminDenied` — the strategy was never
touched, so no sandbox state was mutated). `Emulation.setEmulatedMedia` on
both schemes, one run each; computed `matchMedia` confirmed the emulated
value was actually applied.

- roster light md5 `25cd8d3636183c96b2c2580597a1589f` vs roster dark
  md5 `89106fd116bb771fd5acf2685b1e64c6` — **differ**
- 403 light md5 `395188c74dfbb336fd9e17d223a7c25e` vs 403 dark md5
  `c33482a6dfb83d8c9426abdf91c129c4` — **differ** (full values also in
  ignored `.scratch/theme-1b-md5.json`)
- **crossover check**: the stale A22-b record `03-admin-roster-dark.png` and
  `04-admin-roster-light.png` share md5 `792f1748c652…` (the proof of the
  overclaim); the NEW light render differs from both. The page is no longer
  one theme wearing two labels.
- body background measured live: dark `rgb(16,20,24)` / light
  `rgb(255,255,255)` on both surfaces; native-pixel inspection confirmed no
  off-theme islands in either scheme (badges, buttons, dialog input all
  recoloured).
- `mvn clean verify -o` (CI mirror): BUILD SUCCESS, 117 tests, 0 failures,
  SpotBugs clean — including the new theme pins.

§1-C (A24) deliberately untouched, pending its own spec-first PR.

### §1-D — Production feedback round (mads's live walk, 2026-08-24) — DO THIS NEXT

mads walked the deployed surface in a real browser (log in → MFA →
`/manage/configureSecurity/` → the "Open" link → `/mfaAdmin/`). Two defects,
one settled design ruling. Branch from `develop`; one commit per task.

**D1 — `config.properties` lost a newline (the title renders as a literal key).**
On `/manage/configureSecurity/` the section title shows the raw key
`manageFactorsLink` instead of "Factor recovery (locked-out users)".
Root cause (verified with `cat -A`): in
`src/main/resources/org/sebcru/mfa/DevcruMfaConfig/config.properties` the
`manageFactorsLink=...` entry is GLUED to the tail of the `rememberFor.hint`
line — the newline between them is missing. Consequences: (a) the key does not
exist, so `${%manageFactorsLink}` falls through to the raw key name; (b) the
"remember trusted browsers" hint value carries the glued garbage at its end.
Fix: restore the newline (verify with `cat -A`, not eyeballs — this smells
like a fuzzy-patch mangle, the §7 pitfall). Pin it honestly: a test that
parses the properties file and asserts `manageFactorsLink` exists as a
standalone key with the expected value (the i18n lookup is the external
consumer — pin against it, postmortem rule 10).

**D2 — the admin page is an isolated island: add a back link.**
The roster page has no cancel/back affordance — once you're there you're
stranded. Add a back link in `MfaAdminController/index.jelly` (e.g. "←
Security configuration" targeting `<root>/manage/configureSecurity`, or a
Manage Jenkins breadcrumb). It must be styled in BOTH themes (light block
included — no inherited-colour bets, postmortem rule 12) and present on both
rendered arms (roster + 403 denial). Acceptance: real-browser render, both
schemes, link navigates.

**Settled ruling — do not re-litigate:** mads asked whether the roster could
be inlined into `/manage/configureSecurity/`. Answer: NO. `configureSecurity`
is a single-submit configuration form; the roster is a mutation surface with
its own POST endpoints, crumb, typed-confirmation dialog, and CSP-clean JS.
Inlining it mixes form-submit semantics and drags interactive JS into core's
security page. Jenkins convention agrees: action surfaces get their own page
(script console, user management); config pages get settings. The island
feeling is fixed by D2's back link, not by a transplant.

**Facts for this round (live-verified):** the section renders on
`/manage/configureSecurity/` (NOT `/configure`). Anonymous visitors to
`/mfaAdmin/` get core's "Authentication required" login redirect, NOT the
plugin's 403 denial arm — probe the denial arm with an authenticated
non-admin. The roster is enrolled-only: a fresh test user does not appear on
it until they enrol a TOTP from their own Security page (fresh/unenrolled
users pass the gate, so creating one carries no lockout risk).

**Discipline for this round:** real-browser acceptance ON
`qwen3.8:27b-mtp-q8_0` — state the model in your report (Correction 1);
`mvn clean verify -o` green; BDD docs + same-commit README/docs rule. You do
NOT deploy — get the branch green and let mads/Moldy run the cutover (deploy
shape: local clean-verify `.hpi` → off-host snapshot → jenkins-cli `-http`
stdin `install-plugin = -deploy` → expect `RestartRequiredException` →
`safe-restart`).

### §1-C — A24: the third verb — force-enrol + first-time MFA setup UI (after §1-D)

The next feature (Ruling 4's "for now" companion; tracked in TECH_DEBT "Not in
the code yet"): when an admin enforces MFA fleet-wide, the enrolled-only roster
goes empty, but the admin still needs to see WHO to enrol and enrol them, and a
user hitting their first login needs a first-time MFA setup flow.

- Re-read the A24 entry in TECH_DEBT + the spec's Ruling-4 note before
  designing. Draft the spec delta / plan and get mads's rulings BEFORE
  implementing (spec-first, exactly like A22-b).
- Reuse the roster row-list and the `/mfaAdmin` surface; the follow-up was
  deliberately shaped so a third verb + force-enrol columns don't force a
  rework (pure row-list model, `userId`+operation wire shape).
- The real-browser acceptance for this MUST run on qwen and say so (Correction
  1). This is the task mads explicitly wants you to prove the browser on.

## 2. IT shape + helpers (reference)

File: `src/test/java/org/sebcru/mfa/MfaAdminIT.java`. **6 legs, all green:**

1. `enrolledPasswordOnlySessionIsBouncedByTheGateOffTheAdminSurface` — carve-out 302.
2. `unenrolledAdminCanReadRosterButNotMutate` — Ruling-3 edge.
3. `verifiedAdminCannotClearTheirOwnFactorsSelfStrikePin` — self-strike.
4. `nonAdminIsDeniedTheAdminSurfaceAtTheWire` — least-privilege + the (d)
   verified-non-admin order probe (Defect-2 discriminator).
5. `verifiedAdminClearsLockedOutVictimAndOwnFactorsSurvive` — admin journey.
6. `clearedVictimSurvivesRestartAndRecoveryCompletes` — restart round-trip.

Helpers (reuse, don't rewrite): `rawGet`, `rawPostAdmin` (redirect
disabled/restored), `postAdmin`, `pageHtml`, `enroll`, `verifyTotp`,
`ensureRealm`. The nested `LeastPrivilegeAdministerStrategy` is only for leg 4.

## 3. Verified API facts (do not re-discover — javap/jar-verified)

- Stapler 2030.v88a_855365981; verbs use `StaplerRequest2/Response2`. `doIndex`
  REMOVED — class-dir `MfaAdminController/index.jelly` auto-renders on the empty
  token; page READ gate is `adminPageAllowed()` in the jelly.
- Roster cells are standalone `<j:out value="..."/>`, never attribute-form.
- Core `jenkins-core-2.528.3`; `MatrixAuthorizationStrategy` ABSENT offline;
  `SidACL` fails closed; `hudson.util.AccessDenied` ABSENT.
- **Production permission seam (mads-approved):**
  `Jenkins.get().getACL().hasPermission2(auth, Jenkins.ADMINISTER)`, fail-closed
  on null/Anonymous. NOT `User.hasPermission(...)` (self-granting no-op).
- **`getAdminScriptUrl()` MUST stay context-rooted** (Stapler
  `getContextPath()` + `/plugin/devcru-mfa/mfa-admin.js`) — a relative value
  dies under a non-root context.
- `MfaUserProperty` Secret-setters: `setTotpSecret`/`setEmailCodeSecret`/
  `setPendingCodeHash`. `clearFactorState(p)` = single writer of unenrolled state.
- Persistence: `target.save()` → config.xml; `rule.restart()` reloads from disk.

## 4. Run history (condensed)

Run logs under `/tmp/a22b-*.log`. **Stale-data warning:** surefire reports under
`target/` are per-run — always pair a surefire read with the matching run log's
`Tests run:` line.

## 5. Resolved-defect record (audit trail, DO NOT RE-DO)

- **Defect 1 (admin page never rendered / 404):** `doIndex` forward had no rule;
  two roster cells used `j:out` as an attribute (invalid XML → view dropped →
  silent 404). Fixed: removed `doIndex`, standalone `<j:out/>`, 403 gate in jelly.
- **Defect 2 (permission seam was a no-op):** `User.getACL()` self-grants TRUE
  for the actor's own id. Fixed: current session vs Jenkins ROOT ACL
  (`getRootACL()`, no self-grant). mads-approved; do not alter without sign-off.
- **Filter carve-out:** `MfaFilter` allow-list matches `/mfa` segment-precisely
  so `/mfaAdmin/*` is NOT swept through the gate allow-list. Pinned both ways.
- **Context-safe script URL (real-browser defect):** relative `mfa-admin.js`
  resolved under `/jenkins/mfaAdmin/`, leaving both action buttons dead; fixed
  by rooting at the Stapler context, pinned red→green on the rendered URL.

## 6. Standing instructions (from mads) + process notes

- All next work branches from `develop` AFTER the merge; mads-approved-per-step
  on merges; **no PR** without explicit ask.
- Spec is binding; where spec and ruling conflict, the SIGNED ruling wins,
  documented as a contradiction note — not silently resolved.
- Credentials never in commits/logs/doc; test-only local-realm passwords are
  throwaway fixtures, not real secrets. Clean them off disk after use (§1-A).
- **Process note 1 (report-and-ask):** when implementation surfaces a decision
  that needs mads — a seam change, a spec contradiction, a security-model-
  shifting defect — STOP and report-and-ask. Don't fold it into the flow.
- **Process note 2 (model attribution):** Hermes' bare `/model` persists
  GLOBALLY and once silently swapped you to Sol mid-task. Before and after any
  real-browser (or otherwise model-sensitive) work, confirm the active model is
  qwen3.8:27b and state it in your report. Use `/model <name> --session` if a
  session-only change is ever needed.
- This handoff (v5) supersedes v1–v4 where they conflict.
