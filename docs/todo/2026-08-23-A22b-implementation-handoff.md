# A22-b admin factor-management — handoff (v4, 2026-08-23, PRE-MERGE / NEXT TASKS)

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
survival leg, the context-safe script-URL fix) is green, reviewed, APPROVED.
MERGED 2026-08-23 as PR #18 (`a22b-spec` → `develop`, merge commit `63e5b81`).
All next work branches from `develop` AFTER the merge (new branch, not
`a22b-spec`).

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

### §1-B — Fix the admin page theming (the real light/dark gap)

The admin page is dark-only. Make the theming correct so light and dark are
genuinely distinct:

- Decide the target with the house style (Jenkins' own pages follow the user's
  theme). Either make `MfaAdminController/index.jelly` theme-aware (respect
  `prefers-color-scheme` / Jenkins' theme tokens) or, if dark-only is the
  ruling, document that explicitly — but do NOT leave it silently dark-only
  while claiming both themes.
- Re-render under BOTH emulated schemes and capture two screenshots that are
  actually different (different md5). That is the acceptance for this task.
- This is real-browser work: run it ON qwen and confirm the model in your
  report (Correction 1).

### §1-C — A24: the third verb — force-enrol + first-time MFA setup UI

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
- This handoff (v4) supersedes v1–v3 where they conflict.
