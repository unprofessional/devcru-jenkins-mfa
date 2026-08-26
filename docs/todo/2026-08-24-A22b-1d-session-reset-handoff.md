# A22-b §1-D — session-reset handoff (2026-08-24)

**Supersedes:** all in-chat context from previous sessions on this task,
including the §1-D execution state implied by
`docs/todo/2026-08-23-A22b-implementation-handoff.md` (that file remains the
**spec of record** for D1/D2/D3 — do not overwrite it). This file is the
execution-state handoff written at mads's stop order for a session reset.
Model for the report: `qwen3.8:27b-mtp-q8_0`.

## 1. Headline

- **D1/D2/D3: DONE, committed, unit-green.** Branch
  `a22b-1d-production-feedback`, four commits on `develop`:
  `9f7b98f` (D1), `b333ad3` (D2), `71519ee` (D3), `fd1285a` (D2 rework —
  real non-root-context bug found in the browser).
- **Browser acceptance: IN FLIGHT, not done.** The walk now performs the
  full journey (login → real MFA gate → TOTP through UI → settle on
  destination). It has NOT yet shown the config form rendering to admin:
  one walk on a JVM that demonstrably carried the new fixture still served
  "Access Denied — admin is missing the Overall/Administer" on
  `/manage/configureSecurity/`. OPEN DEFECT — evidence + decisive next
  step in §5.
- **Post-`fd1285a` full offline verify: NOT RUN.** The green 131/131
  (`BUILD SUCCESS`, `MVN_EXIT:0`) predates the D2 rework. Per house rule
  it must be `mvn -o -B clean verify` (mirrors CI; SpotBugs binds to
  verify).
- **Branch NOT pushed. No PR. Report not written.**

Working tree at handoff time (verified by `git status --porcelain`):
```
 M scripts/acceptance/a22b/fixture-src/org/sebcru/mfa/WalkAuthorizationStrategy.java
?? scripts/acceptance/a22b/walk-a22b-1d.py
?? scripts/acceptance/a22b/__pycache__/      <- never commit
```
`src/main/java/org/sebcru/mfa/WalkAuthorizationStrategy.java` (the git-
**excluded** runtime copy) currently matches the modified fixture source —
it is git-excluded and does NOT show in status; verify with
`diff -q scripts/acceptance/a22b/fixture-src/.../WalkAuthorizationStrategy.java src/main/java/...`
before booting.

## 2. DONE and green (per commit, with the proofs)

- **D1** `9f7b98f`: `config.properties` rewritten (30-line, ASCII, all 25
  unique `${%key}` refs from the 9-field `config.jelly`); pin test
  `DevcruMfaConfigI18nTest` (5/5 green, red phase observed first: 20/25
  missing). The original mangle (truncated `rememberFor.hint` born in
  `7bebb6e`; A22-b `d2a9008` glued `manageFactorsLink=` onto a
  no-newline tail) is repaired in full, not just newline-patched.
- **D2** `b333ad3` + rework `fd1285a`: back links on the MFA admin page
  (roster arm + 403 arm), both themes. Rework reason (browser-found, real):
  original commit pinned literal absolute-rooted hrefs; hpi:run serves under
  the `/jenkins` context, so they 404'd in-browser. Fix: model-bound
  getters `manageConsoleLink` / `securityConfigLink` on `MfaAdminController`
  with pure three-branch `backLinkUrl` rooter. Targeted:
  BackLink 4/4, Theme 4/4, MfaAdminIT 6/6 (`/tmp/d2-rework.log`).
- **D3** `71519ee`: `doFillPolicyItems` on `DevcruMfaConfig` returning
  `hudson.util.ListBoxModel` populated from `Policy.values()`;
  `DevcruMfaConfigDropFillTest` 3/3 green.
- **Pre-rework full verify:** `mvn -o` full run, 131/131, `BUILD SUCCESS`,
  `MVN_EXIT:0` (log `/tmp/verify.log`). **Stale relative to fd1285a** — see
  §1.

## 3. In-flight object: `scripts/acceptance/a22b/walk-a22b-1d.py`

Untracked (not yet committed — the walk script + fixture repair are the
two pending commits, see §7). Leg-by-leg status on the best run observed:

1. **Login + MFA gate: PASS, repeatedly.** Real Chromium (Xvfb :99,
   isolated profile `.scratch/chromium-a22b`, CDP :9333), freshly seeded
   sandbox (trust `trustedUntilMs=0`), login form filled, filter bounce to
   bare `…/mfa?redirect=…`, gate screenshot to
   `.scratch/screenshots/1d-admin-mfa-gate.png`, TOTP typed into
   `#code`, `#verifyBtn` clicked, gate passed, settle on destination URL.
2. **Settle comparison: FIXED.** Was building `J + dest` (double `/jenkins`
   prefix) → could never match; fixed to
   `expected = J + dest.replace("/jenkins", "", 1)`.
3. **Destination forcing: FIXED (walk-admin.py pattern).** The filter's
   bounce derives `?redirect=` from the referer (login page), so the
   intended destination is not guaranteed; the walk re-anchors the gate at
   the intended destination (harmless: verify authenticates the session,
   independent of redirect).
4. **Config form render to admin: FAIL (OPEN DEFECT).** Walk reached
   `/jenkins/manage/configureSecurity/` but the page served "Access Denied
   — admin is missing the Overall/Administer" (verified in-page via
   body text, not just URL). The policy select (D1/D3 leg) was therefore
   never rendered. Same-session probe of `/mfaAdmin/` (same permission
   seam) was written (`/tmp/decisive.py`) but NOT yet run — see §5 for why
   it is decisive.
5. Dark/light screenshots, 403-arm link, roster-arm link navigation:
   not yet reached (blocked by leg 4).

Walk-script bugs found and fixed this session (honest history):
- gate matcher required `/mfa/` in URL; filter 302s to bare `/mfa?redirect=`
  → MFA branch never fired.
- settle comparison double-prefix (above).
- TOTP now retyped fresh each iteration spent on the gate (30 s-window
  boundary safety) with a 3 s AJAX settle after click.

## 4. Verified-api-facts (do NOT re-derive)

Jenkins core jar:
`/home/hunter/.m2/repository/org/jenkins-ci/main/jenkins-core/2.528.3/jenkins-core-2.528.3.jar`
(checked with python `zipfile` + `javap`; there is no `unzip`/`gh` on host,
`sqlite3` CLI absent, `execute_code` is approval-blocked on this host —
use python heredocs in `terminal`).

- `hudson.security.SidACL` extends `ACL`: public `hasPermission2` +
  protected `hasPermission(org.acegisecurity.acls.sid.Sid, Permission)`
  hook. **In core 2.528.3 the root-permission seam consulted for real
  user requests is `ACL.hasPermission2(Authentication, Permission)`; the
  Sid hook did NOT fire for user-login tokens** (in-JVM double-false, see
  §5 evidence). The 2026-08-23 `SidACL`-based fixture keyed on
  `sid instanceof PrincipalSid` therefore denied everyone, admin included.
- `jenkins.model.Jenkins$ACL.class` is **not** a separate class file in the
  2.528.3 jar (extraction failed with that key); don't chase it.
- Production seam (do not touch): `MfaAdminController#hasAdminister`
  (lines ~310–319) deliberately checks
  `Jenkins.get().getACL().hasPermission2(Jenkins.getAuthentication2(),
  Jenkins.ADMINISTER)` — not `user.hasPermission(Permission)` — per its
  Defect-2 docstring (user-self-grant hole in `User.getACL()`).
- **Groovy-probe pitfall (cost this session a day of red herrings):**
  `user.hasPermission(Permission)` (no-arg) inside `/scriptText` resolves
  against the *script-console thread's* auth context (anonymous), not the
  named user's. In-JVM `admin.hasPermission(ADMINISTER)=false` readings
  are therefore **not reliable evidence** that the fixture failed. Only a
  real HTTP request carrying the admin session (or a same-session
  `hasPermission2` probe with the right Authentication) is ground truth.
- MFA product seams: filter bounce → `<ctx>/mfa?redirect=…` (bare, no
  trailing slash before query); `postVerify` is an AJAX JSON endpoint, the
  gate page's own JS navigates on success; gate form ids
  `#verifyForm` / `#code` / `#verifyBtn`; trust persists 720 h in
  `work/users/<user>_*/config.xml` (`trustedUntilMs`).
- hpi:run serves the site under the `/jenkins` context — the entire class
  of D2 bugs.
- Seed: `scripts/acceptance/a22b/seed-sandbox.groovy` via scriptText
  **while unsecured** on a fresh `work/` (crumb from
  `crumbIssuer/api/json`, same cookie jar for crumb + scriptText;
  `--data-urlencode 'script@file.groovy'`). Groovy in scriptText: no GDK
  `takeLeft` (use `substring`); use `getACL()` not property `.acl`.

## 5. OPEN DEFECT (with evidence) — the authorization question

**Claim:** on a walk JVM that carried the rewritten
`hasPermission2`-based fixture, admin (post real MFA gate) was still
denied on `/manage/configureSecurity/` with "admin is missing the
Overall/Administer".

Evidence chain:
- PHASE probe (unsecured-boot scriptText, `/tmp/authz-probe.groovy`
  output quoted in chat 2026-08-25): strategy in memory
  (`class=org.sebcru.mfa.WalkAuthorizationStrategy`, `adminUser=admin`
  field read, `admin in realm=true`), XStream round-trip of
  `<authorizationStrategy>` preserves `adminUser` → **the
  restart/persistence theory is DEAD**. PHASE2 `hasPermission`=false
  readings are void per the §4 thread-context pitfall.
- `target/classes/.../WalkAuthorizationStrategy$1.class` verified by
  `javap -p -c`: `hasPermission2(Authentication, Permission)` present,
  no `SidACL`/`PrincipalSid` in bytecode — i.e. the compiled fixture the
  last walk booted was the new one (compile was forced before boot:
  `mvn -o -B -q compile`).
- Yet `/tmp/which-page.py` on that JVM: `Access Denied: True` on
  `/manage/configureSecurity/`, controls=1.

**Decisive next step (not yet run):** same-session, admin-authenticated
checks of BOTH `/mfaAdmin/` (plugin seam: `Jenkins.get().getACL().
hasPermission2(...)`) AND `/manage/configureSecurity/` (core seam).
Probe exists at `/tmp/decisive.py`. Branch on result:
- **Roster also denied** → the fixture's `hasPermission2` still isn't
  consulted (verify the class actually loaded in the JVM — e.g. via
  unsecured-boot scriptText printing
  `Jenkins.get().authorizationStrategy.getDescriptor().id` and the
  strategy instance identity right after seeding, plus
  `getACL().getClass().name`), or admin's Authentication name ≠ "admin"
  (print `Jenkins.getAuthentication2().getName()` during a gated request
  is not possible from scriptText — instead add a temporary
  fail-soft diagnostic in the fixture, or check `securityRealm` user id).
- **Roster OK, config denied** → core's configureSecurity uses a seam the
  fixture doesn't satisfy (e.g. it checks against `Jenkins.get()` ACL
  wrapped differently, or requires more than ADMINISTER). In that case the
  walk's intended destination must switch: D1/D3 legs live on **our own**
  admin surface and D2's 403 link *points at* core — walk the config-leg
  on `/mfaAdmin/` (labels/select/links render there) and assert
  `/manage/configureSecurity/` only for the link-HREF, not for
  rendering. **Do NOT wire D1/D3 rendering through core pages.**
- Either way: **no production seam re-wiring to satisfy the fixture** —
  D1/D2/D3 commits touch no authorization code and must stay that way.

## 6. Run history

| Run | Log/proof | Proved |
| --- | --- | --- |
| D1 red→green | `DevcruMfaConfigI18nTest` 20/25 red → 5/5 green | i18n mangle + fix |
| D2 targeted (both revs) | `/tmp/d2-rework.log`, MVN_EXIT 0 | back links + rooter |
| D3 targeted | 3/3 green | drop fill |
| Full offline verify (PRE-rework) | `/tmp/verify.log` 131/131 BUILD SUCCESS | **stale vs fd1285a** |
| Walks 1–N | `.scratch/screenshots/1d-admin-mfa-gate.png` + chat quotes | gate renders + TOTP UI verify works |
| PHASE probe | `/tmp/authz-probe.groovy` quoted output | strategy in-memory + round-trip clean |
| Which-page probe | `/tmp/which-page.py` quoted output (Access Denied) | the open defect |
| **Full offline verify (POST-rework)** | **NOT RUN** | owed |

Surefire-staleness warning stands: pair every `Tests run:` tally with its
log's `Finished at` timestamp; a compile-phase failure won't refresh
reports.

## 7. Exact next steps (execution order)

1. `diff -q` fixture-src vs src copy (they should match; if not,
   `cp` fixture-src → src copy). Confirm git status shows only the two
   known dirty/untracked files.
2. Boot clean: wipe `work/`, `.scratch/chromium-a22b`,
   `.scratch/sandbox-credentials`, `.scratch/crumb.json`; ensure Xvfb on
   `:99` (`Xvfb :99 &` if dead); start
   `mvn -o -B org.jenkins-ci.tools:maven-hpi-plugin:run -Dport=8081
   -Dhost=127.0.0.1` (background, notify_on_complete); wait for
   `crumbIssuer/api/json` to return a crumb.
3. Seed via scriptText (unsecured): crumb + same jar,
   `--data-urlencode 'script@scripts/acceptance/a22b/seed-sandbox.groovy'`;
   confirm `admin trustedUntilMs = 0`.
4. Start isolated Chromium (CDP 9333, profile as walk expects), then the
   **decisive probe first**: `/tmp/decisive.py` (same-session
   `/mfaAdmin/` vs `/manage/configureSecurity/`). Branch per §5.
5. Fix per §5 branch (fixture is `scripts/acceptance/a22b/fixture-src/` —
   tracked, commit-worthy; walk script is the other commit; keep
   `__pycache__` out — it is not git-excluded, add
   `.git/info/exclude` or a commit that stages files explicitly).
6. Run the full walk to green: D1 labels verbatim (no raw keys), policy
   select REQUIRED/OFF with REQUIRED selected, no fill-contract log spam,
   roster link → security config, 403 link → manage, both themes
   (screenshots in `.scratch/screenshots/`).
7. Post-rework full verify: `mvn -o -B clean verify` (log → /tmp),
   confirm tally + timestamp pair.
8. One commit for the walk script, one for the fixture repair (house
   rules: `-F` message file, read back via `git log`; README "Practical
   usage" touched only if user-facing behaviour changed — harness
   commits arguably exempt, keep the note current if in doubt; test files
   need BDD WHAT/BDD/WHY doc per AGENTS.md if any test changes).
9. Push `a22b-1d-production-feedback` (SSH; no `gh`; git 2.34 — no
   push-opts). **No PR unless mads asks.**
10. Final report: commits, test tallies with log paths, walk screenshots,
    model `qwen3.8:27b-mtp-q8_0`, open defects honestly (none should
    remain unless §5 produced one — in which case report it as such, not
    as acceptance).

## 8. Standing instructions (verbatim, survive reset)

- Branch `a22b-1d-production-feedback`; work branch `develop`; `master`
  only on explicit mads per-step approval; **no force-push ever**.
- **No PR unless mads explicitly asks.**
- Commit messages: write to a file, `git commit -F`, read back with
  `git log`.
- Offline maven: `export PATH="$HOME/.local/bin:$PATH"`; `mvn -o -B`;
  local validation mirrors CI (`clean verify`, not just `test`).
- One commit per subtask; README "Practical usage — what end users should
  expect" updated in the same commit as user-facing changes.
- Test docs: BDD WHAT/BDD/WHY per `src/test/java/org/sebcru/mfa/TotpTest.java`
  standard; a test commit without its docs blocks review.
- Sandbox fixture is **sandbox-only**: homed in
  `scripts/acceptance/a22b/fixture-src/` (tracked), runtime copy in
  `src/main/java/` is git-excluded — never let the runtime copy into a
  commit; `.git/info/exclude` carries it.
- Collector Chromium on `:9222` is mads's — never touch. Acceptance uses
  isolated profile + CDP `:9333` + Xvfb `:99`.
- Kill discipline: kill by PID; `pkill -f` patterns self-match the calling
  shell (use bracketed patterns or PIDs) — this session wasted a few
  cycles on `pkill -f` eating its own command.
- Credentials in chat/logs/docs: `[REDACTED]` only (sandbox creds live in
  `.scratch/sandbox-credentials`, ephemeral, regenerated per seed).
- #showcase audience is watching live; progress messages on multi-step
  jobs; no PII in group channels.

---
Handoff written at mads's stop order (2026-08-25). Environment left quiet:
no servers on 8081/9333, no stray Chromium, collector 9222 serving.
