# Devcru MFA Plugin — Implementation Plan

> **AMENDMENTS (post-landing rulings — these supersede the original text
> wherever they conflict, which remains un-rewritten for provenance):**
> 1. **MFA page mount is `/mfa`, not `/securityRealm/mfa`** (mads, 2026-08-19;
>    executed in Task 8, commit `c34e2b1`; TECH_DEBT A17). Every reference
>    below to `/securityRealm/mfa`, `getUrlName() == "securityRealm/mfa"`,
>    or the allow-list's `/securityRealm` prefix is void. All other plan text
>    stands.
> 2. **A15 resolution (mads, 2026-08-19):** the Bearer case is a real gap,
>    not a core-bet — implement a home-grown Bearer→API-token filter (read
>    `Authorization: <api-token> match against `ApiTokenProperty`, set the
>    api-token request attribute the gate already exempts) rather than
>    voiding the plan line or waiting on core. Tracked as its own small
>    task; no new dependency (Spring Security is `provided`/transitive and
>    Jenkins does not run its web filter chain).
> 3. **Task 9 view-path correction (verified 2026-08-19 against core sources,
>    recorded on the Task 9 section):** the security-tab section renders from
>    `org/sebcru/mfa/MfaUserProperty/config.jelly` (the descriptor's
>    `configPage`), not `views/MfaUserProperty.jelly`, and must NOT nest an
>    `f:form` (the tab already supplies one, wrapped in `f:rowSet`). A wrong
>    view path fails silently — the IT must assert the section renders.

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Build `devcru-mfa`, a self-hosted Jenkins MFA plugin: TOTP (Authy/GA-compatible) and email one-time codes, with remembered-device trust ≥ 24h (default 30 days), no subscription, no dead third-party redirects.

**Architecture:** A `PluginServletFilter` registered via `@Initializer` intercepts every request *after* standard Jenkins auth. If an authenticated user has MFA enabled and the HTTP session is not "MFA-trusted", the request is redirected to the plugin's own MFA login page (`/securityRealm/mfa/login`). Factor state (TOTP secret, registered emails, trust expiry) lives in a per-user `UserProperty`; policy lives in a `GlobalConfiguration`. TOTP is RFC 6238 pure-`javax.crypto` (no external TOTP lib); email codes are HMAC-hashed, single-use, short-validity.

**Tech Stack:** Java 21, Jenkins plugin parent 6.2116.v7501b_67dc517, BOM `bom-2.528.x:6055.v35edb_dc8d0f9` (min Jenkins 2.528 — our instance runs 2.577), zxing 3.5.3 (QR), JUnit 5 + `JenkinsSessionRule`-style `Rule<Jenkins>`, Maven 3.9 via `install-maven`.

---

## Tasks 0–9 — archived (all LANDED)

> The per-task records for Tasks 0–9 (TOTP, property, email codes,
> trust/rate-limit, config, controller, filter, ITs, profile UI) moved to
> **`docs/done/2026-08-17-plan-tasks-0-9.md`** on 2026-08-20 — with the
> original motivation ("Why") and the final-state file tree. Task 10 and
> everything after it remain below.

## Verified environment

- Build host: this machine. Java 21 (OpenJDK 21.0.11). No Maven yet → Task 0 installs it via `uvx apache-maven` or apt.
- Jenkins: `https://jenkins.devcru.org`, core **2.577**, Local Security Realm, agent `yharnam` on this host. We have **no API credential from here** — manual UI steps are marked `(mads)`.
- Live-verified dependency coordinates (HTTP 200 on repo.jenkins-ci.org / Maven Central):
  - parent `org.jenkins-ci.plugins:plugin:6.2116.v7501b_67dc517`
  - `io.jenkins.tools.bom:bom-2.528.x:6055.v35edb_dc8d0f9`
  - `com.google.zxing:core|javase:3.5.3` (Maven Central)
  - `commons-codec` — already bundled in Jenkins core (Base32/`Hex`); do **not** bundle.
- Reference implementation studied (seams, not code to copy): `jenkinsci/openmfa-plugin` master branch — `PluginServletFilter.addFilter` in `@Initializer`, `UserProperty` for factor state, `GlobalConfiguration`, session regeneration after verification.

## Global configuration knobs (`DevcruMfaConfig`, `@Symbol("devcruMfa")`)

| Knob | Default | Notes |
|---|---|---|
| `policy` | `REQUIRED` | `OFF` = filter inactive; `REQUIRED` = MFA mandatory once a user has ≥1 factor; users without factors can still log in (no hard-lockout of unenrolled users) |
| `rememberForHours` | `720` (30d) | Trust window after successful MFA. **Floor: 24h (6240h allowed, 1h min).** |
| `issuer` | `devcru Jenkins` | Shown in authenticator apps |
| `totpWindow` | `1` | ± time-step tolerance (clock skew) |
| `emailCodeTtlSeconds` | `300` | Email code validity |
| `emailResendCooldownSeconds` | `60` | Resend throttle |
| `maxAttempts` | `5` | Failed TOTP attempts per window |
| `attemptWindowMinutes` | `30` | Sliding window for failures |
| `lockoutMinutes` | `15` | Lockout after `maxAttempts` |
| `exemptUsers` | *(empty)* | Newline-separated usernames fully exempt (e.g. service accounts) |
| `trustMinHours` | `24` | Policy floor; mads: never below this |

## Security model decisions (bake these in — do not re-litigate during implementation)

1. **API tokens are exempt** (check `BasicHeaderApiTokenAuthenticator.class.getName()` request attribute) — Jenkins core issues API tokens as first-class credentials; gating them breaks CI.
2. **Email codes are never stored in plaintext**: store `HmacSHA256(code, perUserCodeSecret)`; verify by re-hash.
3. **Session is regenerated** (attribute copy + `invalidate()`) when MFA verification succeeds — anti session-fixation.
4. **TOTP verification uses `MessageDigest.isEqual`** (constant-time) on the 6-digit string.
5. **Rate limiting is per-username, in-memory**, with a sweep on expiry (Jenkins restart clears it — acceptable, matches openmfa; do not persist).
6. **Trust cookie/attribute is server-side session state only** — no client-supplied trust tokens.
7. Recovery path if mads loses everything: admin script clears the user's `DevcruMfaUserProperty` (documented in task 9), then re-enroll.

### Task 10: Deploy to `jenkins.devcru.org` + acceptance

**Objective:** Live on the real box, verified, with a recovery runbook.

1. **Build release:** set `<changelist>1</changelist>` (replace `999999-SNAPSHOT`) in `pom.xml` properties — this yields version `1.0.0-1` (Jenkins changelist convention). `mvn -DskipTests clean package`. Artifact: `target/devcru-mfa.hpi`.
2. **Staging (no live-box access):** run `mvn hpi:run` on this host — standalone Jenkins with the plugin; walk every acceptance flow below against it (Task 8 already covers the important ones; this is a final dress rehearsal). Kill here if anything's off; nothing on the live box has been touched.
3. **Snapshot (mandatory, before anything else on the live box):** execute the **Backup & rollback → Pre-deploy snapshot** procedure. Verify `CHECKSUMS.txt` exists and Jenkins is back up before proceeding. If the snapshot fails, stop — do not deploy on an unbacked-up instance.
4. **Upload (mads):** Manage Jenkins → Plugins → Advanced → Upload plugin → upload `devcru-mfa.hpi` (I hand mads the file; or I scp to the host if mads provides an admin API token — ask which). Restart Jenkins.
5. **Re-enroll mads on the new plugin** (Task 9 UI: TOTP QR via Authy, register email).
6. **Uninstall the old plugin (mads):** Manage Plugins → Installed → remove the old 2FA plugin, restart. Only after step 5 — one factor set active at a time.
7. **Acceptance (manual, mads + me via logs):**
   - [ ] mads logs in → lands on **new** `/mfa` page (not the old dead redirect; the old `/securityRealm/mfa` path was removed in Task 8 — any stale bookmarks 404 by design).
   - [ ] TOTP: scans QR in **Authy** → verifies → lands on `/`.
   - [ ] Email: "Use email code" → code arrives via Jenkins mail config → verifies.
   - [ ] Re-login within 30 days → **no** second prompt (trust honored).
   - [ ] After revoking trust on the profile page → next login prompts again.
   - [ ] CI build triggering via API token on `yharnam` agent → **no** MFA friction (token exempt).
   - [ ] 5 wrong codes → lockout message with countdown.
   - [ ] Jenkins core search/filter UI works, no subscription wall (trivially true — our plugin has no such code path).
8. **Snapshot + staging + rollback:** see the **Backup & rollback** section below — snapshot (with checksums) is the *first* manual action of Task 10 on the live box, before any upload; `mvn hpi:run` staging precedes cutover; the four-rung rollback ladder covers everything from "toggle it off" to "restore the whole install".

**Commit (final):** `release: devcru-mfa 1.0.0-1`

---

## Backup & rollback (read before touching the live box)

**What a Jenkins install actually is:** core (`/var/lib/jenkins/`) + plugins + config.xml + user/credential/secret data + the *secret key files* (`*.key` — without these, encrypted secrets/credentials in config.xml are unreadable garbage). A backup that misses the key files is a backup that looks right and isn't.

**Pre-deploy snapshot (Task 10, first manual step, before uploading anything):**

```bash
# On the Jenkins host (jenkins.devcru.org). Adjust paths to match actual layout if needed
J=/var/lib/jenkins
TS=$(date +%Y%m%d-%H%M%S)
BAK=/home/hunter/jenkins-backups/$TS          # agent host, we live here
mkdir -p $BAK
# 1. Stop Jenkins (clean state, no writes mid-copy)
sudo systemctl stop jenkins
# 2. Full config, incl. secret keys (deliberately NOT excluded)
tar czf $BAK/jenkins-core-$TS.tgz \
  --exclude=$J/war/work \                 # scratch, rebuilds itself
  --exclude=$J/workspace \                # agent working space, not config
  $J/jobs $J/users $J/credentials $J/identity $J/secrets \
  $J/config.xml $J/*.xml $J/plugins \
  2>/dev/null || tar czf $BAK/jenkins-core-$TS.tgz $J   # fallback: whole dir
# 3. Record checksum + size for restore verification
sha256sum $BAK/*.tgz > $BAK/CHECKSUMS.txt
gzip -l $BAK/*.tgz >> $BAK/CHECKSUMS.txt
# 4. Start Jenkins again
sudo systemctl start jenkins
# 5. Keep ONE older snapshot: rm old tgz dirs beyond latest 2
```

- **Where snapshots live:** `/home/hunter/jenkins-backups/` on *this* host (the agent), never on the Jenkins host itself — a host-level disk event should not take backup and primary together. (If the live box is literally this host, use `/home/hunter/jenkins-backups` and exclude it from any sync; say so in the snapshot log.)
- **Keep policy:** latest 2 snapshots, oldest pruned.
- **Dry-run restore = trust test:** once, in staging (see below), actually *restore* a snapshot into a throwaway directory and boot Jenkins from it (`-home` override) to prove the snapshot is bootable, not just present. A backup you've never restored is a rumour.

**Staging before cutover (new step at the top of Task 10, after snapshot):**
1. `mvn hpi:run` on this host → standalone Jenkins with the plugin, all acceptance flows exercised against the in-JVM instance. Zero access to the live box. If anything's broken, nothing has been touched.
2. Snapshot (above).
3. Only then: upload → install → re-enroll → uninstall old.

**Rollback ladder (cheapest first — never blow past a rung you haven't needed):**

| Rung | Trigger | Action | Time |
|---|---|---|---|
| 1 | Bad behaviour, login works | Set `DEVCRU_MFA_OFF=1` env (kill switch) or `policy=OFF` in config UI → restart if env. MFA inert, nobody gated, plugin still installed for fix-forward. | ~1 min |
| 2 | Login itself broken by the plugin | Uninstall `devcru-mfa` → restart. Filter is gone; core login is 100% independent of it, so this always restores access. Old plugin is **still installed** at this point — it's only removed after mads re-enrolls on the new one. | ~2 min |
| 3 | Something worse (data corruption, config.xml damage, key file loss) | **Hard rollback:** stop Jenkins; rsync the last verified snapshot's `$J/jobs $J/users $J/credentials $J/identity $J/secrets $J/*.xml $J/plugins` back over the live dirs (plugins dir: remove `devcru-mfa.jpi/.hpi` and any `.installing` stubs; restore old plugin's file from snapshot); verify `sha256sum -c CHECKSUMS.txt` on the snapshot first; start. | ~10 min |
| 4 | Host-level catastrophe | Full restore from snapshot into a clean Jenkins install; re-point; re-verify checksums. (This is the last one; the others should make it unnecessary.) | 30+ min |

**Never:**
- Delete or "clean up" the old 2FA plugin until mads is fully re-enrolled on the new one.
- Restore a snapshot without checking `CHECKSUMS.txt` first.
- Take the snapshot with Jenkins *running* (config.xml and secrets can be half-written).
- Put the backup on the same filesystem as Jenkins without the exclude rules above.

**Account recovery (mads loses phone + email, at any point, plugin healthy or not):**
```groovy
// Script Console (admin, pre-MFA or with MFA off via rung 1)
u = hudson.model.User.get("USER", false)
p = u?.getProperty(org.sebcru.mfa.MfaUserProperty)
if (p != null) { p.setTotpSecret(null); p.setRegisteredEmail(null); u.save(); "cleared" }
```

## Risks & mitigations

| Risk | Mitigation |
|---|---|
| Jenkins 2.577 vs BOM 2.528 mismatch at runtime | 2.528 is the **minimum**; 2.577 > min. Task 8 in-JVM test uses BOM core (2.528.3) — if the live box diverges, the UI check in Task 10 covers it before cutover. |
| Filter over-matches and locks out Jenkins' own internal calls | Step 2 API-token check + step 7 unenrolled-passthrough keep CI/admin healthy; integration test 3 guards the token path. |
| mads loses phone + email | Script Console recovery above (admin-only, single command). |
> **Do not file upstream issues.** (Repo convention.)
| First Maven run slow | Expected; not a failure. |
| Data damage to live `/var/lib/jenkins` during cutover | Snapshot taken *before* upload, checksummed, off-host; rung-3 hard rollback from it; one-time dry-run restore in staging proves it boots. |
| MFA bug gates *everyone* at login | Rung-1 kill switch (`DEVCRU_MFA_OFF=1`) unblocks without touching the plugin; unenrolled users are never gated by design. |

## Definition of done

- `mvn test` fully green (unit + IT) on this host.
- `target/devcru-mfa.hpi` built at `1.0.0-1`.
- All task-10 acceptance boxes ticked on `jenkins.devcru.org`.
- Repo pushed to GitHub (`unprofessional/devcru-jenkins-mfa`, key `~/.ssh/github` via `core.sshCommand`) so we never lose the source again.
- Old plugin removed.
