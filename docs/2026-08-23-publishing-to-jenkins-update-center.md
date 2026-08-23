# Publishing devcru-mfa to the Jenkins update center (2026-08-23)

**Status:** RESEARCH — decision pending. Written by Moldy at mads's request.
**Purpose:** what it takes to ship this plugin publicly via the official
Jenkins update center (`plugins.jenkins.io`), what we still owe before we
can ask, and what we sign up for by doing it.

---

## The process (three phases)

### Phase 1 — the repo must become public and publishable

Plugins distributed through the official update site **must** live in the
`jenkinsci` GitHub organization, and everything they ship must be free and
open source (source and all dependencies).

Requirements before a hosting request will be accepted:

1. **License.** OSI-approved license (MIT recommended — matches Jenkins core
   and most plugins), declared both in `pom.xml` (`<licenses>`) and as a
   `LICENSE` file in the repo.
2. **Naming convention.** Artifact id must follow the plugin style guide
   (no trademark collisions, short id). `devcru-mfa` appears compliant; the
   hosting team checks this.
3. **`Jenkinsfile`** using `buildPlugin()` from the Jenkins pipeline library
   — this is what ci.jenkins.io builds against (multiple JDK/OS
   configurations).
4. **Documentation-as-code.** plugins.jenkins.io renders the repo's
   README/docs directly; user documentation is expected in-repo (we satisfy
   this already).
5. **"Look for similar plugins" step.** The hosting team asks why we are not
   joining forces with existing maintainers. Current landscape:
   - `miniorange-two-factor` — the SaaS-branded plugin this one replaces
     (email-only free tier, short trust windows, third-party redirects,
     paywalled UI).
   - `openmfa` (jenkinsci/openmfa-plugin) — TOTP-only MFA for interactive
     logins, already in the update center. **This is the one we must
     differentiate against.** Our story: TOTP *and* email one-time codes,
     configurable remembered-device trust (30-day default, 24h floor),
     per-user rate limiting/lockout, a real kill switch, Bearer API-token
     exemption for CI, zero external services or dependencies.
6. **Repo goes public.** Currently private (`unprofessional/devcru-jenkins-mfa`).

### Phase 2 — hosting request

1. File a **hosting-request issue** in
   [`jenkins-infra/repository-permissions-updater`](https://github.com/jenkins-infra/repository-permissions-updater/issues/new?assignees=&labels=hosting-request&template=1-hosting-request.yml)
   (template `1-hosting-request.yml`).
2. The Jenkins **hosting team** reviews within a few days and requests
   changes if needed.
3. On approval the repo is **forked into `jenkinsci/`** (convention:
   `jenkinsci/devcru-mfa-plugin`), and the maintainer is invited to the
   org with admin access to the repo.
4. The original repo is then **deleted** so the jenkinsci fork is the root
   of GitHub's network graph (their automation prefers fork+delete; a
   manual transfer can be requested instead if there is history worth
   preserving — forks carry full commit history, so the loss is
   issues/PRs, not commits).
5. A **release-permissions PR** in the same repository is then
   auto-created (manual fallback per its README if not).

### Phase 3 — release machinery

Two paths; automated is the modern default:

- **Automated releases (recommended):** a GitHub Action builds and
  publishes on merge to the primary branch once ci.jenkins.io is green —
  incrementals versioning (`.mvn/maven.config`: `-Pconsume-incrementals
  -Pmight-produce-incrementals -Dchangelist.format=%d.v%s`), no local
  credentials needed; write access to the repo is enough.
- **Manual releases:** `mvn release:prepare release:perform` against
  Artifactory (`repo.jenkins-ci.org`); requires a Jenkins community
  account (accounts.jenkins.io) logged into Artifactory once.

Either way the artifact lands in Artifactory; the **update center
regenerates roughly every 15 minutes** and picks it up. The plugin then
appears in the Jenkins plugin manager and on plugins.jenkins.io.

Accounts needed: GitHub (have), Jenkins community account at
accounts.jenkins.io (needed for Jira + Artifactory; also where security
vulnerability reports arrive even when issues are tracked on GitHub).

---

## What we owe before we can request hosting (gap list)

| Gap | State today | Work |
|---|---|---|
| License | no `<licenses>` in pom, no LICENSE file | add MIT + pom block |
| Public repo | private | mads's decision — this is the real first gate |
| Jenkinsfile | absent | add `buildPlugin()` Jenkinsfile |
| pom metadata | url/scm point at `unprofessional/devcru-jenkins-mfa` | repoint after fork |
| Admin user management UI | not built (A22-b) | **the functional blocker mads has named**: today an admin who locks themselves out has no recovery path, which is a brutal look for an MFA plugin |
| Baseline | builds against core 2.528.3 (live box runs 2.577) | LTS-aligned baseline recommended for update-center treatment; core APIs drift, so the repo must track |
| Scrub check | repo contains this project's internal docs incl. the post-rollout postmortem and the `DEVCRU_MFA_OFF=1` incident kill switch | mads's call: ship the postmortem publicly (strong "we take rollout honesty seriously" signal) or strip it; the kill switch itself is a legitimate operational feature worth documenting |

---

## What publishing signs us up for (ongoing obligations)

1. **The Jenkins security process.** Maintainers get vulnerabilities
   assigned via Jira, with private-fix and coordinated-disclosure
   timelines and possible CVEs through the Jenkins security team. For an
   MFA plugin this is not optional exposure — it is the job.
2. **Proactive security review (recommended before launch):** the Jenkins
   security team reviews security-sensitive plugins on request. Strongly
   advised here — it is an external oracle for exactly the class of
   defect the 2026-08-22 rollout exposed (see
   `docs/2026-08-22-postmortem-live-rollout.md`).
3. **Baseline maintenance.** Jenkins core moves; LTS bumps and dependency
   updates become recurring work.
4. **Public communication.** The project expects maintainers on the
   jenkinsci-dev mailing list, communicating in public channels.

---

## Honest summary

The **publishing** hoops are light: a few days of repo hygiene, one issue
template, their fork. The real costs are (1) going public, (2) the admin
user management gap, and (3) signing up for permanent security-maintainer
duty. None of that argues against publishing — it argues for sequencing:
admin UI first, security review requested, then hosting request.

## Sources

- <https://www.jenkins.io/doc/developer/publishing/requesting-hosting/> (hosting process)
- <https://www.jenkins.io/doc/developer/publishing/preparation/> (preparation requirements)
- <https://www.jenkins.io/doc/developer/plugin-development/distribution-process/> (distribution pipeline)
- <https://www.jenkins.io/doc/developer/publishing/releasing-cd/> (automated releases)
- <https://github.com/jenkins-infra/repository-permissions-updater> (hosting + release permissions)
