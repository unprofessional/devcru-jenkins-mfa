# A22-b real-browser acceptance fixture

This fixture reproduces the §10 journey against the branch's real
`maven-hpi-plugin:run` server and a separate headful Chromium. It deliberately
does not use JenkinsRule/HtmlUnit or the long-lived collector browser.

## Safety and runtime state

- Bind Jenkins only to `127.0.0.1:8081`.
- Use a separate Chromium profile and CDP port `9333`; do not touch collector
  CDP `9222`.
- Generated passwords, the sacrificial user's candidate TOTP seed, browser
  profile, logs, and screenshots belong under ignored `.scratch/` and mode
  `0600` where applicable.
- `fixture-src/WalkAuthorizationStrategy.java` is sandbox-only. Copy it into
  the Maven source tree for the duration of `hpi:run`, locally exclude that
  one path, and remove it before the final repository build.

## Prepare and boot

From the repository root:

```bash
mkdir -p .scratch
printf '\n/src/main/java/org/sebcru/mfa/WalkAuthorizationStrategy.java\n' \
  >> .git/info/exclude
cp scripts/acceptance/a22b/fixture-src/org/sebcru/mfa/WalkAuthorizationStrategy.java \
  src/main/java/org/sebcru/mfa/WalkAuthorizationStrategy.java
mvn -o -B org.jenkins-ci.tools:maven-hpi-plugin:run \
  -Dport=8081 -Dhost=127.0.0.1
```

The development server lives at `http://127.0.0.1:8081/jenkins/`, not `/`.
On a fresh unsecured `work/` home, seed the local realm, enrolled admin and
victim, READ-only reader, and one-admin ACL through the Script Console. Jenkins
crumbs are session-bound, so preserve the same cookie jar:

```bash
curl -fsS -c .scratch/bootstrap.cookies \
  http://127.0.0.1:8081/jenkins/crumbIssuer/api/json \
  > .scratch/crumb.json
curl -fsS -b .scratch/bootstrap.cookies -X POST \
  -H "$(jq -r .crumbRequestField .scratch/crumb.json):$(jq -r .crumb .scratch/crumb.json)" \
  --data-urlencode script@scripts/acceptance/a22b/seed-sandbox.groovy \
  http://127.0.0.1:8081/jenkins/scriptText
```

The generated credential file is `.scratch/sandbox-credentials` (mode 0600).
The committed fixture contains sandbox-only TOTP seeds; it contains no generated
passwords or production credentials.

## Browser and journey

Launch a second Chromium on the existing Xvfb display:

```bash
uv venv .scratch/cdp-venv
uv pip install --python .scratch/cdp-venv/bin/python websockets
DISPLAY=:99 snap run chromium --password-store=basic --no-first-run \
  --disable-default-apps --disable-sync \
  --user-data-dir="$PWD/.scratch/chromium-a22b" \
  --remote-debugging-port=9333 --window-size=1360,920 about:blank
```

Invoke the scripts explicitly with the acceptance venv:

```bash
.scratch/cdp-venv/bin/python scripts/acceptance/a22b/walk-admin.py
.scratch/cdp-venv/bin/python scripts/acceptance/a22b/walk-recovery.py
```

Restart the actual `hpi:run` JVM, wait for `/jenkins/` to leave HTTP 503, then:

```bash
.scratch/cdp-venv/bin/python scripts/acceptance/a22b/walk-post-restart.py
```

Expected terminal markers:

```text
BROWSER_WALK_OK ... sac_cleared=true
RECOVERY_WALK_OK ... reenrolled=true
POST_RESTART_OK ... reader_403=admin_permission_required
```

Screenshots are written to ignored `.scratch/screenshots/`.

## Teardown and repository gate

Stop Jenkins and the isolated Chromium, then remove the temporary compile input:

```bash
rm -f src/main/java/org/sebcru/mfa/WalkAuthorizationStrategy.java
mvn -o -B clean verify
```

Before committing, verify that the sandbox-only class is absent from
`src/main/java`, generated secrets remain ignored, and only the fixture scripts
under this directory are tracked.
