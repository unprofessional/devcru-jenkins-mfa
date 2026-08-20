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

## Why (the pain being replaced)

The current (SaaS-branded 2FA) plugin is inadequate because:
1. **Email-only free tier** — no TOTP. → We ship RFC 6238 TOTP first; Authy/Google Authenticator scan a QR.
2. **Trust expiry far too short** — constant re-verification. → Remembered devices default **30 days**, configurable, mads requires **≥ 24h**.
3. **Broken/outdated post-login redirect assumptions.** → All redirects built with the **current** Jenkins context path + crumb; verified in integration tests against the running core.
4. **Search/filter UI gated behind a subscription.** → We are self-hosted: **nothing is paywalled**, ever.

**Non-goals (YAGNI):** WebAuthn/passkeys, SMS, YubiKey (HMAC-OTP) hardware keys, LDAP/SSO integration (realm stays `LocalSecurityRealm`), per-job MFA.

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

## File tree (final state)

```
/home/hunter/dev/devcru-jenkins-mfa/
├── pom.xml
├── src/main/java/org/sebcru/mfa/
│   ├── DevcruMfaPlugin.java            # @Extension, registers filter
│   ├── MfaFilter.java                  # the gate
│   ├── MfaController.java              # GlobalAction: /securityRealm/mfa/* (login page, verify, resend)
│   ├── MfaUserProperty.java            # per-user factor state
│   ├── MfaUserPropertyDescriptor.java
│   ├── DevcruMfaConfig.java            # GlobalConfiguration
│   ├── crypto/Totp.java                # RFC 6238 (HMAC-SHA1, default; SHA256 option)
│   ├── email/EmailCodeIssuer.java      # generate/hash/verify/consume
│   ├── email/EmailSender.java          # interface -> Jenkins mailer
│   ├── gate/TrustStore.java            # remembered-device logic
│   └── gate/RateLimiter.java           # failure/lockout logic
├── src/main/resources/
│   ├── index.jelly                          # plugin description (required by hpi:hpi)
│   └── org/sebcru/mfa/
│       ├── MfaController/index.jelly         # MFA login page (TOTP input + "Use email code" link)
│       ├── MfaController/postVerify.jelly    # (not needed — endpoint is @POST)
│       └── views/DevcruMfaUserProperty.jelly # user security-page factor management
└── src/test/java/org/sebcru/mfa/
    ├── TotpTest.java
    ├── EmailCodeIssuerTest.java
    ├── TrustStoreTest.java
    ├── RateLimiterTest.java
    └── MfaFilterIT.java                # Jenkins Rule integration
```

## Tasks

### Task 0: Install Maven + scaffold project (no build yet)

**Objective:** Working toolchain + empty plugin skeleton that compiles.

1. Install Maven: `sudo apt-get install -y maven` (or `uvx apache-maven`). Verify `mvn -version` ≥ 3.9, Java 21 selected.
2. `git init /home/hunter/dev/devcru-jenkins-mfa`, git identity already `Sebastian <sebastian@devcru.org>`. Remote: `git@github.com:unprofessional/devcru-jenkins-mfa.git` (empty, verified via `git ls-remote` with key `~/.ssh/github`). Store key selection in **local** repo config only — never tracked: `git config core.sshCommand 'ssh -i /home/hunter/.ssh/github -o IdentitiesOnly=yes'`. Work branch `develop`; integrate to `master` only when mads approves a step (no force-push ever; git 2.34 has no PR push-options — hand `/pull/new/` URLs if an MR-style review is wanted, otherwise direct push to `master` after approval).
3. Write `pom.xml` (complete, below).
4. Write a placeholder `org/sebcru/mfa/DevcruMfaPlugin.java` (empty `@Extension` class) so the hpi has a body.
   - **Also required:** `src/main/resources/index.jelly` (plugin description — `hpi:hpi` fails with `Missing target/classes/index.jelly` without it). Contents:
     ```
     <?jelly escape-by-default='true'?>
     <div>
         TOTP (Authy-compatible) and email-code MFA with long remembered devices. Self-hosted, no paywall.
     </div>
     ```
5. Build.

**pom.xml (complete):**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>

  <parent>
    <groupId>org.jenkins-ci.plugins</groupId>
    <artifactId>plugin</artifactId>
    <version>6.2116.v7501b_67dc517</version>
    <relativePath/>
  </parent>

  <groupId>org.sebcru.mfa</groupId>
  <artifactId>devcru-mfa</artifactId>
  <version>1.0.0-SNAPSHOT</version>
  <packaging>hpi</packaging>

  <name>Devcru MFA</name>
  <description>TOTP (Authy-compatible) and email-code MFA with long remembered devices. Self-hosted, no paywall.</description>
  <url>https://github.com/unprofessional/devcru-jenkins-mfa</url>

  <scm>
    <connection>scm:git:git@github.com:unprofessional/devcru-jenkins-mfa.git</connection>
    <developerConnection>scm:git:git@github.com:unprofessional/devcru-jenkins-mfa.git</developerConnection>
    <url>https://github.com/unprofessional/devcru-jenkins-mfa</url>
    <tag>HEAD</tag>
  </scm>

  <properties>
    <jenkins.version>2.528.3</jenkins.version>
    <changelist>999999-SNAPSHOT</changelist>
    <zxing.version>3.5.3</zxing.version>
  </properties>

  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>io.jenkins.tools.bom</groupId>
        <artifactId>bom-2.528.x</artifactId>
        <version>6055.v35edb_dc8d0f9</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>

  <dependencies>
    <dependency>
      <groupId>com.google.zxing</groupId>
      <artifactId>core</artifactId>
      <version>${zxing.version}</version>
    </dependency>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <scope>test</scope>
    </dependency>
    <!-- No TOTP lib: core implements RFC 6238.
         commons-codec (Base32) + jakarta.mail are in Jenkins core. -->
  </dependencies>

  <repositories>
    <repository>
      <id>repo.jenkins-ci.org</id>
      <url>https://repo.jenkins-ci.org/public/</url>
    </repository>
  </repositories>
  <pluginRepositories>
    <pluginRepository>
      <id>repo.jenkins-ci.org</id>
      <url>https://repo.jenkins-ci.org/public/</url>
    </pluginRepository>
  </pluginRepositories>

  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-enforcer-plugin</artifactId>
        <configuration>
          <rules>
            <enforceBytecodeVersion>
              <maxJdkVersion>21</maxJdkVersion>
            </enforceBytecodeVersion>
          </rules>
        </configuration>
      </plugin>
    </plugins>
  </build>
</project>
```

**Run:** `mvn -q -e -DskipTests package` (first run is long — downloads the toolchain; use a 20-min timeout).
**Expected:** BUILD SUCCESS, `target/devcru-mfa.hpi` exists.
**Commit:** `chore: scaffold devcru-mfa plugin (parent 6.2116, bom 2.528.x)`

---

### Task 1: Totp (RFC 6238) + TDD

**Objective:** Deterministic, testable TOTP core.

**Files:**
- Create: `src/main/java/org/sebcru/mfa/crypto/Totp.java`
- Test: `src/test/java/org/sebcru/mfa/TotpTest.java`

**Totp.java (complete):**

```java
package org.sebcru.mfa.crypto;

import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base32;

/** RFC 6238 TOTP. Pure JDK crypto. Time step 30s, 6 digits, SHA-1 (Authy-compatible). */
public final class Totp {
  public static final int STEP_SECONDS = 30;
  public static final int DIGITS = 6;
  private static final SecureRandom RANDOM = new SecureRandom();

  private Totp() {}

  /** New random Base32 secret (120 bits, padded to 16 bytes). */
  public static String newBase32Secret() {
    byte[] b = new byte[16];
    RANDOM.nextBytes(b);
    return new Base32().encodeAsString(b).replace("=", "");
  }

  public static byte[] decodeSecret(String base32) {
    return new Base32().decode(base32.toUpperCase());
  }

  /** Core HOTP: counter-based. */
  public static String codeFor(byte[] key, long counter) {
    byte[] msg = new byte[8];
    for (int i = 7; i >= 0; i--) { msg[i] = (byte) (counter & 0xff); counter >>= 8; }
    try {
      Mac mac = Mac.getInstance("HmacSHA1");
      mac.init(new SecretKeySpec(key, "HmacSHA1"));
      byte[] h = mac.doFinal(msg);
      int off = h[h.length - 1] & 0x0f;  // LAST hash byte (h[19] for SHA1; NOT a hardcoded h[15])
      int bin = ((h[off] & 0x7f) << 24) | ((h[off+1] & 0xff) << 16)
              | ((h[off+2] & 0xff) << 8) | (h[off+3] & 0xff);
      int mod = bin % (int) Math.pow(10, DIGITS);
      return String.format("%06d", mod);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /** TOTP at a specific instant. */
  public static String codeAt(byte[] key, long epochMillis) {
    return codeFor(key, epochMillis / 1000 / STEP_SECONDS);
  }

  /** Verify with ±window step tolerance, constant-time compare. */
  public static boolean verify(byte[] key, String input, long epochMillis, int window) {
    String cleaned = (input == null ? "" : input).replaceAll("\\s+", "");
    if (cleaned.length() != DIGITS) return false;
    long step = epochMillis / 1000 / STEP_SECONDS;
    for (long c = step - window; c <= step + window; c++) {
      if (MessageDigest_isEqual(codeFor(key, c), cleaned)) return true;
    }
    return false;
  }

  private static boolean MessageDigest_isEqual(String a, String b) {
    byte[] x = a.getBytes(), y = b.getBytes();
    return javax.xml.bind.DatatypeConverter // NO — use MessageDigest directly:
        true && MessageDigestConstantTime(x, y);
  }

  private static boolean MessageDigestConstantTime(byte[] a, byte[] b) {
    return javax.crypto.spec.MessageDigest.isEqual(a, b);
  }
}
```

> Implementation note (for the coder, not a second design pass): collapse the two `MessageDigest_*` helpers into one `private static boolean constEq(byte[], byte[])` calling `javax.crypto.spec.MessageDigest.isEqual`. The above double-method form is a transcription wart — do not replicate it.

**Test (step 1, write this first):**

> **Implemented version** (see `src/test/java/org/sebcru/mfa/TotpTest.java`): anchors to the
> genuine RFC 4226 Appendix D HOTP vectors (counters 0–9, e.g. counter 0 = `755224`, NOT
> `000054` — an earlier draft of this plan carried a placeholder value that would fail against
> a correct implementation) and the RFC 6238 A.1 TOTP instants (last 6 digits of the 8-digit
> published values). Keep the self-consistency tests below as well.

```java
package org.sebcru.mfa;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.sebcru.mfa.crypto.Totp;

class TotpTest {
  @Test void hotpKnownVectorRfc4226Style() {
    // key "12345678901234567890"; RFC 4226 HOTP counter 1 is 287082 for 6 digits
    byte[] key = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
    assertNotEquals("", Totp.codeFor(key, 1));
    assertEquals("000054", String.format("%06d", Integer.parseInt(Totp.codeFor(key, 0)) % 1000000));
    assertTrue(Totp.codeFor(key, 1).matches("\\d{6}"));
  }
  @Test void verifyAcceptsCurrentAndAdjacentSteps() {
    byte[] key = Totp.decodeSecret(Totp.newBase32Secret());
    long t = 1_700_000_000_000L; // fixed instant
    String code = Totp.codeAt(key, t);
    assertTrue(Totp.verify(key, code, t, 0));
    long next = t + 30_000;
    assertTrue(Totp.verify(key, Totp.codeAt(key, next), t, 1));
    assertFalse(Totp.verify(key, Totp.codeAt(key, t + 60_000), t, 1));
  }
  @Test void rejectsWrongAndMalformed() {
    byte[] key = Totp.decodeSecret(Totp.newBase32Secret());
    long t = 1_700_000_000_000L;
    String code = Totp.codeAt(key, t);
    String wrong = String.format("%06d", Integer.parseInt(code) + 1);
    assertFalse(Totp.verify(key, wrong, t, 0));
    assertFalse(Totp.verify(key, "1234", t, 1));
    assertFalse(Totp.verify(key, null, t, 1));
    assertFalse(Totp.verify(key, "abcdefgh", t, 1));
  }
}
```

**Run:** `mvn test -Dtest=TotpTest` → RED first (no `Totp`), then GREEN.
**Commit:** `feat(totp): RFC 6238 core with TDD`

---

### Task 2: `MfaUserProperty` + descriptor

**Objective:** Per-user factor state, encrypted-at-rest where possible.

**Files:**
- Create: `src/main/java/org/sebcru/mfa/MfaUserProperty.java`
- Create: `src/main/java/org/sebcru/mfa/MfaUserPropertyDescriptor.java`
- Test: (covered in Task 6 integration; unit-test `isMfaEnabled` logic inline here)

**MfaUserProperty (complete shape):**

```java
package org.sebcru.mfa;

import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import hudson.model.userproperty.UserPropertyCategory;
import hudson.util.Secret;

public class MfaUserProperty extends UserProperty {

  private Secret totpSecret;          // Base32, Secret-encrypted
  private Secret emailCodeSecret;     // per-user HMAC key for email codes
  private String registeredEmail;     // target for email codes
  private long trustedUntilMs;        // 0 = not trusted
  private long lastVerifiedFactor;    // 0=totp, 1=email (telemetry only)
  private int failedAttemptStreak;    // for UI display (real limit in RateLimiter)

  public MfaUserProperty() {} // @DataBoundConstructor via empty

  public static MfaUserProperty getOrCreate(User u) throws java.io.IOException {
    MfaUserProperty p = u.getProperty(MfaUserProperty.class);
    if (p == null) { p = new MfaUserProperty(); u.addProperty(p); }
    return p;
  }

  public boolean isMfaEnabled() {
    return (totpSecret != null && !totpSecret.getPlainText().isEmpty())
        || (registeredEmail != null && !registeredEmail.isBlank());
  }

  // getters/setters for UI binding (DataBoundSetter on each)
  // ...

  @Extension
  public static class DescriptorImpl extends UserPropertyDescriptor {
    public DescriptorImpl() { super(MfaUserProperty.class); }
    @Override public String getDisplayName() { return "MFA (Devcru)"; }
    @Override public UserPropertyCategory getUserPropertyCategory() {
      return UserPropertyCategory.get(UserPropertyCategory.Security.class);
    }
    @Override public boolean isSingle() { return true; }
    @Override public MfaUserProperty newInstance(User u) { return new MfaUserProperty(); }
  }
}
```

**Verification:** `mvn -q compile` green. Add one more unit test in `src/test`: property `isMfaEnabled()` false/true toggling (plain JUnit, no Jenkins needed for the boolean logic — construct directly).
**Commit:** `feat(user): MfaUserProperty with TOTP secret + email factor state`

---

### Task 3: `EmailCodeIssuer` + TDD

**Objective:** Hashed, single-use, expiring email codes.

**Files:**
- Create: `src/main/java/org/sebcru/mfa/email/EmailCodeIssuer.java`
- Create: `src/main/java/org/sebcru/mfa/email/EmailSender.java` (interface: `void send(String to, String code, long ttlSeconds)`)
- Test: `src/test/java/org/sebcru/mfa/EmailCodeIssuerTest.java`

**Design:** code = 8 chars from `A-Z0-9` minus ambiguous (`0O1I`), via `SecureRandom`. Store `sha256(HmacSHA256(code, emailCodeSecret))` + issueTime + consumed flag in the `MfaUserProperty` (add fields `Secret pendingCodeHash`, `long codeIssuedAt`, `long lastResendAt` — patch task 2's property in this task). Verify: recompute hash, constant-time compare, enforce TTL and not-consumed, then mark consumed. Resend: block if `now - lastResendAt < cooldown`, else replace.

**Test (write first):**

```java
class EmailCodeIssuerTest {
  @Test void issueVerifyConsumeRejectsSecondUse() {
    EmailCodeIssuer i = new EmailCodeIssuer();
    Secret key = Secret.fromString("0123456789abcdef0123456789abcdef");
    String code = i.issue(key);
    assertTrue(i.verify(key, code, now()));   // first use ok
    assertFalse(i.verify(key, code, now()));  // consumed
  }
  @Test void expiredCodeRejected() { /* set issuedAt = now - ttl - 1s */ }
  @Test void cooldownBlocksResend() { /* lastResendAt=now → issueBlocked() true */ }
  @Test void codeFormatExcludesAmbiguous() {
    for (int k=0;k<100;k++) assertFalse(EmailCodeIssuer.newCode().matches(".*[0O1I].*"));
  }
}
```
(`now()`/state injection: take `long nowMillis` as parameter on `issue/verify` — makes the unit test time-free. Production callers pass `System.currentTimeMillis()`.)

**Run:** `mvn test -Dtest=EmailCodeIssuerTest` RED→GREEN.
**Commit:** `feat(email): hashed single-use codes with tty and cooldown`

---

### Task 4: `TrustStore` + `RateLimiter` + TDD

**Objective:** The two gate brains, time-injectable, unit-testable.

**Files:** Create `gate/TrustStore.java`, `gate/RateLimiter.java`; tests `TrustStoreTest.java`, `RateLimiterTest.java`.

**TrustStore (API):**
```java
public class TrustStore {
  /** true if user has a live trust record. */
  public boolean isTrusted(MfaUserProperty p, DevcruMfaConfig cfg, long now) { return p.getTrustedUntilMs() > now; }
  /** Sets trust to now + rememberForHours (clipped to >= trustMinHours). */
  public void trust(MfaUserProperty p, DevcruMfaConfig cfg, long now) {
    long h = Math.max(cfg.getRememberForHours(), cfg.getTrustMinHours());
    p.setTrustedUntilMs(now + h * 3600_000);
  }
  public void revoke(MfaUserProperty p) { p.setTrustedUntilMs(0); }
}
```

**RateLimiter (API):** per-username `ConcurrentHashMap<String, List<Long>>` failures + `Map<String, Long>` lockoutUntil; methods `boolean isLocked(user, cfg, now)`, `void recordFailure(user, cfg, now)`, `void clear(user)`, internal sweep of expired entries on each call (cap list length at 100).

**Tests:** trust floor (remember=1h but floor 24h → effective 24h); expiry (trust 24h ago → not trusted); lockout trips exactly at `maxAttempts` inside window; lockout expires after `lockoutMinutes`; clearing on success.
**Commit:** `feat(gate): trust + ratelimiter with TDD`

---

### Task 5: `DevcruMfaConfig` (GlobalConfiguration)

**Objective:** The admin surface, with the §defaults table above.

**Files:**
- Create: `src/main/java/org/sebcru/mfa/DevcruMfaConfig.java`
- Create: `src/main/resources/index.jelly`? — **no**: config UI is a global config page. Add `config.jelly` under `org/sebcru/mfa/DevcruMfaConfig` via the `@Extension` + `config.jelly` at `src/main/resources/org/sebcru/mfa/DevcruMfaConfig/config.jelly` (plain form: policy select, remember hours int with min=24, issuer string, window int, email ttl/cooldown ints, rate-limit ints, exempt-users textarea).
- Create: `src/main/resources/org/sebcru/mfa/DevcruMfaConfig/config.properties` (display names).

Implementation: `@Extension @Symbol("devcruMfa") class DevcruMfaConfig extends GlobalConfiguration`, `configure(StaplerRequest2, JSONObject)` → `req.bindJSON(this, json); save(); return true;`, `getCategory() = SECURITY`.

**Verification:** `mvn -q compile` green; (full UI verify in Task 9 against live box).
**Commit:** `feat(config): DevcruMfaConfig global configuration`

---

### Task 6: `MfaController` — the MFA login page + endpoints

**Objective:** The single MFA screen (no dead redirects): TOTP input + "Use email code instead" link; POST endpoints return JSON.

**Files:**
- Create: `src/main/java/org/sebcru/mfa/MfaController.java`
- Create: `src/main/resources/org/sebcru/mfa/MfaController/index.jelly`
- Test: exercised in Task 8 integration.

**MfaController (shape):**
```java
@Extension
public class MfaController implements GlobalAction {
  public String getIconFileName() { return null; } // no side-bar icon
  public String getDisplayName() { return "MFA"; }
  public String getUrlName() { return "securityRealm/mfa"; } // stable, current-core path

  @POST
  public FilePath postVerify(@QueryParameter String code, StaplerRequest2 req, StaplerResponse2 rsp) throws IOException {
    // auth = JenkinsUtil.currentUser (must already be logged in)
    // rate-limit check -> {ok:false, error:"locked", retrySeconds}
    // try TOTP verify (config.totpWindow)  else email-code verify
    // on success: TrustStore.trust; SessionService regenerate; return {ok:true, rememberHours}
    // on failure: RateLimiter.recordFailure; {ok:false,error:code}
  }

  @POST
  public FilePath postResendEmail(@QueryParameter String dest, StaplerRequest2 req, StaplerResponse2 rsp) throws IOException {
    // cooldown check; EmailSender.send; return {ok:true, cooldown}
  }
}
```
`SessionService` (openmfa-style) is inlined here as a small private helper: regenerate + `setAttribute("org.sebcru.mfa.verified", true)`. Filter reads **only** that attribute. JSON via `rsp.addHeader("Content-Type","application/json")` + `rsp.getWriter().print(json)` — no extra deps (use `net.sf.json.JSONObject` from core).

**index.jelly:** one form. Inputs: 6-digit `code`; link button "Use email code instead" that shows the registered-email field (masked by default) + sends via `postResendEmail` with a JS countdown; on submit → `postVerify`; on success the server 302s to `req.getHeader("Referer")` **if in-site and non-login**, else `/` (this is the "no black page" fix — always a valid in-site target). Style with inline CSS (no ionicons dep). Jelly must be well-formed XSL/HTML — validate with `mvn hpi:run` in Task 9.

**Commit:** `feat(ui): MFA login page + verify/resend endpoints`

---

### Task 7: `MfaFilter` + `DevcruMfaPlugin` registration

**Objective:** The gate itself.

**Files:**
- Create: `src/main/java/org/sebcru/mfa/MfaFilter.java`
- Create: `src/main/java/org/sebcru/mfa/DevcruMfaPlugin.java` (replaces Task 0 placeholder)

**MfaFilter (shape):**
```java
public class MfaFilter implements Filter {
  // Kill switch — checked FIRST in doFilter:
  private boolean off() {
    return "1".equals(System.getenv("DEVCRU_MFA_OFF"))
        || DevcruMfaConfig.get().getPolicy() == Policy.OFF;
  }
  ...
}
```
Decision chain (exact order):
0. `off()` → pass (kill switch / policy OFF).
1. `req instanceof HttpServletRequest` else pass through.
2. Request attribute `BasicHeaderApiTokenAuthenticator.class.getName()` is `Boolean` true → pass (API token).
3. No authenticated user (`JenkinsUtil.getCurrentUser()` empty) → pass (core login flow owns it).
4. Path allow-list (prefix): `/login`, `/logout`, `/securityRealm`, `/adjuncts/`, `/static/`, `/assets/`, `/images/`, `/css/`, `/scripts/`, error pages, and `/securityRealm/mfa` (the MFA page itself).
5. `policy == OFF` → pass.
6. User exempt (config `exemptUsers`) → pass.
7. Has `MfaUserProperty` **and** `isMfaEnabled()` == false → pass (unenrolled users are not hard-locked; see security decision).
8. Session attribute `org.sebcru.mfa.verified` true AND `TrustStore.isTrusted` → pass. (Note: session attr alone is sufficient — trust expiry is enforced at *issue* time; a live session that logged in is trusted for its lifetime. The `trustedUntilMs` governs *future* logins. Document this plainly in a comment so nobody "fixes" it into per-request expiry of active sessions — that was the exact UX sin of the old plugin.)
9. Otherwise: 302 to `<contextPath>/securityRealm/mfa?redirect=<target>`.

**DevcruMfaPlugin:** `@Extension @NoArgsConstructor class DevcruMfaPlugin { @Initializer(after=STARTED) void add(){ PluginServletFilter.addFilter(new MfaFilter()); } @Terminator void remove(){ PluginServletFilter.removeFilter(new MfaFilter()); } }`.

**Commit:** `feat(filter): MFA gate with API-token + exemption + trust bypass`

---

### Task 8: Integration test `MfaFilterIT` (Jenkins in-JVM)

**Objective:** Prove the end-to-end flow against a real Jenkins in a temp dir — this is where "broken redirect assumptions" get caught.

**Files:**
- Test: `src/test/java/org/sebcru/mfa/MfaFilterIT.java`
- Test email sender: `src/test/java/org/sebcru/mfa/email/CaptureEmailSender.java` (implements `EmailSender`, records to a `List`)

**Test cases (3):**
1. **totp_flow:** create user, set `MfaUserProperty` TOTP secret; Jenkins rule; `POST /j_acegi_securityCheck` with credentials → 302 to `/securityRealm/mfa`; POST `postVerify` with correct `Totp.codeAt(key, now)` → redirect to `/` (assert **not** to a dead path); subsequent `GET /` with same session cookie → 200 (trusted); fresh session → 302 (untrusted).
2. **email_flow:** enable email factor with `CaptureEmailSender`; `postResendEmail` captures code; `postVerify` with captured code → trusted.
3. **api_token_exempt:** `Authorization: Basic <user>:<api-token> against a protected endpoint (`/api/json`) → 200 **without** MFA.
   *(Note, 2026-08-19: the original text here sketched `Bearer <api-token>` — that case is the
   A21 sibling `MfaFilterIT#bearerTokenExemptFromGate`,
   LANDED 2026-08-19 (`BearerTokenFilter`, see TECH_DEBT A21), NOT a Task 8/9 deliverable.
   It asserts 200 / no `/mfa` the same way, with the documented
   `X-Jenkins-User` companion header, plus the no-oracle mismatch half.)*
4. **lockout:** 5 wrong TOTP → 6th returns locked JSON with `retrySeconds > 0`.
5. **kill-switch:** (unit level, in `RateLimiterTest`'s sibling or a small `FilterLogicTest`) `off()` returns true when a stub config reports policy OFF; the filter's pass-through short-circuit is covered by case 3's shape — document the env-var seam as tested-by-construction (no JVM env in unit tests).

Auth in tests: use the crumb — `CrumbIssuer.get(req).issueFor(Jenkins.ANONYMOUS)` / cookie jar via `org.jvnet.hudson.test.JenkinsRule.WebClient` (it handles crumbs + cookies for you). Assert HTTP 302 locations with `client.getPage(new URL(rule.getURL(), "/"))`.

**Run:** `mvn test -Dtest=MfaFilterIT` (slowest test — first in-JVM Jenkins boot; 5-10 min is normal; set a long timeout).
**Commit:** `test(it): end-to-end TOTP/email/token/lockout flows`

---

### Task 9: User-facing factor management page (security profile)

**LANDED 2026-08-19** (six endpoints + section view + `MfaProfileIT` green on
a booted Jenkins; A7/A8/A2 wired; A22 boundary documented — see the Task 9
handoff in `docs/todo/` for deviations and the TECH_DEBT A22 note).

**Objective:** Enroll/disable factors from **Manage account → Security**, with
QR (zxing) — this replaces the old plugin's paywalled UI.

**CORRECTION (verified 2026-08-19, against jenkins-core 2.528.3 sources) — read
this first, it overrides the file list below:**

1. **The view lives at `src/main/resources/org/sebcru/mfa/MfaUserProperty/config.jelly` — NOT
   `org/sebcru/mfa/views/MfaUserProperty.jelly` as originally sketched.** Core's security-tab
   page (`hudson/model/userproperty/UserPropertyCategorySecurityAction/index.jelly`) does
   `st:include from="${d}" page="${d.configPage}"`, i.e. it resolves the view
   *relative to the descriptor* (`Descriptor.getConfigPage()` = `"config"` by default).
   An `f:` form is bound to the property's `reconfigure(JsonObject)` →
   `@DataBoundSetter`s, so the section needs no custom submit action at all.
   **A view at the wrong path fails *silently* — the tab renders with an
   empty section and nothing else in the build complains.** The IT must
   assert the section is actually present on the live page (below).
2. **NO nested `<f:form>` in the section.** The core security tab already
   wraps everything in one `<f:form action="configSubmit">` and wraps each
   property in `<f:rowSet name="userProperty${i}">`. Nested forms break
   browser form behaviour; the original sketch's "f:form with f:entries"
   must not be taken literally — the section is a set of
   `f:invisibleEntry` (dummy, so the rowSet always has an entry) +
   `f:entry`/`f:block` fields only, no form tag, no save button. Copy the
   shape of core's own live example, `jenkins/console/ConsoleUrlProviderUserProperty/config.jelly`
   (it starts with `<j:if test="${descriptor.enabled}">`).
3. **The `@WebMethod` block below still stands** (A20, added 2026-08-19): every
   one of the five `post*` endpoints needs `@WebMethod(name = "…")` in its
   **own commit** — Stapler auto-maps only get/is/do-prefixed methods; a bare
   `postEnrollTotp` exposes no dispatch token and 404s. `@RequirePOST` is
   policy, not routing.

**Files:**
- Create: `src/main/resources/org/sebcru/mfa/MfaUserProperty/config.jelly`
  (path per correction 1 above) — the section:
  - **TOTP:** hidden `f:invisibleEntry` dummy; "Generate new seed" button →
    POST `<ctx>/mfa/postEnroll` (JSON: new Base32 seed + `otpauth://` URI);
    the section renders the seed (masked `Secret.toStringMasked()` style, as
    the login page does for the email) + QR `<img src="data:image/png;base64,…">`
    built server-side with zxing
    (`MultiFormatWriter().encode(uri, BarcodeFormat.QR_CODE, 300, 300)` →
    ByteArrayOutputStream → Base64; the dep is already in `pom.xml`,
    `zxing 3.5.3`); a confirm-code field; "Confirm & enable" POSTs
    `postEnrollConfirm` with `{seed, code}`.
  - **Email:** `f:entry field="registeredEmail"` (masked input, as the login
    page) + "Send test code" button → `postEmailTestCode` (reuses the
    `EmailCodeIssuer.resend`/`issue` + resend-cooldown path, same shape as
    the login page's `postResendEmail`).
  - **Manage:** "Disable TOTP" (`postDisableTotp`), "Disable email"
    (`postDisableEmail`), "Revoke remembered devices" (`postRevokeTrust`,
    → `TrustStore.revoke(p)` → clears `trustedUntilMs`).
- Extend `MfaController` with `postEnroll`, `postEnrollConfirm`,
  `postEmailTestCode`, `postDisableTotp`, `postDisableEmail`,
  `postRevokeTrust` (each JSON, crumb-checked by core) — all under the
  existing `/mfa` mount.

**Endpoint contracts (JSON out; `VerifyOutcome`-style error codes, same
conventions as Task 6):**

| endpoint | body | success | failure |
|---|---|---|---|
| `postEnroll` | — (admin not required: owns own account) | `{ok:true, seed, otpauthUri, dataUriPng}` | `{ok:false, error:"server_error"}` |
| `postEnrollConfirm` | `{seed, code}` | `{ok:true}` — seed committed to `MfaUserProperty.totpSecret` | `{ok:false, error:"wrong_code"}` — **seed NOT committed** |
| `postEmailTestCode` | — | `{ok:true, resent:true, cooldown}` | `{ok:false, error:"email_not_enrolled" \| "resend_cooldown", retrySeconds}` |
| `postDisableTotp` | — | `{ok:true}` | `{ok:false, error:"not_enrolled"}` |
| `postDisableEmail` | — | `{ok:true}` | `{ok:false, error:"not_enrolled"}` |
| `postRevokeTrust` | — | `{ok:true}` | — (always a no-op-safe success) |

**Enrollment safety (the single-POST commit — no pre-commit staging):** the
confirm flow is *seed + code in ONE POST*. Core generates the seed when the
user clicks "Generate," the UI holds it in the form (hidden input) between
generate and confirm, and `postEnrollConfirm` verifies `code` against
`Totp.verify(decodeSecret(seed), code, now, cfg.getTotpWindow())` **before**
writing the `Secret`. No seed ever reaches user-land storage before a
correct code — and no server-side session state is needed to hold a
pre-commit secret (which would itself be a credential-in-session problem,
and would need its own expiry/teardown lifecycle). A regenerate simply
POSTs `postEnroll` again and replaces the hidden seed + QR.

**A2 mint path — the second, real one:** the email `Secret emailCodeSecret`
must be lazily minted when the email factor becomes live. It is minted
**exactly** inside `MfaController.ensureEmailCodeSecret(p)` (idempotent,
128-bit, `Secret`-encrypted, only behind `hasEmailFactor()`) — the same
seam the login-page `postResendEmail` already uses. The profile's
`postEmailTestCode` and the login-page flow both route through it; no
second mint implementation is allowed (single seam, per the A2 ruling).

**Data-binding boundary (why the form can't forge trust/lockout state):**
`MfaUserProperty` deliberately has `@DataBoundSetter` on **only**
`setTotpSecret` and `setRegisteredEmail`; `trustedUntilMs`,
`failedAttemptStreak`, `lastVerifiedFactor`, and the pending-code state are
plain getters/setters for server code only. `f:rowSet` + `configSubmit`
binds through `reconfigure` → `@DataBoundSetter` only, so a malicious or
buggy form can never set a 30-day trust expiry or zero out the attempt
counter. **Do not add a `@DataBoundSetter` to any server-managed field to
"fix" a missing value — that is a security boundary, not an oversight.**
Note the consequence: the TOTP seed is committed via
`postEnrollConfirm` (JSON endpoint), not via `configSubmit` — `configSubmit`
only carries `registeredEmail` (and the dummy field).

**Testing / verification:**
- Unit (plain JVM, BDD-documented per `AGENTS.md`, `TotpTest` shape): the
  `postEnroll`/`postEnrollConfirm` decision seam extracted pure (seed
  validation: is-it-a-valid-base32, code-verifies, already-enrolled →
  replace semantics), same as `MfaController`'s existing `verifyTotp` seam.
- `MfaFilterIT` (or a new `MfaProfileIT` — prefer extending the existing
  suite, it already has login + crumb + post helpers): (a) login as an
  enrolled user, GET the security page, **assert the section is actually
  rendered** (guards the view-path correction above — the silent-empty-page
  failure mode); (b) `postEnroll` → JSON with seed; `postEnrollConfirm`
  with a correct `Totp.codeAt` → `ok:true` AND the property now
  `hasTotpFactor()`; bad code → `wrong_code` AND property unchanged;
  (c) each disable/revoke endpoint flips the right state; (d) all six
  endpoints 404-free (the A20 guard — the single-POST design means no
  session-side pre-commit state to leak).
- **`mvn clean verify` (full, CI-mirror) green** — do NOT use bare `mvn test`
  (it silently skips SpotBugs, per AGENTS.md; this exact gap shipped a
  default-charset bug once).

**Commit:** `feat(ui): factor management on user security page` (house
rules: README "Practical usage" updated in the same commit; `AGENTS.md`
BDD docs on every new test method).

---

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
