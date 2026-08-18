package org.sebcru.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.util.Secret;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link MfaUserProperty} — the per-user factor-state record.
 *
 * <h2>What this file pins down</h2>
 * <p>One query and one invariant carry the whole gate's correctness:
 * <ul>
 *   <li>{@link MfaUserProperty#isMfaEnabled()} must be the exact predicate the
 *       gate (Task 7) uses to decide "this enrolled user must MFA" vs "this
 *       unenrolled user may log in" (policy {@code REQUIRED}). A false negative
 *       lets an enrolled user skip MFA; a false positive locks out unenrolled
 *       users (including service accounts that never enrolled).</li>
 *   <li>Server-managed trust/telemetry fields default to "not trusted, no
 *       history" and round-trip through getters/setters, so the gate and
 *       RateLimiter can persist state without a form round-trip.</li>
 * </ul>
 *
 * <h2>Why plain JUnit, no Jenkins</h2>
 * <p>{@code isMfaEnabled()} is pure field logic; constructing a
 * {@code MfaUserProperty} and setting a plain {@link Secret} does not require a
 * running {@code Jenkins} instance or the master secret key (XStream encryption
 * of {@code Secret} happens only at {@code save()} time, which this test never
 * calls). This keeps the test fast and free of the plugin-test harness.
 *
 * <h2>Red → green note</h2>
 * <p>No defect was caught here (green on first run) — the value is pinning the
 * gate's key predicate before the gate exists, so Task 7 can trust the boolean
 * contract instead of re-deriving "enrolled" from raw fields. Recorded honestly
 * per AGENTS.md; a red phase is not backfilled.
 */
class MfaUserPropertyTest {

  /**
   * WHAT: the gate's enrollment predicate — default state.
   * <p>BDD:
   * <pre>
   * GIVEN a freshly constructed MfaUserProperty with no factors enrolled
   * WHEN  isMfaEnabled() is queried
   * THEN  it returns false — an unenrolled user is not yet subject to MFA
   * </pre>
   * <p>WHY/SOLVES: under policy REQUIRED, a false positive here locks out every
   * user (including service accounts) who has never enrolled — a hard outage.
   * This is the "safe default is open" half of the predicate.
   */
  @Test
  void unenrolledDefaultIsNotMfaEnabled() {
    MfaUserProperty p = new MfaUserProperty();
    assertFalse(p.isMfaEnabled());
  }

  /**
   * WHAT: enrollment via the TOTP factor is detected.
   * <p>BDD:
   * <pre>
   * GIVEN a fresh property
   * WHEN  a non-empty TOTP secret is set (setTotpSecret)
   * THEN  isMfaEnabled() returns true and the secret round-trips via the getter
   * </pre>
   * <p>WHY/SOLVES: enrolling TOTP is the primary path; the gate depends on the
   * boolean flipping true the moment a real seed exists. Round-trip confirms
   * the data-bound setter stored the exact {@link Secret} the gate will later
   * call {@code getPlainText()} on for verification.
   */
  @Test
  void totpEnrolmentEnablesMfa() {
    MfaUserProperty p = new MfaUserProperty();
    p.setTotpSecret(Secret.fromString("JBSWY3DPEHPK3PXP"));
    assertTrue(p.isMfaEnabled());
    assertEquals("JBSWY3DPEHPK3PXP", p.getTotpSecret().getPlainText());
  }

  /**
   * WHAT: enrollment via the email factor alone is detected.
   * <p>BDD:
   * <pre>
   * GIVEN a fresh property
   * WHEN  a non-blank registered email is set (setRegisteredEmail) and no TOTP is
   *       enrolled
   * THEN  isMfaEnabled() returns true even though the TOTP secret is still null
   * </pre>
   * <p>WHY/SOLVES: a user may have <em>only</em> the email factor (e.g. no
   * authenticator app). The gate must count that as enrolled or such a user
   * would silently bypass MFA. Asserting {@code getTotpSecret()==null} guards
   * against the boolean being true "by accident" from the TOTP branch.
   */
  @Test
  void emailEnrolmentAloneEnablesMfa() {
    MfaUserProperty p = new MfaUserProperty();
    p.setRegisteredEmail("mads@devcru.org");
    assertTrue(p.isMfaEnabled());
    assertNull(p.getTotpSecret());
  }

  /**
   * WHAT: empty/whitespace values do <em>not</em> count as enrolled.
   * <p>BDD:
   * <pre>
   * GIVEN a property whose TOTP secret is empty plaintext and whose email is
   *       blank or all-whitespace
   * WHEN  isMfaEnabled() is queried
   * THEN  it returns false — no real factor exists
   * </pre>
   * <p>WHY/SOLVES: form binding can yield empty strings and whitespace rather
   * than null (an untouched text field submits ""). Treating those as enrolled
   * reproduces the lockout outage from the previous test; treating a whitespace
   * email as a delivery target would also make Task 3 try to "send" to
   * "   ". Both are pinned to unenrolled here.
   */
  @Test
  void emptyAndBlankFactorsDoNotEnableMfa() {
    MfaUserProperty p = new MfaUserProperty();
    p.setTotpSecret(Secret.fromString(""));
    p.setRegisteredEmail("   ");
    assertFalse(p.isMfaEnabled());

    MfaUserProperty noTotp = new MfaUserProperty();
    noTotp.setRegisteredEmail("");
    assertFalse(noTotp.isMfaEnabled());
  }

  /**
   * WHAT: server-managed trust/telemetry fields — defaults and round-trip.
   * <p>BDD:
   * <pre>
   * GIVEN a fresh property
   * WHEN  trustedUntilMs / lastVerifiedFactor / failedAttemptStreak are read
   *       they default to 0 / 0 / 0 (not trusted, no telemetry)
   * WHEN  each is then set to a non-zero value
   *       the matching getter returns that value exactly
   * </pre>
   * <p>WHY/SOLVES: the gate (Task 7) persists device trust in
   * {@code trustedUntilMs} and the RateLimiter reads/writes the attempt
   * counters — both need a reliable persist-then-reread contract (here
   * simulated as set→get; the same round-trip that XStream performs at
   * save/load). Defaults of 0 pin "not yet trusted" so a freshly created
   * property never confers trust.
   */
  @Test
  void serverManagedStateDefaultsAndRoundTrips() {
    MfaUserProperty p = new MfaUserProperty();
    assertEquals(0L, p.getTrustedUntilMs());
    assertEquals(0L, p.getLastVerifiedFactor());
    assertEquals(0, p.getFailedAttemptStreak());

    p.setTrustedUntilMs(999_999_999_999L);
    p.setLastVerifiedFactor(1L);
    p.setFailedAttemptStreak(3);
    assertEquals(999_999_999_999L, p.getTrustedUntilMs());
    assertEquals(1L, p.getLastVerifiedFactor());
    assertEquals(3, p.getFailedAttemptStreak());
  }
}
