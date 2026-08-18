package org.sebcru.mfa;

/**
 * Admin-configurable knobs for the gate, as a plain, time-testable POJO.
 *
 * <p>This is the <em>shape</em> of the plan's {@code DevcruMfaConfig}. Task 5
 * turns it into a Jenkins {@code GlobalConfiguration}
 * ({@code @Extension @Symbol("devcruMfa")}, config.jelly, {@code bindJSON}
 * persistence) and adds the UI-only knobs (issuer, TOTP window, email TTL,
 * resend cooldown, exempt-users). Task 4's {@code TrustStore} and
 * {@code RateLimiter} depend on the config object, not on Jenkins, so the
 * gate's two brains stay unit-testable in the JVM with no Jenkins harness.
 *
 * <p>Defaults come from the plan's §defaults table — they are the
 * documented, accepted values (mads signed the "trustMinHours: never below
 * this" floor), not implementation choices. Do not re-litigate them here.
 */
public final class DevcruMfaConfig {

  /** Gate policy. Task 7's filter treats OFF as the kill-switch path. */
  public enum Policy { OFF, REQUIRED }

  private static volatile DevcruMfaConfig instance = new DevcruMfaConfig();

  public static DevcruMfaConfig get() {
    return instance;
  }

  /** Test seam: reset the singleton so each unit test starts from defaults. */
  public static void setForTest(DevcruMfaConfig c) {
    instance = c == null ? new DevcruMfaConfig() : c;
  }

  private Policy policy = Policy.REQUIRED;
  /** Trust window after a successful MFA; default 30 days. */
  private int rememberForHours = 720;
  /** Policy floor — trust is never granted below this. mads: never below. */
  private int trustMinHours = 24;
  /** Failed attempts tolerated inside the window before lockout. */
  private int maxAttempts = 5;
  /** Sliding window over which failures accumulate. */
  private int attemptWindowMinutes = 30;
  /** Lockout duration after maxAttempts is reached. */
  private int lockoutMinutes = 15;

  public Policy getPolicy() {
    return policy;
  }

  public void setPolicy(Policy policy) {
    this.policy = policy;
  }

  public int getRememberForHours() {
    return rememberForHours;
  }

  public void setRememberForHours(int rememberForHours) {
    this.rememberForHours = rememberForHours;
  }

  public int getTrustMinHours() {
    return trustMinHours;
  }

  public void setTrustMinHours(int trustMinHours) {
    this.trustMinHours = trustMinHours;
  }

  public int getMaxAttempts() {
    return maxAttempts;
  }

  public void setMaxAttempts(int maxAttempts) {
    this.maxAttempts = maxAttempts;
  }

  public int getAttemptWindowMinutes() {
    return attemptWindowMinutes;
  }

  public void setAttemptWindowMinutes(int attemptWindowMinutes) {
    this.attemptWindowMinutes = attemptWindowMinutes;
  }

  public int getLockoutMinutes() {
    return lockoutMinutes;
  }

  public void setLockoutMinutes(int lockoutMinutes) {
    this.lockoutMinutes = lockoutMinutes;
  }
}
