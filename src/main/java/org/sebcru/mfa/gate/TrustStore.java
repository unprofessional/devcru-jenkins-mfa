package org.sebcru.mfa.gate;

import org.sebcru.mfa.DevcruMfaConfig;
import org.sebcru.mfa.MfaUserProperty;

/**
 * Remembered-device ("remember me") trust for the MFA gate.
 *
 * <p>The policy: a successful MFA check marks the user's trust as valid
 * until {@code now + max(rememberForHours, trustMinHours)}. This is the
 * <em>grant-time</em> enforcement of the trust floor: whatever the admin
 * set the remember window to, it is never granted below {@code
 * trustMinHours}. A <em>second</em> layer (added in Task 5, in
 * {@code DevcruMfaConfig#configure()}) clamps the {@code trustMinHours}
 * knob itself to at least 24 h at save time, so the admin's UI cannot
 * lower the floor knob below the plan's signed minimum. Together the two
 * layers mean: a successful MFA never grants trust below 24 h under
 * normal admin operation, and the "remember for 1 h" knob cannot silently
 * degrade a user's security posture. (A config.xml edit that bypasses the
 * UI to set {@code trustMinHours < 24} would still be limited by the
 * grant-time max() to whatever the admin-set value is — a defence-in-depth
 * limitation, not a gap in the normal admin path.)
 *
 * <p>This is the canonical "how long does a trust last" arithmetic. The
 * Task 7 filter, the Task 9 "revoke remembered devices" button, and the
 * admin-recovery path all share one definition — there is no per-request
 * expiry of an active session (the exact UX sin of the old plugin).
 *
 * <p>All methods take an explicit {@code now} (ms epoch). There is no
 * hidden {@code System.currentTimeMillis()} call anywhere in this class,
 * which is what lets the unit tests pin the trust window exactly — no
 * wall-clock flake, no "sometimes fails when run at midnight" tests.
 */
public final class TrustStore {

  private static final long HOUR_MS = 3_600_000L;

  /**
   * @return true iff the user's trust record is currently live. A trust
   *         stamped exactly at {@code now} is already expired (strict
   *         &gt;, matching "valid until, not including that instant").
   */
  public boolean isTrusted(MfaUserProperty p, DevcruMfaConfig cfg, long now) {
    return p.getTrustedUntilMs() > now;
  }

  /**
   * Grant trust for {@code max(rememberForHours, trustMinHours)} from
   * {@code now}. A null config falls back to the plan defaults.
   */
  public void trust(MfaUserProperty p, DevcruMfaConfig cfg, long now) {
    long hours = Math.max(hours(cfg), floor(cfg));
    p.setTrustedUntilMs(now + hours * HOUR_MS);
  }

  /**
   * Kill trust immediately.
   *
   * <p>Used by the Task 9 profile page's "Revoke remembered devices"
   * button and by the admin recovery path (plan's security decision 7:
   * clear the user's factor state, re-enroll). Not used for
   * account-lockout; that's the RateLimiter's job.
   */
  public void revoke(MfaUserProperty p) {
    p.setTrustedUntilMs(0L);
  }

  /** The effective trust window in hours, floor applied. Exposed for the
   *   controller to report "you'll be remembered for N hours" in the
   *   post-verify JSON response, so the UI and the code agree on one
   *   number rather than each doing its own arithmetic. */
  public long effectiveTrustHours(DevcruMfaConfig cfg) {
    return Math.max(hours(cfg), floor(cfg));
  }

  private static int hours(DevcruMfaConfig cfg) {
    return cfg == null ? 720 : cfg.getRememberForHours();
  }

  private static int floor(DevcruMfaConfig cfg) {
    return cfg == null ? 24 : cfg.getTrustMinHours();
  }
}
