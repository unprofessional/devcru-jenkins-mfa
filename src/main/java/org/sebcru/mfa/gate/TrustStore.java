package org.sebcru.mfa.gate;

import org.sebcru.mfa.DevcruMfaConfig;
import org.sebcru.mfa.MfaUserProperty;

/**
 * Remembered-device ("remember me") trust for the MFA gate.
 *
 * <p>The policy: a successful MFA check marks the user's trust as valid
 * until {@code now + max(rememberForHours, trustMinHours)}. Nothing below
 * the floor is ever granted, no matter what the admin configured the
 * remember window to, so "remember for 1 h" cannot silently degrade a
 * user's security posture. The floor is enforced in exactly one place —
 * here — so the Task 7 filter, the Task 9 "revoke remembered devices"
 * button, and the admin-recovery path all share one definition of "how
 * long a trust lasts."
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
