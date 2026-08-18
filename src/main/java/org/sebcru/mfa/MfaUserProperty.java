package org.sebcru.mfa;

import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import hudson.model.userproperty.UserPropertyCategory;
import hudson.util.Secret;
import java.io.IOException;
import org.kohsuke.stapler.DataBoundSetter;

/**
 * Per-user MFA factor state, persisted as a Jenkins {@link UserProperty}.
 *
 * <p>This is the single source of truth the gate (Task 7) and the
 * controller (Task 6) read and write a user's MFA posture from: which
 * factors are enrolled, when the current device is trusted, and a few
 * telemetry counters. It is deliberately dumb storage + one query — all
 * policy (trust floor, lockout window) lives in {@code DevcruMfaConfig}
 * (Task 5), and time-based enforcement lives in the gate/RateLimiter.
 *
 * <h2>Confidentiality-at-rest</h2>
 * <p>{@link Secret} fields are XStream-serialized as Jenkins {@code <Secret>}
 * values, which the master key encrypts at rest — the enrolled TOTP seed and
 * the per-user email-code HMAC key are never written to {@code config.xml}
 * in plaintext. The registered email is stored as-is (it is not a credential,
 * only a delivery address, so plaintext is acceptable and grep-able for
 * admins investigating lockouts).
 *
 * <h2>Data-binding scope (a deliberate refinement of the plan)</h2>
 * <p>The plan suggested {@code @DataBoundSetter} on every field. That was
 * narrowed to the two <em>user-facing factor</em> fields only
 * ({@link #setTotpSecret}, {@link #setRegisteredEmail}). The remaining
 * fields ({@code trustedUntilMs}, {@code lastVerifiedFactor},
 * {@code failedAttemptStreak}) are <strong>server-managed</strong> trust /
 * telemetry state: if they were data-bound, the user's security-profile form
 * could forge a 30-day trust expiry or zero out the attempt counter by
 * submitting a crafted page. They are exposed as plain getters/setters for
 * the gate and the RateLimiter to use, but are not reachable from form
 * binding.
 */
public class MfaUserProperty extends UserProperty {

  /** Enrolled TOTP seed (canonical unpadded Base32), Secret-encrypted at rest. */
  private Secret totpSecret;
  /** Per-user HMAC key for email one-time codes, Secret-encrypted at rest. */
  private Secret emailCodeSecret;
  /** Target address for email codes; null/blank = email factor not enrolled. */
  private String registeredEmail;
  /** Epoch ms until which this session/device is MFA-trusted; 0 = not trusted. */
  private long trustedUntilMs;
  /** Which factor last verified: 0 = totp, 1 = email. Telemetry only. */
  private long lastVerifiedFactor;
  /** Consecutive failures, for UI display; the real limit lives in RateLimiter. */
  private int failedAttemptStreak;

  /** No-arg constructor for XStream deserialization and direct construction. */
  public MfaUserProperty() {
    super();
  }

  /** Fetch the property for {@code u}, creating and attaching it if absent. */
  public static MfaUserProperty getOrCreate(User u) throws IOException {
    MfaUserProperty p = u.getProperty(MfaUserProperty.class);
    if (p == null) {
      p = new MfaUserProperty();
      u.addProperty(p);
    }
    return p;
  }

  /**
   * @return true iff the user has enrolled at least one MFA factor — a
   *         non-empty TOTP secret or a non-blank registered email. This is the
   *         predicate the gate keys its "mandatory vs exempt" decision on
   *         (policy {@code REQUIRED}: enrolled users must MFA, unenrolled may
   *         log in without it).
   */
  public boolean isMfaEnabled() {
    boolean totpEnrolled = totpSecret != null && !totpSecret.getPlainText().isEmpty();
    if (totpEnrolled) {
      return true;
    }
    return registeredEmail != null && !registeredEmail.isBlank();
  }

  // ---- TOTP factor (user-facing) ----

  public Secret getTotpSecret() {
    return totpSecret;
  }

  @DataBoundSetter
  public void setTotpSecret(Secret totpSecret) {
    this.totpSecret = totpSecret;
  }

  // ---- Email factor (user-facing address; HMAC key is server-managed) ----

  public String getRegisteredEmail() {
    return registeredEmail;
  }

  @DataBoundSetter
  public void setRegisteredEmail(String registeredEmail) {
    this.registeredEmail = registeredEmail;
  }

  public Secret getEmailCodeSecret() {
    return emailCodeSecret;
  }

  /** Server-managed: set by Task 3 when the email factor is first enrolled. */
  public void setEmailCodeSecret(Secret emailCodeSecret) {
    this.emailCodeSecret = emailCodeSecret;
  }

  // ---- Server-managed trust + telemetry (NOT data-bound) ----

  public long getTrustedUntilMs() {
    return trustedUntilMs;
  }

  public void setTrustedUntilMs(long trustedUntilMs) {
    this.trustedUntilMs = trustedUntilMs;
  }

  public long getLastVerifiedFactor() {
    return lastVerifiedFactor;
  }

  public void setLastVerifiedFactor(long lastVerifiedFactor) {
    this.lastVerifiedFactor = lastVerifiedFactor;
  }

  public int getFailedAttemptStreak() {
    return failedAttemptStreak;
  }

  public void setFailedAttemptStreak(int failedAttemptStreak) {
    this.failedAttemptStreak = failedAttemptStreak;
  }

  @Extension
  public static class DescriptorImpl extends UserPropertyDescriptor {
    public DescriptorImpl() {
      super(MfaUserProperty.class);
    }

    @Override
    public String getDisplayName() {
      return "MFA (Devcru)";
    }

    @Override
    public UserPropertyCategory getUserPropertyCategory() {
      return UserPropertyCategory.get(UserPropertyCategory.Security.class);
    }

    @Override
    public MfaUserProperty newInstance(User u) {
      return new MfaUserProperty();
    }
  }
}
