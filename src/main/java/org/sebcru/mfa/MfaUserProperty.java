package org.sebcru.mfa;

import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import hudson.model.userproperty.UserPropertyCategory;
import hudson.security.csrf.CrumbIssuer;
import hudson.util.Secret;
import java.io.IOException;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest2;

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
 * narrowed to the ONE <em>user-facing factor</em> field that config
 * binding is safe for: {@link #setRegisteredEmail} (a delivery address,
 * bound by core's {@code configSubmit}). {@code trustedUntilMs},
 * {@code lastVerifiedFactor}, {@code failedAttemptStreak}, and the
 * email-code state ({@code pendingCodeHash}/{@code codeIssuedAt}/
 * {@code lastResendAt}) are <strong>server-managed</strong> trust /
 * telemetry / secret state: if they were data-bound, the user's
 * security-profile form could forge a 30-day trust expiry, zero out the
 * attempt counter, or submit a crafted pending hash. They are exposed as
 * plain getters/setters for the gate, the RateLimiter, and
 * {@code EmailCodeIssuer} to use, but are not reachable
 * by form binding.
 *
 * <p><strong>The TOTP seed is NOT data-bound at all (A23 fix, 2026-08-20).</strong>
 * {@link #setTotpSecret} used to carry {@code @DataBoundSetter}; that was
 * removed. The seed is committed by exactly one path —
 * {@code MfaController.postEnrollConfirm} through the
 * {@code confirmEnrollDecision} seam, after the candidate code is proven —
 * and config binding (core's {@code configSubmit}, which binds a user's
 * security section) would otherwise be a second, code-less,
 * gate-exempt path for writing a TOTP seed. With the setter as a plain
 * method, the enrolment/confirm path is the ONLY writer, by construction,
 * not by convention.
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
  /** Hash of the currently pending email code; null = none pending. */
  private Secret pendingCodeHash;
  /** Epoch ms the pending email code was issued; 0 = none pending. */
  private long codeIssuedAt;
  /** Epoch ms of the last code issue/resend (drives the resend cooldown). */
  private long lastResendAt;

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

  /** @return true iff the TOTP factor is enrolled (a non-empty seed exists). */
  public boolean hasTotpFactor() {
    return totpSecret != null && !totpSecret.getPlainText().isEmpty();
  }

  /** @return true iff the email factor is enrolled (a non-blank register
   *  address exists). The controller's factor-selection logic and the page's
   *  "use email code" affordance both key off this, so "email enrolled" has
   *  one definition in this class, not one per caller. */
  public boolean hasEmailFactor() {
    return registeredEmail != null && !registeredEmail.isBlank();
  }

  // ---- TOTP factor (user-facing) ----

  public Secret getTotpSecret() {
    return totpSecret;
  }

  /**
   * A23: NOT {@code @DataBoundSetter} — deliberately removed 2026-08-20.
   * The only caller that writes the seed is
   * {@code MfaController.confirmEnrollDecision} (via the
   * {@code postEnrollConfirm} endpoint, after the candidate code is
   * proven). See the class-level "Data-binding scope" note for why config
   * binding is not allowed to write a TOTP seed.
   */
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

  // ---- Email one-time-code state (server-managed, NOT data-bound) ----

  public Secret getPendingCodeHash() {
    return pendingCodeHash;
  }

  /** Server-managed: written by {@code EmailCodeIssuer} (issue/resend) only. */
  public void setPendingCodeHash(Secret pendingCodeHash) {
    this.pendingCodeHash = pendingCodeHash;
  }

  public long getCodeIssuedAt() {
    return codeIssuedAt;
  }

  public void setCodeIssuedAt(long codeIssuedAt) {
    this.codeIssuedAt = codeIssuedAt;
  }

  public long getLastResendAt() {
    return lastResendAt;
  }

  public void setLastResendAt(long lastResendAt) {
    this.lastResendAt = lastResendAt;
  }

  // ---------------------------------------------------------------------
  // Task 9 — the security-tab section render model.
  //
  // Only PRESENTATION-of-the-property helpers live here, and only
  // null-safe ones: a FRESH user's security tab binds instance=null (they
  // have not yet enrolled a factor, so no MfaUserProperty exists), and the
  // section must still render for them — an NPE here is exactly the
  // "empty section, green build, the QR never works" silent failure the IT's
  // render-presence case guards. The request-scoped helpers the section's
  // JS needs (crumb field/value, the /mfa/ endpoint base) live on
  // DescriptorImpl instead: the descriptor is bound as it in the section's
  // include (see core's UserPropertyCategory*Action views) and is ALWAYS
  // non-null, so the section can reach them without ever touching a null
  // instance.
  // ---------------------------------------------------------------------

  /** Masked registered mailbox for display (e.g. {@code m***@devcru.org}). Empty — not null — when not enrolled. */
  public String getMaskedRegisteredEmail() {
    if (registeredEmail == null || registeredEmail.isBlank()) {
      return "";
    }
    int at = registeredEmail.indexOf('@');
    if (at < 1) {
      return registeredEmail.charAt(0) + "***";
    }
    String local = registeredEmail.substring(0, at);
    String domain = registeredEmail.substring(at);
    return local.charAt(0) + "***" + domain;
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

    // -- Task 9 section render model (descriptor-bound, always non-null) --

    /**
     * The CSRF crumb field name — core policy, delegated to
     * {@link hudson.Functions#getCrumbRequestField()} (the same core static
     * the login page's {@code MfaController.getCrumbField()} uses, so crumb
     * policy stays in core across both pages). Null-safe for the pre-boot
     * call path (falls back to the core default name).
     */
    public String getMfaCrumbField() {
      try {
        return hudson.Functions.getCrumbRequestField();
      } catch (RuntimeException e) {
        return CrumbIssuer.DEFAULT_CRUMB_NAME;
      }
    }

    /**
     * The current request's CSRF crumb value — delegated to
     * {@link hudson.Functions#getCrumb(StaplerRequest2)} (the same core call
     * the login page makes). "" when no crumb can be issued (the section's
     * JS then refuses POSTs rather than sending a crumb-less request,
     * matching the login page). The factor-management POSTs (postEnroll,
     * postEnrollConfirm, …) ride this crumb — the endpoints are crumb-checked
     * by core via {@code @RequirePOST}, exactly as postVerify/postResendEmail
     * are on the login page.
     */
    public String getMfaCrumbValue() {
      try {
        StaplerRequest2 req2 = org.kohsuke.stapler.Stapler.getCurrentRequest2();
        if (req2 == null) {
          return "";
        }
        String crumb = hudson.Functions.getCrumb(req2);
        return crumb == null ? "" : crumb;
      } catch (RuntimeException e) {
        return "";
      }
    }

    /**
     * The section's factor-management endpoint base — {@code <root>/mfa/}
     * with a trailing slash, so the section's JS appends an endpoint name to
     * reach {@code <root>/mfa/postEnroll} etc. The security tab lives at
     * {@code <root>/user/<id>/security/}, so a <em>relative</em> endpoint
     * URL from it would 404; this makes the base absolute. Delegated to
     * {@link hudson.model.Jenkins#getRootUrl()} (core policy). Falls back to
     * the context-relative {@code "mfa/"} if the root URL is not yet
     * determined (pre-boot), which is still correct under a real host.
     */
    public String getMfaBaseUrl() {
      try {
        String root = jenkins.model.Jenkins.get().getRootUrl();
        if (root == null) {
          return "mfa/";
        }
        String b = root.endsWith("/") ? root : root + "/";
        return b + "mfa/";
      } catch (RuntimeException e) {
        return "mfa/";
      }
    }

    @Override
    public MfaUserProperty newInstance(User u) {
      return new MfaUserProperty();
    }
  }
}
