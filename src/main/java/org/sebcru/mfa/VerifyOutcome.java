package org.sebcru.mfa;

import net.sf.json.JSONObject;

/**
 * The machine-shaped result of an MFA endpoint — the exact JSON
 * {@code MfaController} writes for {@code postVerify} / {@code postResendEmail},
 * and the shape the page's JavaScript (and Task 8's integration test) parse.
 *
 * <p>Kept as a plain, Jenkins-free value type next to the controller's pure
 * seams so it is unit-testable in a plain JVM: a success is
 * {@code {ok:true, rememberHours, redirect}}; a failure is
 * {@code {ok:false, error}} with an optional {@code retrySeconds}; a locked
 * response is {@code {ok:false, error:"locked", retrySeconds}}; a resend
 * succeeds as {@code {ok:true, "resent":true, cooldown}} and stays
 * distinguishable from a verify success (the client does different things:
 * navigate on verify, start a countdown on resend).
 *
 * <h2>Why the redirect lives here, not in JS</h2>
 * <p>{@code redirect} is already the <em>validated</em> target, produced by
 * {@link MfaController#resolveRedirectTarget(...)}. The JS must navigate only
 * to this field, never to the raw {@code Referer} — that is what makes
 * "no dead redirect / no open redirect" hold end to end. Pinning the field
 * names here in one test is the seam that keeps the client and server
 * agreeing on the contract.
 */
public final class VerifyOutcome {

  /** Stable error codes (the only user-facing strings on failure). */
  public static final String ERR_WRONG_CODE = "wrong_code";
  public static final String ERR_NO_PENDING = "no_pending_code";
  public static final String ERR_EXPIRED = "expired";
  public static final String ERR_LOCKED = "locked";
  public static final String ERR_COOLDOWN = "resend_cooldown";
  public static final String ERR_EMAIL_NOT_ENROLLED = "email_not_enrolled";
  public static final String ERR_NOT_ENROLLED = "not_enrolled";
  public static final String ERR_NOT_AUTHENTICATED = "not_authenticated";
  /**
   * A23 (2026-08-20): the six factor-management endpoints deny a session that
   * has not proven a second factor — enrolled, but neither verified this
   * session nor holding live remembered trust. The stable reason the 403
   * carries; the UI maps it to "complete verification first."
   */
  public static final String ERR_VERIFICATION_REQUIRED = "verification_required";
  /**
   * A22-b: the admin factor-management surface denies a session whose actor
   * has not proven a second factor — the admin surface's A23-analogue
   * (the actor may even be ADMINISTER, but a password-only admin must not
   * clear another user's factors). Carried by the 403 the controller
   * answers; the UI maps it to "verify first, then reload."
   */
  public static final String ERR_ADMIN_VERIFICATION_REQUIRED = "admin_verification_required";
  /**
   * A22-b: an admin posting against their OWN user id through the admin
   * surface — the load-bearing self-management prohibition (a password-only
   * admin stripping their own factors through the admin endpoint is A23's
   * hole one endpoint to the left). Self-service has its own endpoints.
   */
  public static final String ERR_ADMIN_SELF_MANAGEMENT = "admin_self_management_forbidden";
  /**
   * A22-b: the typed-user-id confirmation failed — the {@code confirmUserId}
   * field did not match the named target (the server-side half of the
   * page's type-to-confirm dialog; ruling 5).
   */
  public static final String ERR_ADMIN_CONFIRM = "admin_confirm_required";
  /**
   * The actor is not an ADMINISTER holder — the PERMISSION axis of A22-b
   * (spec §4). Deliberately distinct from {@link #ERR_ADMIN_VERIFICATION_
   * REQUIRED} (the CREDENTIAL axis: verified-or-trusted): a fully-verified
   * non-admin is denied on permission, not credential, so the two failure
   * modes stay tellable at the wire and in the log.
   */
  public static final String ERR_ADMIN_PERMISSION = "admin_permission_required";
  public static final String ERR_SERVER = "server_error";
  /**
   * The mutation committed in memory but {@code User.save()} threw — the
   * factor/trust is live for THIS session and will be LOST on restart.
   * Reported honestly to the client (landmine fix, 2026-08-22: the old code
   * swallowed the IOException and answered ok).
   */
  public static final String ERR_PERSISTENCE = "persistence_failed";
  /**
   * A24: the named admin-verb target does not exist (never created by lookup
   * — the read plane stays get-only).
   */
  public static final String ERR_USER_NOT_FOUND = "user_not_found";
  /**
   * A24: force-enrol refused because the target already carries a live,
   * self-service-enrolled factor state (ordinary enrolment). Recovery and
   * correction verbs keep their own contracts; force-enrol is not one.
   */
  public static final String ERR_ALREADY_ENROLLED = "already_enrolled";
  /**
   * A24: the supplied mailbox is blank or not a syntactically valid address.
   * Blank is refused deliberately: writing a blank mailbox would silently
   * un-enrol the user, which is clearFactors' single-writer job.
   */
  public static final String ERR_INVALID_EMAIL = "invalid_email";
  /**
   * A24 (D6): the target's realm state positively says DISABLED — visible in
   * the roster with its indicator, but force-enrol is refused (a disabled
   * account cannot complete setup, so enrolment would only strand it).
   */
  public static final String ERR_USER_DISABLED = "user_disabled";
  /**
   * A24 (D12): exempt users stay visible and labelled but their force action
   * is disabled; A24 governs interactive browser access and says so honestly.
   */
  public static final String ERR_USER_EXEMPT = "user_exempt";

  private final boolean ok;
  private final String error;          // null on success
  private final Long retrySeconds;     // nullable — present on locked / cooldown
  private final Long rememberHours;    // verify success only
  private final String redirect;       // verify success only
  private final boolean resent;        // resend success only
  private final Long cooldownSeconds;  // resend success only

  private VerifyOutcome(boolean ok, String error, Long retrySeconds,
                        Long rememberHours, String redirect, boolean resent, Long cooldownSeconds) {
    this.ok = ok;
    this.error = error;
    this.retrySeconds = retrySeconds;
    this.rememberHours = rememberHours;
    this.redirect = redirect;
    this.resent = resent;
    this.cooldownSeconds = cooldownSeconds;
  }

  /** A successful verification, remembered for {@code rememberHours}. */
  public static VerifyOutcome ok(long rememberHours, String redirect) {
    return new VerifyOutcome(true, null, null, rememberHours, redirect, false, null);
  }

  /** A failed verification with a stable reason (counts toward lockout). */
  public static VerifyOutcome fail(String error) {
    return new VerifyOutcome(false, error, null, null, null, false, null);
  }

  /** A live lockout: the user is told to retry in {@code retrySeconds}. */
  public static VerifyOutcome locked(long retrySeconds) {
    return new VerifyOutcome(false, ERR_LOCKED, retrySeconds, null, null, false, null);
  }

  /** A successful resend: the new code is on its way, resend cools down. */
  public static VerifyOutcome resent(long cooldownSeconds) {
    return new VerifyOutcome(true, null, null, null, null, true, cooldownSeconds);
  }

  /** Attach a countdown to a failure (used by the resend cooldown path). */
  public VerifyOutcome withRetrySeconds(long seconds) {
    return new VerifyOutcome(ok, error, seconds, rememberHours, redirect, resent, cooldownSeconds);
  }

  /**
   * The canonical JSON body. Field presence, not just values, is part of the
   * contract: failure responses omit {@code rememberHours}/{@code redirect};
   * success responses omit {@code error}. {@code net.sf.json} omits nulls, so
   * the shape is exactly the fields that are set.
   */
  public JSONObject toJSONObject() {
    JSONObject j = new JSONObject();
    j.put("ok", ok);
    if (error != null) {
      j.put("error", error);
    }
    if (retrySeconds != null) {
      j.put("retrySeconds", retrySeconds);
    }
    if (rememberHours != null) {
      j.put("rememberHours", rememberHours);
    }
    if (redirect != null) {
      j.put("redirect", redirect);
    }
    if (resent) {
      j.put("resent", true);
    }
    if (cooldownSeconds != null) {
      j.put("cooldown", cooldownSeconds);
    }
    return j;
  }
}
