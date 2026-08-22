package org.sebcru.mfa;

import hudson.Extension;
import hudson.model.RootAction;
import hudson.model.User;
import hudson.security.csrf.CrumbIssuer;
import hudson.util.Secret;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Enumeration;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.StaplerResponse2;
import org.kohsuke.stapler.WebMethod;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.sebcru.mfa.crypto.Totp;
import org.sebcru.mfa.email.EmailCodeIssuer;
import org.sebcru.mfa.email.EmailSender;
import org.sebcru.mfa.email.JenkinsEmailSender;
import org.sebcru.mfa.gate.RateLimiter;
import org.sebcru.mfa.gate.TrustStore;

/**
 * The MFA login screen + its two POST endpoints — the single place a user
 * proves the second factor.
 *
 * <p>This is the plan's {@code MfaController} (Task 6). It mounts at the
 * stable Jenkins path
 * {@code <root>/mfa}: the gate filter (Task 7) 302s a
 * password-authenticated, still-MFA-unverified user here, the user types a
 * 6-digit TOTP or an 8-character email code, and on success the session is
 * marked MFA-verified and the user is redirected <em>back to where they
 * actually were</em> (a valid in-site URL) rather than to a dead/black page.
 *
 * <h2>The "no dead redirect" contract</h2>
 * <p>The whole reason to leave the SaaS plugin it replaces is that its
 * post-MFA redirect landed on deprecated/blank pages. Here the redirect
 * target is <strong>server-computed and validated</strong> by
 * {@link #resolveRedirectTarget(String, String, String, String)} from the
 * request's {@code ?redirect=} parameter — canonical, hand-off from the Task 7
 * gate (A3 ruling, mads 2026-08-18) — falling back to the {@code Referer}
 * header when the parameter is absent; anything cross-origin,
 * protocol-relative, missing, or pointing at a login/security path degrades
 * to the site root. The client JS never constructs its own target from the
 * raw {@code Referer} or the raw parameter —
 * it only navigates to the {@code redirect} field the server already vouched
 * for in the JSON response. That single seam is what makes the guarantee
 * hold, and it is the pure method the unit tests pin down (the parameter-over-
 * header precedence is pinned by {@code MfaControllerTest.resolveTargetPrefersCanonicalParameter});
 * the end-to-end pre-login round trip is pinned by Task 8's IT (A5).
 *
 * <h2>Three deliberate deviations from the plan sketch (flagged for review)</h2>
 * <ol>
 *   <li><b>{@code hudson.model.RootAction}, not
 *       {@code jenkins.model.GlobalAction}.</b> The plan's sketch
 *       {@code implements GlobalAction} predates this core layout:
 *       {@code jenkins.model.GlobalAction} does <em>not</em> exist in
 *       jenkins-core 2.528.3 (verified against the resolved artifact —
 *       same "plan named an old signature" family as Task 5's
 *       {@code jenkins.model.*} / {@code getCategory()} deltas and the
 *       dropped {@code @Symbol}). The in-core idiom for a top-level action is
 *       {@code RootAction} (a {@code @Extension}; {@code IdentityRootAction}
 *       in core implements it). {@link #getUrlName()} stays
 *       {@code "securityRealm/mfa"} exactly as the plan wants, so the URL is
 *       (unchanged until Task 8's Defect B moved it — see deviation 3).
 *       {@code RootAction} is <em>not</em>
 *       {@code UnprotectedRootAction}, so it remains behind authentication
 *       (the requirement).
 *   <li><b>{@code postResendEmail} takes <em>no</em> {@code dest}
 *       parameter.</b> The plan sketch had
 *       {@code postResendEmail(@QueryParameter String dest, …)}. That is an
 *       open mail-relay / address-injection oracle: the code is single-use
 *       but tied to a mailbox, and letting the requester steer it to an
 *       arbitrary address defeats the "codes only go to the registered
 *       mailbox" property the README's threat model relies on. The resend
 *       always goes to the user's own {@code getRegisteredEmail()}. The plan
 *       and this class disagree; this class follows the signed security
 *       decision (codes to the registered address, never an attacker point
 *       target) over the sketch.
 *   <li><b>The mount moved from {@code securityRealm/mfa} to
 *       {@code mfa} (Task 8, Defect B — mads-ruled 2026-08-19).</b> Tasks 1–7
 *       ran with the plan's path because every harness up to that point used
 *       the default test realm, which owns no node at {@code securityRealm}.
 *       The Task 8 end-to-end IT booted the production shape — a
 *       ModelObject-backed local realm (HPSR) with real password users — and
 *       the page 404'd: Stapler mounts the *active realm* at the top-level
 *       {@code securityRealm} node and it claims the whole prefix (decoded
 *       404 body: {@code No matching rule was found on
 *       hudson.security.HudsonPrivateSecurityRealm for \"/mfa\"}). On the
 *       live box — a local realm — every enrolled user's gate bounce would
 *       404, so this was production-blocking, not a harness artifact.
 *       {@code mfa} is a free single segment (no core mount, nothing a
 *       realm can squat), survives any realm shape, and the allow-list /
 *       {@code isSecurityPath} / unit pins / IT moved with it in the same
 *       commit. The plan's path sketch is superseded here; the rule this
 *       defect teaches — enumerate what core mounts at a planned top-level
 *       segment for every realm shape that can be live — is recorded in the
 *       Task 8 handoff.
 * </ol>
 *
 * <h2>Endpoint returns (plan sketch was debris)</h2>
 * <p>The plan's {@code postVerify(…FilePath return)} is sketch debris (a
 * {@code FilePath} return on a web endpoint is meaningless). Both endpoints
 * return {@code void} and write a JSON body straight to the response, using
 * core's {@code net.sf.json.JSONObject} — no new dependency. The response
 * response shape is the {@link VerifyOutcome} contract (field names pinned
 * by {@code MfaControllerTest}).
 *
 * <h2>Unit-testability seam (deliberate, documented)</h2>
 * <p>The security-relevant, <em>pure</em> logic is extracted to
 * package-private {@code static} methods so it is testable in a plain JVM with
 * no running Jenkins and no mail round trip — the same dependency-direction
 * discipline Tasks 3–5 used:
 * <ul>
 *   <li>{@link #resolveRedirectTarget(String, String, String, String)} —
 *       the no-dead-redirect / no-open-redirect validator.</li>
 *   <li>{@link #classifyFactor(String)} — which factor a submitted code's
 *       shape selects (6 digits ⇒ TOTP, 8 email-alphabet chars ⇒ email,
 *       else unknown), and therefore the attempt order.</li>
 *   <li>{@link #maskEmail(String)} — the registered address is shown on the
 *       page masked; the user must not be able to read a full mailbox off the
 *       MFA page before proving the factor.</li>
 *   <li>{@link VerifyOutcome#toJSONObject()} — the exact JSON the client JS
 *       (and Task 8's integration test) parse.</li>
 * </ul>
 * The endpoint <em>glue</em> (fetch the current user, call
 * {@code RateLimiter}/{@code TrustStore}/{@code EmailCodeIssuer}, regenerate
 * the session, write the response) is deliberately left to Task 8's
 * Jenkins-in-JVM integration test. It is not exercised by the plain-JVM unit
 * suite. Recorded deliberately, not backfilled.
 *
 * <h2>Time seam</h2>
 * <p>As in every gate class, the clock is explicit: production callers pass
 * {@code System.currentTimeMillis()}; there is no hidden clock in the pure
 * seams (they take no time at all — they are purely functional over strings).
 */
@Extension
public class MfaController implements RootAction {

  private static final Logger LOGGER =
      Logger.getLogger(MfaController.class.getName());

  /** Session attribute the Task 7 gate reads to know this session is MFA-verified. */
  static final String VERIFIED_ATTR = "org.sebcru.mfa.verified";

  /** One shared limiter for the whole process (the controller is a Jenkins singleton). */
  private final RateLimiter rateLimiter = new RateLimiter();
  /** Stateless trust arithmetic; one instance is fine. */
  private final TrustStore trustStore = new TrustStore();
  /** Stateless code issuer; the sender is what carries delivery. */
  private final EmailCodeIssuer emailIssuer = new EmailCodeIssuer();
  /**
   * Production delivery = Jenkins' standard Mailer (global SMTP config, the
   * same one that mails build results). Overridable in tests via
   * {@link #setSenderForTest} (Task 8 injects a {@code CaptureEmailSender}).
   */
  private EmailSender emailSender = new JenkinsEmailSender();

  // ---------------------------------------------------------------------
  // RootAction — mounts the page at <root>/mfa (moved from
  // <root>/securityRealm/mfa by Task 8's Defect B, see class doc), no
  // action-bar icon (getIconFileName() null), still behind authentication.
  // ---------------------------------------------------------------------

  @Override
  public String getIconFileName() {
    return null;
  }

  @Override
  public String getDisplayName() {
    return "MFA";
  }

  @Override
  public String getUrlName() {
    // Stable, current-core path (see class doc, deviation 3): a free single
    // segment nothing in core or in any realm shape occupies.
    return "mfa";
  }

  // ---------------------------------------------------------------------
  // Read-only page model (index.jelly binds to these via ${it.…}).
  // All null-safe: an anonymous / no-User access renders an empty page.
  // ---------------------------------------------------------------------

  /** The current authenticated user, or null (never throws). */
  private User currentUser() {
    // One definition of "who is in this request", shared with the gate
    // filter (A1: the filter and the controller must agree on the same user
    // and the same config, or the gate enforces against a different person
    // than the page the filter sent them to).
    return MfaFilter.findCurrentUser();
  }

  private MfaUserProperty propertyOrNull() {
    User u = currentUser();
    if (u == null) {
      return null;
    }
    try {
      return u.getProperty(MfaUserProperty.class);
    } catch (RuntimeException e) {
      return null;
    }
  }

  /** Masked registered address ("m***@devcru.org") or "" when no email factor. */
  public String getMaskedEmail() {
    MfaUserProperty p = propertyOrNull();
    if (p == null) {
      return "";
    }
    return maskEmail(p.getRegisteredEmail());
  }

  /** True when the email factor is enrolled (drives the "use email code" UI). */
  public boolean hasEmailFactor() {
    MfaUserProperty p = propertyOrNull();
    return p != null && p.hasEmailFactor();
  }

  /** True when the TOTP factor is enrolled. */
  public boolean hasTotpFactor() {
    MfaUserProperty p = propertyOrNull();
    return p != null && p.hasTotpFactor();
  }

  /** Issuer label shown in the authenticator app, for the page header. */
  public String getIssuer() {
    try {
      // A1: read the authoritative (descriptor) config, not the stale process
      // default — same source the gate filter reads, so the label a user sees
      // and the policy enforced agree on one live object.
      return DevcruMfaConfig.currentSafe().getIssuer();
    } catch (RuntimeException e) {
      return "Jenkins";
    }
  }

  /**
   * The CSRF crumb field name — core policy, delegated to {@link
   * hudson.Functions}, the same source core's own {@code login.jelly}
   * uses via {@code h.getCrumbRequestField()}. Returns null-safe for the
   * pre-boot call path (the page then renders no crumb and the POST is
   * rejected by core's filter — fail closed).
   */
  public String getCrumbField() {
    try {
      return hudson.Functions.getCrumbRequestField();
    } catch (RuntimeException e) {
      return CrumbIssuer.DEFAULT_CRUMB_NAME;
    }
  }

  /**
   * The current request's CSRF crumb value — core policy, delegated to
   * {@link hudson.Functions#getCrumb(StaplerRequest2)} (it resolves the
   * installed {@code CrumbIssuer} and issues per its settings). "" when
   * there is no request context; core's filter rejects a missing/blank
   * crumb, so the page degrades to login-refuses rather than to login
   * without CSRF protection.
   *
   * <p>Why in Java instead of the {@code h} taglib: the {@code h} variable
   * is only bound inside core's {@code <l:view>} wrapper, and this page is a
   * deliberately self-contained document. Calling the same static method
   * from the model keeps crumb policy in core while keeping the page
   * dependency-free.
   */
  public String getCrumbValue() {
    try {
      StaplerRequest2 req2 = Stapler.getCurrentRequest2();
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
   * The URL of this page's static JS file — {@code <root>/plugin/
   * devcru-mfa/mfa-gate.js}. Jenkins' CSP is {@code script-src 'self'}
   * (no 'unsafe-inline'), so the verify-form script cannot live inline in
   * index.jelly — it never executes there. Same fix, same incident
   * (2026-08-22) as the section's {@code mfa-section.js}: without it the
   * gate page renders but can never POST a code — an enrolment-time
   * lockout. A plain script tag with this URL is same-origin and CSP-clean;
   * the root-URL policy is core's ({@code Jenkins.getRootUrl()}), with the
   * context-relative fallback for pre-boot.
   */
  public String getGateScriptUrl() {
    try {
      String root = jenkins.model.Jenkins.get().getRootUrl();
      if (root == null) {
        return "plugin/devcru-mfa/mfa-gate.js";
      }
      String b = root.endsWith("/") ? root : root + "/";
      return b + "plugin/devcru-mfa/mfa-gate.js";
    } catch (RuntimeException e) {
      return "plugin/devcru-mfa/mfa-gate.js";
    }
  }

  // ---------------------------------------------------------------------
  // POST endpoints. Core's crumb filter + @RequirePOST guard them; this is
  // belt-and-suspenders on method, not on policy. The page embeds the hidden
  // crumb field from the Java model (getCrumbField()/getCrumbValue()), not
  // via the `h` taglib — the page is a self-contained document without an
  // <l:view> wrapper, where the `h` variable is unbound — but the model
  // calls the same core static (Functions.getCrumb), so crumb policy stays
  // in core.
  //
  // URL ROUTING (Task 8 Defect D, 2026-08-19): @RequirePOST is a *policy*
  // guard (it rejects non-POST) — it does NOT declare a dispatch token.
  // Stapler's dynamic-method dispatch only auto-maps get/is/do-prefixed
  // methods (plus @WebMethod), so a method named bare "postVerify" exposes
  // no URL token at all and <ctx>/mfa/postVerify 404'd — the booted-Jenkins
  // 404 body named it explicitly. @WebMethod(name="…") declares the exact
  // token the page's JS (postForm("postVerify")) and the plan already rely
  // on, keeping the contract while making it routable.
  // ---------------------------------------------------------------------

  /**
   * Verify the submitted second factor.
   *
   * <p>Order (the plan's "rate-limit check first"): lockout → factor
   * classification → factor verify (with fallback to the other enrolled
   * factor) → on success grant trust + regenerate + mark verified +
   * redirect; on failure record the failure and report the reason.
   *
   * <p>Glue for Task 8. The pure decisions it delegates to are unit-tested.
   */
  @RequirePOST
  @WebMethod(name = "postVerify")
  public void postVerify(StaplerRequest2 req, StaplerResponse2 rsp) throws IOException {
    User u = currentUser();
    if (u == null) {
      write(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_NOT_AUTHENTICATED));
      return;
    }
    MfaUserProperty p;
    try {
      p = MfaUserProperty.getOrCreate(u);
    } catch (IOException e) {
      write(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_SERVER));
      return;
    }
    DevcruMfaConfig cfg = DevcruMfaConfig.currentSafe();
    String name = u.getId();
    long now = System.currentTimeMillis();

    // 1. Lockout first — a probing attacker must not get to guess codes while
    //    a legitimate user's countdown is running (the RateLimiter's whole point).
    if (rateLimiter.isLocked(name, cfg, now)) {
      write(rsp, VerifyOutcome.locked(rateLimiter.retrySeconds(name, cfg, now)));
      return;
    }

    String submitted = req.getParameter("code");
    Factor f = classifyFactor(submitted);

    // 2. Attempt ordering: try the factor the input's shape selects; if the
    //    user hasn't enrolled that one, fall back to the other enrolled factor;
    //    if neither is enrolled, say so (no factor to check against).
    //    The email path mints the per-user HMAC key lazily (idempotent) inside
    //    verifyEmail/postResendEmail — only for users who actually have the
    //    email factor, so a TOTP-only account is never handed a key it has no
    //    use for.
    boolean verified = false;
    // A8: which factor actually PASSED (null until proven). Records the factor
    // that verified, not the shape submitted — a 6-digit-shaped input that
    // fell back to the email factor (or vice versa) records EMAIL/TOTP exactly.
    Factor proven = null;
    String failReason = VerifyOutcome.ERR_NOT_ENROLLED;
    switch (f) {
      case TOTP:
        if (p.hasTotpFactor()) {
          verified = verifyTotp(p, cfg, submitted, now);
          proven = verified ? Factor.TOTP : null;
          failReason = VerifyOutcome.ERR_WRONG_CODE;
        } else if (p.hasEmailFactor()) {
          EmailCodeIssuer.VerifyResult r = verifyEmail(p, cfg, submitted, now);
          verified = r == EmailCodeIssuer.VerifyResult.CONSUMED;
          proven = verified ? Factor.EMAIL : null;
          failReason = emailFailReason(r);
        }
        break;
      case EMAIL:
        if (p.hasEmailFactor()) {
          EmailCodeIssuer.VerifyResult r = verifyEmail(p, cfg, submitted, now);
          verified = r == EmailCodeIssuer.VerifyResult.CONSUMED;
          proven = verified ? Factor.EMAIL : null;
          failReason = emailFailReason(r);
        } else if (p.hasTotpFactor()) {
          verified = verifyTotp(p, cfg, submitted, now);
          proven = verified ? Factor.TOTP : null;
          failReason = VerifyOutcome.ERR_WRONG_CODE;
        }
        break;
      default:
        // Garbled / wrong-length input: not a valid code.
        verified = false;
        failReason = VerifyOutcome.ERR_WRONG_CODE;
    }

    if (verified) {
      // 3. Success: A7/A8 (mads ruling 2026-08-18) — the clear path resets
      //    the failure streak (consumed for display by the Task 9 profile
      //    section) and logs which factor was actually PROVEN (last-write
      //    log; a shape that fell back to the other enrolled factor records
      //    the factor that verified, not the shape submitted). Both persist
      //    on the exact u.save() below — no extra round trip.
      p.setFailedAttemptStreak(0);
      if (proven != null) {
        p.setLastVerifiedFactor(proven == Factor.EMAIL ? 1L : 0L);
      }
      // Grant trust (floor applied inside TrustStore), regenerate the session
      // to kill any fixated id, and mark it verified so the Task 7 gate passes
      // it.
      try {
        trustStore.trust(p, cfg, now);
        u.save();
      } catch (IOException e) {
        // The session attribute still authorises THIS session, so the user
        // is not stranded — but the trust + streak are lost on restart.
        // Loud, not silent (landmine fix 2026-08-22).
        LOGGER.log(Level.WARNING,
            "MFA verify succeeded but trust/streak failed to persist for user "
                + u.getId() + " — user re-verifies once after next restart", e);
      }
      rateLimiter.clear(name);
      regenerateVerified(req);
      long hours = trustStore.effectiveTrustHours(cfg);
      // A3 (mads ruling, 2026-08-18): the ?redirect= query parameter the gate
      // 302'd to (/mfa?redirect=…) is CANONICAL over Referer —
      // and for good reason: a browser POST of this form carries the MFA page's
      // OWN url as its Referer, so a Referer-only contract lands a verified
      // user back on the MFA page (immediate re-prompt loop). The parameter is
      // present on the GET that rendered the page; the form JS resubmits it
      // (index.jelly preserves it on the POST). Both inputs flow through the
      // one shared pure seam (MfaFilter.resolveTarget → resolveRedirectTarget),
      // not two shaped validators.
      String redirect = MfaFilter.resolveTarget(req.getParameter(MfaFilter.REDIRECT_PARAM),
          req.getHeader("Referer"), req.getServerName(),
          String.valueOf(req.getServerPort()), req.getContextPath());
      write(rsp, VerifyOutcome.ok(hours, redirect));
    } else {
      // 4. Failure: count it. The 5th in-window failure trips the lockout;
      //    the user is told the reason (never a stack trace / 500).
      rateLimiter.recordFailure(name, cfg, now);
      p.setFailedAttemptStreak(p.getFailedAttemptStreak() + 1);
      try {
        u.save();
      } catch (IOException e) {
        // Telemetry counter only — but an unpersisted streak means the
        // lockout can be evaded by a restart. Log it (landmine fix).
        LOGGER.log(Level.WARNING,
            "MFA failure-streak increment failed to persist for user "
                + u.getId() + " — lockout counter may reset on restart", e);
      }
      write(rsp, VerifyOutcome.fail(failReason));
    }
  }

  /**
   * Re-issue the email one-time code to the <em>registered</em> address only
   * (see class doc, deviation 2 — no {@code dest}).
   */
  @RequirePOST
  @WebMethod(name = "postResendEmail")
  public void postResendEmail(StaplerRequest2 req, StaplerResponse2 rsp) throws IOException {
    User u = currentUser();
    if (u == null) {
      write(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_NOT_AUTHENTICATED));
      return;
    }
    MfaUserProperty p;
    try {
      p = MfaUserProperty.getOrCreate(u);
    } catch (IOException e) {
      write(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_SERVER));
      return;
    }
    if (!p.hasEmailFactor()) {
      write(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_EMAIL_NOT_ENROLLED));
      return;
    }
    DevcruMfaConfig cfg = DevcruMfaConfig.currentSafe();
    long now = System.currentTimeMillis();
    long cooldownMs = (long) cfg.getEmailResendCooldownSeconds() * 1000L;
    long last = p.getLastResendAt();
    // Surface the remaining cooldown so the page can count down instead of
    // silently failing (matches the "at most one fresh code per minute" pin).
    if (last > 0 && now - last < cooldownMs) {
      long remainSec = (cooldownMs - (now - last)) / 1000L + 1L;
      write(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_COOLDOWN).withRetrySeconds(remainSec));
      return;
    }
    String perUserSecret = ensureEmailCodeSecret(p);
    String code = emailIssuer.resend(p, perUserSecret, now,
        cfg.getEmailResendCooldownSeconds(), cfg.getEmailCodeTtlSeconds(), emailSender);
    if (code == null) {
      write(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_COOLDOWN)
          .withRetrySeconds(cfg.getEmailResendCooldownSeconds()));
      return;
    }
    try {
      u.save();
    } catch (IOException e) {
      // The pending hash/issued-at live in memory, so THIS code still
      // verifies — but it dies on restart. Log it (landmine fix).
      LOGGER.log(Level.WARNING,
          "MFA email-code issue failed to persist for user " + u.getId()
              + " — pending code lost on restart", e);
    }
    write(rsp, VerifyOutcome.resent(cfg.getEmailResendCooldownSeconds()));
  }

  // ---------------------------------------------------------------------
  // Task 9 — the profile-page factor-management endpoints (six).
  //
  // AUTHORIZATION (A23 — mads-directed fix, 2026-08-20; do NOT
  // "simplify" this away): the gate's "/mfa" allow-list exists so a
  // gated-unverified session can reach postVerify/postResendEmail, and
  // that same prefix passes ALL SIX of these endpoints to a session that
  // has proved ONLY the password (crumbs are obtainable too — /crumbIssuer
  // is allow-listed). The external review (2026-08-19) found the two
  // attack chains that opens: factor stripping (postDisableTotp +
  // postDisableEmail wipe both factors, isMfaEnabled() flips false, the
  // gate passes the session — MFA defeated) and the unthrottled seed-swap
  // brute force through postEnrollConfirm. Every endpoint below therefore
  // runs the PURE seam {@link #managementAllowed} at its top, BEFORE any
  // state mutation: deny 403 verification_required when the user is
  // enrolled and has NEITHER verified this session NOR holds live
  // remembered trust (an attacker with only the password has neither —
  // trust is granted by a prior successful verify, the flag by postVerify).
  // Unenrolled users pass (they are passed by the gate itself and must
  // keep self-enrolment access). API-token requests (Basic AND A21
  // Bearer) remain exempt from the gate itself exactly as everywhere
  // else; whether they carry the management authority depends on the
  // user's own verified/trust state (flagged in the A23 fix commit).
  //
  // URL ROUTING (A20, same rule as postVerify/postResendEmail — non-
  // negotiable per endpoint, landed in this commit with the method):
  // @RequirePOST is policy, not routing. Every one of the six carries
  // @WebMethod(name = "…") or <ctx>/mfa/<token> 404s and the section's
  // buttons are dead. MfaProfileIT's six-endpoint 404 guard (now run
  // from a VERIFIED session, A23) is the boot proof for all of them, A20-
  // style.
  // ---------------------------------------------------------------------

  /**
   * Generate a fresh TOTP enrolment candidate: a new 128-bit Base32 seed,
   * its {@code otpauth://} URI, and the QR as a data-URI PNG. NOTHING is
   * written to the user's property — the candidate lives only in the form's
   * hidden inputs until {@code postEnrollConfirm} proves a code for it
   * (single-POST commit; no server-side pre-commit state — that would be a
   * credential in the session with its own expiry lifecycle).
   *
   * <p>Contract (plan Task 9 table): success {@code {ok:true, seed,
   * otpauthUri, dataUriPng}}; render failure is still ok:true with an EMPTY
   * dataUriPng (QR is the convenience, manual entry is the fallback);
   * only an unexpected server fault is {@code {ok:false, error:"server_error"}}.
   */
  @RequirePOST
  @WebMethod(name = "postEnroll")
  public void postEnroll(StaplerRequest2 req, StaplerResponse2 rsp) throws IOException {
    // A23: the guard runs FIRST, before any state (or seed) is produced.
    if (answerManagementDeniedIfUnverified(req, rsp)) {
      return;
    }
    User u = currentUser();
    if (u == null) {
      write(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_NOT_AUTHENTICATED));
      return;
    }
    try {
      String seed = Totp.newBase32Secret();
      String issuer = DevcruMfaConfig.currentSafe().getIssuer();
      String uri = buildOtpauthUri(issuer, u.getId(), seed);
      // net.sf.json's JSONObject.put returns Object (not JSONObject), so no
      // put-chaining — build the JSON with discrete puts.
      JSONObject j = okJson();
      j.put("seed", seed);
      j.put("otpauthUri", uri);
      j.put("dataUriPng", qrDataUri(uri));
      writeProfileJson(rsp, j);
    } catch (RuntimeException e) {
      write(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_SERVER));
    }
  }

  /**
   * Commit a TOTP enrolment: verify the presented code against the
   * presented seed (± the admin window) and ONLY then write the seed to the
   * user's property (the {@link #confirmEnrollDecision} seam decides +
   * performs the write; the single {@code u.save()} below persists it).
   *
   * <p>Contract: success {@code {ok:true}} — the seed is now the user's TOTP
   * factor (replacing a previous one: re-enrolling with a new device IS the
   * failure {@code {ok:false, error:"invalid_seed"|"wrong_code"}}
   * — the presented seed is NEVER committed on a failed confirm, so a wrong
   * code while testing a second phone cannot clobber the working factor.
   * No rate limit on the CODE itself: the candidate seed is in the
   * user's own form and an unverified code proves nothing (the seed is
   * the key, the code is derived). The PRE-FIX framing — "10⁶ guesses
   * per presented seed burn only the presenter's own patience" — assumed
   * the presenter is the owner; the 2026-08-19 review showed a
   * password-only attacker can present their OWN seed and brute-force it
   * (~333K attempts for 50%, no throttle). The A23 guard above removes
   * that pre-verify door: only a session that has already proved a
   * factor (or holds live trust) may reach the commit path at all, which
   * is what makes the absent per-code throttle safe.
   */
  @RequirePOST
  @WebMethod(name = "postEnrollConfirm")
  public void postEnrollConfirm(StaplerRequest2 req, StaplerResponse2 rsp) throws IOException {
    // A23: guard FIRST — the commit path (confirmEnrollDecision writes the
    // seed) must be unreachable to a password-only session.
    if (answerManagementDeniedIfUnverified(req, rsp)) {
      return;
    }
    User u = currentUser();
    if (u == null) {
      write(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_NOT_AUTHENTICATED));
      return;
    }
    MfaUserProperty p;
    try {
      p = MfaUserProperty.getOrCreate(u);
    } catch (IOException e) {
      write(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_SERVER));
      return;
    }
    long now = System.currentTimeMillis();
    EnrollDecision d = confirmEnrollDecision(p,
        req.getParameter("seed"), req.getParameter("code"), now,
        DevcruMfaConfig.currentSafe().getTotpWindow());
    if (d.error() != null) {
      write(rsp, VerifyOutcome.fail(d.error()));
      return;
    }
    try {
      u.save();
    } catch (IOException e) {
      // The in-memory property carries the factor, so this session works —
      // but answering ok here HIDES data loss: the enrolment vanishes on the
      // next restart and the user's authenticator app holds a dead secret.
      // Report honestly; the user can retry confirm (landmine fix).
      LOGGER.log(Level.SEVERE,
          "MFA TOTP enrolment committed in memory but FAILED to persist for user "
              + u.getId() + " — factor WILL BE LOST on restart", e);
      writeProfileJson(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_PERSISTENCE).toJSONObject());
      return;
    }
    writeProfileJson(rsp, okJson());
  }

  /**
   * Issue a test one-time code for the profile section — the same delivery
   * path as the login page's {@code postResendEmail} (registered mailbox
   * only, single live code, one-per-minute cooldown), routed through the
   * SINGLE mint seam {@link #ensureEmailCodeSecret} (A2: the enrolment-UI
   * path is the second minting path mads ruled; there is no second
   * implementation here).
   *
   * <p>Contract: success {@code {ok:true, resent:true, cooldown}};
   * failure {@code {ok:false, error:"email_not_enrolled"|
   * "resend_cooldown"[, retrySeconds]}}.
   */
  @RequirePOST
  @WebMethod(name = "postEmailTestCode")
  public void postEmailTestCode(StaplerRequest2 req, StaplerResponse2 rsp) throws IOException {
    // A23: guard FIRST — the send path (ensureEmailCodeSecret + sendEmailCode)
    // must be unreachable to a password-only session.
    if (answerManagementDeniedIfUnverified(req, rsp)) {
      return;
    }
    User u = currentUser();
    if (u == null) {
      write(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_NOT_AUTHENTICATED));
      return;
    }
    MfaUserProperty p;
    try {
      p = MfaUserProperty.getOrCreate(u);
    } catch (IOException e) {
      write(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_SERVER));
      return;
    }
    if (!p.hasEmailFactor()) {
      write(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_EMAIL_NOT_ENROLLED));
      return;
    }
    DevcruMfaConfig cfg = DevcruMfaConfig.currentSafe();
    long now = System.currentTimeMillis();
    long cooldownMs = (long) cfg.getEmailResendCooldownSeconds() * 1000L;
    long last = p.getLastResendAt();
    if (last > 0 && now - last < cooldownMs) {
      long remainSec = (cooldownMs - (now - last)) / 1000L + 1L;
      write(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_COOLDOWN).withRetrySeconds(remainSec));
      return;
    }
    // The A2 seam: one mint, idempotent, behind hasEmailFactor() — the
    // exact same call postResendEmail/verifyEmail make. One key per account,
    // ever.
    String perUserSecret = ensureEmailCodeSecret(p);
    String code = emailIssuer.resend(p, perUserSecret, now,
        cfg.getEmailResendCooldownSeconds(), cfg.getEmailCodeTtlSeconds(), emailSender);
    if (code == null) {
      write(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_COOLDOWN)
          .withRetrySeconds(cfg.getEmailResendCooldownSeconds()));
      return;
    }
    try {
      u.save();
    } catch (IOException e) {
      // The pending hash/issued-at live in memory, so THIS code still
      // verifies — but it dies on restart. Log it (landmine fix).
      LOGGER.log(Level.WARNING,
          "MFA email-code issue failed to persist for user " + u.getId()
              + " — pending code lost on restart", e);
    }
    write(rsp, VerifyOutcome.resent(cfg.getEmailResendCooldownSeconds()));
  }

  /**
   * Disable the TOTP factor (remove it from the property; the user may
   * re-enroll at any time — re-enrolment IS the new-device swap path).
   *
   * <p>Contract: success {@code {ok:true}} (idempotent-safe: disabling an
   * already-absent factor is still a no-op success — the button does not
   * 500 on an empty state); failure {@code {ok:false, error:"not_enrolled"}}
   * is reserved for the NOT-LOGGED-IN shape (nothing to act on).
   *
   * <p>WHY/SOLVES: self-service removal is the user's recovery lever
   * (lost phone → admin recovery path, plan decision 7, clears the WHOLE
   * property; this removes ONE factor). It is deliberately NOT confirmed
   * with a second factor, because the A23 guard (this commit) is the real
   * protection: the endpoint answers 403 {@code verification_required}
   * unless the session has verified a factor this login ({@code
   * VERIFIED_ATTR}) or holds live remembered trust — an enrolled, GATED,
   * UNVERIFIED session (password only, the exact threat MFA exists for)
   * cannot reach the write at all. (The pre-fix javadoc here claimed the
   * GATE alone blocked such a session; that was false — the gate's
   * {@code /mfa} allow-list passed every management endpoint through,
   * which is precisely the hole the attack-chain IT in MfaProfileIT now
   * pins closed.)
   */
  @RequirePOST
  @WebMethod(name = "postDisableTotp")
  public void postDisableTotp(StaplerRequest2 req, StaplerResponse2 rsp) throws IOException {
    // A23: guard FIRST — this endpoint is the factor-strip half of the
    // audit's attack chain 1; the write must be unreachable to a
    // password-only session.
    if (answerManagementDeniedIfUnverified(req, rsp)) {
      return;
    }
    User u = currentUser();
    if (u == null) {
      write(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_NOT_AUTHENTICATED));
      return;
    }
    MfaUserProperty p;
    try {
      p = MfaUserProperty.getOrCreate(u);
    } catch (IOException e) {
      write(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_SERVER));
      return;
    }
    p.setTotpSecret(null);
    try {
      u.save();
    } catch (IOException e) {
      write(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_SERVER));
      return;
    }
    writeProfileJson(rsp, okJson());
  }

  /**
   * Disable the email factor: clear the registered mailbox (which is
   * {@code hasEmailFactor()}'s definition, so the factor goes with it) AND
   * retire the per-user HMAC key (it is meaningless without a mailbox and
   * keeping it would re-arm the mint seam on the next enrol).
   *
   * <p>Contract: success {@code {ok:true}} (idempotent-safe as above);
   * {@code {ok:false, error:"not_enrolled"}} for the not-logged-in shape.
   */
  @RequirePOST
  @WebMethod(name = "postDisableEmail")
  public void postDisableEmail(StaplerRequest2 req, StaplerResponse2 rsp) throws IOException {
    // A23: guard FIRST — the second factor-strip half of the audit's
    // attack chain 1; the write must be unreachable to a password-only
    // session.
    if (answerManagementDeniedIfUnverified(req, rsp)) {
      return;
    }
    User u = currentUser();
    if (u == null) {
      write(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_NOT_AUTHENTICATED));
      return;
    }
    MfaUserProperty p;
    try {
      p = MfaUserProperty.getOrCreate(u);
    } catch (IOException e) {
      write(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_SERVER));
      return;
    }
    p.setRegisteredEmail(null);
    p.setEmailCodeSecret(null);
    try {
      u.save();
    } catch (IOException e) {
      write(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_SERVER));
      return;
    }
    writeProfileJson(rsp, okJson());
  }

  /**
   * Revoke remembered devices: kill the user's persisted trust record so
   * the NEXT login from any browser prompts for the second factor again
   * (the CURRENT session keeps its verified flag — this is a "future
   * logins" lever, the signed trust semantics; killing the live session
   * would log the acting user out of their own admin work).
   *
   * <p>Contract: always {@code {ok:true}} — a revoke with no live trust is
   * a no-op-safety success by design (the plan table's "— (always a
   * no-op-safe success)").
   */
  @RequirePOST
  @WebMethod(name = "postRevokeTrust")
  public void postRevokeTrust(StaplerRequest2 req, StaplerResponse2 rsp) throws IOException {
    User u = currentUser();
    if (u == null) {
      write(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_NOT_AUTHENTICATED));
      return;
    }
    // A23: guard before the trust write — revoking remembered devices is a
    // state mutation; the revocation must not run and must not even load-
    //touch the property for a password-only session (its trust record must
    // be byte-identical to the moment before the denied POST).
    if (answerManagementDeniedIfUnverified(req, rsp)) {
      return;
    }
    MfaUserProperty p;
    try {
      p = MfaUserProperty.getOrCreate(u);
    } catch (IOException e) {
      write(rsp, VerifyOutcome.fail(VerifyOutcome.ERR_SERVER));
      return;
    }
    trustStore.revoke(p);
    try {
      u.save();
    } catch (IOException e) {
      // In-memory trust is already 0 so this session is fine — but without
      // the save the revocation is undone by the next restart. Log it.
      LOGGER.log(Level.WARNING,
          "MFA trust revocation failed to persist for user " + u.getId()
              + " — remembered-device revocation undone on restart", e);
    }
    writeProfileJson(rsp, okJson());
  }

  // ---------------------------------------------------------------------
  // Private glue (Task 8 territory) — kept small and obvious.
  // ---------------------------------------------------------------------

  private boolean verifyTotp(MfaUserProperty p, DevcruMfaConfig cfg, String submitted, long now) {
    return Totp.verify(Totp.decodeSecret(p.getTotpSecret().getPlainText()), submitted,
        now, cfg.getTotpWindow());
  }

  private EmailCodeIssuer.VerifyResult verifyEmail(MfaUserProperty p, DevcruMfaConfig cfg, String submitted, long now) {
    return emailIssuer.verify(p, ensureEmailCodeSecret(p), submitted, now, cfg.getEmailCodeTtlSeconds());
  }

  /**
   * Map an email verify result to a public error string. {@code NO_PENDING}
   * means "no code is live" (never sent, or already used) — tell the user to
   * request one. The fine-grained result stays internal; this is the only
   * external signal, so it must not reveal whether a specific code matched.
   */
  private static String emailFailReason(EmailCodeIssuer.VerifyResult r) {
    switch (r) {
      case EXPIRED:
        return VerifyOutcome.ERR_EXPIRED;
      case NO_PENDING:
        return VerifyOutcome.ERR_NO_PENDING;
      case WRONG_CODE:
      case CONSUMED:
      default:
        return VerifyOutcome.ERR_WRONG_CODE;
    }
  }

  /**
   * Regenerate the session (fresh id) and mark it MFA-verified, preserving
   * the existing authentication. The standard session-fixation mitigation:
   * copy every current attribute (including Spring Security's context, which
   * is what keeps the user logged in) onto the new session, then flag it.
   * Glue for Task 8; not plain-JVM-testable (needs a real request/session).
   */
  private void regenerateVerified(StaplerRequest2 req) {
    HttpSession old = req.getSession(false);
    if (old == null) {
      HttpSession fresh = req.getSession(true);
      fresh.setAttribute(VERIFIED_ATTR, Boolean.TRUE);
      return;
    }
    // Snapshot every attribute name/value before invalidating. Spring Security
    // stores its context in the session under SPRING_SECURITY_CONTEXT_KEY;
    // copying it as an ordinary attribute is what keeps the user authenticated
    // across the id change.
    java.util.Map<String, Object> copy = new java.util.HashMap<>();
    for (Enumeration<String> e = old.getAttributeNames(); e.hasMoreElements(); ) {
      String n = e.nextElement();
      copy.put(n, old.getAttribute(n));
    }
    old.invalidate();
    HttpSession fresh = req.getSession(true);
    for (java.util.Map.Entry<String, Object> en : copy.entrySet()) {
      fresh.setAttribute(en.getKey(), en.getValue());
    }
    fresh.setAttribute(VERIFIED_ATTR, Boolean.TRUE);
  }

  private void write(StaplerResponse2 rsp, VerifyOutcome o) throws IOException {
    rsp.setStatus(200);
    rsp.setHeader("Content-Type", "application/json;charset=UTF-8");
    rsp.setHeader("Cache-Control", "no-store");
    rsp.setHeader("X-Content-Type-Options", "nosniff");
    JSONObject j = o.toJSONObject();
    PrintWriter w = rsp.getWriter();
    w.print(j.toString());
    w.flush();
  }

  /**
   * The Task 9 profile-section JSON writer: same header treatment as
   * {@link #write}, a different body — a free {@link JSONObject} (usually
   * rooted at {@link #okJson()}) because the section's responses carry
   * enrolment payloads (seed / otpauthUri / dataUriPng) the
   * {@code VerifyOutcome} contract deliberately does not know about.
   * 500s are the caller's problem: every Task 9 endpoint answers 200 +
   * JSON, the stable {@code error} string is the contract, and a 500 here
   * would be an unhandled-exception symptom the page cannot distinguish.
   */
  private void writeProfileJson(StaplerResponse2 rsp, JSONObject j) throws IOException {
    rsp.setStatus(200);
    rsp.setHeader("Content-Type", "application/json;charset=UTF-8");
    rsp.setHeader("Cache-Control", "no-store");
    rsp.setHeader("X-Content-Type-Options", "nosniff");
    PrintWriter w = rsp.getWriter();
    w.print(j.toString());
    w.flush();
  }

  /** The success root for a profile-section response: {@code {"ok":true}}. */
  private static JSONObject okJson() {
    JSONObject j = new JSONObject();
    j.put("ok", true);
    return j;
  }

  // Test seam (package-private): Task 8 injects a capture sender.
  void setSenderForTest(EmailSender sender) {
    this.emailSender = sender;
  }

  // =====================================================================
  // Pure, unit-tested seams (see class doc). No Jenkins, no I/O, no clock.
  // =====================================================================

  public enum Factor { TOTP, EMAIL, UNKNOWN }

  /**
   * Return the per-user email-code HMAC key, minting it the first time and
   * never re-minting afterwards (idempotent).
   *
   * <p>This is the A2 audit finding, ruled 2026-08-18: the controller
   * previously fed a <em>blank-string</em> key to {@link EmailCodeIssuer}
   * because nothing anywhere provisioned the per-user key, so every
   * account's pending codes hashed under the same key and the
   * "per-user-keyed, encrypted at rest, states cannot be correlated"
   * confidentiality story was false. Minting on first use closes that gap
   * before the Task 9 enrolment UI exists (this is the first of the two
   * minting paths mads ruled; the enrolment UI is the second).
   *
   * <p>GIVEN a property with no {@code emailCodeSecret} yet
   * WHEN  called, THEN it stores a fresh 128-bit random key
   *       (Secret-encrypted at rest on the next {@code u.save()}) and
   *       returns its plaintext.
   * WHEN  the property already has a key, THEN it returns that key
   *       unchanged — never re-minting. Re-minting would invalidate a code
   *       that was just issued under the previous key, turning a resend
   *       into a "wrong code."
   *
   * <p>Pure over a {@link MfaUserProperty} (no Jenkins, no I/O, no clock),
   * so it is pinned in a plain-JVM unit test exactly like the other seams.
   * Only call sites behind {@code hasEmailFactor()} — a TOTP-only user is
   * never handed a key it has no use for.
   */
  static String ensureEmailCodeSecret(MfaUserProperty p) {
    Secret existing = p.getEmailCodeSecret();
    if (existing != null && !existing.getPlainText().isEmpty()) {
      return existing.getPlainText();
    }
    String minted = Totp.newBase32Secret();
    p.setEmailCodeSecret(Secret.fromString(minted));
    return minted;
  }

  // =====================================================================
  // Task 9 — the factor-management (profile page) seams. Pure: no Jenkins,
  // no I/O, no hidden clock. The profile section's six endpoints are the
  // thin glue around these; the decisions themselves live here so they are
  // pinable in a plain JVM (MfaProfileSeamTest) before any boot.
  // =====================================================================

  /**
   * The A23 authorization decision for the six factor-management
   * endpoints (postEnroll, postEnrollConfirm, postEmailTestCode,
   * postDisableTotp, postDisableEmail, postRevokeTrust): MAY this session
   * manage factors?
   *
   * <p>The gate's {@code /mfa} allow-list exists so a gated-unverified
   * session can reach {@code postVerify} — and with {@code startsWith}
   * matching it passes EVERY path under {@code /mfa}, including all six
   * management endpoints, to a session that has proved ONLY the password
   * (TECH_DEBT A23, external review 2026-08-19). The gate is therefore
   * NOT the protection these endpoints rely on; this seam is.
   *
   * <p>GIVEN the user's enrollment, whether THIS session has verified a
   * factor ({@code VERIFIED_ATTR}, the same attribute the gate reads), and
   * whether the user holds live remembered trust WHEN decided THEN:
   * <ul>
   *   <li>unenrolled → ALLOW (the gate passes unenrolled users outright;
   *       they must keep self-enrolment access and their sessions never
   *       carry the flag, so the flag alone would lock them out of the
   *       enrolment UI);</li>
   *   <li>enrolled + verified this session → ALLOW (the natural
   *       self-service flow: login → verify → manage);</li>
   *   <li>enrolled + unverified but remembered trust live → ALLOW (a
   *       trusted-device login already proved a factor within the trust
   *       window — without this clause the guard would break the
   *       legitimate disable/re-enrol flow from a remembered browser);</li>
   *   <li>enrolled + unverified + no trust → DENY 403
   *       {@code verification_required}. The password-only attacker holds
   *       exactly this state, and neither instrument can be forged by it:
   *       the flag is set only by postVerify success, {@code
   *       trustedUntilMs} only by a prior successful verify's trust grant.</li>
   * </ul>
   *
   * <p>WHY/SOLVES: without this guard, CRITICAL-1 (factor stripping) is two
   * requests — POST the two disables, both factors wipe,
   * {@code isMfaEnabled()} is false, the gate passes the session: MFA is
   * defeated against the exact threat (password compromise) it exists for,
   * and the README's "no self-service reset, by design" is false. CRITICAL-2
   * (seed-swap brute force: the attacker's OWN seed + guessed codes, ~333K
   * attempts expected) commits through the same door. The seam is pure and
   * unit-pinned (MfaProfileSeamTest) exactly so this decision cannot
   * regress; the endpoints apply it BEFORE any state mutation — a denied
   * request touches nothing.
   *
   * @param enrolled        whether the user has at least one factor (the
   *                        gate's own {@code isMfaEnabled()} predicate)
   * @param sessionVerified the session carries {@link #VERIFIED_ATTR}
   * @param trustLive       {@code trustedUntilMs > now} at request time
   *                        (the same trust arithmetic the gate uses)
   * @return true iff the management endpoints may proceed
   */
  static boolean managementAllowed(boolean enrolled, boolean sessionVerified, boolean trustLive) {
    if (!enrolled) {
      return true;
    }
    return sessionVerified || trustLive;
  }

  /**
   * The four-line endpoint glue around {@link #managementAllowed}: compute
   * the three inputs off the live request (READ-ONLY on the property —
   * never {@code getOrCreate} on this path, the gate's hot-path rule) and,
   * on deny, answer the stable 403 contract and report "stop" so the
   * endpoint returns BEFORE any state mutation.
   *
   * <p>The 403 (not a silent no-op 200) is deliberate: the section's JS
   * maps {@code verification_required} to a user-visible "complete
   * verification first" state, and a 200-from-a-denied-request is exactly
   * the shape the audit's pinned test (case e) exists to catch.
   *
   * @return true iff the endpoint must answer 403 and return (deny);
   *         false iff it may proceed (allow)
   */
  private boolean answerManagementDeniedIfUnverified(StaplerRequest2 req,
      StaplerResponse2 rsp) throws IOException {
    User u = currentUser();
    if (u == null) {
      // The endpoints themselves answer not_authenticated; the guard hands
      // the not-logged-in shape back to them (nothing to authorise).
      return false;
    }
    DevcruMfaConfig cfg = DevcruMfaConfig.currentSafe();
    MfaUserProperty prop;
    try {
      prop = u.getProperty(MfaUserProperty.class);
    } catch (RuntimeException e) {
      prop = null;
    }
    boolean enrolled = prop != null && prop.isMfaEnabled();
    HttpSession session = req.getSession(false);
    boolean sessionVerified = session != null
        && Boolean.TRUE.equals(session.getAttribute(VERIFIED_ATTR));
    boolean trustLive = prop != null && trustStore.isTrusted(prop, cfg, System.currentTimeMillis());
    if (managementAllowed(enrolled, sessionVerified, trustLive)) {
      return false;
    }
    rsp.setStatus(403);
    rsp.setHeader("Content-Type", "application/json;charset=UTF-8");
    rsp.setHeader("Cache-Control", "no-store");
    rsp.setHeader("X-Content-Type-Options", "nosniff");
    PrintWriter w = rsp.getWriter();
    w.print(VerifyOutcome.fail(VerifyOutcome.ERR_VERIFICATION_REQUIRED).toJSONObject().toString());
    w.flush();
    return true;
  }

  /** Stable reason for {@link #confirmEnrollDecision} when the seed is not usable Base32. */
  public static final String ERR_INVALID_SEED = "invalid_seed";

  /**
   * Build the {@code otpauth://} URI that enrolment QR codes encode — the
   * exact string every RFC 6238 authenticator app (Authy, Google
   * Authenticator, 1Password) parses.
   *
   * <p>GIVEN an issuer, an account id, and a canonical unpadded Base32
   * secret WHEN built THEN the URI is
   * {@code otpauth://totp/<label>?secret=<s>&issuer=<i>&algorithm=SHA1&digits=6&period=30}
   * where the label is {@code <issuer>:<account>} (the OTPAuth convention,
   * the colon unencoded — it separates label parts, not query parts) and
   * EVERYTHING else percent-encoded: label characters, the issuer
   * parameter, the secret (uppercase — apps are case-agnostic, but
   * canonical form avoids double-encoders lowercasing it). A raw
   * space/ampersand/equals/percent/plus anywhere would either break strict
   * parsers or let the label/issuer inject query structure, so the
   * round-trip test pins hostile characters, not just the happy path.
   *
   * <p>WHY/SOLVES: this string is the interop boundary with the user's
   * phone. A dropped parameter silently downgrades the app to defaults
   * (wrong digits/period/algorithm → "your codes never work", no error in
   * Jenkins at all); an unencoded space in the issuer breaks strict
   * parsers the same way. The QR is built FROM this string in the same
   * commit, so a bad URI and a bad QR cannot drift apart.
   */
  static String buildOtpauthUri(String issuer, String account, String base32Secret) {
    String label = enc(issuer) + ":" + enc(account);
    return "otpauth://totp/" + label
        + "?secret=" + enc(base32Secret.toUpperCase(java.util.Locale.ROOT))
        + "&issuer=" + enc(issuer)
        + "&algorithm=SHA1"
        + "&digits=" + Totp.DIGITS
        + "&period=" + Totp.STEP_SECONDS;
  }

  /**
   * Percent-encode a value for a URI structural position (label or query
   * parameter), preserving the unreserved set plus the label separator
   * characters that are safe here. Everything else — space, {@code & = % +
   * / ? #} — is escaped, so a value can never be re-parsed as URI structure
   * by the app that decodes the QR.
   *
   * <p>(The alternative, {@code URLEncoder.encode(…, UTF_8)}, turns spaces
   * into {@code +}, which a query-position consumer decodes back to a
   * space — right in a query, wrong inside a label. {@code %20} is correct
   * in BOTH positions, so everything here uses it.)
   */
  private static final char[] HEX = "0123456789ABCDEF".toCharArray();

  private static String enc(String s) {
    if (s == null) {
      return "";
    }
    StringBuilder out = new StringBuilder(s.length());
    for (byte b : s.getBytes(java.nio.charset.StandardCharsets.UTF_8)) {
      int v = b & 0xff;
      char c = (char) v;
      if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
          || c == '-' || c == '_' || c == '.' || c == '~' || c == ':' || c == ',') {
        out.append(c);
      } else {
        out.append('%').append(HEX[(v >> 4) & 0x0f]).append(HEX[v & 0x0f]);
      }
    }
    return out.toString();
  }

  /**
   * Render a URI as a 300×300 QR code and return it as a
   * {@code data:image/png;base64,….} string for an {@code <img>} tag.
   *
   * <p>Fail-closed per the seam contract: an unrenderable input (blank,
   * null, or too large for the fixed size) returns the empty string — the
   * profile section then shows NO image and the manual-secret field remains
   * the working path; the endpoint still answers JSON. A zxing
   * {@code WriterException} must never escape into the 200-or-500 choice of
   * a web endpoint: the QR is a convenience, manual entry is the fallback,
   * and a 500 would hide both. The 300×300 size is a fixed constant
   * (a version ~5–6 QR that every camera decodes cleanly at phone distance,
   * not a parameter the caller can twist).
   *
   * <p>WHY/SOLVES: single render path (same A2 discipline as
   * {@link #ensureEmailCodeSecret}) — the endpoint cannot have a second,
   * divergent QR builder, and the round-trip test in
   * {@code MfaProfileSeamTest} pins "the PNG decodes back to EXACTLY the
   * input URI" so a truncating render (working image, wrong secret) is a
   * loud red instead of a "QR never works" support ticket.
   */
  static String qrDataUri(String uri) {
    if (uri == null || uri.isBlank()) {
      return "";
    }
    try {
      com.google.zxing.common.BitMatrix matrix = new com.google.zxing.qrcode.QRCodeWriter()
          .encode(uri, com.google.zxing.BarcodeFormat.QR_CODE, 300, 300);
      java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
      com.google.zxing.client.j2se.MatrixToImageWriter.writeToStream(matrix, "PNG", bos);
      return "data:image/png;base64,"
          + java.util.Base64.getEncoder().encodeToString(bos.toByteArray());
    } catch (com.google.zxing.WriterException | java.io.IOException e) {
      // Unrenderable (size/charset/IO). Fail to "" (no image), never up.
      // (Exactly these two checked exceptions — SpotBugs REC_CATCH_EXCEPTION
      // forbids the broad catch Exception here; nothing else in this block
      // is checked.)
      return "";
    }
  }

  /**
   * The decision of {@code postEnrollConfirm}: does this (seed, code) pair
   * commit? A tiny public record so the IT and the unit test assert the
   * SAME contract object the endpoint returns.
   */
  public static final class EnrollDecision {
    private final String error; // null on success
    EnrollDecision(String error) {
      this.error = error;
    }
    /** @return the stable error string, or null when the commit succeeded. */
    public String error() {
      return error;
    }
  }

  /**
   * Decide + perform the single-POST enrolment commit (plan Task 9 "the
   * single-POST commit — no pre-commit staging").
   *
   * <p>GIVEN a property, a presented Base32 seed, a presented 6-digit code,
   * an instant, and the configured ±window WHEN decided THEN exactly one of:
   * <ul>
   *   <li>seed is blank or not valid Base32 (odd length, or a character
   *       outside the A–Z2–7 alphabet) → {@code invalid_seed}, property
   *       untouched;</li>
   *   <li>seed valid but the code does not verify against that seed within
   *       the window → {@code wrong_code} ({@link
   *       VerifyOutcome#ERR_WRONG_CODE}), property untouched — including
   *       the case where the property already has a DIFFERENT working seed:
   *       a failed confirm of a regenerate-candidate must not clobber the
   *       factor the user can actually prove;</li>
   *   <li>code verifies → the seed (EXACTLY the presented canonical form —
   *       the same string the QR was built from, so app and server agree)
   *       is written to the property's TOTP secret, decision is
   *       success (null error).</li>
   * </ul>
   * Nothing is written before the code is proven: the seed is
   * user-controllable JSON; only a live code for that seed is the credential
   * that makes it safe to store. The write happens IN THIS method (so the
   * caller's single {@code u.save()} persists it — same seam pattern as
   * {@link #ensureEmailCodeSecret}); the caller still owns the save and the
   * rate-limiting.
   *
   * <p>WHY/SOLVES: this is the enrolment's trust anchor. Committing before
   * verifying would let a session-holder pin a factor they cannot prove
   * (gate passes, factor useless); letting a failed confirm clobber an
   * enrolled seed is a self-inflicted lockout ("typed a wrong code while
   * testing a new phone" → old phone's factor gone).
   */
  static EnrollDecision confirmEnrollDecision(MfaUserProperty p, String seed, String code,
      long now, int window) {
    if (seed == null || !seed.matches("[A-Z2-7]{8,}")) {
      // Canonical unpadded Base32: whole 5-bit groups (length multiple of 8
      // for unpadded) or, for odd-bit counts that our generator never
      // produces, at least one group — but ONLY the alphabet + no padding
      // characters. Anything else (space, '=', lowercase, unicode) is "not
      // a seed", not a 500.
      return new EnrollDecision(ERR_INVALID_SEED);
    }
    byte[] key;
    try {
      key = Totp.decodeSecret(seed);
    } catch (RuntimeException e) {
      return new EnrollDecision(ERR_INVALID_SEED);
    }
    if (!Totp.verify(key, code, now, window)) {
      return new EnrollDecision(VerifyOutcome.ERR_WRONG_CODE);
    }
    p.setTotpSecret(Secret.fromString(seed));
    return new EnrollDecision(null);
  }

  /**
   * Classify a submitted code by its <em>shape</em>, which selects the factor
   * it is tried against first (and therefore the attempt order).
   *
   * <p>GIVEN any submitted string WHEN it is classified THEN:
   * <ul>
   *   <li>exactly 6 ASCII digits ⇒ {@link Factor#TOTP} (the RFC 6238 output,
   *       and the only thing an authenticator app emits),</li>
   *   <li>exactly 8 chars of the email-code alphabet (case-insensitive) ⇒
   *       {@link Factor#EMAIL},</li>
   *   <li>everything else ⇒ {@link Factor#UNKNOWN} (rejected as a wrong code,
   *       never a 500).</li>
   * </ul>
   *
   * <p>WHY/SOLVES: the TOTP and email alphabets are disjoint in length (6 vs
   * 8), so a correctly-shaped code can never be misrouted — a 6-digit TOTP is
   * never fed to the email check and vice versa, which keeps each factor's
   * constant-time comparison over only the right pending state. Garbled /
   * wrong-length input lands in {@code UNKNOWN} and is counted as one failed
   * attempt, so the rate limiter (not a parser error) is what bounds abuse.
   */
  static Factor classifyFactor(String input) {
    if (input == null) {
      return Factor.UNKNOWN;
    }
    String s = input.replaceAll("\\s+", "");
    if (s.length() == 6 && s.matches("[0-9]{6}")) {
      return Factor.TOTP;
    }
    if (s.length() == 8 && s.toUpperCase(java.util.Locale.ROOT).matches("[2-9A-HJ-NP-Z]{8}")) {
      return Factor.EMAIL;
    }
    return Factor.UNKNOWN;
  }

  /**
   * Decide where a successful verification redirects the user to: the
   * {@code Referer} <em>only if</em> it is the same origin and not a
   * login/security path, otherwise the site root. This is the "no dead
   * redirect / no open redirect" seam.
   *
   * <p>GIVEN a {@code referer} and the site's {@code host}/{@code port}/
   * {@code contextPath} WHEN resolved THEN exactly one of:
   * <ul>
   *   <li>the same-origin, non-login path the user came from, or</li>
   *   <li>the site root (the {@code contextPath}, or {@code "/"}), when the
   *       referer is missing, cross-origin, protocol-relative ({@code //…}),
   *       not an absolute-or-"/"-relative URL, or a security page.</li>
   * </ul>
   *
   * <p>WHY/SOLVES: the plan's whole point is that MFA completion returns to
   * the requested page instead of a black/dead page (the SaaS plugin's sin).
   * But trusting {@code Referer} wholesale is an <em>open-redirect</em> hole —
   * an attacker could set {@code Referer: https://evil.com} and bounce a
   * verified user off-site. This validator is the boundary between "helpful
   * back-navigation" and "open redirect / dead page": it is pure, so the unit
   * tests pin each branch of the decision without a live Jenkins.
   *
   * @param referer     the raw {@code Referer} header value (may be null/blank)
   * @param host        the site's current host name (from {@code getServerName})
   * @param port        the site's current port (from {@code getServerPort});
   *                    compared only when the referer carries an explicit
   *                    port. A port-less referer is accepted on host match
   *                    alone — benign in practice: browsers put a port in a
   *                    URL only when it is non-default, so on a single-origin
   *                    Jenkins the (same-origin) referer arrives with the
   *                    site's real port whenever one is non-default.
   * @param contextPath the Jenkins context path ("" for root-installed Jenkins)
   * @return an absolute in-site path (leading "/", includes {@code contextPath}),
   *         never empty; the root fallback when nothing valid applies
   */
  static String resolveRedirectTarget(String referer, String host, String port, String contextPath) {
    String root = normalizeRoot(contextPath);
    if (referer == null) {
      return root;
    }
    String ref = referer.trim();
    if (ref.isEmpty()) {
      return root;
    }
    // Protocol-relative ("//evil.com/…") is an open redirect: block.
    if (ref.startsWith("//")) {
      return root;
    }
    String path;
    int schemeIdx = ref.indexOf("://");
    if (schemeIdx >= 0) {
      // Absolute URL: require same scheme + host (+ port when explicit).
      String scheme = ref.substring(0, schemeIdx).toLowerCase(java.util.Locale.ROOT);
      if (!scheme.equals("http") && !scheme.equals("https")) {
        return root;
      }
      URI uri;
      try {
        uri = new URI(ref);
      } catch (URISyntaxException e) {
        return root;
      }
      String uHost = uri.getHost();
      if (uHost == null || host == null
          || !uHost.equalsIgnoreCase(host)) {
        return root;
      }
      int uPort = uri.getPort();
      if (uPort != -1 && port != null && !port.isEmpty()) {
        if (uPort != Integer.parseInt(port)) {
          return root;
        }
      }
      path = uri.getPath();
    } else if (ref.startsWith("/")) {
      // Server-relative path: already in-site by construction.
      path = ref;
    } else {
      // Relative that isn't "/"-rooted (e.g. "evil.com/…"): not a safe target.
      return root;
    }
    if (path == null || path.isEmpty()) {
      return root;
    }
    // Strip the context path to test the security path against the in-site
    // route, not the deployment mount.
    String siteRel = stripContext(path, contextPath);
    if (isSecurityPath(siteRel)) {
      return root;
    }
    return join(contextPath, siteRel);
  }

  private static String normalizeRoot(String contextPath) {
    if (contextPath == null || contextPath.isEmpty()) {
      return "/";
    }
    String c = contextPath;
    if (c.charAt(0) != '/') {
      c = "/" + c;
    }
    while (c.length() > 1 && c.endsWith("/")) {
      c = c.substring(0, c.length() - 1);
    }
    return c;
  }

  private static String stripContext(String path, String contextPath) {
    if (contextPath != null && !contextPath.isEmpty()) {
      String c = contextPath;
      if (c.charAt(0) != '/') {
        c = "/" + c;
      }
      while (c.length() > 1 && c.endsWith("/")) {
        c = c.substring(0, c.length() - 1);
      }
      if (path.startsWith(c)) {
        String rest = path.substring(c.length());
        return rest.isEmpty() ? "/" : rest;
      }
    }
    return path;
  }

  private static String join(String contextPath, String siteRel) {
    String c = (contextPath == null || contextPath.isEmpty()) ? "" : contextPath;
    String r = (siteRel == null || siteRel.isEmpty()) ? "/" : siteRel;
    if (r.charAt(0) != '/') {
      r = "/" + r;
    }
    String out = c + r;
    return out.isEmpty() ? "/" : out;
  }

  /**
   * The in-site routes that must never be a post-verification redirect target:
   * the login/logout flow and the MFA/security page itself. Redirecting back
   * to the MFA page after a success would be an immediate re-prompt loop;
   * redirecting to login would drop the just-completed authentication.
   */
  private static boolean isSecurityPath(String siteRel) {
    String p = (siteRel == null) ? "/" : siteRel;
    if (p.charAt(0) != '/') {
      p = "/" + p;
    }
    String first;
    int end = p.indexOf('/', 1);
    if (end < 0) {
      first = p.substring(1);
    } else {
      first = p.substring(1, end);
    }
    first = first.toLowerCase(java.util.Locale.ROOT);
    switch (first) {
      case "login":
      case "logout":
      case "postlogout":
      case "logoutpost":
      case "signup":
      case "j_acegi":
      case "mfa":
      case "securityrealm":
      case "security":
        return true;
      default:
        return false;
    }
  }

  /**
   * Mask a registered mailbox for display on the MFA page: keep the first
   * character of the local part and the full domain, hide the middle
   * ("mads@devcru.org" → "m***@devcru.org").
   *
   * <p>GIVEN a registered address WHEN masked THEN the viewer sees enough to
   * confirm "yes, that's my mailbox, send it there" without the page exposing
   * the full address before the factor is proven. A missing/unparseable
   * address masks to "***" (never the raw input); blank/null mask to "".
   *
   * <p>WHY/SOLVES: the resend button on this page would be an address oracle
   * otherwise — anyone who can reach the page (password-authenticated, not yet
   * MFA) could read the exact mailbox of the account they are sitting in.
   * Masking keeps the "send to my real inbox" affordance while denying the
   * full address to the not-yet-verified viewer.
   */
  static String maskEmail(String email) {
    if (email == null || email.trim().isEmpty()) {
      return "";
    }
    String e = email.trim();
    int at = e.indexOf('@');
    if (at < 0) {
      return "***";
    }
    String local = e.substring(0, at);
    String domain = e.substring(at); // includes the '@'
    String maskedLocal = local.isEmpty() ? "***" : local.charAt(0) + "***";
    return maskedLocal + domain;
  }
}
