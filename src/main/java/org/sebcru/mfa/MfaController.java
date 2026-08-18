package org.sebcru.mfa;

import hudson.Extension;
import hudson.model.RootAction;
import hudson.model.User;
import hudson.security.csrf.CrumbIssuer;
import hudson.util.Secret;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Enumeration;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.StaplerResponse2;
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
 * {@code <root>/securityRealm/mfa}: the gate filter (Task 7) 302s a
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
 * <h2>Two deliberate deviations from the plan sketch (flagged for review)</h2>
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
 *       unchanged. {@code RootAction} is <em>not</em>
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
  // RootAction — mounts the page at <root>/securityRealm/mfa, no action-bar
  // icon (getIconFileName() null), still behind authentication.
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
    // Stable, current-core path (see class doc, deviation 1).
    return "securityRealm/mfa";
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

  // ---------------------------------------------------------------------
  // POST endpoints. Core's crumb filter + @RequirePOST guard them; this is
  // belt-and-suspenders on method, not on policy. The page embeds the hidden
  // crumb field from the Java model (getCrumbField()/getCrumbValue()), not
  // via the `h` taglib — the page is a self-contained document without an
  // <l:view> wrapper, where the `h` variable is unbound — but the model
  // calls the same core static (Functions.getCrumb), so crumb policy stays
  // in core.
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
    String failReason = VerifyOutcome.ERR_NOT_ENROLLED;
    switch (f) {
      case TOTP:
        if (p.hasTotpFactor()) {
          verified = verifyTotp(p, cfg, submitted, now);
          failReason = VerifyOutcome.ERR_WRONG_CODE;
        } else if (p.hasEmailFactor()) {
          EmailCodeIssuer.VerifyResult r = verifyEmail(p, cfg, submitted, now);
          verified = r == EmailCodeIssuer.VerifyResult.CONSUMED;
          failReason = emailFailReason(r);
        }
        break;
      case EMAIL:
        if (p.hasEmailFactor()) {
          EmailCodeIssuer.VerifyResult r = verifyEmail(p, cfg, submitted, now);
          verified = r == EmailCodeIssuer.VerifyResult.CONSUMED;
          failReason = emailFailReason(r);
        } else if (p.hasTotpFactor()) {
          verified = verifyTotp(p, cfg, submitted, now);
          failReason = VerifyOutcome.ERR_WRONG_CODE;
        }
        break;
      default:
        // Garbled / wrong-length input: not a valid code.
        verified = false;
        failReason = VerifyOutcome.ERR_WRONG_CODE;
    }

    if (verified) {
      // 3. Success: grant trust (floor applied inside TrustStore), clear the
      //    failure history, regenerate the session to kill any fixated id,
      //    and mark it verified so the Task 7 gate passes it.
      try {
        trustStore.trust(p, cfg, now);
        u.save();
      } catch (IOException ignore) {
        // Persistence hiccup must not strand a user who already proved
        // the factor; the session attribute still authorises this session.
      }
      rateLimiter.clear(name);
      regenerateVerified(req);
      long hours = trustStore.effectiveTrustHours(cfg);
      // A3 (mads ruling, 2026-08-18): the ?redirect= query parameter the gate
      // 302'd to (/securityRealm/mfa?redirect=…) is CANONICAL over Referer —
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
      } catch (IOException ignore) {
        // Telemetry counter only; non-fatal.
      }
      write(rsp, VerifyOutcome.fail(failReason));
    }
  }

  /**
   * Re-issue the email one-time code to the <em>registered</em> address only
   * (see class doc, deviation 2 — no {@code dest}).
   */
  @RequirePOST
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
    } catch (IOException ignore) {
      // Non-fatal; the pending hash/issued-at are already set in memory.
    }
    write(rsp, VerifyOutcome.resent(cfg.getEmailResendCooldownSeconds()));
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
