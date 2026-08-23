package org.sebcru.mfa;

import hudson.Extension;
import hudson.model.RootAction;
import hudson.model.User;
import jakarta.servlet.http.HttpServletResponse;
import jenkins.model.Jenkins;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.StaplerResponse2;
import org.kohsuke.stapler.WebMethod;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.sebcru.mfa.gate.TrustStore;

/**
 * A22-b — the admin management surface for OTHER users' MFA factor state.
 * Mounts at {@code <root>/mfaAdmin} (a free top-level segment: core owns no
 * such node in any realm shape — checked the same way {@code /mfa} was in
 * Task 8's Defect B ruling).
 *
 * <p>Deliberately a SEPARATE surface from the six self-service
 * {@link MfaController} endpoints (mads ruling 2026-08-23, question 1:
 * "new page for sure"): the profile endpoints are guarded for the
 * {@code currentUser()} whose own factors they touch; this surface's verbs
 * touch a NAMED other user, so the authorization is a different, stricter
 * chain. See spec
 * {@code docs/todo/2026-08-23-A22b-admin-factor-management-spec.md} §4/§9.
 *
 * <h2>Not on the gate allow-list (spec §4, ruling 1)</h2>
 * Nothing here is added to {@link MfaFilter}'s {@code ALLOWED_PREFIXES}:
 * the admin surface is reached only after the normal decision chain, and a
 * password-only enrolled user is bounced to the MFA page before any
 * controller code runs. (The gate's own allow-list, which carried the bare
 * {@code /mfa} prefix, matched {@code /mfaAdmin/*} by prefix coincidence —
 * the second instance of the A23 sibling-sweep class — and the allow-list
 * test now matches the {@code /mfa} entry segment-precisely (the bare page,
 * its {@code ?redirect=} query, and its {@code /mfa/} endpoints) rather than
 * by {@code startsWith}. Pinned both directions in
 * {@code FilterLogicTest}.) The two verbs' own authorization chain below is
 * the authoritative control on the mutation either way.
 */
@Extension
public final class MfaAdminController implements RootAction {

  /** The audit line — spec §3, the loud-not-silent landmine standard. */
  private static final Logger LOGGER =
      Logger.getLogger(MfaAdminController.class.getName());

  // ---------------------------------------------------------------------
  // RootAction — mounts the page at <root>/mfaAdmin, no action-bar icon
  // (getIconFileName() null), still behind authentication.
  // ---------------------------------------------------------------------

  @Override
  public String getUrlName() {
    return "mfaAdmin";
  }

  @Override
  public String getIconFileName() {
    return null;
  }

  @Override
  public String getDisplayName() {
    return "MFA administration";
  }

  // ==================================================================
  // The two verbs (ruling 2: clear-all + revoke-trust only, for now).
  // ==================================================================

  /**
   * Clear ALL factors on a named user's property (the documented lockout
   * recovery: README "an admin clears the user's factor state").
   *
   * <h2>Authorization chain (the A23-analogue guard, spec §4/§8 — order is
   * load-bearing, every check before any mutation)</h2>
   * <pre>
   *  1. actor present + ADMINISTER      (403 admin_permission_required)
   *  2. adminManageAllowed seam         (403 admin_verification_required — Ruling-3 edge)
   *  3. self-management forbidden       (200 admin_self_management_forbidden)
   *  4. typed-id confirm matches target (200 admin_confirm_required)
   *  5. target exists + is enrolled     (200 not_enrolled)
   *  6. mutate + persist (honestly)     (200 persistence_failed if the save throws)
   * </pre>
   *
   * <p>Check 2's quadrilateral (the seam below, unit-pinned in
   * {@code AdminManageAllowedTest}): an UNENROLLED admin — password-only,
   * no credential to hold (the Ruling-3 edge: "DENY") — cannot pass it;
   * a verified actor passes; a trust-live actor passes (a remembered
   * device already proved a factor — the A23 trust-clause symmetry); the
   * unverified-and-untrusty enrolled actor — the password-only attacker's
   * exact state, also what the gate bounces before it lands here — is
   * denied. Check 3 is the load-bearing rule: without it a password-only
   * admin who slips a verify could strip their OWN factors through this
   * surface — A23's hole one endpoint to the left (spec §8).
   */
  @RequirePOST
  @WebMethod(name = "clearFactors")
  public void postClearFactors(StaplerRequest2 req, StaplerResponse2 rsp)
      throws IOException {
    if (answerAdminDenied(req, rsp)) {
      return;
    }
    String error = denyOrConfirmError(req);
    if (error != null) {
      writeJson(rsp, error, null);
      return;
    }
    String userId = req.getParameter("userId");
    User target = User.getById(userId, false);
    if (target == null || !isEnrolled(target)) {
      writeJson(rsp, VerifyOutcome.ERR_NOT_ENROLLED, null);
      return;
    }
    MfaUserProperty p = target.getProperty(MfaUserProperty.class);
    clearFactorState(p);
    try {
      target.save();
    } catch (IOException e) {
      LOGGER.log(Level.SEVERE, "MFA admin " + actorId() + " cleared factor state for "
          + userId + " but the save FAILED (in-memory only, lost on restart)", e);
      writeJson(rsp, VerifyOutcome.ERR_PERSISTENCE, null);
      return;
    }
    LOGGER.log(Level.WARNING, "MFA admin " + actorId() + " cleared factor state for user " + userId);
    writeJson(rsp, null, "clearFactors");
  }

  /**
   * Revoke the named user's live remembered-device trust (forced re-verify:
   * their browsers will re-prompt the factor at next login). IDENTICAL
   * authorization chain to {@link #postClearFactors} — ruling 5's typed-id
   * confirmation applies to both verbs (one rule for the whole surface);
   * the mutation differs only in scope (trust goes to 0, factors stay).
   */
  @RequirePOST
  @WebMethod(name = "revokeTrust")
  public void postRevokeTrust(StaplerRequest2 req, StaplerResponse2 rsp)
      throws IOException {
    if (answerAdminDenied(req, rsp)) {
      return;
    }
    String error = denyOrConfirmError(req);
    if (error != null) {
      writeJson(rsp, error, null);
      return;
    }
    String userId = req.getParameter("userId");
    User target = User.getById(userId, false);
    if (target == null || !isEnrolled(target)) {
      writeJson(rsp, VerifyOutcome.ERR_NOT_ENROLLED, null);
      return;
    }
    MfaUserProperty p = target.getProperty(MfaUserProperty.class);
    p.setTrustedUntilMs(0L);
    try {
      target.save();
    } catch (IOException e) {
      LOGGER.log(Level.SEVERE, "MFA admin " + actorId() + " revoked trust for "
          + userId + " but the save FAILED (in-memory only, lost on restart)", e);
      writeJson(rsp, VerifyOutcome.ERR_PERSISTENCE, null);
      return;
    }
    LOGGER.log(Level.WARNING, "MFA admin " + actorId() + " revoked trust for user " + userId);
    writeJson(rsp, null, "revokeTrust");
  }

  /**
   * The clearFactors mutation, extracted as the single writer of the
   * "fully unenrolled" state (spec §3: one {@code save()}, every factor and
   * piece of pending state cleared in one pass). Extracted so the IT can
   * assert the EXACT cleared state byte-for-byte against this one method's
   * contract, and so a future "clear one more field" can't drift between
   * two call sites.
   */
  static void clearFactorState(MfaUserProperty p) {
    p.setTotpSecret(null);
    p.setEmailCodeSecret(null);
    p.setRegisteredEmail(null);
    p.setTrustedUntilMs(0L);
    p.setPendingCodeHash(null);
    p.setCodeIssuedAt(0L);
    p.setLastResendAt(0L);
    p.setFailedAttemptStreak(0);
  }

  /** The current authenticated user's id, or "?" (the audit-line actor). */
  private static String actorId() {
    User actor = MfaFilter.findCurrentUser();
    return actor == null ? "?" : actor.getId();
  }

  // ==================================================================
  // The authorization chain (A23-analogue guard — see spec §4/§8).
  // ==================================================================

  /**
   * The PURE seam of the admin surface's authorization — unit-pinned in
   * {@code AdminManageAllowedTest} exactly the way A23's
   * {@code managementAllowed} is pinned in
   * {@code MfaControllerManagementTest}. Two axes, checked in order (spec
   * §4: permission → credential):
   * <ol>
   *   <li><b>Permission (administer).</b> The actor must hold
   *       {@code Jenkins.ADMINISTER} — the privilege axis. A fully-verified
   *       NON-admin is denied here, before any credential is even read; this
   *       is the axis the {@code FullControlOnceLoggedInAuthorizationStrategy}
   *       IT (every logged-in user is admin) cannot exercise, so it is
   *       pinned at the seam and in a least-privilege IT.</li>
   *   <li><b>Credential (Ruling-3 edge).</b> The actor must hold a PROVEN
   *       CREDENTIAL: verified this session (the gate's own
   *       {@code VERIFIED_ATTR}, set only by a successful verify) or a live
   *       remembered device (the gate's own trust arithmetic, written only by
   *       a successful verify). An UNENROLLED actor can hold neither
   *       instrument — they have no factors to verify — which IS the Ruling-3
   *       edge: they can (if ADMINISTER) read the roster, they cannot clear
   *       or revoke.</li>
   * </ol>
   */
  static boolean adminManageAllowed(boolean administer, boolean enrolled,
      boolean sessionVerified, boolean trustLive) {
    if (!administer) {
      return false;
    }
    if (!enrolled) {
      return false; // ruling 3
    }
    return sessionVerified || trustLive;
  }

  private final TrustStore trustStore = new TrustStore();

  /**
   * The 403 glue (A23's house shape): runs at the TOP of every verb,
   * BEFORE any read or mutation, and returns true so the endpoint stops.
   * The 403 (never a silent 200) is the shape that distinguishes a DENIAL
   * from a processed request — the bug A23's ITs pin. Denies on two axes
   * in spec-§4 order: (1) PERMISSION — no {@code ADMINISTER} →
   * {@code admin_permission_required} (checked FIRST, so a non-admin is
   * told it is a privilege denial, whatever their credential state); (2)
   * CREDENTIAL — the pure seam below, whose deny is the A23-analogue: a
   * verified-or-trusted-or-enrolled-but-not admin →
   * {@code admin_verification_required}. The credential axis reads the SAME
   * instruments the gate reads ({@code VERIFIED_ATTR} + one
   * {@code TrustStore.isTrusted} against the gate's config), so a session
   * the gate passes cannot be denied here and vice versa — the two chains
   * agree by construction.
   */
  private boolean answerAdminDenied(StaplerRequest2 req, StaplerResponse2 rsp)
      throws IOException {
    User actor = MfaFilter.findCurrentUser();
    boolean administer = actor != null && hasAdminister(actor);
    if (actor == null || !administer) {
      writeAdminDenied(rsp, VerifyOutcome.ERR_ADMIN_PERMISSION);
      return true;
    }
    MfaUserProperty self = actor.getProperty(MfaUserProperty.class);
    boolean enrolled = self != null && self.isMfaEnabled();
    boolean sessionVerified = req.getSession(false) != null
        && Boolean.TRUE.equals(req.getSession(false).getAttribute(MfaController.VERIFIED_ATTR));
    DevcruMfaConfig cfg = DevcruMfaConfig.currentSafe();
    boolean trustLive = enrolled && self != null
        && trustStore.isTrusted(self, cfg, System.currentTimeMillis());
    if (!adminManageAllowed(administer, enrolled, sessionVerified, trustLive)) {
      writeAdminDenied(rsp, VerifyOutcome.ERR_ADMIN_VERIFICATION_REQUIRED);
      return true;
    }
    return false;
  }

  /**
   * ADMINISTER for the CURRENT session — the permission axis (never throws
   * here; fails closed on any unknown state).
   *
   * <p><b>Defect-2 finding (2026-08-23, bytecode-proven):</b> this seam
   * deliberately does NOT use {@code actor.hasPermission(Jenkins.ADMINISTER)}
   * (the spec §4 text). In this core (2.528.3, javap-verified)
   * {@code User.getACL()} wraps the strategy's ACL in a delegate whose
   * {@code hasPermission2} self-grants BEFORE consulting the strategy:
   * <pre>
   *   if (idStrategy.equals(auth.getName(), thisUser.id)
   *       &amp;&amp; !(auth instanceof AnonymousAuthenticationToken))
   *     return TRUE;
   *   return strategyACL.hasPermission2(auth, perm);
   * </pre>
   * The actor in this surface is ALWAYS the logged-in user's own {@code
   * User} instance, so that self-grant fires for every authenticated actor
   * and the permission check was a NO-OP: under a least-privilege strategy
   * even a non-admin read {@code true} (run-3 IT evidence: "lowly" reached
   * the page forward). The check on the {@code Jenkins} instance is the
   * first ACL that is not self-referential: {@code Jenkins.getACL()} is
   * {@code getAuthorizationStrategy().getRootACL()} verbatim (no wrapper,
   * no self-grant); core's own admin affordances use exactly this shape.
   * This changes the production seam from the spec's one-line text —
   * flagged for mads sign-off in the 2026-08-23 handoff; the spec's
   * INTENT ("the actor must hold ADMINISTER under the live strategy") is
   * what this implements, and its letter is a core self-grant hole. Under
   * FCOL the two forms agree (both true); under least-privilege only this
   * form is honest, and least-privilege is where the axis exists at all.
   */
  static boolean hasAdminister(User actor) {
    org.springframework.security.core.Authentication auth =
        Jenkins.getAuthentication2();
    if (auth == null
        || auth instanceof org.springframework.security.authentication.AnonymousAuthenticationToken
        || hudson.security.ACL.ANONYMOUS_USERNAME.equals(auth.getName())) {
      return false; // anonymous / unauthenticated: the surface is closed
    }
    return Jenkins.get().getACL().hasPermission2(auth, Jenkins.ADMINISTER);
  }

  /**
   * The READ-SIDE gate for the page render (index.jelly): ADMINISTER only.
   * Ruling 3 is the semantics: an unenrolled admin CAN read the roster
   * (read ≠ mutation — the credential axis is demanded by the VERBS, and
   * only by the verbs), but cannot touch anything. The verbs keep their
   * fuller chain (permission → credential → confirm → self) — this getter
   * answers the page's single question: "may this session even see the
   * roster rows?" Fails closed on any unknown authentication state.
   */
  public boolean adminPageAllowed() {
    return hasAdminister(MfaFilter.findCurrentUser());
  }

  /**
   * The single 403 JSON-denial writer (both the page GET and the two verbs
   * share it — one shape for every "you may not" on this surface):
   * {@code 403 {ok:false, error:<reason>}}, no-store, nosniff.
   */
  private static void writeAdminDenied(StaplerResponse2 rsp, String error) throws IOException {
    rsp.setStatus(HttpServletResponse.SC_FORBIDDEN);
    rsp.setHeader("Content-Type", "application/json;charset=UTF-8");
    rsp.setHeader("Cache-Control", "no-store");
    rsp.setHeader("X-Content-Type-Options", "nosniff");
    PrintWriter w = rsp.getWriter();
    w.print(writeEnvelope(error, null));
    w.flush();
  }

  /**
   * The per-request denials after the credential check (spec §8, checks 3+4):
   * returns the stable error string, or null when the request may proceed.
   * Self-management is checked FIRST — the load-bearing rule (a verified
   * admin posting against their OWN id is refused: that is self-service
   * territory, where their own credential is the point of the act). The
   * typed-id confirmation (Ruling 5, "100% user typed confirmation") is
   * the server-side half of the page's dialog: {@code confirmUserId} must
   * match the named target verbatim — the client dialog is UX; this check
   * is the control.
   */
  private static String denyOrConfirmError(StaplerRequest2 req) {
    User actor = MfaFilter.findCurrentUser();
    String userId = req.getParameter("userId");
    if (actor == null) {
      return VerifyOutcome.ERR_ADMIN_VERIFICATION_REQUIRED;
    }
    if (userId == null || userId.isBlank()) {
      return VerifyOutcome.ERR_ADMIN_CONFIRM;
    }
    if (userId.equals(actor.getId())) {
      return VerifyOutcome.ERR_ADMIN_SELF_MANAGEMENT;
    }
    String confirm = req.getParameter("confirmUserId");
    if (confirm == null || !confirm.equals(userId)) {
      return VerifyOutcome.ERR_ADMIN_CONFIRM;
    }
    return null;
  }

  /** A user is enrolled iff they carry an MfaUserProperty with a live factor. */
  private static boolean isEnrolled(User u) {
    MfaUserProperty p = u.getProperty(MfaUserProperty.class);
    return p != null && p.isMfaEnabled();
  }

  /** The JSON envelope: {ok,error} for a denial, {ok,op} for a success. */
  private static JSONObject writeEnvelope(String error, String op) {
    JSONObject j = new JSONObject();
    if (error != null) {
      j.put("ok", false);
      j.put("error", error);
    } else {
      j.put("ok", true);
      j.put("op", op);
    }
    return j;
  }

  /** The 200-JSON-envelope writer (house pattern from MfaController). */
  private static void writeJson(StaplerResponse2 rsp, String error, String op) throws IOException {
    rsp.setStatus(200);
    rsp.setHeader("Content-Type", "application/json;charset=UTF-8");
    rsp.setHeader("Cache-Control", "no-store");
    rsp.setHeader("X-Content-Type-Options", "nosniff");
    PrintWriter w = rsp.getWriter();
    w.print(writeEnvelope(error, op).toString());
    w.flush();
  }

  // ==================================================================
  // Roster render model (view-facing getters — see index.jelly).
  // ==================================================================

  /**
   * The enrolled-only roster (Ruling 4, "FOR NOW" — the follow-up
   * force-enrol view per the same ruling reuses this row list; tracked as
   * A24). Unenrolled users have no row: they cannot be locked out and
   * need no recovery surface. Sorted by id for a stable DOM. Every read
   * is get-only — never getOrCreate (the audit's no-write-hot-path rule),
   * never the actor's session state. The mailbox is MASKED at the source
   * (MfaController.maskEmail, A16): the plaintext never enters the DOM.
   */
  public List<AdminRow> getRosterRows() {
    List<AdminRow> rows = new ArrayList<>();
    try {
      for (User u : User.getAll()) {
        MfaUserProperty p = u.getProperty(MfaUserProperty.class);
        if (p == null || !p.isMfaEnabled()) {
          continue; // registered-but-unenrolled: out of roster scope
        }
        String mail = (p.getRegisteredEmail() != null && !p.getRegisteredEmail().isBlank())
            ? p.getRegisteredEmail() : "(no mailbox)";
        rows.add(new AdminRow(u.getId(), u.getFullName(), MfaController.maskEmail(mail),
            p.hasTotpFactor(), p.hasEmailFactor(),
            p.getTrustedUntilMs() > System.currentTimeMillis()));
      }
    } catch (RuntimeException e) {
      // Jenkins not fully up (early bootstrap): the page renders an empty
      // roster rather than 500-ing; the verbs still deny everything, so an
      // empty read plane is the safe degradation.
    }
    rows.sort((a, b) -> a.getUserId().compareTo(b.getUserId()));
    return rows;
  }

  /** The page's base — {@code <root>/mfaAdmin/} (context-relative pre-boot). */
  public String getMfaAdminBaseUrl() {
    try {
      String root = Jenkins.get().getRootUrl();
      if (root == null || root.isBlank()) {
        return "mfaAdmin/";
      }
      return (root.endsWith("/") ? root : root + "/") + "mfaAdmin/";
    } catch (RuntimeException e) {
      return "mfaAdmin/";
    }
  }

  public String getCrumbField() {
    return hudson.Functions.getCrumbRequestField();
  }

  public String getCrumbValue() {
    return hudson.Functions.getCrumb(Stapler.getCurrentRequest2());
  }

  /**
   * The page's static-verb script URL — {@code <root>/plugin/devcru-mfa/
   * mfa-admin.js} (the plugin's webapp resources, the mfa-section.js
   * pattern; Jenkins' CSP script-src 'self' forbids the inline script).
   */
  public String getAdminScriptUrl() {
    return "plugin/devcru-mfa/mfa-admin.js";
  }

  /**
   * One roster row — a plain value bean the jelly reads field-by-field.
   * Nothing in here is a credential; the mailbox is pre-masked.
   */
  public static final class AdminRow {
    private final String userId;
    private final String displayName;
    private final String maskedMail;
    private final boolean hasTotp;
    private final boolean hasEmail;
    private final boolean trustLive;

    AdminRow(String userId, String displayName, String maskedMail,
             boolean hasTotp, boolean hasEmail, boolean trustLive) {
      this.userId = userId;
      this.displayName = displayName;
      this.maskedMail = maskedMail;
      this.hasTotp = hasTotp;
      this.hasEmail = hasEmail;
      this.trustLive = trustLive;
    }

    public String getUserId() {
      return userId;
    }

    public String getDisplayName() {
      return displayName;
    }

    public String getMaskedMail() {
      return maskedMail;
    }

    public boolean isTotp() {
      return hasTotp;
    }

    public boolean isEmail() {
      return hasEmail;
    }

    public boolean isTrustLive() {
      return trustLive;
    }
  }
}
