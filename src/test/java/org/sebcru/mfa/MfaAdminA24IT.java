package org.sebcru.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.Descriptor;
import hudson.model.FreeStyleProject;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.FullControlOnceLoggedInAuthorizationStrategy;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.Permission;
import hudson.security.SidACL;
import hudson.security.AuthorizationStrategy;
import hudson.util.Secret;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import net.sf.json.JSONObject;
import org.acegisecurity.acls.sid.Sid;
import org.acegisecurity.acls.sid.PrincipalSid;
import jenkins.model.Jenkins;
import org.htmlunit.FailingHttpStatusCodeException;
import org.htmlunit.HttpMethod;
import org.htmlunit.WebRequest;
import org.htmlunit.WebResponse;
import org.htmlunit.html.HtmlPage;
import org.htmlunit.util.NameValuePair;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.sebcru.mfa.DevcruMfaConfig.Policy;
import org.sebcru.mfa.email.CaptureEmailSender;
import org.sebcru.mfa.email.EmailCodeIssuer;

/**
 * A24 §7 — the booted integration legs of the force-enrol matrix (spec of
 * record: {@code docs/done/2026-08-25-A24-force-enrol-spec-delta.md} §7
 * items 4–10; all rulings AS RECOMMENDED, 2026-08-25).
 *
 * <h2>Why this file exists</h2>
 * <p>The A24 implementation (PR #28) is seam-pinned
 * ({@code A24ForceEnrolSeamTest}, 10 pins over the pure decision/apply
 * seams) with one booted leg ({@code MfaAdminIT} leg 7, the
 * setup-pending {@code clearFactors} recovery). The seam tests answer
 * "does the decision do what the decision says"; this class answers the
 * booted question for the A24 verb and the first-time setup flow:
 * <ul>
 *   <li><b>Dispatch</b> — {@code @WebMethod(name="forceEnrol")} is the
 *       only routing token (the Task 8 A20 404 lesson); the wire shape is
 *       the real one: crumb from the rendered MFA page
 *       (+ {@code userId} + {@code confirmUserId} [+ {@code email}]).</li>
 *   <li><b>Both authorization chains at the wire</b> — the permission axis
 *       ({@code admin_permission_required}, checked FIRST) and the
 *       credential axis ({@code admin_verification_required}), on the
 *       A24 verb, for the unenrolled admin, the password-only admin, the
 *       unenrolled non-admin, and the fully-VERIFIED non-admin (the
 *       Defect-2 check-order probe).</li>
 *   <li><b>The gate's bounce</b> — a force-enrolled target's LIVE
 *       pre-existing session is bounced to the setup variant on its next
 *       request, and the setup variant is a CLOSED surface (verify form
 *       only; no link escapes it).</li>
 *   <li><b>Persistence</b> — {@code target.save()} writes the marker to
 *       disk (anti-vacuity {@code config.xml} anchor), the marker-clear +
 *       trust grant survive {@code rule.restart()}, and the D16
 *       persistence-failure branch refuses to claim setup completion
 *       over an unpersisted clear.</li>
 *   <li><b>Email delivery</b> — via the {@code CaptureEmailSender}
 *       double (Task 8's seam): codes go to the REGISTERED mailbox only
 *       (the signed no-open-relay decision), and the captured code is the
 *       one that verifies.</li>
 * </ul>
 * <p>Companion to {@code MfaAdminIT}: same house shape (JUnit 5 +
 * {@code @WithJenkins}, per-method helpers, HPSR + FCOL default world,
 * least-privilege {@link SidACL} swap for the privilege axis), new
 * fixtures ({@code target/other/…} ids, new TOTP seeds) so the classes
 * never share boot state.
 *
 * <h2>Red → green history (honest — per run)</h2>
 * <p>New class 2026-08-28, written first-run red-if-genuine per
 * {@code AGENTS.md}; the first run's result is recorded per leg when it
 * lands (plan: {@code docs/plans/2026-08-28-A24-booted-it-matrix.md}).
 */
@WithJenkins
class MfaAdminA24IT {

  private static final String ADMIN_PW = "a24-admin-pw-1";
  private static final String ADMIN_SECRET = "KRSXG5CTMVRXEZLU";
  private static final String TARGET_PW = "a24-target-pw-1";
  private static final String LP_ADMIN_PW = "a24-lpadmin-pw-1";
  private static final String LOWLY_PW = "a24-lowly-pw-1";

  /** 8-char codes from the issuer's unambiguous alphabet (23456789A–Z
   *  minus 0/1/I/O) — for the wrong-code arms; shaped to select the
   *  email factor (8 non-digit chars) so the factor router keys on the
   *  right enrolled factor. */
  private static final String SHAPED_WRONG_CODE = "ABCD2345";

  private String crumbName = "Jenkins-Crumb"; // overwritten from the page below

  // ==================================================================
  // Leg 4 (spec §7.4) — the force-enrol journey with restart: the single
  //   most mutating admin op on this surface, proven end to end at the
  //   wire. (Plus the §7.10 regression half within the leg: admin's own
  //   factors survive.)
  // ==================================================================

  /**
   * WHAT — the A24 force-enrol journey (spec §7.4, red-first where
   * genuine): a verified admin force-enrols a never-enrolled target with
   * a mailbox; the target's LIVE pre-existing session is bounced to the
   * FIRST-TIME SETUP variant on its next request; the setup variant
   * renders (closed surface: verify form, no escape links); an emailed
   * code (captured at the delivery seam, registered mailbox only)
   * completes the setup — and the completion (marker-clear + trust)
   * SURVIVES {@code rule.restart()}: the target's fresh password session
   * then passes the gate on live remembered trust alone, and the admin's
   * own factors show no collateral loss.
   *
   * <pre>
   * GIVEN  HPSR + FCOL; "admin" enrolled TOTP (+ mailbox), logged in and
   *        TOTP-verified this session; "target" a password-only account
   *        whose LIVE session already reached the dashboard (unenrolled,
   *        unbounced)
   * WHEN   the verified admin POSTs forceEnrol(target, email=target@…)
   *        (wire shape: crumb + userId + confirmUserId + email)
   * THEN   200 {ok:true, op:"forceEnrol"}; the target's property is
   *        email-ONLY (registeredEmail set, marker PENDING, no TOTP
   *        factor, NO emailCodeSecret minted — obligation, never proof,
   *        spec §4.1); the on-disk users/&lt;target&gt;/config.xml carries
   *        the registeredEmail AND the forcedSetupPending element — the
   *        anti-vacuity anchor: the enrolment REALLY reached disk
   * WHEN   the target's ORIGINAL session requests the dashboard again
   * THEN   302 Location→/mfa?redirect… — the live session is bounced by
   *        the gate (enrolled, unverified, no trust)
   * WHEN   the bounce is followed
   * THEN   the FIRST-TIME SETUP variant renders: the "Finish MFA setup"
   *        title, the single verify form with #code + a crumb input, and
   *        NO &lt;a href&gt; anywhere in the body — no escape link off the
   *        half-set-up session (spec §7.6 preview; leg 3 pins it deeply)
   * WHEN   the target POSTs postResendEmail (no destination parameter)
   * THEN   200 {ok:true, resent:true}; EXACTLY ONE mail captured,
   *        addressed to the REGISTERED mailbox, carrying an 8-char
   *        alphabet code
   * WHEN   the target POSTs postVerify with that captured code
   * THEN   200 {ok:true, redirect:…}; the marker is CLEARED, the trust
   *        is GRANTED (trustedUntilMs&gt;0), and lastVerifiedFactor==1 —
   *        the EMAIL factor, set by the verify endpoint alone
   * WHEN   the target requests the dashboard again
   * THEN   200 — the verified session passes the gate
   * WHEN   rule.restart() — the instance reloads from disk
   * THEN   the reloaded property: marker STILL cleared (the obligation
   *        did not resurrect), email factor STILL live, trust STILL
   *        &gt;0; the admin's TOTP seed + mailbox reload byte-for-byte
   * WHEN   a FRESH password-only session for the target requests the
   *        dashboard
   * THEN   200 — the gate passes it on LIVE REMEMBERED TRUST alone (no
   *        VERIFIED_ATTR on a fresh session): the setup's trust grant
   *        is what survives, not the verify's session flag
   * WHEN   a fresh verified admin renders the roster
   * THEN   the target sits in the ENROLLED slice (not pending, not the
   *        complement) — the rollout state settled
   * </pre>
   *
   * WHY — this is the op that ENFORCES MFA on someone who has nothing:
   * if any link in the chain regressed (the marker not persisting → the
   * obligation vanishes on restart and the user never sees setup; the
   * trust grant not persisting → the user is bounced forever after
   * completing setup; the session not bouncing → the enrolment is
   * cosmetic; a credential minted by the verb → "obligation, never
   * proof" is violated and the whole threat model leans on a
   * side-channel), the failure is a locked-out user or a silently
   * un-enforced account — the two worst A24 outcomes, and neither is
   * visible to the seam tests, which have no gate, no session, and no
   * disk.
   */
  @Test
  void forceEnrolJourneyWithRestartCompletesSetupEndToEnd(JenkinsRule rule) throws Throwable {
    ensureRealm(rule);
    User admin = enroll(rule, "admin", ADMIN_PW, ADMIN_SECRET);
    admin.getProperty(MfaUserProperty.class).setRegisteredEmail("admin@example.com");
    admin.save();
    User target = createPasswordUser(rule, "target", TARGET_PW);

    // The target's LIVE pre-existing session — unbounced today (unenrolled).
    JenkinsRule.WebClient t = rule.createWebClient();
    t.login("target", TARGET_PW);
    assertEquals(200, t.getPage(rule.getURL()).getWebResponse().getStatusCode(),
        "precondition — the unenrolled target reaches the dashboard before force-enrol");

    // The admin's natural flow: login → verify TOTP → the verb at the wire.
    JenkinsRule.WebClient a = rule.createWebClient();
    a.login("admin", ADMIN_PW);
    verifyTotp(a, rule, "admin", ADMIN_SECRET);

    // (a) The verb: wire shape crumb + userId + confirmUserId + email.
    JSONObject enrol = postAdminWith(a, rule, "forceEnrol", 200,
        field("userId", target.getId()), field("confirmUserId", target.getId()),
        field("email", "target@example.com"));
    assertTrue(enrol.optBoolean("ok"), "the verified admin's forceEnrol must succeed: " + enrol);
    assertEquals("forceEnrol", enrol.optString("op"),
        "success envelope carries the op token the wire contract pins: " + enrol);

    MfaUserProperty tp = target.getProperty(MfaUserProperty.class);
    assertNotNull(tp, "forceEnrol must create the target's property (the one sanctioned getOrCreate)");
    assertEquals("target@example.com", tp.getRegisteredEmail(), "the mailbox is provisioned verbatim");
    assertTrue(tp.isForcedSetupPending(), "the obligation marker must be PENDING");
    assertFalse(tp.hasTotpFactor(), "forceEnrol provisions EMAIL ONLY — no TOTP seed");
    assertNull(tp.getEmailCodeSecret(), "obligation, never proof (spec §4.1): NO credential may be minted by the verb");
    assertEquals(0L, tp.getTrustedUntilMs(), "forceEnrol grants NO trust");

    // (a-anchor) ANTI-VACUITY: the enrolment persisted to DISK before any
    // restart-dependent assertion runs (the house rule, per MfaAdminIT
    // leg 6's disk-anchor pattern).
    File targetXml = new File(userDir(rule, target.getId()), "config.xml");
    assertTrue(targetXml.exists(), "target.save() must materialise the user's config.xml: " + targetXml);
    String disk = java.nio.file.Files.readString(targetXml.toPath());
    assertTrue(disk.contains("target@example.com"),
        "the on-disk config.xml must carry the provisioned mailbox (disk truth, not memory)");
    assertTrue(disk.contains("forcedSetupPending"),
        "the on-disk config.xml must carry the forcedSetupPending element — the obligation reached disk");

    // (b) The target's LIVE session is now bounced by the gate.
    WebResponse bounced = rawGet(t, rule, "/");
    assertEquals(302, bounced.getStatusCode(),
        "the target's pre-existing session must be bounced by the gate after force-enrol: "
            + bounced.getStatusCode());
    assertTrue(isMfaRedirect(bounced),
        "the bounce must target the MFA page (the setup variant lives here): "
            + bounced.getResponseHeaderValue("Location"));

    // (c) The setup variant renders — and is a CLOSED surface.
    String setupHtml = followToMfaPage(t, rule).getWebResponse().getContentAsString();
    assertTrue(setupHtml.contains("Finish MFA setup"),
        "the first-time-setup variant title must render: " + head(setupHtml));
    assertTrue(setupHtml.contains("verifyForm") && setupHtml.contains("id=\"code\""),
        "the verify form (#code) must render on the setup variant");
    assertTrue(setupHtml.indexOf("<a href") == -1 && setupHtml.indexOf("<a  href") == -1,
        "the setup variant must carry NO escape links (it is the only door out): " + head(setupHtml));

    // (d) The code is ISSUED to the registered mailbox only (capture double
    // wired into the live controller — Task 8's seam).
    MfaController controller = Jenkins.get().getExtensionList(MfaController.class).get(0);
    CaptureEmailSender cap = new CaptureEmailSender();
    controller.setSenderForTest(cap);
    JSONObject resent = postMfaProfile(rule, t, "postResendEmail");
    assertTrue(resent.optBoolean("ok") && resent.optBoolean("resent"),
        "postResendEmail must issue the code: " + resent);
    assertTrue(cap.exactlyOne(),
        "exactly ONE mail, to the REGISTERED mailbox (no-open-relay decision): " + cap.sent());
    assertEquals("target@example.com", cap.last().to(), "the mail destination must be the registered mailbox");
    String code = cap.last().code();
    assertEquals(EmailCodeIssuer.CODE_LENGTH, code.length(), "8-char code: " + code);

    // (e) The captured code completes the setup.
    JSONObject verified = postMfaProfile(rule, t, "postVerify", field("code", code));
    assertTrue(verified.optBoolean("ok"), "the emailed code must verify: " + verified);
    MfaUserProperty tpAfter = target.getProperty(MfaUserProperty.class);
    assertFalse(tpAfter.isForcedSetupPending(), "a successful verification CLEARS the marker (D10)");
    assertTrue(tpAfter.hasEmailFactor(), "the email factor survives setup completion (it IS the enrolled factor)");
    assertTrue(tpAfter.getTrustedUntilMs() > System.currentTimeMillis(),
        "trust is GRANTED on successful setup — the instrument that survives the restart");
    assertEquals(1L, tpAfter.getLastVerifiedFactor(),
        "lastVerifiedFactor==1 (EMAIL) — set by the verify endpoint alone (A8/A24 §7.4)");

    // (f) The verified session now passes the gate.
    assertEquals(200, t.getPage(rule.getURL()).getWebResponse().getStatusCode(),
        "after setup the verified target reaches the dashboard");

    // (g) THE RESTART — the round-trip leg proper.
    rule.restart();

    User targetAfter = User.getById("target", true);
    User adminAfter = User.getById("admin", true);
    assertNotNull(targetAfter, "the target must survive the restart");
    assertNotNull(adminAfter, "the admin must survive the restart");
    MfaUserProperty tpReload = targetAfter.getProperty(MfaUserProperty.class);
    assertFalse(tpReload.isForcedSetupPending(),
        "the cleared marker must NOT resurrect across the restart (the obligation is done)");
    assertEquals("target@example.com", tpReload.getRegisteredEmail(),
        "the provisioned mailbox must survive the restart (the factor is still the enrolled one)");
    assertTrue(tpReload.getTrustedUntilMs() > System.currentTimeMillis(),
        "the trust grant must survive the restart — this is what a fresh session passes on");

    // The admin's own factors: no collateral loss, byte-for-byte.
    MfaUserProperty apre = adminAfter.getProperty(MfaUserProperty.class);
    assertTrue(apre.hasTotpFactor(), "the admin's TOTP factor must survive the restart");
    assertEquals(ADMIN_SECRET, apre.getTotpSecret().getPlainText(),
        "the admin's TOTP seed must reload byte-for-byte across the restart");
    assertEquals("admin@example.com", apre.getRegisteredEmail(),
        "the admin's mailbox must survive the restart");

    // (h) A FRESH password-only session passes the gate on live trust alone.
    JenkinsRule.WebClient fresh = rule.createWebClient();
    fresh.login("target", TARGET_PW);
    assertEquals(200, fresh.getPage(rule.getURL()).getWebResponse().getStatusCode(),
        "after the restart the setup-complete target passes the gate on REMEMBERED TRUST "
            + "(no verified flag on a fresh session) — the trust grant is what persisted");

    // (i) The roster settles: the target is in the ENROLLED slice now.
    JenkinsRule.WebClient a2 = rule.createWebClient();
    a2.login("admin", ADMIN_PW);
    verifyTotp(a2, rule, "admin", ADMIN_SECRET);
    String roster = pageHtmlAdmin(a2, rule);
    String enrolledSlice = sliceBetween(roster, "Enrolled", "Setup pending");
    String pendingSlice = sliceBetween(roster, "Setup pending", "Not enrolled");
    assertTrue(enrolledSlice.contains(target.getId()),
        "the settled target must sit in the ENROLLED slice after the restart: " + head(enrolledSlice));
    assertFalse(pendingSlice.contains(target.getId()),
        "the settled target must have LEFT the setup-pending slice: " + head(pendingSlice));
  }

  // ==================================================================
  // Leg 5 (spec §7.5) — the guard pins at the wire: every denial of the
  //   A24 verb, at every layer, with the stable error string the wire
  //   contract pins, and the target's bytes untouched on each.
  // ==================================================================

  /**
   * WHAT — every denial arm of {@code POST /mfaAdmin/forceEnrol} at the
   * wire (spec §7.5): the self-management refusal (200 envelope per the
   * A22-b house contract), the typed-confirm refusal, the
   * already-enrolled refusal, the password-only-admin 403 (credential
   * axis, {@code admin_verification_required} + no-store/nosniff), and —
   * under the least-privilege strategy — the permission axis
   * ({@code admin_permission_required}) for the unenrolled non-admin AND
   * for the fully-verified non-admin, the latter being the check-order
   * probe: permission is read BEFORE any credential is.
   *
   * <pre>
   * GIVEN  HPSR + FCOL; "admin" enrolled TOTP + mailbox, TOTP-verified
   *        (the permitted actor); "other" enrolled TOTP (an
   *        already-enrolled target); "target" password-only (the would-be
   *        victim of every denied op)
   * WHEN   the verified admin POSTs forceEnrol with userId=<admin's own id>
   * THEN   200 {ok:false, error:"admin_self_management_forbidden"} — the
   *        200-envelope shape the A22-b house contract pins (denials the
   *        actor may legitimately reach answer 200; the 403 is reserved
   *        for the authorization-chain denials) — and the admin's factor
   *        state is byte-identical before/after
   * WHEN   the verified admin POSTs forceEnrol with confirmUserId ≠ userId
   * THEN   200 {ok:false, error:"admin_confirm_required"}; "target"
   *        carries NO MFA material (no seed, mailbox, code secret, trust,
   *        or marker — denied before any read-plane write, let alone the
   *        sanctioned getOrCreate)
   * WHEN   the verified admin POSTs forceEnrol against "other" (TOTP
   *        enrolled, no marker)
   * THEN   200 {ok:false, error:"already_enrolled"}; "other"'s seed,
   *        mailbox, and trust are byte-identical before/after
   * WHEN   (d1) an ENROLLED password-only admin (pwadmin — not verified,
   *        no remember-trust) POSTs forceEnrol(target)
   * THEN   the GATE bounces it: 302, Location targets the MFA page — the
   *        admin surface is NOT gate allow-listed (ruling 1): the
   *        password-only attacker is bounced off the mutation before the
   *        request reaches the controller; "target" carries no MFA
   *        material — the bounce mutated nothing
   * WHEN   (d2) an UNENROLLED admin (admin-nounroll — passes the gate,
   *        reads the roster: read != mutation, ruling 3) POSTs
   *        forceEnrol(target)
   * THEN   403 {ok:false, error:"admin_verification_required"} with
   *        no-store + nosniff headers — the controller's credential seam
   *        (an unenrolled actor holds neither session-verify nor trust);
   *        "target" carries no MFA material
   * WHEN   a LEAST-PRIVILEGE strategy is swapped in (exactly one user —
   *       "lpadmin", unenrolled — holds ADMINISTER; the enrolled,
   *        verified "admin" from above LOSES ADMINISTER under it)
   * THEN   (e1) lpadmin: GET /mfaAdmin still 200 (ruling 3: read ≠
   *        mutation — the unenrolled admin SEES the roster) but
   *        forceEnrol → 403 {ok:false, error:"admin_verification_required"}
   *        (the Ruling-3 credential edge, on the A24 verb)
   * THEN   (e2) the verified "admin" (TOTP-verified THIS session but no
   *        ADMINISTER) → 403 {ok:false, error:"admin_permission_required"}
   *        — NOT admin_verification_required: the PERMISSION axis is
   *        read first, so a fully-verified non-admin learns it is a
   *        privilege denial. The check-order probe: only the Defect-2
   *        (root-ACL) seam survives it — the old User.getACL()
   *        self-grant would have reported the permission as present and
   *        fallen through to the credential axis.
   * THEN   (e3) an unenrolled non-admin "lowly" (no factors, no
   *        ADMINISTER) → 403 {ok:false, error:"admin_permission_required"};
   *        "target" still carries no property
   * </pre>
   *
   * WHY — the A24 verb is the one op that creates an obligation on
   * another user; every arm of its denial is a security property at the
   * wire. A self-management leak is an A23-class self-service hole on a
   * surface meant to be admin-only; a missing confirm check is a
   * click-jack vector (the typed-id dialog is UX, the server check is
   * the control); a verified-non-admin falling to the CREDENTIAL reason
   * would mean the permission axis regressed past the credential axis —
   * the exact order the spec §4 pins as "permission first, because it is
   * the coarser, cheaper, and more honest denial".
   */
  @Test
  void guardPinsDenyTheForceEnrolVerbAtTheWire(JenkinsRule rule) throws Exception {
    ensureRealm(rule);
    User admin = enroll(rule, "admin", ADMIN_PW, ADMIN_SECRET);
    admin.getProperty(MfaUserProperty.class).setRegisteredEmail("admin@example.com");
    admin.save();
    User other = enroll(rule, "other", "other-pw-1", "JBSWY3DPEHPK3PXP");
    other.getProperty(MfaUserProperty.class).setRegisteredEmail("other@example.com");
    other.save();
    User target = createPasswordUser(rule, "target", TARGET_PW);
    // The pin-(d) actor: enrolled (TOTP) but has NEVER verified, so holds no
    // "remember" trust. A fresh password session for the verified "admin"
    // above could NOT model this state — that admin's earlier verify
    // persisted a live 720h remember trust, which (correctly) admits a
    // subsequent password-only session. The A23-analogue state needs its own
    // user.
    User pwadmin = enroll(rule, "pwadmin", "pwadmin-pw-1", "JBSWY3DPEHPK3PXP");

    JenkinsRule.WebClient a = rule.createWebClient();
    a.login("admin", ADMIN_PW);
    verifyTotp(a, rule, "admin", ADMIN_SECRET);

    // (a) Self-management refused — the 200-envelope house shape.
    MfaUserProperty adminBefore = admin.getProperty(MfaUserProperty.class);
    JSONObject self = postAdminWith(a, rule, "forceEnrol", 200,
        field("userId", admin.getId()), field("confirmUserId", admin.getId()),
        field("email", "admin@example.com"));
    assertFalse(self.optBoolean("ok"), "self-target must be denied: " + self);
    assertEquals(VerifyOutcome.ERR_ADMIN_SELF_MANAGEMENT, self.optString("error"),
        "the self-management refusal carries the stable string: " + self);
    assertFactorStateByteIdentical(adminBefore, admin.getProperty(MfaUserProperty.class));

    // (b) Typed-confirm mismatch — denied before any write of any kind.
    JSONObject confirm = postAdminWith(a, rule, "forceEnrol", 200,
        field("userId", target.getId()), field("confirmUserId", "nobody"),
        field("email", "target@example.com"));
    assertFalse(confirm.optBoolean("ok"), "the confirm mismatch must be denied: " + confirm);
    assertEquals(VerifyOutcome.ERR_ADMIN_CONFIRM, confirm.optString("error"),
        "the confirm refusal carries the stable string: " + confirm);
    assertMfaMaterialAbsent(User.getById(target.getId(), false),
        "a denied op must mint no MFA material for the target (deny-before-mutation, at the wire)");

    // (c) Already-enrolled target refused; its bytes untouched.
    MfaUserProperty otherBefore = other.getProperty(MfaUserProperty.class);
    JSONObject already = postAdminWith(a, rule, "forceEnrol", 200,
        field("userId", other.getId()), field("confirmUserId", other.getId()),
        field("email", "other@example.com"));
    assertFalse(already.optBoolean("ok"), "an already-enrolled target must be refused: " + already);
    assertEquals(VerifyOutcome.ERR_ALREADY_ENROLLED, already.optString("error"),
        "the already-enrolled refusal carries the stable string: " + already);
    assertFactorStateByteIdentical(otherBefore, other.getProperty(MfaUserProperty.class));

    // (d1) The ENROLLED password-only admin (pwadmin: not verified, no
    // remember-trust) meets the GATE first — the admin surface is not
    // gate allow-listed (ruling 1), so the bounce is a 302 to the MFA
    // page, before the request can reach the controller. Nothing mutates.
    JenkinsRule.WebClient passwordOnly = rule.createWebClient();
    passwordOnly.login(pwadmin.getId(), "pwadmin-pw-1");
    WebResponse bounced = rawPostAdminWith(passwordOnly, rule, "forceEnrol",
        field("userId", target.getId()), field("confirmUserId", target.getId()),
        field("email", "target@example.com"));
    assertEquals(302, bounced.getStatusCode(),
        "the enrolled password-only admin must be bounced by the GATE (the "
            + "admin surface is not allow-listed): " + bounced.getStatusCode()
            + " body=" + bounced.getContentAsString());
    assertTrue(isMfaRedirect(bounced),
        "the gate bounce must target the MFA page: Location="
            + bounced.getResponseHeaderValue("Location"));
    assertMfaMaterialAbsent(User.getById(target.getId(), false),
        "the gate bounce must not have minted any MFA material for the target");

    // (d2) The UNENROLLED admin passes the gate (unenrolled = exempt), reads
    // the roster fine (read != mutation, ruling 3) — but is denied the verb
    // at the controller's credential seam: 403 admin_verification_required.
    User nounroll = createPasswordUser(rule, "admin-nounroll", "nounroll-pw-1");
    JenkinsRule.WebClient noun = rule.createWebClient();
    noun.login("admin-nounroll", "nounroll-pw-1");
    WebResponse rosters = rawGet(noun, rule, "/mfaAdmin");
    for (int h = 0; rosters.getStatusCode() == 302 && h++ < 3; ) {
      rosters = noun.loadWebResponse(new WebRequest(
          hostAbs(rule, rosters.getResponseHeaderValue("Location"))));
    }
    assertEquals(200, rosters.getStatusCode(),
        "the unenrolled admin must READ the roster (ruling 3): " + rosters.getStatusCode());
    assertTrue(rosters.getContentAsString().contains(target.getId()),
        "the roster the unenrolled admin reads must list the target: "
            + rosters.getContentAsString());
    WebResponse denied = rawPostAdminWith(noun, rule, "forceEnrol",
        field("userId", target.getId()), field("confirmUserId", target.getId()),
        field("email", "target@example.com"));
    assertEquals(403, denied.getStatusCode(),
        "the unenrolled admin must get the 403 shape (the credential seam): "
            + denied.getStatusCode() + " body=" + denied.getContentAsString());
    assertTrue(denied.getContentAsString().contains(VerifyOutcome.ERR_ADMIN_VERIFICATION_REQUIRED),
        "the 403 body carries the credential-axis reason: " + denied.getContentAsString());
    assertNotNull(denied.getResponseHeaderValue("Cache-Control"), "the 403 must be no-store");
    assertTrue(denied.getResponseHeaderValue("Cache-Control").contains("no-store"),
        "the 403 must carry no-store: " + denied.getResponseHeaderValue("Cache-Control"));
    assertEquals("nosniff", denied.getResponseHeaderValue("X-Content-Type-Options"),
        "the 403 must carry nosniff");
    assertMfaMaterialAbsent(User.getById(target.getId(), false),
        "the 403 is before any mutation — the target carries no MFA material");

    // (e) The permission axis under a least-privilege strategy. FCOL makes
    // everyone an admin, so the one axis FCOL cannot produce gets its own
    // world: exactly "lpadmin" holds ADMINISTER.
    AuthorizationStrategy previous = rule.jenkins.getAuthorizationStrategy();
    rule.jenkins.setAuthorizationStrategy(
        new LeastPrivilegeAdministerStrategy("lpadmin", LP_ADMIN_PW, rule));
    try {
      // (e1) The unenrolled lpadmin: READS the roster (ruling 3) but the
      // credential axis denies the verb.
      User lpadmin = createPasswordUser(rule, "lpadmin", LP_ADMIN_PW);
      JenkinsRule.WebClient lpa = rule.createWebClient();
      lpa.login("lpadmin", LP_ADMIN_PW);
      String page = pageHtmlAdmin(lpa, rule);
      assertTrue(page.contains("Setup pending"),
          "the unenrolled lpadmin must still READ the roster (ruling 3: read ≠ mutation): "
              + head(page));
      WebResponse lpaDenied = rawPostAdminWith(lpa, rule, "forceEnrol",
          field("userId", target.getId()), field("confirmUserId", target.getId()),
          field("email", "target@example.com"));
      assertEquals(403, lpaDenied.getStatusCode(),
          "the unenrolled admin must get the 403 on the verb: " + lpaDenied.getStatusCode());
      assertTrue(lpaDenied.getContentAsString().contains(VerifyOutcome.ERR_ADMIN_VERIFICATION_REQUIRED),
          "the unenrolled admin's denial is the CREDENTIAL reason (ruling-3 edge): "
              + lpaDenied.getContentAsString());

      // (e2) THE CHECK-ORDER PROBE: "admin" is enrolled AND TOTP-verified
      // this session (the client logged in + verified before the strategy
      // swap; the session's VERIFIED_ATTR survives) but holds NO
      // ADMINISTER under the new strategy.
      WebResponse verifiedNonAdmin = rawPostAdminWith(a, rule, "forceEnrol",
          field("userId", target.getId()), field("confirmUserId", target.getId()),
          field("email", "target@example.com"));
      assertEquals(403, verifiedNonAdmin.getStatusCode(),
          "the verified non-admin must still be denied: " + verifiedNonAdmin.getStatusCode());
      assertTrue(verifiedNonAdmin.getContentAsString().contains(VerifyOutcome.ERR_ADMIN_PERMISSION),
          "a fully-verified non-admin must learn it is a PERMISSION denial (permission axis "
              + "first — the Defect-2 check-order probe on the A24 verb): "
              + verifiedNonAdmin.getContentAsString());
      assertFalse(verifiedNonAdmin.getContentAsString().contains(VerifyOutcome.ERR_ADMIN_VERIFICATION_REQUIRED),
          "…and NOT the credential reason: " + verifiedNonAdmin.getContentAsString());

      // (e3) The plain unenrolled non-admin.
      User lowly = createPasswordUser(rule, "lowly", LOWLY_PW);
      JenkinsRule.WebClient lowlyC = rule.createWebClient();
      lowlyC.login("lowly", LOWLY_PW);
      WebResponse lowlyDenied = rawPostAdminWith(lowlyC, rule, "forceEnrol",
          field("userId", target.getId()), field("confirmUserId", target.getId()),
          field("email", "target@example.com"));
      assertEquals(403, lowlyDenied.getStatusCode(),
          "the unenrolled non-admin must get the 403: " + lowlyDenied.getStatusCode());
      assertTrue(lowlyDenied.getContentAsString().contains(VerifyOutcome.ERR_ADMIN_PERMISSION),
          "…with the PERMISSION reason: " + lowlyDenied.getContentAsString());
      assertMfaMaterialAbsent(User.getById(target.getId(), false),
          "none of the denied ops may have minted any MFA material for the target");
    } finally {
      rule.jenkins.setAuthorizationStrategy(previous);
    }
  }

  // ==================================================================
  // Leg 6+7 (spec §7.6 + §7.7) — the setup variant is a closed surface
  //   AND the pending-state machine (idempotence, correction) holds at
  //   the wire.
  // ==================================================================

  /**
   * WHAT — the setup variant as a closed surface (spec §7.6) plus the
   * pending-state machine at the wire (spec §7.7): the rendered setup
   * page offers exactly the verify form (one form, no links); a direct
   * fetch of protected content from the half-set-up session is still
   * gated; a same-address repeat forceEnrol is UNCHANGED (D5
   * idempotence: no second write, no second candidate, no credential
   * minted); a different address CORRECTS (D5: new mailbox live, marker
   * still pending, the OLD address's pending code is invalidated); the
   * pending row sits in the pending slice — never the enrolled slice —
   * because the marker outranks {@code isMfaEnabled()}.
   *
   * <pre>
   * GIVEN  HPSR + FCOL; verified "admin"; "target" force-enrolled at
   *        mailbox A (pending), whose session is on the setup variant
   * WHEN   the rendered setup page is inspected
   * THEN   exactly ONE &lt;form in the body, no &lt;a href anywhere, the
   *        "Finish MFA setup" title — the variant is closed
   * WHEN   the half-set-up session directly GETs the dashboard AND a
   *        protected job page
   * THEN   both 302 to the MFA page — the setup variant offers NO door
   *        to authenticated content (spec §7.6)
   * WHEN   the verified admin POSTs forceEnrol(target, A) AGAIN (same
   *        address, case-insensitively equal)
   * THEN   200 {ok:true, op:"forceEnrol"} (UNCHANGED short-circuit, D5);
   *        EXACTLY ONE mail captured in total (the first issue); the
   *        property's pendingCodeHash/issued-at untouched; NO
   *        emailCodeSecret minted by either call; trust still 0
   * WHEN   a code is issued at A, THEN forceEnrol(target, B) (B ≠ A)
   * THEN   200 ok — CORRECT: the mailbox is now B, the marker is STILL
   *        pending, and the code mailed to A CANNOT complete the setup:
   *        verifying it answers {ok:false, error:"no_pending_code"}
   *        (the old-address pending state was invalidated at the
   *        correction — D5)
   * WHEN   the roster renders
   * THEN   the target sits in the SETUP-PENDING slice (with the
   *        clearFactors recovery action) and NOT in the ENROLLED slice —
   *        the marker outranks isMfaEnabled() (spec §7 unit criterion 2,
   *        at the wire)
   * </pre>
   *
   * WHY — the setup variant is the one page a half-authenticated user
   * occupies; a link out of it is a broken-gate vector (an enrolled,
   * unverified session reaching root content is MFA defeated). The
   * idempotence/correction pins protect the admin from two realistic
   * mistakes: double-clicking force-enrol (must be a no-op, not a second
   * candidate or a second credential), and a typo'd address (the
   * correction must move the obligation to the new box and void the old
   * box's code — otherwise a code mailed to the wrong address completes
   * setup on the old one and the user is stranded on a mailbox they
   * don't check).
   */
  @Test
  void setupVariantIsClosedAndThePendingStateMachineHoldsAtTheWire(JenkinsRule rule) throws Exception {
    ensureRealm(rule);
    User admin = enroll(rule, "admin", ADMIN_PW, ADMIN_SECRET);
    admin.getProperty(MfaUserProperty.class).setRegisteredEmail("admin@example.com");
    admin.save();
    createPasswordUser(rule, "target", TARGET_PW);
    rule.createProject(FreeStyleProject.class, "a24-protected-job");

    JenkinsRule.WebClient a = rule.createWebClient();
    a.login("admin", ADMIN_PW);
    verifyTotp(a, rule, "admin", ADMIN_SECRET);

    MfaController controller = Jenkins.get().getExtensionList(MfaController.class).get(0);
    CaptureEmailSender cap = new CaptureEmailSender();
    controller.setSenderForTest(cap);

    // Force-enrol at mailbox A.
    JSONObject enrol = postAdminWith(a, rule, "forceEnrol", 200,
        field("userId", "target"), field("confirmUserId", "target"),
        field("email", "a-target@example.com"));
    assertTrue(enrol.optBoolean("ok"), "the initial force-enrol must succeed: " + enrol);

    // (a)+(b) The closed-surface pins.
    JenkinsRule.WebClient t = rule.createWebClient();
    t.login("target", TARGET_PW);
    assertTrue(isMfaRedirect(rawGet(t, rule, "/")),
        "precondition — the pending target's session is gated on the dashboard");
    String setup = followToMfaPage(t, rule).getWebResponse().getContentAsString();
    assertEquals(1, setup.split("<form", -1).length - 1,
        "the setup variant must render EXACTLY one form (the verify form): " + head(setup));
    assertTrue(setup.indexOf("<a href") == -1, "no links of any kind on the setup variant");
    assertTrue(setup.contains("Finish MFA setup"), "the setup title renders");
    assertTrue(isMfaRedirect(rawGet(t, rule, "/")), "dashboard direct-fetch: still gated");
    assertTrue(isMfaRedirect(rawGet(t, rule, "job/a24-protected-job/")),
        "a protected path direct-fetch from the half-set-up session: still gated (spec §7.6)");

    // (c) D5 idempotence: same-address repeat is UNCHANGED — no second
    // candidate, no credential, one mail in the world.
    JSONObject repeat = postAdminWith(a, rule, "forceEnrol", 200,
        field("userId", "target"), field("confirmUserId", "target"),
        field("email", "A-target@example.com")); // case-variant of the same address
    assertTrue(repeat.optBoolean("ok"), "the same-address repeat must answer ok (UNCHANGED path): " + repeat);
    assertTrue(cap.sent().isEmpty(), "idempotent UNCHANGED mints NOTHING — no mail, no candidate");
    MfaUserProperty tp = User.getById("target", true).getProperty(MfaUserProperty.class);
    assertEquals("a-target@example.com", tp.getRegisteredEmail(), "unchanged: the mailbox is the original (trimmed/case-preserved as stored)");
    assertTrue(tp.isForcedSetupPending(), "unchanged: the marker stays pending");
    assertNull(tp.getPendingCodeHash(), "unchanged: no second candidate minted");
    assertNull(tp.getEmailCodeSecret(), "two admin requests never mint a credential (spec §7.7, D5)");
    assertEquals(0L, tp.getTrustedUntilMs(), "…and never grant trust");

    // (d) D5 correction: a code issued at A is invalidated by the move to B.
    JSONObject issued = postMfaProfile(rule, t, "postResendEmail");
    assertTrue(issued.optBoolean("resent"), "a code must be issuable to the pending user: " + issued);
    assertEquals(1, cap.sent().size(), "the issue went to the registered mailbox (A): " + cap.sent());
    String codeAtA = cap.last().code();
    JSONObject correct = postAdminWith(a, rule, "forceEnrol", 200,
        field("userId", "target"), field("confirmUserId", "target"),
        field("email", "b-target@example.com"));
    assertTrue(correct.optBoolean("ok"), "the correction must succeed: " + correct);
    MfaUserProperty tpCorrected = User.getById("target", true).getProperty(MfaUserProperty.class);
    assertEquals("b-target@example.com", tpCorrected.getRegisteredEmail(),
        "correction: the obligation moved to the new mailbox");
    assertTrue(tpCorrected.isForcedSetupPending(),
        "correction: the marker STAYS pending — still an obligation, now at the new box");
    assertNull(tpCorrected.getPendingCodeHash(),
        "correction invalidates the OLD address's pending-code state (D5)");
    JSONObject oldCodeAtNewOwner = postMfaProfile(rule, t, "postVerify", field("code", codeAtA));
    assertFalse(oldCodeAtNewOwner.optBoolean("ok"),
        "the code mailed to the OLD address must NOT complete setup: " + oldCodeAtNewOwner);
    assertEquals(VerifyOutcome.ERR_NO_PENDING, oldCodeAtNewOwner.optString("error"),
        "…with the stable no-pending reason: " + oldCodeAtNewOwner);
    JSONObject reissued = postMfaProfile(rule, t, "postResendEmail");
    assertTrue(reissued.optBoolean("resent"), "a fresh code is issuable at the new mailbox: " + reissued);
    assertEquals("b-target@example.com", cap.last().to(),
        "the re-issued code goes to the CORRECTED mailbox (the registered one)");

    // (e) Roster-state wire check: pending, not enrolled (marker outranks
    // isMfaEnabled()).
    String roster = pageHtmlAdmin(a, rule);
    String enrolledSlice = sliceBetween(roster, "Enrolled", "Setup pending");
    String pendingSlice = sliceBetween(roster, "Setup pending", "Not enrolled");
    assertFalse(enrolledSlice.contains("target"),
        "a pending user is NEVER in the enrolled slice — the marker outranks isMfaEnabled(): "
            + head(enrolledSlice));
    assertTrue(pendingSlice.contains("data-user-id=\"target\""),
        "the pending slice lists the target: " + head(pendingSlice));
    String pendingRow = sliceBetween(pendingSlice, "data-user-id=\"target\"", "</tr>");
    assertTrue(pendingRow.contains("Clear factors"),
        "the pending row exposes the clearFactors recovery action (A24 review fix): "
            + head(pendingRow));
    assertFalse(pendingRow.contains("Force enrol "),
        "the pending row does NOT expose force-enrol again: " + head(pendingRow));
    assertFalse(pendingRow.contains("Revoke trust"),
        "the pending row carries NO enrolled-only actions: " + head(pendingRow));
  }

  // ==================================================================
  // Leg 8 (spec §7.8) — failure honesty at the wire: wrong/expired codes
  //   do not release the user, the cooldown is real, and the D16
  //   persistence-failure branch refuses to claim setup completion.
  // ==================================================================

  /**
   * WHAT — the failure-honesty pins (spec §7.8) at the wire: a wrong
   * code fails without consuming the pending state (the right code still
   * verifies after the miss); an EXPIRED code fails with the real
   * (non-comment-drift) {@code expired} reason, with the obligation
   * still pending; the resend cooldown is enforced (immediate resend →
   * {@code resend_cooldown} + retry seconds); and the D16 persistence
   * failure — a verify that succeeds in memory but cannot PERSIST the
   * marker-clear/trust grant — answers {@code persistence_failed}, grants
   * NO verified session (the bounce stands), and leaves the on-disk
   * obligation intact, after which the retry completes.
   *
   * <pre>
   * GIVEN  HPSR + FCOL; verified "admin"; "t1" force-enrolled at
   *        t1@example.com (pending)
   * WHEN   t1 POSTs postVerify with a well-shaped WRONG 8-char code
   * THEN   200 {ok:false, error:"wrong_code"}; the pending state SURVIVES
   *        the miss (single-use is on CONSUME, not on attempt)
   * THEN   verifying the ISSUED (correct) code succeeds — the miss did
   *        not poison the pending state
   * GIVEN  "t2" force-enrolled at t2@example.com; a code is issued; the
   *        live config's email TTL is set to 1s (the test seam the
   *        A1/A3 policy-flip legs use)
   * WHEN   the code verifies ~1.6s after issue
   * THEN   200 {ok:false, error:"expired"} — the REAL expiry path (the
   *        wire proof the A23-review "EXPIRED comment/code discrepancy"
   *        minor class does not bite this flow), and the marker is STILL
   *        pending — expiry is a failure, not a completion
   * WHEN   t2 immediately POSTs postResendEmail again
   * THEN   200 {ok:false, error:"resend_cooldown"} with retrySeconds&gt;0
   *        (the cooldown is enforced at the wire, not asserted)
   * GIVEN  "t3" force-enrolled at t3@example.com, a code issued, t3's
   *        user dir made read-only AND its config.xml removed (so the
   *        verify-success save CANNOT persist)
   * WHEN   the correct code verifies
   * THEN   200 {ok:false, error:"persistence_failed"} — D16: never claim
   *        setup over an unpersisted marker-clear
   * THEN   the live session is STILL gated (the bounce stands — no
   *        verified session was granted), and the on-disk config.xml is
   *        STILL ABSENT — nothing unpersisted was written
   * WHEN   persistence is restored and the code is re-issued (cooldown
   *        reset via the in-JVM state setter — the time-advance the
   *        IT may legitimately make)
   * THEN   the fresh code verifies ok; the marker clears; trust is
   *        granted; the session passes the gate — the retry completed
   *        what the failure honestly refused to claim
   * </pre>
   *
   * WHY — "works in this session" is not "works": D16 is the
   * implementation of the spec's binding line that a successful
   * verification that cannot persist must NOT mark the session verified
   * — answering ok over an unpersisted marker-clear would let a user
   * finish setup, lose everything on the next restart, and the plugin
   * would have LIED about it (the session works, the disk says pending,
   * and the next login re-prompts setup with the code already gone).
   * The wrong-code and expiry pins close the "failure that releases"
   * class: any path where a failed attempt consumes the pending state
   * or the marker is a user who can finish setup only by begging for a
   * resend they can't see the cooldown of.
   */
  @Test
  void failureHonestyRefusesToClaimSetupOverUnpersistedState(JenkinsRule rule) throws Exception {
    ensureRealm(rule);
    User admin = enroll(rule, "admin", ADMIN_PW, ADMIN_SECRET);
    admin.getProperty(MfaUserProperty.class).setRegisteredEmail("admin@example.com");
    admin.save();
    createPasswordUser(rule, "t1", TARGET_PW);
    createPasswordUser(rule, "t2", "t2-pw-1");
    createPasswordUser(rule, "t3", "t3-pw-1");

    JenkinsRule.WebClient a = rule.createWebClient();
    a.login("admin", ADMIN_PW);
    verifyTotp(a, rule, "admin", ADMIN_SECRET);

    MfaController controller = Jenkins.get().getExtensionList(MfaController.class).get(0);
    CaptureEmailSender cap = new CaptureEmailSender();
    controller.setSenderForTest(cap);

    forceEnrolAt(a, rule, "t1", "t1@example.com");
    forceEnrolAt(a, rule, "t2", "t2@example.com");
    forceEnrolAt(a, rule, "t3", "t3@example.com");

    // (a)+(b) wrong code → the pending state survives the miss.
    JenkinsRule.WebClient t1 = rule.createWebClient();
    t1.login("t1", TARGET_PW);
    JSONObject issued1 = postMfaProfile(rule, t1, "postResendEmail");
    assertTrue(issued1.optBoolean("resent"), "t1's code issues: " + issued1);
    String code1 = cap.last().code();
    JSONObject wrong = postMfaProfile(rule, t1, "postVerify", field("code", SHAPED_WRONG_CODE));
    assertFalse(wrong.optBoolean("ok"), "a well-shaped wrong code must fail: " + wrong);
    assertEquals(VerifyOutcome.ERR_WRONG_CODE, wrong.optString("error"),
        "…with the stable wrong_code reason: " + wrong);
    JSONObject right = postMfaProfile(rule, t1, "postVerify", field("code", code1));
    assertTrue(right.optBoolean("ok"),
        "the miss must NOT have consumed the pending state — the right code still verifies: " + right);
    assertFalse(User.getById("t1", true).getProperty(MfaUserProperty.class).isForcedSetupPending(),
        "t1's setup completed (marker cleared)");

    // (c) expiry — real, at the wire, TTL 1s via the live-config seam.
    JenkinsRule.WebClient t2 = rule.createWebClient();
    t2.login("t2", "t2-pw-1");
    DevcruMfaConfig cfg = DevcruMfaConfig.currentSafe();
    int originalTtl = cfg.getEmailCodeTtlSeconds();
    cfg.setEmailCodeTtlSeconds(1);
    cfg.save();
    try {
      JSONObject issued2 = postMfaProfile(rule, t2, "postResendEmail");
      assertTrue(issued2.optBoolean("resent"), "t2's code issues: " + issued2);
      String code2 = cap.last().code();
      Thread.sleep(1600); // beyond the 1s TTL: the real clock does the work
      JSONObject expired = postMfaProfile(rule, t2, "postVerify", field("code", code2));
      assertFalse(expired.optBoolean("ok"), "an expired code must fail: " + expired);
      assertEquals(VerifyOutcome.ERR_EXPIRED, expired.optString("error"),
          "…with the stable expired reason — the real expiry path, not comment drift: " + expired);
      assertTrue(User.getById("t2", true).getProperty(MfaUserProperty.class).isForcedSetupPending(),
          "expiry is a FAILURE, not a completion — the marker stays pending");

      // (d) the cooldown, enforced at the wire (t2's last resend ≈ now).
      JSONObject tooSoon = postMfaProfile(rule, t2, "postResendEmail");
      assertFalse(tooSoon.optBoolean("ok"), "an immediate resend must cool down: " + tooSoon);
      assertEquals(VerifyOutcome.ERR_COOLDOWN, tooSoon.optString("error"),
          "…with the stable resend_cooldown reason: " + tooSoon);
      assertTrue(tooSoon.optLong("retrySeconds") > 0,
          "the cooldown response carries the countdown: " + tooSoon);
    } finally {
      cfg.setEmailCodeTtlSeconds(originalTtl);
      cfg.save();
    }

    // (e) D16 — the persistence-failure branch, at the wire.
    JenkinsRule.WebClient t3 = rule.createWebClient();
    t3.login("t3", "t3-pw-1");
    JSONObject issued3 = postMfaProfile(rule, t3, "postResendEmail");
    assertTrue(issued3.optBoolean("resent"), "t3's code issues: " + issued3);
    String code3 = cap.last().code();

    // Make the verify-success save UNABLE to persist: remove the
    // config.xml (so save() must CREATE the file) and read-only the user
    // dir (so the create fails with EACCES). Restored in finally.
    File t3dir = userDir(rule, "t3");
    File t3xml = new File(t3dir, "config.xml");
    File[] t3files = t3dir.listFiles();
    if (t3files != null) {
      for (File f : t3files) {
        f.setWritable(true); // ensure a clean removal
      }
    }
    boolean xmlWasThere = t3xml.exists();
    if (!t3xml.delete()) {
      throw new IllegalStateException("could not remove t3's config.xml to arm the D16 failure: " + t3xml);
    }
    t3dir.setReadable(true, false);
    t3dir.setWritable(false);
    try {
      JSONObject pfail = postMfaProfile(rule, t3, "postVerify", field("code", code3));
      assertFalse(pfail.optBoolean("ok"),
          "D16: a verify that cannot persist must NOT answer ok: " + pfail);
      assertEquals(VerifyOutcome.ERR_PERSISTENCE, pfail.optString("error"),
          "…with the stable persistence_failed reason: " + pfail);
      // The faithful D16 gate pin (house MfaAdminIT leg-1 idiom): the gate's
      // step 9 is `sessionVerified || trustLive`, so a REDIRECT proves NEITHER
      // holds — the requester's session was not marked verified AND no live
      // in-memory trust was granted (which would otherwise admit a user whose
      // setup is not on disk). This is the composite the ruling demands:
      // "does not issue a trust/verified-session success" + "leave setup
      // pending until a retry persists."
      assertTrue(isMfaRedirect(rawGet(t3, rule, "/")),
          "D16: the bounce still stands — no verified session, no in-memory "
              + "trust after the failure (gate step 9)");
      assertTrue(!t3xml.exists(),
          "D16: nothing unpersisted was written — the on-disk obligation file is still absent");
    } finally {
      t3dir.setWritable(true);
      t3dir.setReadable(true);
    }
    // (Note: xmlWasThere is informational — after the arm, the file's
    // absence IS the anchor; a later successful save recreates it.)

    // The retry: the code is already consumed in memory by the failed
    // attempt's hash-match (the issuer consumes on match, before the
    // save) — a resend is the documented recovery. Reset the cooldown via
    // the in-JVM state setter (the IT's legitimate time-advance), re-issue,
    // and the completion persists for real.
    User t3user = User.getById("t3", true);
    MfaUserProperty t3p = t3user.getProperty(MfaUserProperty.class);
    t3p.setLastResendAt(0L);
    t3user.save();
    JSONObject reissued3 = postMfaProfile(rule, t3, "postResendEmail");
    assertTrue(reissued3.optBoolean("resent"), "the recovery resend issues: " + reissued3);
    JSONObject completed = postMfaProfile(rule, t3, "postVerify", field("code", cap.last().code()));
    assertTrue(completed.optBoolean("ok"),
        "the retry completes the setup once persistence is restored: " + completed);
    MfaUserProperty t3done = User.getById("t3", true).getProperty(MfaUserProperty.class);
    assertFalse(t3done.isForcedSetupPending(), "the marker cleared — and this time it PERSISTED");
    assertTrue(t3done.getTrustedUntilMs() > System.currentTimeMillis(), "…and the trust is live");
    assertEquals(200, t3.getPage(rule.getURL()).getWebResponse().getStatusCode(),
        "the completed session passes the gate");
  }

  // ==================================================================
  // Leg 9 (spec §7.9) — the policy/identity edges: OFF hides the
  //   complement (not the pending slice), exempt is refused and passed
  //   by the gate, unknown-realm is ENROLLED (D6: refusal is
  //   positive-signal only), and a user deleted between render and POST
  //   lands user_not_found with NO record created on lookup.
  // ==================================================================

  /**
   * WHAT — the A24 edges the seam cannot see (spec §7.9): under policy
   * OFF the gate no longer bounces the pending user AND the admin's
   * NOT-ENROLLED complement is hidden (D9: with the gate off it is a
   * directory, not a worklist) while the SETUP-PENDING slice stays
   * visible (the obligation is honest regardless of enforcement); an
   * EXEMPT user's force-enrol is refused with the stable reason and
   * their gate pass is real; an UNKNOWN-REalm user (no realm signal —
   * never guessed active) is STILL force-enrollable (D6: only a
   * POSITIVE disabled signal refuses) and their row labels {@code
   * unknown}; a user DELETED between the roster render and the POST
   * lands {@code user_not_found} and the lookup creates nothing.
   *
   * <pre>
   * GIVEN  HPSR + FCOL; verified "admin"; "toff" pending at t@…; "exm"
   *        on the exemption list; "unk" a realm-less record (no HPSR
   *        Details); "gone" a password account present at render time
   * WHEN   policy flips to OFF (the live-config seam the A1/A3 legs use)
   * THEN   toff's session reaches the dashboard 200 (the gate is off);
   *        the roster's NOT-ENROLLED section is HIDDEN from the page
   *        while the SETUP-PENDING slice STILL lists toff and the
   *        ENROLLED slice still renders
   * WHEN   policy restores to REQUIRED
   * THEN   toff is bounced again (302) — enforcement re-armed
   * WHEN   the verified admin POSTs forceEnrol(exm)
   * THEN   200 {ok:false, error:"user_exempt"}; exm carries NO property
   *        (denied before the sanctioned getOrCreate); exm's login
   *        reaches the dashboard 200 at all times (the exemption is
   *        live end-to-end)
   * WHEN   the verified admin POSTs forceEnrol(unk, u@…)
   * THEN   200 ok — D6: an unknown account state is NOT a disabled one;
   *        the refusal is positive-signal only (a stock server cannot
   *        positively disable an HPSR record, so unknown ≠ blocked)
   * THEN   the rendered row carries the "unknown" account label —
   *        honest, never guessed
   * WHEN   "gone" (present in the rendered complement) is deleted
   *        in-JVM before the POST
   * THEN   200 {ok:false, error:"user_not_found"}; User.getById("gone",
   *        false) is still null — the lookup is read-only even on the
   *        miss (spec §5: the read plane never writes)
   * </pre>
   *
   * WHY — these edges are where a fleet admin's intuition and the
   * enforcement model meet: with the gate OFF the worklist must not turn
   * into a directory of force-enrol-able people (D9 — the complement
   * exists to find WHO to enforce, and enforcement is what it enforces
   * for); the exemption list is a signed carve-out (CI tokens, service
   * accounts) and a leaked force-enrol path would defeat it; a user whose
   * realm signal cannot be resolved must be force-enrollable-but-labelled
   * (otherwise every user on an unusual realm is silently un-enrollable,
   * which is a fleet-deployment blind spot D6 exists to close); and a
   * render-then-delete gap that created a record on lookup would be a
   * phantom-user vector — a user that exists for MFA and for nothing
   * else, mintable by an admin click on someone who is already gone.
   */
  @Test
  void policyAndIdentityEdgesBehavePerRulings(JenkinsRule rule) throws Exception {
    ensureRealm(rule);
    User admin = enroll(rule, "admin", ADMIN_PW, ADMIN_SECRET);
    admin.getProperty(MfaUserProperty.class).setRegisteredEmail("admin@example.com");
    admin.save();
    createPasswordUser(rule, "toff", "toff-pw-1");
    createPasswordUser(rule, "exm", "exm-pw-1");
    createPasswordUser(rule, "gone", "gone-pw-1");
    // "unk": a realm-less record — created through the id-based factory,
    // then stripped of the HPSR Details property HPSR attaches at
    // creation (no public removeProperty; the properties map is the
    // documented write path), so accountStateOf() has no realm signal
    // to resolve.
    User unk = User.getOrCreateByIdOrFullName("unk");
    if (unk.getProperty(HudsonPrivateSecurityRealm.Details.class) != null) {
      unk.getProperties().remove(HudsonPrivateSecurityRealm.Details.class);
      unk.save();
    }

    JenkinsRule.WebClient a = rule.createWebClient();
    a.login("admin", ADMIN_PW);
    verifyTotp(a, rule, "admin", ADMIN_SECRET);
    forceEnrolAt(a, rule, "toff", "toff@example.com");

    JenkinsRule.WebClient toff = rule.createWebClient();
    toff.login("toff", "toff-pw-1");
    assertTrue(isMfaRedirect(rawGet(toff, rule, "/")),
        "precondition — the pending toff is gated under REQUIRED");

    // (a) Policy OFF: the gate stands down; the complement hides; the
    // pending slice stays.
    DevcruMfaConfig cfg = DevcruMfaConfig.currentSafe();
    Policy original = cfg.getPolicy();
    cfg.setPolicy(Policy.OFF);
    cfg.save();
    try {
      assertEquals(200, toff.getPage(rule.getURL()).getWebResponse().getStatusCode(),
          "policy OFF: the pending user is no longer bounced (the gate is a setting, not a wall)");
      String page = pageHtmlAdmin(a, rule);
      int notEnrolledIdx = page.indexOf("Not enrolled");
      assertEquals(-1, notEnrolledIdx,
          "policy OFF: the NOT-ENROLLED complement is HIDDEN (D9: a directory is not a worklist): "
              + head(page));
      assertTrue(sliceBetween(page, "Setup pending", "Not enrolled").contains("data-user-id=\"toff\"")
          || page.contains("data-user-id=\"toff\""),
          "policy OFF: the SETUP-PENDING slice stays visible (the obligation is honest): " + head(page));
    } finally {
      cfg.setPolicy(original);
      cfg.save();
    }
    assertTrue(isMfaRedirect(rawGet(toff, rule, "/")),
        "policy restored: the pending user is bounced again");

    // (b) Exempt: refused at the verb, passed by the gate, end to end.
    String originalExempt = cfg.getExemptUsers();
    cfg.setExemptUsers("exm");
    cfg.save();
    try {
      JenkinsRule.WebClient exm = rule.createWebClient();
      exm.login("exm", "exm-pw-1");
      assertEquals(200, exm.getPage(rule.getURL()).getWebResponse().getStatusCode(),
          "the exempt user reaches the dashboard (the exemption is live)");
      JSONObject exemptDenied = postAdminWith(a, rule, "forceEnrol", 200,
          field("userId", "exm"), field("confirmUserId", "exm"),
          field("email", "exm@example.com"));
      assertFalse(exemptDenied.optBoolean("ok"), "force-enrolling an exempt user must be refused: " + exemptDenied);
      assertEquals(VerifyOutcome.ERR_USER_EXEMPT, exemptDenied.optString("error"),
          "…with the stable user_exempt reason: " + exemptDenied);
      assertMfaMaterialAbsent(User.getById("exm", false),
          "the refusal is before the sanctioned getOrCreate — no MFA material is minted");
    } finally {
      cfg.setExemptUsers(originalExempt);
      cfg.save();
    }

    // (c) Unknown-realm: force-ENROLLABLE (D6), labelled unknown.
    JSONObject unkEnrol = postAdminWith(a, rule, "forceEnrol", 200,
        field("userId", "unk"), field("confirmUserId", "unk"),
        field("email", "unk@example.com"));
    assertTrue(unkEnrol.optBoolean("ok"),
        "D6: an unknown account state is NOT disabled — the enrolment proceeds: " + unkEnrol);
    MfaUserProperty unkP = User.getById("unk", true).getProperty(MfaUserProperty.class);
    assertTrue(unkP != null && unkP.isForcedSetupPending(), "the unk record carries the obligation");
    String edgePage = pageHtmlAdmin(a, rule);
    assertTrue(edgePage.contains("acct-unknown"),
        "the unk row carries the 'unknown' account label (never guessed active): " + head(edgePage));

    // (d) Deleted between render and POST: user_not_found, nothing created.
    String rendered = pageHtmlAdmin(a, rule);
    // The rendered row starts <tr data-display="gone" data-user-id="gone"
    // data-acct-state=...> (attribute order per jelly) — anchor on the
    // stable data-user-id token inside the rendered Not-enrolled slice.
    String goneSlice = rendered.substring(
        rendered.indexOf("<h2 class=\"section-h\">Not enrolled"));
    String goneRow = sliceBetween(goneSlice, "data-user-id=\"gone\"", "</tr>");
    assertTrue(goneRow.contains("forceEnrol") && goneRow.contains("Force enrol"),
        "precondition — 'gone' is in the rendered complement with its force-enrol action: "
            + head(goneRow));
    User.getById("gone", false).delete();
    JSONObject goneDenied = postAdminWith(a, rule, "forceEnrol", 200,
        field("userId", "gone"), field("confirmUserId", "gone"),
        field("email", "gone@example.com"));
    assertFalse(goneDenied.optBoolean("ok"), "a deleted target must be refused: " + goneDenied);
    assertEquals(VerifyOutcome.ERR_USER_NOT_FOUND, goneDenied.optString("error"),
        "…with the stable user_not_found reason: " + goneDenied);
    assertNull(User.getById("gone", false),
        "the lookup creates NOTHING on the miss (the read plane is get-only, spec §5)");
  }

  // ==================================================================
  // Helpers (self-contained, house IT shape per MfaAdminIT/MfaFilterIT).
  // ==================================================================

  /** HPSR + FCOL world (the house IT shape — every logged-in user is
   * ADMINISTER, so the credential axis is what the FCOL legs exercise). */
  private HudsonPrivateSecurityRealm ensureRealm(JenkinsRule rule) {
    Jenkins j = Jenkins.get();
    if (j.getSecurityRealm() instanceof HudsonPrivateSecurityRealm realm) {
      j.setAuthorizationStrategy(new FullControlOnceLoggedInAuthorizationStrategy());
      return realm;
    }
    HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false); // no signup
    j.setSecurityRealm(realm);
    j.setAuthorizationStrategy(new FullControlOnceLoggedInAuthorizationStrategy());
    return realm;
  }

  /** Create a password user with NO MFA factor (the force-enrol victim
   * / the unenrolled non-admin). */
  private User createPasswordUser(JenkinsRule rule, String name, String pw) throws IOException {
    HudsonPrivateSecurityRealm realm = (HudsonPrivateSecurityRealm) rule.jenkins.getSecurityRealm();
    User u = realm.createAccount(name, pw);
    u.save();
    return u;
  }

  /** Create a password user and enrol TOTP (the admin shape). */
  private User enroll(JenkinsRule rule, String name, String pw, String secret) throws IOException {
    HudsonPrivateSecurityRealm realm = (HudsonPrivateSecurityRealm) rule.jenkins.getSecurityRealm();
    User u = realm.createAccount(name, pw);
    MfaUserProperty p = MfaUserProperty.getOrCreate(u);
    p.setTotpSecret(Secret.fromString(secret));
    u.save();
    return u;
  }

  /** Verify TOTP so the session holds the verified credential. */
  private void verifyTotp(JenkinsRule.WebClient c, JenkinsRule rule, String user, String secret)
      throws Exception {
    byte[] key = org.sebcru.mfa.crypto.Totp.decodeSecret(secret);
    String code = org.sebcru.mfa.crypto.Totp.codeAt(key, System.currentTimeMillis());
    JSONObject j = postMfaProfile(rule, c, "postVerify", field("code", code));
    assertTrue(j.optBoolean("ok"),
        "the TOTP verify (session credential) must succeed: " + j);
  }

  /** POST crumb + userId + confirmUserId + email for the A24 verb. */
  private void forceEnrolAt(JenkinsRule.WebClient a, JenkinsRule rule, String userId, String email)
      throws Exception {
    JSONObject j = postAdminWith(a, rule, "forceEnrol", 200,
        field("userId", userId), field("confirmUserId", userId), field("email", email));
    assertTrue(j.optBoolean("ok"), "force-enrol of " + userId + " must succeed: " + j);
  }

  /** POST a crumb-bearing verb to the admin surface with extra fields;
   * assert the expected HTTP status; return the 200/403 JSON envelope. */
  private JSONObject postAdminWith(JenkinsRule.WebClient c, JenkinsRule rule,
      String endpoint, int expectedStatus, NameValuePair... extra) throws Exception {
    String crumb = mfaCrumb(c, rule);
    WebRequest req = new WebRequest(new URL(rule.getURL(), "mfaAdmin/" + endpoint), HttpMethod.POST);
    List<NameValuePair> params = new ArrayList<>();
    params.add(new NameValuePair(crumbName, crumb));
    for (NameValuePair f : extra) {
      params.add(f);
    }
    req.setRequestParameters(params);
    WebResponse resp;
    try {
      resp = c.loadWebResponse(req);
    } catch (FailingHttpStatusCodeException e) {
      resp = e.getResponse();
    }
    assertEquals(expectedStatus, resp.getStatusCode(),
        endpoint + " must answer " + expectedStatus + ": " + resp.getStatusCode()
            + " body=" + resp.getContentAsString());
    return JSONObject.fromObject(resp.getContentAsString());
  }

  /** The raw-admin POST: stops at the first response (redirect disabled
   * for this request, restored after) — for the legs where the status is
   * the pin. Carries the crumb nonetheless (the A19/house shape: the pin
   * is honest even WITH a valid crumb). */
  private WebResponse rawPostAdminWith(JenkinsRule.WebClient c, JenkinsRule rule,
      String endpoint, NameValuePair... extra) throws Exception {
    String crumb = mfaCrumb(c, rule);
    WebRequest req = new WebRequest(new URL(rule.getURL(), "mfaAdmin/" + endpoint), HttpMethod.POST);
    List<NameValuePair> params = new ArrayList<>();
    params.add(new NameValuePair(crumbName, crumb));
    for (NameValuePair f : extra) {
      params.add(f);
    }
    req.setRequestParameters(params);
    boolean was = c.isRedirectEnabled();
    c.setRedirectEnabled(false);
    try {
      return c.loadWebResponse(req);
    } catch (FailingHttpStatusCodeException e) {
      return e.getResponse();
    } finally {
      c.setRedirectEnabled(was);
    }
  }

  /** POST a crumb-bearing self-service /mfa profile endpoint (no dest
   * parameter — the signed no-destination contract); assert the 200
   * JSON envelope; return it. */
  private JSONObject postMfaProfile(JenkinsRule rule, JenkinsRule.WebClient c, String endpoint,
      NameValuePair... fields) throws Exception {
    String crumb = mfaCrumb(c, rule);
    WebRequest req = new WebRequest(new URL(rule.getURL(), "mfa/" + endpoint), HttpMethod.POST);
    List<NameValuePair> params = new ArrayList<>();
    params.add(new NameValuePair(this.crumbName, crumb));
    for (NameValuePair f : fields) {
      params.add(f);
    }
    req.setRequestParameters(params);
    WebResponse resp;
    try {
      resp = c.loadWebResponse(req);
    } catch (FailingHttpStatusCodeException e) {
      resp = e.getResponse();
    }
    assertEquals(200, resp.getStatusCode(),
        "a /mfa profile endpoint must answer its 200 JSON envelope: " + resp.getStatusCode()
            + " body=" + resp.getContentAsString());
    return JSONObject.fromObject(resp.getContentAsString());
  }

  /** The MFA page crumb — the one page that renders for EVERY session
   * shape (the house helper). */
  private String mfaCrumb(JenkinsRule.WebClient c, JenkinsRule rule) throws Exception {
    WebResponse resp = rawGet(c, rule, "/mfa");
    for (int h = 0; resp.getStatusCode() == 302 && h++ < 3; ) {
      String loc = resp.getResponseHeaderValue("Location");
      resp = c.loadWebResponse(new WebRequest(hostAbs(rule, loc)));
    }
    assertEquals(200, resp.getStatusCode(), "the MFA page must render 200 (crumb source)");
    String flat = resp.getContentAsString().replaceAll("\\s+", " ");
    java.util.regex.Matcher m = java.util.regex.Pattern
        .compile("<input\\s+name=\"([^\"]*[Cc]rumb[^\"]*)\"\\s+[^>]*?value=\"([^\"]*)\"")
        .matcher(flat);
    assertTrue(m.find(), "the MFA page HTML must carry a crumb input: " + flat.substring(0, 400));
    this.crumbName = m.group(1);
    return m.group(2);
  }

  /** GET the rendered /mfaAdmin page's HTML (following redirects to the
   * 200; a 403 body is a failure of this helper's precondition, not a
   * return value — the caller's session must be roster-readable). */
  private String pageHtmlAdmin(JenkinsRule.WebClient c, JenkinsRule rule) throws Exception {
    WebResponse r = rawGet(c, rule, "/mfaAdmin/");
    List<String> hops = new ArrayList<>();
    for (int h = 0; r.getStatusCode() == 302 && h++ < 3; ) {
      String loc = r.getResponseHeaderValue("Location");
      hops.add(r.getStatusCode() + " -> " + loc);
      r = c.loadWebResponse(new WebRequest(hostAbs(rule, loc)));
    }
    assertEquals(200, r.getStatusCode(),
        "the admin page must render 200 (the caller's session reads the roster); chain: "
            + (hops.isEmpty() ? "(direct " + r.getStatusCode() + ")" : String.join("; ", hops)));
    return r.getContentAsString();
  }

  /** A raw GET that stops at the first response (302 not followed) —
   * the A19 discipline. */
  private WebResponse rawGet(JenkinsRule.WebClient c, JenkinsRule rule, String path) throws Exception {
    String r = path.startsWith("/") ? path.substring(1) : path;
    WebRequest req = new WebRequest(new URL(rule.getURL(), r));
    boolean was = c.isRedirectEnabled();
    c.setRedirectEnabled(false);
    try {
      return c.loadWebResponse(req);
    } catch (FailingHttpStatusCodeException e) {
      return e.getResponse();
    } finally {
      c.setRedirectEnabled(was);
    }
  }

  private static boolean isMfaRedirect(WebResponse r) {
    String loc = r.getResponseHeaderValue("Location");
    return r.getStatusCode() == 302 && loc != null && loc.contains("/mfa?");
  }

  /** Follow a gate bounce to the MFA page and return it (200 asserted). */
  private HtmlPage followToMfaPage(JenkinsRule.WebClient c, JenkinsRule rule) throws Exception {
    WebResponse r = rawGet(c, rule, "/");
    assertTrue(isMfaRedirect(r),
        "the session must be gated (302 to the MFA page) before the page can be read: "
            + r.getStatusCode());
    return c.getPage(hostAbs(rule, r.getResponseHeaderValue("Location")));
  }

  /** Resolve an already context-absolute Location to an absolute URL at
   * the host authority (NOT under the context — that would double it). */
  private static URL hostAbs(JenkinsRule rule, String ctxAbsolutePath) throws Exception {
    String b = rule.getURL().toString();
    int slash = b.indexOf("/", b.indexOf("//") + 2);
    String authority = (slash == -1) ? b : b.substring(0, slash);
    String p = ctxAbsolutePath.startsWith("/") ? ctxAbsolutePath : "/" + ctxAbsolutePath;
    return new URL(authority + p);
  }

  /** One NameValuePair shorthand. */
  private static NameValuePair field(String name, String value) {
    return new NameValuePair(name, value);
  }

  /** Resolve the on-disk user directory for the given id (Jenkins
   * sanitises the id — hyphens dropped, hash appended — so match the
   * sanitised prefix; the house helper from MfaAdminIT). */
  private static File userDir(JenkinsRule rule, String userId) {
    String sanitized = userId.replaceAll("[^A-Za-z0-9_]", "");
    File usersRoot = new File(rule.jenkins.getRootDir(), "users");
    File[] dirs = usersRoot.listFiles((d, n) -> n.startsWith(sanitized + "_"));
    assertNotNull(dirs, "the users directory must exist");
    assertEquals(1, dirs.length, "exactly one user directory for " + userId
        + ": " + Arrays.toString(dirs));
    return dirs[0];
  }

  /** The text of the roster section BETWEEN two section headings (the
   * slices: Enrolled / Setup pending / Not enrolled). The last slice goes
   * to the end of the body. Tolerant of the heading markup: finds the
   * heading substring, then the next one. */
  private static String sliceBetween(String page, String fromHeading, String toHeading) {
    int from = page.indexOf(fromHeading);
    assertTrue(from >= 0, "the roster section '" + fromHeading + "' must render on the admin page");
    int to = page.indexOf(toHeading, from + fromHeading.length());
    return to > from ? page.substring(from, to) : page.substring(from);
  }

  /** The target's factor state must be byte-identical before/after a
   * denied op (the deny-before-mutation pin, field by field). */
  /**
   * The deny-before-mutation invariant, expressed honestly: core
   * {@code User.getProperty(Class)} lazily instantiates the property via the
   * descriptor ({@code newInstance(User)}), so "no property at all" is not
   * observable through that accessor — a fresh user reads as carrying an
   * EMPTY {@code MfaUserProperty}. The real security invariant is that a
   * DENIED op mints no MFA material whatsoever: no TOTP seed, no registered
   * mailbox, no per-user code secret, no trust grant, no obligation marker.
   * Null (a descriptor not yet instantiated) satisfies it vacuously.
   */
  private static void assertMfaMaterialAbsent(User u, String msg) {
    MfaUserProperty p = u.getProperty(MfaUserProperty.class);
    if (p == null) {
      return;
    }
    assertFalse(p.hasTotpFactor(), msg + " — a TOTP seed materialised for " + u.getId());
    assertFalse(p.hasEmailFactor(), msg + " — a registered mailbox materialised for " + u.getId());
    assertNull(p.getEmailCodeSecret(), msg + " — a per-user code secret was minted for " + u.getId());
    assertFalse(p.isForcedSetupPending(), msg + " — the obligation marker was set for " + u.getId());
    assertEquals(0L, p.getTrustedUntilMs(), msg + " — a trust grant appeared for " + u.getId());
  }

  private static void assertFactorStateByteIdentical(MfaUserProperty before, MfaUserProperty after) {
    assertNotNull(before, "the target must have a property before the denied op");
    assertNotNull(after, "the target must still have its property after the denied op");
    assertEquals(before.getTotpSecret() == null ? null : before.getTotpSecret().getPlainText(),
        after.getTotpSecret() == null ? null : after.getTotpSecret().getPlainText(),
        "denied op touched the TOTP seed");
    assertEquals(before.getRegisteredEmail(), after.getRegisteredEmail(),
        "denied op touched the registered mailbox");
    assertEquals(before.getEmailCodeSecret() == null ? null : before.getEmailCodeSecret().getPlainText(),
        after.getEmailCodeSecret() == null ? null : after.getEmailCodeSecret().getPlainText(),
        "denied op touched the email-code secret");
    assertEquals(before.getTrustedUntilMs(), after.getTrustedUntilMs(), "denied op touched trust");
    assertFalse(after.isForcedSetupPending() != before.isForcedSetupPending(),
        "denied op touched the forced-setup marker");
  }

  private static String head(String s) {
    return s == null ? "" : s.substring(0, Math.min(400, s.length()));
  }

  /** The LEAST-PRIVILEGE strategy (copied from {@code MfaAdminIT}: the
   * privilege axis is the one axis FCOL cannot produce — FCOL makes
   * every logged-in user an admin). Exactly one user holds
   * {@code ADMINISTER}; every authenticated principal holds READ; all
   * else fails closed. MatrixAuthorizationStrategy is absent from this
   * offline classpath (host fact, verified 2026-08-23), so the hand-
   * rolled SidACL strategy stands in. */
  static final class LeastPrivilegeAdministerStrategy extends AuthorizationStrategy {
    private final String adminUser;

    LeastPrivilegeAdministerStrategy(String adminUser, String adminPwUnused, JenkinsRule ruleUnused) {
      this.adminUser = adminUser;
    }

    @Override
    public ACL getRootACL() {
      return new SidACL() {
        @Override
        protected Boolean hasPermission(Sid sid, Permission p) {
          if (sid instanceof PrincipalSid ps) {
            String u = ps.getPrincipal();
            if (!ACL.ANONYMOUS_USERNAME.equals(u)) {
              if (Jenkins.ADMINISTER.equals(p) && adminUser.equals(u)) {
                return Boolean.TRUE;
              }
              if (Jenkins.READ.equals(p)) {
                return Boolean.TRUE;
              }
            }
          }
          return null; // null → SidACL fails closed → denied.
        }
      };
    }

    @Override
    public Collection<String> getGroups() {
      return Collections.emptyList();
    }

    private static final Descriptor<AuthorizationStrategy> DESCRIPTOR =
        new Descriptor<AuthorizationStrategy>(AuthorizationStrategy.class) {
          @Override
          public String getDisplayName() {
            return "Test least-privilege (A24 IT): one admin user";
          }

          @Override
          public String getId() {
            return "test-least-privilege-administer-a24";
          }
        };

    @Override
    public Descriptor<AuthorizationStrategy> getDescriptor() {
      return DESCRIPTOR;
    }
  }
}
