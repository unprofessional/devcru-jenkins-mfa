package org.sebcru.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.FreeStyleProject;
import hudson.model.User;
import hudson.security.FullControlOnceLoggedInAuthorizationStrategy;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.util.Secret;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.htmlunit.FailingHttpStatusCodeException;
import org.htmlunit.HttpMethod;
import org.htmlunit.WebRequest;
import org.htmlunit.WebResponse;
import org.htmlunit.util.NameValuePair;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.sebcru.mfa.crypto.Totp;

/**
 * Task 9 — the user-facing factor-management IT (Jenkins booted in-JVM).
 *
 * <h2>Why this file exists</h2>
 * <p>The six {@code MfaController} profile endpoints and the section view are
 * only correct when they speak a <em>live booted</em> Jenkins: the section must
 * render inside core's real {@code Manage account → Security} page (a view-path
 * bug there is SILENT — empty section, green build, "the QR never works"), a
 * {@code postEnroll} → {@code postEnrollConfirm} round trip must actually commit
 * the seed to the persisted {@link MfaUserProperty}, a bad confirm must NOT
 * commit, and every one of the six endpoints must be routed (A20). This suite
 * boots a real Jenkins (same mechanics as {@link MfaFilterIT}) and walks those
 * flows end to end.
 *
 * <h2>The single-POST enrolment this pins</h2>
 * <p>Enrolment is "seed + code in ONE POST" ({@code postEnrollConfirm},
 * {@code {seed, code}}): the candidate seed lives only in the form's hidden
 * inputs between {@code postEnroll} ("Generate") and "Confirm"; {@code
 * postEnrollConfirm} verifies the code against that seed and writes the seed to
 * the property ONLY on success. A wrong code must leave the previously-working
 * factor untouched (the self-inflicted-lockout case: "typed a wrong code while
 * testing a second phone" must not clobber the working phone).
 *
 * <h2>Red → green history</h2>
 * <p>The render-presence case (a) is the boot proof against Task 9's named
 * silent-failure mode: a section view at the wrong path renders nothing yet
 * stays green. If a future edit moves the view off the descriptor-relative
 * {@code config.jelly} path, case (a) turns red on the assertion that the
 * {@code <div id="mfaSection">} marker actually appears in core's security page
 * HTML — the one thing the wrong path leaves out.
 */
@WithJenkins
class MfaProfileIT {

  private String crumbName = "Jenkins-Crumb"; // overwritten from the page below

  // ==================================================================
  // Case a — render presence: the section ACTUALLY renders on the live
  //                 security page (the 5.1 silent-failure guard).
  // ==================================================================

  /**
   * WHAT: the security-tab section view — for BOTH an enrolled user (TOTP
   * factor present) and a fresh, not-yet-enrolled user (null bound instance) —
   * renders into core's real {@code Manage account → Security} page, proving
   * the view resolved at the descriptor-relative path and that the null-instance
   * (fresh user) path does not 500 or vanish.
   *
   * <p>BDD:
   * <pre>
   * GIVEN an enrolled TOTP user and, separately, a fresh (no factor) user,
   *       both logged in (FullControlOnceLoggedIn → admin over own profile)
   * WHEN  the security page /user/<id>/security/ is GET
   * THEN  the HTML contains the section marker <div id="mfaSection">
   * AND   the enrolled user's page shows the "Enabled"/disable affordance
   *       (#mfaTotpDisable) while the fresh user's shows the generate
   *       affordance (#mfaTotpGenerate)
   * </pre>
   *
   * <p>WHY/SOLVES: this is the single assertion standing between "the section
   * renders" and "the section is silently empty." The original plan's view
   * path ({@code views/MfaUserProperty.jelly}) would pass every unit test and
   * still leave the tab blank for every real user; only asserting the rendered
   * marker on a booted page catches it. The fresh-user half also proves the
   * instance=null guard (a fresh enrollee's security tab must not 500).
   */
  @Test
  void sectionRendersOnTheSecurityPageForEnrolledAndFreshUsers(JenkinsRule rule) throws Exception {
    String enrolled = "it-prof-enrolled";
    String fresh = "it-prof-fresh";
    String pw = "secret123";
    String enSecret = Totp.newBase32Secret();
    enrollTotp(enrolled, pw, enSecret);
    User fb = ensureRealm().createAccount(fresh, pw); // no factor written
    rule.createProject(FreeStyleProject.class, "it-prof-job");
    URL base = rule.getURL();

    // Enrolled user: the section renders with the TOTP-enabled affordance.
    JenkinsRule.WebClient ce = rule.createWebClient();
    ce.setJavaScriptEnabled(false);
    ce.setThrowExceptionOnFailingStatusCode(false);
    ce.login(enrolled, pw);
    // Enrolled users are gated until they prove a factor — verify the TOTP
    // (the natural self-service flow) so the security-page GET passes.
    verifyTotpToPassGate(ce, base, enrolled, enSecret, "/job/it-prof-job/");
    String hEnrolled = securityPageHtml(ce, base, enrolled);
    assertTrue(hEnrolled.contains("id=\"mfaSection\""),
        "the MFA section must render on the live security page (view-path guard): marker absent:\n"
            + head(hEnrolled));
    assertTrue(hEnrolled.contains("id=\"mfaTotpDisable\""),
        "an enrolled TOTP user must see the disable affordance: " + head(hEnrolled));
    assertFalse(hEnrolled.contains("id=\"mfaTotpGenerate\""),
        "an already-enrolled TOTP user must NOT show generate (it's on already): " + head(hEnrolled));

    // Fresh user: the section still renders (instance=null must not vanish/500).
    JenkinsRule.WebClient cf = rule.createWebClient();
    cf.setJavaScriptEnabled(false);
    cf.setThrowExceptionOnFailingStatusCode(false);
    cf.login(fresh, pw);
    String hFresh = securityPageHtml(cf, base, fresh);
    assertTrue(hFresh.contains("id=\"mfaSection\""),
        "the MFA section must render for a fresh (no factor, null instance) user too: " + head(hFresh));
    assertTrue(hFresh.contains("id=\"mfaTotpGenerate\""),
        "a fresh user must see the generate affordance (not yet enrolled): " + head(hFresh));
    assertFalse(hFresh.contains("id=\"mfaTotpDisable\""),
        "a fresh user must NOT see the disable affordance (nothing to disable): " + head(hFresh));
    MfaUserProperty freshProp = User.getById(fresh, false).getProperty(MfaUserProperty.class);
    assertFalse(freshProp != null && freshProp.hasTotpFactor(),
        "precondition: the fresh user has NO TOTP factor (the generate path is the one to render)");
  }

  // ==================================================================
  // Case b — enrolment round trip: generate → confirm commits;
  //          a bad code does NOT commit (factor left untouched).
  // ==================================================================

  /**
   * WHAT: the single-POST enrolment commit, end to end. {@code postEnroll}
   * returns a fresh seed + otpauth URI + QR data-URI without touching the
   * property; {@code postEnrollConfirm} with a correct {@code Totp.codeAt}
   * commits that exact seed ({@code hasTotpFactor()} true); a confirm with a
   * WRONG code returns {@code wrong_code} and leaves the property's existing
   * factor untouched (no clobber on a failed regenerate).
   *
   * <p>BDD:
   * <pre>
   * GIVEN a fresh user (no TOTP factor yet), logged in, with a security-page
   *       crumb
   * WHEN  postEnroll is POSTed
   * THEN  the JSON is {ok:true, seed, otpauthUri, dataUriPng} and the property
   *       still hasTotpFactor()==false (nothing pre-committed)
   * WHEN  postEnrollConfirm is POSTed with {seed, the correct 6-digit code}
   * THEN  the JSON is {ok:true} AND the persisted property now hasTotpFactor()
   *       true with that EXACT seed
   * GIVEN  (on a user that already has a working factor, see the second phase)
   * WHEN  postEnrollConfirm is POSTed with a fresh candidate seed + a WRONG code
   * THEN  the JSON is {ok:false, error:"wrong_code"} AND the property keeps its
   *       ORIGINAL (working) seed, not the presented candidate
   * </pre>
   *
   * <p>WHY/SOLVES: this is the enrolment's trust anchor, proven live. Committing
   * before verifying would let a session holder pin a factor they cannot prove;
   * a failed confirm clobbering the working seed is a self-inflicted
   * lockout. Only an endpoint round trip with a real TOTP proves the seed is
   * written only after a code is right.
   */
  @Test
  void enrollConfirmRoundTripCommitsOnlyOnACorrectCode(JenkinsRule rule) throws Exception {
    String user = "it-prof-enroll";
    String pw = "secret123";
    ensureRealm().createAccount(user, pw); // fresh, no factor
    rule.createProject(FreeStyleProject.class, "it-prof2-job");
    URL base = rule.getURL();

    JenkinsRule.WebClient c = rule.createWebClient();
    c.setJavaScriptEnabled(false);
    c.setThrowExceptionOnFailingStatusCode(false);
    c.login(user, pw);
    String crumb = securityPageCrumb(c, base, user);

    // -- Generate: returns seed/uri/qr; commits NOTHING.
    JSONObject gen = postMfaProfile(c, base, "postEnroll", crumb);
    assertTrue(gen.optBoolean("ok"), "postEnroll must succeed: " + gen);
    String seed = gen.optString("seed");
    assertTrue(seed.matches("[A-Z2-7]{16,}"),
        "the generated seed is canonical unpadded Base32 (>=16 chars): " + seed);
    assertTrue(gen.optString("otpauthUri").startsWith("otpauth://otp/"),
        "the otpauth URI is well-shaped: " + gen.optString("otpauthUri"));
    assertTrue(gen.optString("dataUriPng").startsWith("data:image/png;base64,"),
        "the QR is a PNG data-URI: " + head(gen.optString("dataUriPng")));
    MfaUserProperty before = MfaUserProperty.getOrCreate(User.getById(user, true));
    assertFalse(before.hasTotpFactor(),
        "postEnroll must NOT commit the seed (single-POST: nothing pre-committed)");

    // -- Confirm with the CORRECT code: commits that exact seed.
    byte[] key = Totp.decodeSecret(seed);
    String goodCode = Totp.codeAt(key, System.currentTimeMillis());
    JSONObject okR = postMfaProfile(c, base, "postEnrollConfirm", crumb,
        new NameValuePair("seed", seed), new NameValuePair("code", goodCode));
    assertTrue(okR.optBoolean("ok"), "a correct-code confirm must succeed: " + okR);
    MfaUserProperty after = User.getById(user, true).getProperty(MfaUserProperty.class);
    assertNotNull(after, "a persisted MfaUserProperty must exist after enrolment");
    assertTrue(after.hasTotpFactor(), "a successful confirm must commit the TOTP factor");
    assertEquals(seed, after.getTotpSecret().getPlainText(),
        "the committed seed is EXACTLY the presented (QR-built) seed, so app and server agree");

    // -- Phase 2: an ALREADY-working user tries a second phone with a WRONG
    //    code for a fresh candidate seed. It must NOT clobber the working one.
    JSONObject gen2 = postMfaProfile(c, base, "postEnroll", crumb);
    assertTrue(gen2.optBoolean("ok"), "a regenerate must succeed: " + gen2);
    String candidate = gen2.optString("seed");
    // A code one step in the FUTURE is still within the window; instead craft a
    // WRONG code explicitly (all zeros) — must not verify against the candidate.
    JSONObject bad = postMfaProfile(c, base, "postEnrollConfirm", crumb,
        new NameValuePair("seed", candidate), new NameValuePair("code", "000000"));
    assertFalse(bad.optBoolean("ok"), "a wrong-code confirm must fail: " + bad);
    assertEquals(VerifyOutcome.ERR_WRONG_CODE, bad.optString("error"),
        "a wrong code reports wrong_code (never invalid_seed for a well-shaped one): " + bad);
    MfaUserProperty intact = User.getById(user, true).getProperty(MfaUserProperty.class);
    assertEquals(seed, intact.getTotpSecret().getPlainText(),
        "a failed confirm must NOT clobber the working factor (self-inflicted-lockout guard): "
            + intact.getTotpSecret().getPlainText());
    // The stored working seed must still verify its own current code (it is live).
    assertTrue(Totp.verify(Totp.decodeSecret(intact.getTotpSecret().getPlainText()),
        goodCode, System.currentTimeMillis(), DevcruMfaConfig.currentSafe().getTotpWindow()),
        "the surviving factor must still be live (verify a current code against it)");
  }

  // ==================================================================
  // Case c — disable/revoke: each endpoint flips exactly the right flag.
  // ==================================================================

  /**
   * WHAT: each of the three state-changing endpoints flips exactly the
   * persisted flag it names and nothing else: {@code postDisableTotp} clears
   * {@code hasTotpFactor()}; {@code postDisableEmail} clears {@code
   * hasEmailFactor()} (and the per-user mail key); {@code postRevokeTrust}
   * zeroes {@code trustedUntilMs}. The same session also pins the A7/A8
   * telemetry wire contract of {@code postVerify}: a wrong code increments
   * {@code failedAttemptStreak}; a succeeding TOTP verify resets the streak to
   * 0 AND overwrites {@code lastVerifiedFactor} with the factor that actually
   * verified (here: TOTP=0, over a fabricated "last verified by email"=1).
   *
   * <p>BDD:
   * <pre>
   * GIVEN an enrolled user (both a TOTP factor and a registered email), a
   *       live trust record, and a fabricated lastVerifiedFactor=1 (email)
   * WHEN  postVerify is POSTed with a WRONG code
   * THEN  {ok:false} AND failedAttemptStreak is 1
   * WHEN  a correct TOTP verify succeeds (passes the gate)
   * THEN  {ok:true} AND failedAttemptStreak is 0 (A7 reset) AND
   *       lastVerifiedFactor is 0 (A8 — the factor that verified, TOTP,
   *       overwrote the fabricated 1)
   * WHEN  postDisableTotp is POSTed
   * THEN  {ok:true} AND hasTotpFactor() is false, registered email INTACT
   * WHEN  postDisableEmail is POSTed
   * THEN  {ok:true} AND hasEmailFactor() is false AND the emailCodeSecret is
   *       retired (null), TOTP factor INTACT
   * WHEN  postRevokeTrust is POSTed
   * THEN  {ok:true} AND trustedUntilMs is 0
   * </pre>
   *
   * <p>WHY/SOLVES: these are the user's recovery levers (lost phone → disable
   * / re-enrol; "log everyone out again" → revoke trust). A handler that hit
   * the wrong field would silently leave a removed factor live or wipe a
   * working one; pinning each endpoint to exactly one flag keeps them
   * surgical. The A7/A8 half is the wire proof for the 2026-08-18 mads ruling
   * ("the clear path resets the streak; the factor UI writes which factor
   * proved"): without a wire pin, a refactor that dropped the reset or
   * recorded the SUBMITTED shape instead of the PROVEN factor would stay
   * green on every unit test and ship a monotonically-growing streak / a
   * lying telemetry field. (The email-proven branch of A8 — index 1 — is the
   * same ternary in postVerify and is not exercised here: it needs a captured
   * mailbox, which the filter IT already covers for the email path.)
   */
  @Test
  void disableAndRevokeEndpointsFlipExactlyTheRightFlags(JenkinsRule rule) throws Exception {
    String user = "it-prof-flip";
    String pw = "secret123";
    String mail = user + "@devcru.example";
    String flipSecret = Totp.newBase32Secret();
    User u = enrollTotp(user, pw, flipSecret);
    MfaUserProperty p = MfaUserProperty.getOrCreate(u);
    p.setRegisteredEmail(mail);
    u.save();
    // Give it a live trust record to revoke.
    p.setTrustedUntilMs(System.currentTimeMillis() + 30L * 24 * 3600 * 1000);
    // FABRICATE an email verification so the A8 assertion is a real change
    // (lastVerifiedFactor 1 -> 0 on a TOTP success), not a no-op 0 -> 0.
    p.setLastVerifiedFactor(1L);
    u.save();
    rule.createProject(FreeStyleProject.class, "it-prof3-job");
    URL base = rule.getURL();

    JenkinsRule.WebClient c = rule.createWebClient();
    c.setJavaScriptEnabled(false);
    c.setThrowExceptionOnFailingStatusCode(false);
    c.login(user, pw);

    // -- A7: a wrong verify increments the failure streak (persisted).
    String crumb0 = mfaCrumb(c, base);
    JSONObject wrong = postMfaProfile(c, base, "postVerify", crumb0,
        new NameValuePair("code", "000000"));
    assertFalse(wrong.optBoolean("ok"), "a wrong verify code must not verify: " + wrong);
    assertEquals(1, User.getById(user, true).getProperty(MfaUserProperty.class).getFailedAttemptStreak(),
        "A7: a failed verify increments persisted failedAttemptStreak");

    // Enrolled user: verify the TOTP (natural flow) so the security page
    // renders (rather than bouncing to /mfa) and its configSubmit form
    // supplies the crumb for the factor-management POSTs.
    verifyTotpToPassGate(c, base, user, flipSecret, "/job/it-prof3-job/");
    // -- A7 reset + A8 write: the success cleared the streak and recorded the
    //    factor that actually verified (TOTP), over the fabricated email=1.
    MfaUserProperty telem = User.getById(user, true).getProperty(MfaUserProperty.class);
    assertEquals(0, telem.getFailedAttemptStreak(),
        "A7: a successful verify resets persisted failedAttemptStreak to 0");
    assertEquals(0L, telem.getLastVerifiedFactor(),
        "A8: lastVerifiedFactor records the factor that VERIFIED (TOTP=0), "
            + "overwriting the fabricated email=1");
    String crumb = securityPageCrumb(c, base, user);

    // -- Revoke trust: zeroes trustedUntilMs, touches no factor.
    JSONObject rev = postMfaProfile(c, base, "postRevokeTrust", crumb);
    assertTrue(rev.optBoolean("ok"), "revoke must succeed: " + rev);
    MfaUserProperty pr = User.getById(user, true).getProperty(MfaUserProperty.class);
    assertEquals(0L, pr.getTrustedUntilMs(), "revoke zeroed the trust record");
    assertTrue(pr.hasTotpFactor(), "revoke must not touch the TOTP factor");

    // -- Disable TOTP: clears the factor, leaves the email factor.
    JSONObject dt = postMfaProfile(c, base, "postDisableTotp", crumb);
    assertTrue(dt.optBoolean("ok"), "disable-totp must succeed: " + dt);
    MfaUserProperty pd = User.getById(user, true).getProperty(MfaUserProperty.class);
    assertFalse(pd.hasTotpFactor(), "disable-totp cleared the TOTP factor");
    assertTrue(pd.hasEmailFactor(), "disable-totp left the email factor intact");

    // -- Disable email: clears the mailbox AND retires the per-user mail key.
    String mailBefore = pd.getRegisteredEmail();
    assertNotNull(mailBefore, "precondition: a registered email existed");
    JSONObject de = postMfaProfile(c, base, "postDisableEmail", crumb);
    assertTrue(de.optBoolean("ok"), "disable-email must succeed: " + de);
    MfaUserProperty pe = User.getById(user, true).getProperty(MfaUserProperty.class);
    assertFalse(pe.hasEmailFactor(), "disable-email cleared the email factor");
    assertTrue(pe.getEmailCodeSecret() == null || pe.getEmailCodeSecret().getPlainText().isEmpty(),
        "disable-email retired the per-user mail key (it is meaningless without a mailbox)");
  }

  // ==================================================================
  // Case d — the six-endpoint 404 guard (A20, boot proof).
  // ==================================================================

  /**
   * WHAT: all six profile endpoints are routed and answer (200), not 404 —
   * the A20 boot guard. A {@code @RequirePOST}-only method (no
   * {@code @WebMethod}) 404s on this Stapler, so a 200 here is proof each
   * carries its routing token on a live instance.
   *
   * <p>BDD:
   * <pre>
   * GIVEN a logged-in enrolled user with a security-page crumb
   * WHEN  each of postEnroll / postEnrollConfirm / postEmailTestCode /
   *       postDisableTotp / postDisableEmail / postRevokeTrust is POSTed
   * THEN  every one answers status 200 (a JSON envelope), never 404
   * </pre>
   *
   * <p>WHY/SOLVES: Task 8 shipped {@code postVerify}/{@code postResendEmail}
   * unroutable until a booted 404 caught them — the annotation alone does
   * nothing; only @WebMethod routes. This is the standing guard that all six
   * of Task 9's endpoints actually resolve on a booted Jenkins, so the
   * section's buttons can never be silently dead.
   */
  @Test
  void allSixProfileEndpointsAreRoutedNot404(JenkinsRule rule) throws Exception {
    String user = "it-prof-404";
    String pw = "secret123";
    enrollTotp(user, pw, Totp.newBase32Secret());
    rule.createProject(FreeStyleProject.class, "it-prof4-job");
    URL base = rule.getURL();

    JenkinsRule.WebClient c = rule.createWebClient();
    c.setJavaScriptEnabled(false);
    c.setThrowExceptionOnFailingStatusCode(false);
    c.login(user, pw);
    String crumb = securityPageCrumb(c, base, user);

    String[] endpoints = {"postEnroll", "postEnrollConfirm", "postEmailTestCode",
        "postDisableTotp", "postDisableEmail", "postRevokeTrust"};
    for (String ep : endpoints) {
      WebRequest req = new WebRequest(href(base, "mfa/" + ep), HttpMethod.POST);
      List<NameValuePair> params = new ArrayList<>();
      params.add(new NameValuePair(crumbName, crumb));
      params.add(new NameValuePair("seed", "ABCDEFGHIJKLMNOP")); // plausible dummy for confirm
      params.add(new NameValuePair("code", "000000"));
      req.setRequestParameters(params);
      WebResponse resp;
      try {
        resp = c.loadWebResponse(req);
      } catch (FailingHttpStatusCodeException e) {
        resp = e.getResponse();
      }
      assertEquals(200, resp.getStatusCode(),
          "endpoint " + ep + " must be routed and answer 200 (A20 guard), not 404/405: "
              + resp.getStatusCode());
      String body = resp.getContentAsString();
      assertTrue(body.contains("\"ok\""),
          "endpoint " + ep + " must answer a JSON {ok...} envelope: " + head(body));
    }
  }

  // ==================================================================
  // Helpers.
  // ==================================================================

  /** Ensure an HPSR realm + FCOL strategy (idempotent). */
  private HudsonPrivateSecurityRealm ensureRealm() {
    Jenkins j = Jenkins.get();
    if (j.getSecurityRealm() instanceof HudsonPrivateSecurityRealm realm) {
      return realm;
    }
    HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false); // no signup
    j.setSecurityRealm(realm);
    j.setAuthorizationStrategy(new FullControlOnceLoggedInAuthorizationStrategy());
    return realm;
  }

  /** Create a password user and enrol TOTP (the property the section renders). */
  private User enrollTotp(String name, String pw, String secret) throws Exception {
    User u = ensureRealm().createAccount(name, pw);
    MfaUserProperty p = MfaUserProperty.getOrCreate(u);
    p.setTotpSecret(Secret.fromString(secret));
    u.save();
    return u;
  }

  /** Context-absolute security-page URL, built context-preserving. */
  private String securityPath(String user) {
    return "/user/" + user + "/security/";
  }

  /**
   * A valid, session-scoped CSRF crumb for the /mfa endpoint POSTs, sourced
   * from the MFA page itself. The /mfa page is ALWAYS allow-listed by the
   * gate (never gated) and ALWAYS renders its verifyForm — for ANY logged-in
   * user, enrolled or fresh — so it is a crumb source that works for every
   * case regardless of gate state. We deliberately do NOT try to read a crumb
   * off the security page: core's f:form does not inject a crumb hidden input
   * (only our hand-written verifyForm has one), which is what the earlier
   * "no crumb hidden input" failures were.
   */
  private String mfaCrumb(JenkinsRule.WebClient c, URL base) throws Exception {
    // Raw GET to the always-allow-listed MFA page. Pass the SITE-RELATIVE
    // path "/mfa" (rawGet→href appends it under the context-bearing base;
    // passing a context-absolute path here would double the context → 404).
    WebResponse resp = rawGet(c, base, "/mfa");
    for (int h = 0; resp.getStatusCode() == 302 && h++ < 3; ) {
      String loc = resp.getResponseHeaderValue("Location");
      resp = c.loadWebResponse(new WebRequest(hostAbs(base, loc)));
    }
    assertEquals(200, resp.getStatusCode(),
        "the MFA page must render 200 (crumb source): " + resp.getStatusCode());
    // The MFA page embeds the crumb as <input type="hidden" name="Jenkins-Crumb"
    // value="..."/> (MfaController.getCrumbField/Value). Jelly pretty-prints with
    // arbitrary whitespace, so collapse it before matching and tolerate the
    // attribute order/spacing.
    String flat = resp.getContentAsString().replaceAll("\\s+", " ");
    // <input name="Jenkins-Crumb" type="hidden" value="..."/> — attributes are
    // in that order, so allow anything (e.g. type="hidden") between name and value.
    java.util.regex.Matcher m = java.util.regex.Pattern
        .compile("<input\\s+name=\"([^\"]*[Cc]rumb[^\"]*)\"\\s+[^>]*?value=\"([^\"]*)\"")
        .matcher(flat);
    assertTrue(m.find(), "the MFA page HTML must carry a crumb input (name/value): " + head(flat));
    this.crumbName = m.group(1);
    return m.group(2);
  }

  /**
   * Verify the user's TOTP so the session PASSES the MFA gate. Enrolled users
   * are bounced by {@code MfaFilter} on every non-allowlisted GET (including
   * the security page) until they prove a factor; this is the natural
   * self-service flow (login → verify → manage). Returns the verify JSON for
   * the caller to assert on.
   */
  private JSONObject verifyTotpToPassGate(JenkinsRule.WebClient c, URL base,
      String user, String secret, String protectedPath) throws Exception {
    String crumb = mfaCrumb(c, base);
    byte[] key = Totp.decodeSecret(secret);
    String code = Totp.codeAt(key, System.currentTimeMillis());
    WebRequest req = new WebRequest(href(base, "mfa/postVerify"), HttpMethod.POST);
    List<NameValuePair> params = new ArrayList<>();
    params.add(new NameValuePair(crumbName, crumb));
    params.add(new NameValuePair("code", code));
    req.setRequestParameters(params);
    WebResponse resp;
    try {
      resp = c.loadWebResponse(req);
    } catch (FailingHttpStatusCodeException e) {
      resp = e.getResponse();
    }
    JSONObject j = JSONObject.fromObject(resp.getContentAsString());
    assertTrue(j.optBoolean("ok"), "the TOTP verify must succeed to pass the gate: " + j);
    return j;
  }

  /** A raw GET that stops at the first response (302 not followed). */
  private WebResponse rawGet(JenkinsRule.WebClient c, URL base, String path) throws Exception {
    WebRequest req = new WebRequest(href(base, path));
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

  /** Resolve an already context-absolute Location to an absolute URL at the
   *  host authority (NOT under the context, which would duplicate it). */
  private static URL hostAbs(URL base, String ctxAbsolutePath) throws Exception {
    String b = base.toString();
    int slash = b.indexOf("/", b.indexOf("//") + 2);
    String authority = (slash == -1) ? b : b.substring(0, slash);
    String p = ctxAbsolutePath.startsWith("/") ? ctxAbsolutePath : "/" + ctxAbsolutePath;
    return new URL(authority + p);
  }

  /**
   * GET the user's security page and return the FINAL page's HTML. The caller
   * must have passed the gate first for enrolled users (verify the factor); a
   * fresh, unenrolled user is passed by the gate automatically. Asserts 200
   * and surfaces the hop chain in any failure.
   */
  private String securityPageHtml(JenkinsRule.WebClient c, URL base, String user) throws Exception {
    WebResponse resp = rawGet(c, base, securityPath(user));
    List<String> hops = new ArrayList<>();
    for (int h = 0; resp.getStatusCode() == 302 && h++ < 3; ) {
      String loc = resp.getResponseHeaderValue("Location");
      hops.add(resp.getStatusCode() + " -> " + loc);
      resp = c.loadWebResponse(new WebRequest(hostAbs(base, loc)));
    }
    String chain = hops.isEmpty() ? "(direct " + resp.getStatusCode() + ")"
        : String.join("; ", hops) + "; final " + resp.getStatusCode();
    assertEquals(200, resp.getStatusCode(),
        "the user's own security page must render 200 (gate passed, view resolved); chain: "
            + chain);
    return resp.getContentAsString();
  }

  /**
   * A valid crumb for the /mfa profile-endpoint POSTs. Delegated to
   * {@link #mfaCrumb} — the crumb is never read off the security page (core's
   * configSubmit form has no crumb input).
   */
  private String securityPageCrumb(JenkinsRule.WebClient c, URL base, String user) throws Exception {
    return mfaCrumb(c, base);
  }

  /** Build a context-preserving absolute URL (mirrors MfaFilterIT.href). */
  private static URL href(URL base, String rel) throws Exception {
    String r = rel.startsWith("/") ? rel.substring(1) : rel;
    String b = base.toString();
    if (!b.endsWith("/")) {
      b = b + "/";
    }
    return new URL(b + r);
  }

  /** POST a crumb-bearing form to a /mfa profile endpoint; return the JSON. */
  private JSONObject postMfaProfile(JenkinsRule.WebClient c, URL base, String endpoint,
      String crumb, NameValuePair... fields) throws Exception {
    WebRequest req = new WebRequest(href(base, "mfa/" + endpoint), HttpMethod.POST);
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
        "a /mfa profile endpoint must answer its 200 JSON envelope: " + resp.getStatusCode());
    return JSONObject.fromObject(resp.getContentAsString());
  }

  private static String head(String s) {
    if (s == null) {
      return null;
    }
    return s.length() <= 400 ? s : s.substring(0, 400) + "…";
  }
}
