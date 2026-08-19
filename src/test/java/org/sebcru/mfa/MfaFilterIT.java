package org.sebcru.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.AbstractProject;
import hudson.model.User;
import hudson.security.FullControlOnceLoggedInAuthorizationStrategy;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.HudsonPrivateSecurityRealm.Details;
import hudson.util.Secret;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.htmlunit.FailingHttpStatusCodeException;
import org.htmlunit.HttpMethod;
import org.htmlunit.WebRequest;
import org.htmlunit.WebResponse;
import org.htmlunit.html.HtmlElement;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlInput;
import org.htmlunit.html.HtmlPage;
import org.htmlunit.util.Cookie;
import org.htmlunit.util.NameValuePair;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.sebcru.mfa.DevcruMfaConfig.Policy;
import org.sebcru.mfa.crypto.Totp;
import org.sebcru.mfa.email.CaptureEmailSender;

/**
 * Task 8 — the end-to-end MFA integration test (Jenkins in a JVM).
 *
 * <h2>Why this file exists</h2>
 * <p>Tasks 1–7 pinned each seam <em>pure</em>: the TOTP math, the trust and
 * rate-limiter arithmetic, the redirect validator, the gate decision table,
 * the factor router. None of them exercise the <em>glue</em> — the bits that
 * only speak a live booted Jenkins: the real {@code /login} password flow,
 * the session the browser actually holds, the live-registered {@code
 * MfaFilter} (Task 7) bouncing a real request at a real 302, the
 * {@code ?redirect=} parameter travelling round trip, the session id
 * rotating on a successful verify, and the {@code MfaController} endpoints
 * writing real JSON through servlet I/O. This suite boots a real Jenkins
 * under JUnit (via the {@code @WithJenkins} harness — the same boot
 * {@code InjectedTest} uses) and walks those flows end to end. This is where
 * the plan's stated Task 8 objective — catching "broken redirect
 * assumptions" — actually gets caught: no unit test expresses the 302
 * {@code Location} the filter emits on a real request, or the session id the
 * browser ends up holding after a verify.
 *
 * <h2>One honest deviation from the plan's case 1 (flagged for mads)</h2>
 * <p>The plan's case 1 says "fresh session → 302 (untrusted)". Read literally
 * for a <em>post-verify</em> fresh session, that conflicts with the mads-
 * signed trust semantics (architecture §5 + the plan's own step-9 note, plan
 * §Task 7 line 559): a successful verify <em>grants a remembered device</em>
 * and persists {@code trustedUntilMs} (default 30 days) on the user
 * property. A <em>fresh</em> session for that same user therefore has a live
 * trust record and must <em>pass</em> the gate — that is the entire point of
 * remembered devices (README "Remembered devices" + {@code MfaFilter}'s
 * step-9 OR disjunction). The 302-on-fresh-session only holds <em>before any
 * verify has ever granted trust</em>. This suite pins the honest signed
 * behaviour: a genuinely pre-trust browser → 302 (case 1), and a post-trust
 * fresh browser → 200 on the protected path (case 6, the remembered-device
 * half). If mads intended the plan's literal line to also hold <em>after a
 * verify</em>, that contradicts the signed §5 semantics and needs its own
 * ruling; as written, the remembered window is the feature, not the bug.
 *
 * <h2>How the flows are driven</h2>
 * <p>Each test builds a real password-backed user in a
 * {@code HudsonPrivateSecurityRealm} (the core's local-realm shape) with a
 * TOTP or email factor enrolled, logs in through the <em>real</em>
 * {@code /login} form flow (the harness's own login mechanics: fields
 * {@code j_username}/{@code j_password}, no stubbed auth), and then exercises
 * the gate + the {@code MfaController} POSTs as plain form requests
 * carrying that session's cookie + the crumb the MFA page itself rendered
 * (the page's own JS does exactly this; we mirror it with raw fields so the
 * A3 param-first carrier is exercised wire to wire). The JSON the endpoints
 * write is parsed back from the raw {@link WebResponse}. Redirects are read
 * from the raw 302 {@code Location} (never followed by the client) so the
 * A3/A5 carriers are assertable as the gate emitted them.
 *
 * <h2>Red → green history</h2>
 * <p>Fresh Task 8 suite written after Tasks 1–7 landed; there is no prior
 * red to claim. The honest value is that it is the first <em>live-boot</em>
 * acceptance of the gate + endpoints together, and the highest-value
 * assertions (the live 302 {@code Location}, the session-id rotation, the
 * post-verify redirect target) are only expressible against a boot. If a
 * boot surfaces a real defect in the glue (a registration milestone, the
 * session-copy-on-regen, a 302 target the validator mishandles on a live
 * request), that red is recorded here exactly the way the plan's RFC-vector
 * reds were recorded in {@code TotpTest}.
 */
@WithJenkins
class MfaFilterIT {

  // The booted JenkinsRule is INJECTED per method by @WithJenkins (verified
  // against the harness: its JUnit5 extension matches JenkinsRule parameters
  // in supportsParameter and computes one shared instance per method). We do
  // NOT hold an instance field — a new JenkinsRule() here would be detached
  // from the booted instance.
  private String crumbName = "Jenkins-Crumb"; // overwritten from the page below

  // ==================================================================
  // Case 1 — TOTP end to end (carries the A5 pre-login round trip).
  // ==================================================================

  /**
   * WHAT: the full TOTP end-to-end — a fresh, pre-trust browser does the
   * real password login; the <em>live</em> gate filter then bounces the
   * post-login GET of the protected path to the MFA page with the pre-login
   * destination in {@code ?redirect=} (the A3 carrier on the wire); a
   * correct TOTP verify returns JSON whose {@code redirect} is that same
   * pre-login target (A5 — not the MFA page, not a generic default); the
   * JSESSIONID rotates on success (antifixation); the verified session
   * reaches the protected path without a further bounce.
   *
   * <p>BDD:
   * <pre>
   * GIVEN an enrolled TOTP user, a protected job, and a pre-trust browser
   * WHEN  the real /login form is posted (j_username/j_password only)
   *       and the client then GETs the protected path it was aiming at
   * THEN  the response is a 302 with Location =
   *       /securityRealm/mfa?redirect=&lt;the protected path&gt;
   *       (the gate's A3 carrier, asserted off the raw Location header)
   * WHEN  the MFA page is loaded and its own form is POSTed to
   *       postVerify with (code = correct current TOTP, redirect =
   *       the protected path, crumb = the page's rendered crumb)
   * THEN  the JSON is {ok:true, rememberHours:720,
   *                    redirect:&lt;the protected path&gt;}   (the A5 pin)
   * AND   the JSESSIONID the client now holds DIFFERS from the one it
   *       held after the password login (session regeneration)
   * AND   a GET of the protected path in the verified session → 200,
   *       with no securityRealm/mfa in the Location (no re-prompt)
   * </pre>
   *
   * <p>WHY/SOLVES: this is the plan's "broken redirect assumptions" catch.
   * A regression that sent a verified user back to the MFA page (a
   * Referer-only contract), dropped the {@code ?redirect=} carrier on the
   * 302, or failed to rotate the session on success would each turn red
   * here, at the live-boot path, not in a unit test of the pure seams.
   */
  @Test
  void totpFlowEndToEndWithPreLoginRoundTrip(JenkinsRule rule) throws Exception {
    String user = "it-totp";
    String pw = "secret123";
    String secret = Totp.newBase32Secret();
    byte[] key = Totp.decodeSecret(secret);
    enrollTotp(user, pw, secret);
    String job = rule.createProject(AbstractProject.class, "it-totp-job").getFullName();
    String preLogin = "/job/" + job + "/";
    URL base = rule.getURL();

    JenkinsRule.WebClient c = rule.createWebClient();
    c.setJavaScriptEnabled(false);
    c.setThrowExceptionOnFailingStatusCode(false);

    // -- 1. Real password login (session only; no MFA yet).
    doPostLogin(c, base, user, pw);
    String preLoginSession = jsessionId(c);
    assertNotNull(preLoginSession, "the password login must have established a JSESSIONID");

    // -- 2. The gate bounces the protected GET to the MFA page (A3 carrier).
    WebResponse bounce = rawGet(c, base, preLogin);
    assertEquals(302, bounce.getStatusCode(),
        "an enrolled, unverified user is bounced by the live gate (302): " + bounce.getStatusCode());
    String location = bounce.getResponseHeaderValue("Location");
    assertNotNull(location);
    assertTrue(location.contains("/securityRealm/mfa"),
        "the bounce must land on the MFA page: " + location);
    assertEquals(preLogin, extractRedirectParam(location),
        "A3 — the live 302 must carry the pre-login destination in ?redirect=: " + location);

    // -- 3. Load the MFA page the user would see; read ITS rendered crumb.
    Url mfa = new Url(base, resolve(base, location));
    HtmlPage page = (HtmlPage) c.getPage(mfa.abs);
    String crumb = crumbFromPage(page);
    assertNotNull(crumb, "the MFA page must render a usable crumb hidden field");

    // -- 4. Verify with the correct TOTP, re-attaching ?redirect= (A3).
    JSONObject ok = postMfaForm(c, base, "postVerify", crumb,
        new NameValuePair("code", Totp.codeAt(key, System.currentTimeMillis())),
        new NameValuePair("redirect", preLogin));
    assertTrue(ok.optBoolean("ok"), "a correct current TOTP must verify: " + ok);
    assertEquals(preLogin, ok.optString("redirect"),
        "A5 — the successful verify must return the PRE-LOGIN target, not the MFA "
            + "page or a generic default: " + ok);
    assertTrue(ok.optLong("rememberHours", 0L) >= 720L,
        "rememberHours honours the plan default (30 days = 720h, floor 24h): " + ok);

    // -- 5. The session id rotated on success (antifixation).
    String postSession = jsessionId(c);
    assertNotNull(postSession, "expected a JSESSIONID after verify");
    assertFalse(postSession.equals(preLoginSession),
        "the session id MUST rotate on a successful verify (session fixation mitigation)");

    // -- 6. The verified session reaches the protected path (no re-prompt).
    WebResponse got = rawGet(c, base, preLogin);
    assertEquals(200, got.getStatusCode(),
        "a MFA-verified session must reach the protected path (200): " + got.getStatusCode());
  }

  // ==================================================================
  // Case 2 — email-code end to end (the live mail round trip).
  // ==================================================================

  /**
   * WHAT: the email-code round trip — a {@code CaptureEmailSender} is
   * injected into the live {@code MfaController}; a real
   * {@code postResendEmail} issues a code and the captured mail goes to the
   * <em>registered</em> mailbox only (the signed "no open relay" decision);
   * a real {@code postVerify} with the captured code succeeds.
   *
   * <p>BDD:
   * <pre>
   * GIVEN an email-enrolled user (registered mailbox known) with a
   *       CaptureEmailSender wired into the live controller
   * WHEN  postResendEmail is POSTed (authenticated, crumb-bearing)
   * THEN  the JSON is {ok:true, resent:true, cooldown:&gt;0}
   * AND   exactly one "mail" was captured, addressed to the registered
   *       mailbox, carrying the 8-char non-ambiguous-alphabet code
   * WHEN  postVerify is POSTed with that captured code
   * THEN  the JSON is {ok:true, redirect:&lt;pre-login target&gt;}
   * </pre>
   *
   * <p>WHY/SOLVES: the README's "codes are always mailed to the registered
   * mailbox — never to an address an attacker can point them at" and the
   * single-use guarantee are <em>delivery-shaped</em> claims; only a real
   * endpoint call + a capture double can pin them. A regression that let
   * {@code postResendEmail} steer the destination, or that issued a code the
   * registered mailbox never received, turns red here. (The hashing /
   * single-use core itself stays unit-pinned in {@code EmailCodeIssuerTest}.)
   */
  @Test
  void emailFlowRoundTripToRegisteredMailbox(JenkinsRule rule) throws Exception {
    String user = "it-email";
    String pw = "secret123";
    String mail = user + "@devcru.example";
    enrollEmail(user, pw, mail);
    rule.createProject(AbstractProject.class, "it-email-job");
    String preLogin = "/job/it-email-job/";
    URL base = rule.getURL();

    JenkinsRule.WebClient c = rule.createWebClient();
    c.setJavaScriptEnabled(false);
    c.setThrowExceptionOnFailingStatusCode(false);
    doPostLogin(c, base, user, pw);

    // Reach the MFA page via the live bounce (so we use the real crumb).
    HtmlPage page = mfaPage(c, base, preLogin);
    String crumb = crumbFromPage(page);

    // Inject the capture double into the live controller (@Extension singleton).
    MfaController controller = Jenkins.get().getExtensionList(MfaController.class).get(0);
    CaptureEmailSender cap = new CaptureEmailSender();
    controller.setSenderForTest(cap);

    // -- Resend (the endpoint deliberately takes NO destination: the
    //    registered mailbox only — the signed deviation the mail double
    //    verifies end to end).
    JSONObject res = postMfaForm(c, base, "postResendEmail", crumb,
        new NameValuePair("redirect", preLogin));
    assertTrue(res.optBoolean("ok"), "a fresh resend must succeed: " + res);
    assertTrue(res.optBoolean("resent"), "resent:true must be present: " + res);
    assertTrue(res.optLong("cooldown", 0L) > 0, "the resend cooldown must be positive: " + res);

    assertEquals(1, cap.sent().size(), "exactly one mail must be captured for one resend");
    CaptureEmailSender.Sent s = cap.last();
    assertEquals(mail, s.to(), "the code must go to the REGISTERED mailbox only");
    assertTrue(s.code() != null && s.code().matches("[2-9A-HJ-NP-Z]{8}"),
        "the captured code is 8 chars from the non-ambiguous email alphabet: " + s.code());
    assertTrue(s.ttlSeconds() > 0, "the code carries a positive TTL");

    // -- Verify with the captured code.
    JSONObject ok = postMfaForm(c, base, "postVerify", crumb,
        new NameValuePair("code", s.code()),
        new NameValuePair("redirect", preLogin));
    assertTrue(ok.optBoolean("ok"), "the captured email code must verify: " + ok);
    assertEquals(preLogin, ok.optString("redirect"),
        "the email-code success must also honour the ?redirect= target: " + ok);
  }

  // ==================================================================
  // Case 3 — API token is exempt from the gate (attribute re-pin).
  // ==================================================================

  /**
   * WHAT: an API-token request (Basic {@code username:apitoken} — the only
   * token header jenkins-core 2.528.3 supports) is exempt from the live
   * gate: it reaches a protected endpoint with 200, never a 302 to the MFA
   * page.
   *
   * <p>BDD:
   * <pre>
   * GIVEN an enrolled TOTP user, an API token, and policy REQUIRED
   * WHEN  the protected /api/json is fetched with Basic auth
   *       username:token (what core 2.528.3's
   *       BasicHeaderApiTokenAuthenticator marks, in-chain, ahead of the
   *       plugin filter)
   * THEN  the response is 200 with no 302 to securityRealm/mfa
   * </pre>
   *
   * <p>WHY/SOLVES: {@code MfaFilter}'s step 2 is the load-bearing exemption.
   * If a future build dropped the attribute check or mis-pinned its class
   * name, every CI trigger against this Jenkins would stall at the second
   * factor — a silent, expensive break. Re-pinning the attribute against a
   * real security chain is the cheapest live proof it still holds.
   *
   * <p><b>A15 (named gap, TECH_DEBT):</b> the plan's case 3 specifies
   * {@code Authorization: Bearer *** but jenkins-core 2.528.3 has
   * <em>no</em> Bearer token authenticator (verified — only
   * {@code BasicHeader*} token classes exist). This IT therefore pins the
   * <strong>Basic</strong> header, and Bearer is a ruling-needed gap for
   * mads: either core gains Bearer in a future LTS and the seam follows, or
   * the ruling is "attribute is the contract on 2.528.3 and the plan's
   * Bearer line is void". The attribute check is the right shape for either
   * outcome — nothing in the filter changes on ruling.
   */
  @Test
  void apiTokenExemptFromGate(JenkinsRule rule) throws Exception {
    String user = "it-token";
    String pw = "secret123";
    String secret = Totp.newBase32Secret();
    User u = enrollTotp(user, pw, secret);
    String job = rule.createProject(AbstractProject.class, "it-token-job").getFullName();
    URL base = rule.getURL();

    String token = rule.createApiToken(u);
    JenkinsRule.WebClient api = rule.createWebClient().withBasicCredentials(user, token);
    api.setJavaScriptEnabled(false);
    api.setThrowExceptionOnFailingStatusCode(false);

    WebResponse resp = rawGet(api, base, "/job/" + job + "/api/json");
    assertEquals(200, resp.getStatusCode(),
        "an API-token request must reach the protected endpoint (200), not be gated: "
            + resp.getStatusCode());
    String loc = resp.getResponseHeaderValue("Location");
    assertTrue(loc == null || !loc.contains("securityRealm/mfa"),
        "an API-token request must NOT be redirected to the MFA page: " + loc);
  }

  // ==================================================================
  // Case 4 — lockout: dense wrong codes trip the 15-minute lockout.
  // ==================================================================

  /**
   * WHAT: five wrong TOTP codes inside the window lock the account; the
   * sixth — even with a <em>correct</em> code — is refused as
   * {@code locked} with a positive {@code retrySeconds} before any code is
   * compared, and the gate still bounces (a locked account cannot be probed
   * for codes).
   *
   * <p>BDD:
   * <pre>
   * GIVEN an enrolled TOTP user with the default 5-attempt / 15-min policy
   * WHEN  five different wrong 6-digit codes are POSTed to postVerify
   * THEN  each returns {ok:false, error:"wrong_code"}
   * AND   the 5th trip has armed a live lockout server-side
   * WHEN  a 6th postVerify is made (now with the CORRECT TOTP)
   * THEN  the JSON is {ok:false, error:"locked", retrySeconds:&gt;0}
   *       — the lockout check ran BEFORE the code was compared
   * AND   the protected GET is still a 302 to the MFA page (no code oracle)
   * </pre>
   *
   * <p>WHY/SOLVES: the README's "5 wrong codes inside 30 min locks for 15
   * min" is the load-bearing brute-force bound, and the lockout-first
   * ordering is what makes a locked account <em>quiet</em> — no
   * accept/reject signal per attempt to time. This pins both, end to end:
   * the unit suite proves the arithmetic; only this proves the live
   * endpoint checks it before touching the code.
   */
  @Test
  void lockoutTripsAfterFiveWrongCodes(JenkinsRule rule) throws Exception {
    String user = "it-locked";
    String pw = "secret123";
    String secret = Totp.newBase32Secret();
    byte[] key = Totp.decodeSecret(secret);
    enrollTotp(user, pw, secret);
    rule.createProject(AbstractProject.class, "it-locked-job");
    String preLogin = "/job/it-locked-job/";
    URL base = rule.getURL();

    JenkinsRule.WebClient c = rule.createWebClient();
    c.setJavaScriptEnabled(false);
    c.setThrowExceptionOnFailingStatusCode(false);
    doPostLogin(c, base, user, pw);
    HtmlPage page = mfaPage(c, base, preLogin);
    String crumb = crumbFromPage(page);

    // Five wrong codes. (Different values; the 6-digit shape routes to TOTP.)
    for (int i = 0; i < 5; i++) {
      JSONObject r = postMfaForm(c, base, "postVerify", crumb,
          new NameValuePair("code", String.format("00000%d", i)),
          new NameValuePair("redirect", preLogin));
      assertFalse(r.optBoolean("ok"), "a wrong TOTP must not verify");
      assertEquals(VerifyOutcome.ERR_WRONG_CODE, r.optString("error"),
          "the first five wrong codes report wrong_code (the 5th trip is not an error): " + r);
    }

    // The 6th, with the CORRECT code, is refused as locked — the code is
    // never even compared (lockout check runs first).
    JSONObject locked = postMfaForm(c, base, "postVerify", crumb,
        new NameValuePair("code", Totp.codeAt(key, System.currentTimeMillis())),
        new NameValuePair("redirect", preLogin));
    assertFalse(locked.optBoolean("ok"));
    assertEquals(VerifyOutcome.ERR_LOCKED, locked.optString("error"),
        "the 6th attempt (even correct) must be refused as locked: " + locked);
    assertTrue(locked.optLong("retrySeconds", 0L) > 0,
        "a live lockout must report a positive retry countdown: " + locked);

    // The gate still bounces a locked, unverified user (not a code oracle).
    WebResponse got = rawGet(c, base, preLogin);
    assertEquals(302, got.getStatusCode(), "a locked, unverified user is still gated (302)");
    assertTrue(got.getResponseHeaderValue("Location") != null
        && got.getResponseHeaderValue("Location").contains("securityRealm/mfa"),
        "the locked user is bounced to the MFA page, not through");
  }

  // ==================================================================
  // Case 5 — kill switch: policy OFF is a setting, not an uninstall.
  // ==================================================================

  /**
   * WHAT: flipping the <em>live descriptor</em> policy to OFF makes the
   * live-registered gate inert — an enrolled, pre-trust, unverified user
   * reaches the protected path with no MFA page in between — and restoring
   * the policy re-arms the gate.
   *
   * <p>BDD:
   * <pre>
   * GIVEN an enrolled, password-logged-in, MFA-unverified user
   * WHEN  DevcruMfaConfig.currentSafe() policy is set to OFF and saved
   * THEN  a GET of the protected path → 200 (NOT a 302 to the MFA page)
   * WHEN  the policy is restored to REQUIRED and saved
   * THEN  the same GET → 302 to the MFA page again
   * </pre>
   *
   * <p>WHY/SOLVES: the README's "disabling the whole gate is a setting, not
   * an uninstall" is the incident escape hatch — the case where an admin is
   * troubleshooting the very config the gate reads. It must work <em>on a
   * booted instance</em>: the unit suite pins the {@code off()} OR in
   * {@code FilterLogicTest}, but only this proves the live filter actually
   * reads the live descriptor (the A1 ruling, end to end) rather than a
   * stale process default.
   */
  @Test
  void killSwitchPolicyOffPassesEnrolledUser(JenkinsRule rule) throws Exception {
    String user = "it-kill";
    String pw = "secret123";
    String secret = Totp.newBase32Secret();
    enrollTotp(user, pw, secret);
    String job = rule.createProject(AbstractProject.class, "it-kill-job").getFullName();
    String preLogin = "/job/" + job + "/";
    URL base = rule.getURL();

    JenkinsRule.WebClient c = rule.createWebClient();
    c.setJavaScriptEnabled(false);
    c.setThrowExceptionOnFailingStatusCode(false);
    doPostLogin(c, base, user, pw);

    // Sanity: the gate is live before the flip (302).
    assertEquals(302, rawGet(c, base, preLogin).getStatusCode(),
        "precondition — the gate must be live (302) before the policy flip");

    DevcruMfaConfig cfg = DevcruMfaConfig.currentSafe();
    Policy original = cfg.getPolicy();
    try {
      cfg.setPolicy(Policy.OFF);
      cfg.save();

      WebResponse r = rawGet(c, base, preLogin);
      assertEquals(200, r.getStatusCode(),
          "with policy OFF, an enrolled unverified user reaches the protected path: "
              + r.getStatusCode());
      String loc = r.getResponseHeaderValue("Location");
      assertTrue(loc == null || !loc.contains("securityRealm/mfa"),
          "policy OFF must not bounce to the MFA page: " + loc);
    } finally {
      cfg.setPolicy(original);
      cfg.save();
    }

    // Restored: the gate is live again for the same session.
    WebResponse r = rawGet(c, base, preLogin);
    assertEquals(302, r.getStatusCode(), "with policy restored the gate re-arms (302)");
    assertTrue(r.getResponseHeaderValue("Location") != null
        && r.getResponseHeaderValue("Location").contains("securityRealm/mfa"),
        "the restored gate bounces the unverified user to the MFA page");
  }

  // ==================================================================
  // Case 6 — trusted fresh session: the remembered-device half.
  // ==================================================================

  /**
   * WHAT: after a successful verify that grants the remembered-device
   * window (30 days, persisted on the user property), a <em>fresh</em>
   * browser for the same user — new session, no verified flag — logs in
   * with the password alone and reaches the protected path <em>directly</em>,
   * no MFA bounce. This is the mads-signed step-9 <em>trust</em> operand,
   * end to end (the OR whose AND-variant the plan's step-9 prose floated).
   *
   * <p>BDD:
   * <pre>
   * GIVEN user A: first browser logs in (password) and verifies (TOTP),
   *       which persists trustedUntilMs ≈ now + 30 days
   * WHEN  a SECOND fresh browser (no session, no trust cookie, brand-new
   *       JSESSIONID) logs in with A's password
   * THEN  the protected-path GET → 200 with NO 302 to securityRealm/mfa
   *       — the remembered window governs this future login
   * </pre>
   *
   * <p>WHY/SOLVES: this is the exact judgment call (plan prose AND vs the
   * signed disjunction) plus the README's "a future login from that browser
   * inside the window skips the code". A regression that AND-ed the session
   * flag into step 9 (so a trusted fresh login re-prompted) or that expired
   * active-session trust per request (the old plugin's sin) would turn red
   * here. The inverse half (pre-trust fresh → 302) is pinned by case 1.
   */
  @Test
  void trustedFreshSessionSkipsMfa(JenkinsRule rule) throws Exception {
    String user = "it-trust";
    String pw = "secret123";
    String secret = Totp.newBase32Secret();
    byte[] key = Totp.decodeSecret(secret);
    enrollTotp(user, pw, secret);
    String job = rule.createProject(AbstractProject.class, "it-trust-job").getFullName();
    String preLogin = "/job/" + job + "/";
    URL base = rule.getURL();

    // -- First browser: log in + verify (grants the trust record).
    JenkinsRule.WebClient first = rule.createWebClient();
    first.setJavaScriptEnabled(false);
    first.setThrowExceptionOnFailingStatusCode(false);
    doPostLogin(first, base, user, pw);
    HtmlPage page = mfaPage(first, base, preLogin);
    String crumb = crumbFromPage(page);
    JSONObject ok = postMfaForm(first, base, "postVerify", crumb,
        new NameValuePair("code", Totp.codeAt(key, System.currentTimeMillis())),
        new NameValuePair("redirect", preLogin));
    assertTrue(ok.optBoolean("ok"), "the first browser must verify (trust granted): " + ok);

    // -- Second browser: fresh everything; the persisted trust must carry
    //    it straight through.
    JenkinsRule.WebClient second = rule.createWebClient();
    second.setJavaScriptEnabled(false);
    second.setThrowExceptionOnFailingStatusCode(false);
    doPostLogin(second, base, user, pw);
    WebResponse got = rawGet(second, base, preLogin);
    assertEquals(200, got.getStatusCode(),
        "a fresh session for a trusted (remembered) user must reach the protected "
            + "path directly — trustedUntilMs governs future logins (or-branch): "
            + got.getStatusCode());
    String loc = got.getResponseHeaderValue("Location");
    assertTrue(loc == null || !loc.contains("securityRealm/mfa"),
        "the trusted re-login must NOT be bounced to the MFA page: " + loc);
  }

  // ==================================================================
  // Case 7 — error dispatch: a broken URL must not loop into the gate.
  // ==================================================================

  /**
   * WHAT: once a user is MFA-verified, a protected URL that resolves to no
   * view produces the core's own error response — NOT a 302 to the MFA page
   * and no redirect loop. This is the live-boot proof of Task 7's
   * ERROR-dispatch pass (an extension beyond the plan, architecture §9):
   * the error page a user actually lands on must never be re-gated.
   *
   * <p>BDD:
   * <pre>
   * GIVEN an enrolled user on a MFA-verified session (the gate passes it)
   * WHEN  a GET is made to a protected path that has no view
   * THEN  the final response is NOT a 302 to securityRealm/mfa
   *       (the core's own 4xx/error page is what renders — no loop)
   * </pre>
   *
   * <p>WHY/SOLVES: without the ERROR-dispatch pass, a broken URL for a
   * verified user would render as a core error page whose own resources
   * (and the error rendering itself) re-enter the filter as ERROR
   * dispatches — and if the MFA page or error page had a missing resource,
   * the chain 302 → 404 → 302 loops forever ("Too many redirects" in
   * {@code InjectedTest} is exactly that symptom). The decision-table half
   * is unit-pinned in {@code FilterLogicTest#errorDispatchPassesAndOnlyThen};
   * this is the boot-proof that a real error dispatch flows through it.
   * The assertion is scoped to the safety property (no bounce to the MFA
   * page); the exact 4xx status is a core concern, not ours.
   */
  @Test
  void errorDispatchDoesNotLoopIntoTheGate(JenkinsRule rule) throws Exception {
    String user = "it-404";
    String pw = "secret123";
    String secret = Totp.newBase32Secret();
    byte[] key = Totp.decodeSecret(secret);
    enrollTotp(user, pw, secret);
    rule.createProject(AbstractProject.class, "it-404-job");
    String preLogin = "/job/it-404-job/";
    URL base = rule.getURL();

    JenkinsRule.WebClient c = rule.createWebClient();
    c.setJavaScriptEnabled(false);
    c.setThrowExceptionOnFailingStatusCode(false);
    doPostLogin(c, base, user, pw);
    HtmlPage page = mfaPage(c, base, preLogin);
    String crumb = crumbFromPage(page);
    JSONObject ok = postMfaForm(c, base, "postVerify", crumb,
        new NameValuePair("code", Totp.codeAt(key, System.currentTimeMillis())),
        new NameValuePair("redirect", preLogin));
    assertTrue(ok.optBoolean("ok"), "verify first so the request passes the gate: " + ok);

    // A sub-path with no view for this project: the core produces a 4xx
    // (sendError → ERROR dispatch on re-entry), not a normal response.
    WebResponse resp = follow(c, base, "/job/it-404-job/no-such-action");
    String loc = resp.getResponseHeaderValue("Location");
    assertTrue(loc == null || !loc.contains("securityRealm/mfa"),
        "a core error dispatch must not be bounced into the gate (recursion guard): " + loc);
    assertTrue(resp.getStatusCode() != 302 || loc == null || !loc.contains("securityRealm/mfa"),
        "no 302 into the MFA page off an error dispatch: status=" + resp.getStatusCode());
  }

  // ==================================================================
  // Helpers — pure glue, keep them small.
  // ==================================================================

  private record Url(URL abs, String raw) {}

  private URL resolve(URL base, String location) throws Exception {
    if (location == null) {
      return base;
    }
    if (location.startsWith("http://") || location.startsWith("https://")) {
      return new URL(location);
    }
    String l = location;
    if (l.startsWith("/")) {
      l = l.substring(1);
    }
    // The Jenkins base includes the context path already.
    String b = base.toString();
    if (b.endsWith("/")) {
      b = b.substring(0, b.length() - 1);
    }
    return new URL(b + (location.startsWith("/") ? location : "/" + location));
  }

  /** Build a password-backed HPSR realm + FCOL strategy (idempotent). */
  private void realmSetup() {
    Jenkins j = Jenkins.get();
    if (!(j.getSecurityRealm() instanceof HudsonPrivateSecurityRealm)) {
      j.setSecurityRealm(new HudsonPrivateSecurityRealm(false)); // no signup
      j.setAuthorizationStrategy(new FullControlOnceLoggedInAuthorizationStrategy());
    }
  }

  private void enrollTotp(String name, String pw, String secret) throws Exception {
    realmSetup();
    User u = User.get(name, true);
    u.addProperty(Details.fromPlainPassword(pw));
    MfaUserProperty p = MfaUserProperty.getOrCreate(u);
    p.setTotpSecret(Secret.fromString(secret));
    u.save();
  }

  private User enrollEmailAndReturn(String name, String pw, String mail) throws Exception {
    realmSetup();
    User u = User.get(name, true);
    u.addProperty(Details.fromPlainPassword(pw));
    MfaUserProperty p = MfaUserProperty.getOrCreate(u);
    p.setRegisteredEmail(mail);
    u.save();
    return u;
  }

  private void enrollEmail(String name, String pw, String mail) throws Exception {
    enrollEmailAndReturn(name, pw, mail);
  }

  /** POST the real /login form (j_username/j_password — the harness's own flow). */
  private void doPostLogin(JenkinsRule.WebClient c, URL base, String user, String pw)
      throws Exception {
    WebRequest req = c.getWebConnection().getWebRequest(new URL(base, "/login"));
    req.setMethod(HttpMethod.POST);
    List<NameValuePair> params = new ArrayList<>();
    params.add(new NameValuePair("j_username", user));
    params.add(new NameValuePair("j_password", pw));
    req.setRequestParameters(params);
    // Core excludes the login endpoint from the crumb filter (the harness's
    // own login() posts exactly these two fields and nothing else).
    c.loadWebResponse(req); // no redirect following — the session cookie lands here
  }

  /** A raw GET (no redirect-following) — the wire assertions live here. */
  private WebResponse rawGet(JenkinsRule.WebClient c, URL base, String path) throws Exception {
    WebRequest req = c.getWebConnection().getWebRequest(new URL(base, path));
    try {
      return c.loadWebResponse(req);
    } catch (FailingHttpStatusCodeException e) {
      return e.getWebResponse();
    }
  }

  /**
   * Follow 302s of a GET manually (one hop at a time, no client follow),
   * stopping at a non-302 or after 5 hops. Used where a final-status check
   * is the point (not the raw bounce).
   */
  private WebResponse follow(JenkinsRule.WebClient c, URL base, String path) throws Exception {
    WebResponse resp = rawGet(c, base, path);
    for (int hops = 0; resp.getStatusCode() == 302 && hops++ < 5; ) {
      String loc = resp.getResponseHeaderValue("Location");
      resp = rawGet(c, base, loc);
    }
    return resp;
  }

  /** Navigate the client to the MFA gate-bounce page and return the HTML. */
  private HtmlPage mfaPage(JenkinsRule.WebClient c, URL base, String preLogin) throws Exception {
    WebResponse bounce = rawGet(c, base, preLogin);
    assertEquals(302, bounce.getStatusCode(),
        "the enrolled unverified user must be bounced (302) to the MFA page: "
            + bounce.getStatusCode());
    String loc = bounce.getResponseHeaderValue("Location");
    assertNotNull(loc, "the bounce must carry a Location header");
    Url mfa = new Url(resolve(base, loc), loc);
    return (HtmlPage) c.getPage(mfa.abs);
  }

  /** The value of the MFA page's single hidden (crumb) input; remembers its name. */
  private String crumbFromPage(HtmlPage page) {
    HtmlForm form = page.getFormByName("verifyForm");
    List<HtmlInput> hidden = new ArrayList<>();
    for (HtmlElement el : form.getFormElements()) {
      if (el instanceof HtmlInput in && "hidden".equalsIgnoreCase(in.getTypeAttribute())) {
        hidden.add(in);
      }
    }
    assertEquals(1, hidden.size(),
        "the MFA page's verifyForm carries exactly one hidden (the crumb) input");
    HtmlInput crumbField = hidden.get(0);
    this.crumbName = crumbField.getNameAttribute();
    return crumbField.getValueAttribute();
  }

  /**
   * A plain form POST to a MfaController endpoint, crumb-bearing, mirroring
   * what the MFA page's JS does (form-encoded, same-origin, ?redirect=
   * re-attached — A3). Parses + returns the JSON envelope.
   */
  private JSONObject postMfaForm(JenkinsRule.WebClient c, URL base, String endpoint,
      String crumbValue, NameValuePair... fields) throws Exception {
    WebRequest req = c.getWebConnection().getWebRequest(
        new URL(base, "/securityRealm/mfa/" + endpoint));
    req.setMethod(HttpMethod.POST);
    List<NameValuePair> params = new ArrayList<>();
    params.add(new NameValuePair(this.crumbName, crumbValue));
    for (NameValuePair f : fields) {
      params.add(f);
    }
    req.setRequestParameters(params);
    WebResponse resp;
    try {
      resp = c.loadWebResponse(req);
    } catch (FailingHttpStatusCodeException e) {
      resp = e.getWebResponse();
    }
    assertEquals(200, resp.getStatusCode(),
        "the MFA endpoint must answer with its 200 JSON envelope: " + resp.getStatusCode());
    return JSONObject.fromObject(resp.getContentAsString());
  }

  private static String extractRedirectParam(String url) {
    Matcher m = Pattern.compile("redirect=([^&]+)").matcher(url);
    if (!m.find()) {
      return null;
    }
    return java.net.URLDecoder.decode(m.group(1), java.nio.charset.StandardCharsets.UTF_8);
  }

  private static String jsessionId(JenkinsRule.WebClient c) {
    for (Cookie cookie : c.getCookieManager().getCookies()) {
      if ("JSESSIONID".equals(cookie.getName())) {
        return cookie.getCookieValue();
      }
    }
    return null;
  }
}
