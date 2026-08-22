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
 * only speak a live booted Jenkins: the real password login flow, the session
 * the browser actually holds, the live-registered {@code MfaFilter} (Task 7)
 * bouncing a real request at a real 302, the {@code ?redirect=} parameter
 * travelling round trip, the session id rotating on a successful verify, and
 * the {@code MfaController} endpoints writing real JSON through servlet I/O.
 * This suite boots a real Jenkins under JUnit (via {@code @WithJenkins} — the
 * same boot {@code InjectedTest} uses) and walks those flows end to end. This
 * is where the plan's stated Task 8 objective — catching "broken redirect
 * assumptions" — actually gets caught: no unit test expresses the 302
 * {@code Location} the filter emits on a real request, or the session id the
 * browser ends up holding after a verify.
 *
 * <h2>The redirect contract this pins (A3 / A5) — framed honestly</h2>
 * <p>The gate's send-back target comes from <strong>one</strong> validated
 * carrier, not from the request the user happened to be on:
 * <ul>
 *   <li><strong>With no {@code ?redirect=} parameter and no {@code Referer}</strong>
 *       (the raw no-carrier GET this suite issues first), the target falls back
 *       to the <em>context root</em> — the plan's own case-1 "redirect to
 *       {@code /}, not a dead path". Core consumes the original pre-login
 *       destination for its OWN post-login redirect, so by the time the filter
 *       sees the protected GET that destination is already gone; the honest
 *       fallback is the site root, which must never be a dead path.</li>
 *   <li><strong>With an in-site {@code ?redirect=} parameter present</strong> on
 *       the request, that value is canonical (the A3 ruling) and must
 *       <em>round-trip verbatim</em>: the gate's 302 {@code Location} carries it,
 *       the MFA page's JS re-attaches it to the verify POST, and the success
 *       JSON returns it. Case 1 pins all three hops.</li>
 * </ul>
 * Off-site or security-internal targets are refused by the shared validator
 * (unit-pinned in {@code FilterLogicTest}); the end-to-end assertion here is
 * that a legitimate in-site target survives the full wire round trip unchanged.
 *
 * <h2>How the flows are driven</h2>
 * <p>The harness boots the instance under a non-root context
 * ({@code http://host:PORT/jenkins/}), so every request URL in this file is
 * built through {@link #href}/{@link #hostAbs} which keep that context path —
 * a naive {@code new URL(base, "/job/…")} drops it and 404s at the server
 * root. Authentication uses the harness's own {@code WebClient.login(user,
 * pw)} (the real acely login flow, the one the plan named). The MFA endpoints
 * are then exercised as plain crumb-bearing form POSTs that carry the session
 * cookie the browser holds, and redirect targets are read from the raw 302
 * {@code Location} (never followed by the client) so the A3/A5 carriers are
 * assertable exactly as the gate emitted them.
 *
 * <h2>Red → green history</h2>
 * <p>The first in-JVM boot of this project (Task 7's own {@code InjectedTest})
 * already exercised the filter's registration live. This suite is the first
 * <em>flow-level</em> acceptance: the honest value is that the highest-value
 * assertions (the live 302 {@code Location}, the session-id rotation, the
 * post-verify redirect target) are only expressible against a boot. A very
 * first run surfaced two of this <em>test's</em> own defects, both now
 * corrected and load-bearing lessons: (a) the context path must be preserved
 * in every request URL, and (b) the gate's no-carrier bounce honestly targets
 * the context root, not the pre-login job URL — the suite was over-claiming
 * the latter and is now re-framed to pin the signed A3/A5 param round-trip
 * instead. If a future boot surfaces a real defect in the glue (a
 * registration milestone, the session copy-on-renew, a 302 target the
 * validator mishandles on a live request), that red is recorded here exactly
 * the way the plan's RFC-vector reds were recorded in {@code TotpTest}.
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
  // Case 1 — TOTP end to end (carries the A5 ?redirect= round trip).
  // ==================================================================

  /**
   * WHAT: the full TOTP end-to-end — a fresh, pre-trust browser does the real
   * password login; the <em>live</em> gate filter then bounces the protected
   * GET to the MFA page. With no carrier the bounce falls back to the context
   * root (the plan's "redirect to /", never a dead path). When an in-site
   * {@code ?redirect=} parameter IS present, it round-trips verbatim through
   * the bounce 302 AND the verify-success JSON (the A3/A5 pin). A correct TOTP
   * verify rotates the JSESSIONID (antifixation) and the verified session
   * reaches the protected path without a further bounce.
   *
   * <p>BDD:
   * <pre>
   * GIVEN an enrolled TOTP user, a protected job, and a pre-trust browser
   * WHEN  the real password login is performed (the harness's own flow)
   * AND   the browser GETs the protected path with NO ?redirect= and no
   *       Referer (no carrier)
   * THEN  the response is a 302 to /mfa?redirect=&lt;context
   *       root&gt; — never a dead path (the plan's case-1 root fallback)
   * WHEN  the same protected GET carries ?redirect=&lt;the protected job
   *       path&gt; (an in-site carrier)
   * THEN  the 302 Location carries EXACTLY that job path in ?redirect=
   *       (A3 — the parameter is canonical)
   * WHEN  the MFA page is loaded and its own form is POSTed to postVerify
   *       with (code = correct current TOTP, redirect = that same job path,
   *       crumb = the page's rendered crumb)
   * THEN  the JSON is {ok:true, rememberHours:&gt;=720, redirect:&lt;that job
   *       path&gt;} (A5 — the carrier survives the full wire round trip)
   * AND   the JSESSIONID the client now holds DIFFERS from after the
   *       password login (session regeneration / antifixation)
   * AND   a GET of the protected path in the verified session → 200
   *       (no re-prompt)
   * </pre>
   *
   * <p>WHY/SOLVES: this is the plan's "broken redirect assumptions" catch.
   * A regression that (a) dropped the context path from a bounce location,
   * (b) mutated or refused a legitimate in-site {@code ?redirect=} target,
   * (c) made the no-carrier bounce land on a dead path, or (d) failed to
   * rotate the session on success would each turn red here, at the
   * live-boot path, not in a unit test of the pure seams.
   */
  @Test
  void totpFlowEndToEndWithRedirectRoundTrip(JenkinsRule rule) throws Exception {
    String user = "it-totp";
    String pw = "secret123";
    String secret = Totp.newBase32Secret();
    byte[] key = Totp.decodeSecret(secret);
    enrollTotp(user, pw, secret);
    String job = rule.createProject(FreeStyleProject.class, "it-totp-job").getFullName();
    URL base = rule.getURL();
    String ctx = ctxOf(base);
    String siteJob = "/job/" + job + "/";
    String ctxAbsJob = ctxAbs(ctx, siteJob);

    JenkinsRule.WebClient c = rule.createWebClient();
    c.setJavaScriptEnabled(false);
    c.setThrowExceptionOnFailingStatusCode(false);

    // -- 1. Real password login (the harness's own flow).
    c.login(user, pw);
    String preLoginSession = jsessionId(c);
    assertNotNull(preLoginSession, "the password login must have established a JSESSIONID");

    // -- 2. No-carrier bounce: enrolled, unverified → the MFA page; with no
    //    ?redirect= param and no Referer the target is the context root
    //    (never a dead path). Load the page so we read ITS rendered crumb.
    WebResponse bounce = rawGet(c, base, siteJob);
    assertEquals(302, bounce.getStatusCode(),
        "an enrolled, unverified user is bounced by the live gate (302): " + bounce.getStatusCode());
    String location = bounce.getResponseHeaderValue("Location");
    assertNotNull(location);
    assertTrue(location.contains("/mfa"),
        "the bounce must land on the MFA page: " + location);
    assertEquals(ctxRoot(ctx), extractRedirectParam(location),
        "the no-carrier bounce must fall back to the context root, not a dead path: " + location);
    HtmlPage page = (HtmlPage) c.getPage(hostAbs(base, location));
    String crumb = crumbFromPage(page);
    assertNotNull(crumb, "the MFA page must render a usable crumb hidden field");

    // -- 3. The A3/A5 carrier on the wire: the same protected GET carrying an
    //    in-site ?redirect= parameter must round-trip THAT target into the
    //    bounce location verbatim.
    WebResponse carried = rawGet(c, base, siteJob + "?redirect=" + ctxAbsJob);
    assertEquals(302, carried.getStatusCode(),
        "the carrier-carrying bounce is also a 302: " + carried.getStatusCode());
    String carriedLoc = carried.getResponseHeaderValue("Location");
    assertEquals(ctxAbsJob, extractRedirectParam(carriedLoc),
        "A3 — the in-site ?redirect= target must survive the bounce verbatim: " + carriedLoc);

    // -- 4. Verify with the correct TOTP, re-attaching ?redirect= (the page's
    //    JS does exactly this). The success JSON must echo the SAME target.
    JSONObject ok = postMfaForm(c, base, "postVerify", crumb,
        new NameValuePair("code", Totp.codeAt(key, System.currentTimeMillis())),
        new NameValuePair("redirect", ctxAbsJob));
    assertTrue(ok.optBoolean("ok"), "a correct current TOTP must verify: " + ok);
    assertEquals(ctxAbsJob, ok.optString("redirect"),
        "A5 — the successful verify must return the ?redirect= target, not a dead path: " + ok);
    assertTrue(ok.optLong("rememberHours", 0L) >= 720L,
        "rememberHours honours the plan default (30 days = 720h, floor 24h): " + ok);

    // -- 5. The session id rotated on success (antifixation).
    String postSession = jsessionId(c);
    assertNotNull(postSession, "expected a JSESSIONID after verify");
    assertFalse(postSession.equals(preLoginSession),
        "the session id MUST rotate on a successful verify (session-fixation mitigation)");

    // -- 6. The verified session reaches the protected path (no re-prompt).
    WebResponse got = rawGet(c, base, siteJob);
    assertEquals(200, got.getStatusCode(),
        "a MFA-verified session must reach the protected path (200): " + got.getStatusCode());
  }

  // ==================================================================
  // Case 2 — email-code end to end (the live mail round trip).
  // ==================================================================
  // Case — the gate's own static assets pass a GATED session
  // (live incident round 4, 2026-08-22: mfa-gate.js 302'd back to the
  // gate page, Chrome refused the text/html "script", Verify was dead).
  // ==================================================================

  /**
   * WHAT: a gated (enrolled, unverified, no trust) session must still load
   * THIS plugin's own static assets — the gate page's verify-form JS lives
   * at {@code /plugin/devcru-mfa/mfa-gate.js} (CSP forbids inline scripts).
   * If the gate bounces that request, the "script" comes back as the gate
   * page's text/html, Chrome refuses to execute it (strict MIME checking),
   * and the Verify button is dead — the gate bricks its own key. Scoped
   * pin: another plugin's asset path stays gated.
   *
   * <p>BDD:
   * <pre>
   * GIVEN an enrolled user, logged in with the password ONLY (gated)
   * WHEN  GET /plugin/devcru-mfa/mfa-gate.js
   * THEN  200 with a text/javascript content type (NOT a 302 to /mfa)
   * WHEN  GET /plugin/some-other-plugin/script.js
   * THEN  302 (only THIS plugin's assets are ungated)
   * </pre>
   */
  @Test
  void gatedSessionStillLoadsThisPluginsStaticAssets(JenkinsRule rule) throws Exception {
    String user = "it-static";
    String pw = "secret123";
    enrollTotp(user, pw, Totp.newBase32Secret());
    URL base = rule.getURL();

    JenkinsRule.WebClient c = rule.createWebClient();
    c.setJavaScriptEnabled(false);
    c.setThrowExceptionOnFailingStatusCode(false);
    c.login(user, pw);

    // Precondition: the session IS gated (a protected GET bounces).
    WebResponse bounce = rawGet(c, base, "/");
    assertEquals(302, bounce.getStatusCode(),
        "precondition: an enrolled unverified session is gated: " + bounce.getStatusCode());

    // The gate's own JS must pass — 200, executable content type.
    WebResponse js = rawGet(c, base, "/plugin/devcru-mfa/mfa-gate.js");
    assertEquals(200, js.getStatusCode(),
        "the gate's own JS must NOT be bounced — a 302 here turns the script into "
            + "the gate page's text/html and Chrome refuses to run it (Verify dead): "
            + js.getStatusCode());
    assertNotNull(js.getResponseHeaderValue("Content-Type"),
        "the JS must carry a content type");
    assertTrue(js.getResponseHeaderValue("Content-Type").contains("javascript"),
        "the JS content type must be executable: " + js.getResponseHeaderValue("Content-Type"));

    // Scope pin: other plugins' assets stay gated.
    WebResponse other = rawGet(c, base, "/plugin/some-other-plugin/script.js");
    assertEquals(302, other.getStatusCode(),
        "only devcru-mfa's own assets are ungated; other plugin paths stay gated: "
            + other.getStatusCode());
  }

  // ==================================================================

  /**
   * WHAT: the email-code round trip — a {@code CaptureEmailSender} is
   * injected into the live {@code MfaController}; a real
   * {@code postResendEmail} issues a code and the captured mail goes to the
   * <em>registered</em> mailbox only (the signed "no open relay" decision);
   * a real {@code postVerify} with the captured code succeeds and returns
   * the carried {@code ?redirect=} target.
   *
   * <p>BDD:
   * <pre>
   * GIVEN an email-enrolled user (registered mailbox known) with a
   *       CaptureEmailSender wired into the live controller
   * WHEN  postResendEmail is POSTed (authenticated, crumb-bearing)
   * THEN  the JSON is {ok:true, resent:true, cooldown&gt;0}
   * AND   exactly one "mail" was captured, addressed to the REGISTERED
   *       mailbox, carrying the 8-char non-ambiguous-alphabet code
   *       (and a positive TTL)
   * WHEN  postVerify is POSTed with that captured code (+ ?redirect=)
   * THEN  the JSON is {ok:true, redirect:&lt;the carried in-site target&gt;}
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
    rule.createProject(FreeStyleProject.class, "it-email-job");
    URL base = rule.getURL();
    String ctx = ctxOf(base);
    String siteJob = "/job/it-email-job/";
    String ctxAbsJob = ctxAbs(ctx, siteJob);

    JenkinsRule.WebClient c = rule.createWebClient();
    c.setJavaScriptEnabled(false);
    c.setThrowExceptionOnFailingStatusCode(false);
    c.login(user, pw);

    // Reach the MFA page via the live bounce (so we use the real crumb).
    HtmlPage page = mfaPage(c, base, siteJob);
    String crumb = crumbFromPage(page);

    // Inject the capture double into the live controller (@Extension singleton).
    MfaController controller = Jenkins.get().getExtensionList(MfaController.class).get(0);
    CaptureEmailSender cap = new CaptureEmailSender();
    controller.setSenderForTest(cap);

    // -- Resend (the endpoint deliberately takes NO destination: the
    //    registered mailbox only — the signed deviation the capture double
    //    verifies end to end).
    JSONObject res = postMfaForm(c, base, "postResendEmail", crumb,
        new NameValuePair("redirect", siteJob));
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
        new NameValuePair("redirect", siteJob));
    assertTrue(ok.optBoolean("ok"), "the captured email code must verify: " + ok);
    assertEquals(ctxAbsJob, ok.optString("redirect"),
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
   * THEN  the response is 200 with no 302 to /mfa
   * </pre>
   *
   * <p>WHY/SOLVES: {@code MfaFilter}'s step 2 is the load-bearing exemption.
   * If a future build dropped the attribute check or mis-pinned its class
   * name, every CI trigger against this Jenkins would stall at the second
   * factor — a silent, expensive break. Re-pinning the attribute against a
   * real security chain is the cheapest live proof it still holds.
   *
   * <p><b>A15 / A21 (now LANDED):</b> the plan's case 3 specified a Bearer
   * API-token request. jenkins-core 2.528.3 has <em>no</em> core Bearer
   * authenticator, so A21 (mads ruling 2026-08-19) is a home-grown Bearer
   * authenticator in this plugin — see the sibling case
   * {@code bearerTokenExemptFromGate} in this suite, which pins the same
   * gate exemption over a real Bearer header on a booted Jenkins. This
   * Basic case stands as the proof of the core-owned Basic path; the two
   * cases together pin that the exemption contract is identical for both.
   */
  @Test
  void apiTokenExemptFromGate(JenkinsRule rule) throws Exception {
    String user = "it-token";
    String pw = "secret123";
    String secret = Totp.newBase32Secret();
    User u = enrollTotp(user, pw, secret);
    String job = rule.createProject(FreeStyleProject.class, "it-token-job").getFullName();
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
    assertTrue(loc == null || !loc.contains("/mfa"),
        "an API-token request must NOT be redirected to the MFA page: " + loc);
  }

  // ==================================================================
  // Case 3b — A21: Bearer API-token request is exempt from the gate the
  // same way Basic is (home-grown Bearer authenticator, booted proof).
  // ==================================================================

  /**
   * WHAT: a Bearer API-token request — sent with {@code Authorization:
   * Bearer <token> + the A21 companion {@code X-Jenkins-User} header, the exact
   * documented client contract of the home-grown {@link BearerTokenFilter} —
   * is <strong>exempt from the gate</strong> exactly like the equivalent Basic
   * request ({@code apiTokenExemptFromGate}): 200, no 302 to the MFA page, on
   * a <em>booted</em> Jenkins with a <em>real</em> API token.
   *
   * <p>BDD:
   * <pre>
   * GIVEN an enrolled TOTP user, a REAL api token minted via
   *       rule.createApiToken (the same primitive the Basic IT uses), and
   *       policy REQUIRED, and a fresh unauthed web client (anonymous)
   * WHEN  the protected /api/json is fetched with
   *       Authorization: Bearer <token>  AND X-Jenkins-User: &lt;user&gt;
   * THEN  the BearerTokenFilter (which core's absent Bearer authenticator
   *       would never set) recognises the token, sets the api-token request
   *       attribute + the security context, the gate sees the attribute and
   *       EXEMPTs the request
   * AND   the response is 200 with no 302 to /mfa
   * </pre>
   *
   * <p>WHY/SOLVES: this is A21's acceptance criterion (b) — the load-bearing
   * proof that a Bearer client (the convention a wide range of tooling, CI,
   * and the rest of the ecosystem uses) is NOT broken by the live gate. jenkins-core
   * 2.528.3 has <em>no</em> Bearer authenticator, so without the home-grown filter
   * every such request would be anonymous and, for an enrolled user, bounced to
   * the MFA page or denied. Pinning the 200 / no-{@code /mfa} on a real booted
   * token is the only proof the exemption wiring actually holds end-to-end (the
   * unit suite pins the <em>parse</em>; this pins the <em>glue</em>).
   *
   * <p><b>Negative (A21 step 6 — fail-open, no oracle).</b> The same method
   * also runs the mismatch half of the contract:
   * <pre>
   * GIVEN the same real token, policy REQUIRED, and a fresh anonymous client
   * WHEN  a baseline /api/json with NO headers at all is fetched
   * AND   the same /api/json is fetched with Authorization: Bearer <token>
   *       token but X-Jenkins-User naming a WRONG caller id
   * THEN  the wrong-caller response's status AND Location are byte-for-byte
   *       identical to the no-token baseline — the filter touched nothing
   *       (no attr, no context), so a bad caller is indistinguishable from
   *       no token (no oracle for token/caller-id probing)
   * </pre>
   * <p>WHY/SOLVES: fail-open is the security-critical half of A21. A 500 would
   * turn token probing into a DoS; a 302 to /mfa would mean the filter
   * authenticated the enrolled user from a WRONG caller id — turning Bearer
   * into a user-id oracle and defeating the gate's whole point. In this
   * harness the anonymous user has read access to the job API, so "no token"
   * is 200; the wrong-caller Bearer must be 200 too, not a bounce. If
   * anonymous access is ever removed from this Jenkins, both sides of the
   * comparison move together (the assertion compares the two, not a hardcoded
   * status), so the no-oracle guarantee keeps pinning itself.
   */
  @Test
  void bearerTokenExemptFromGate(JenkinsRule rule) throws Exception {
    String user = "it-bearer";
    String pw = "secret123";
    String secret = Totp.newBase32Secret();
    User u = enrollTotp(user, pw, secret);
    String job = rule.createProject(FreeStyleProject.class, "it-bearer-job").getFullName();
    URL base = rule.getURL();

    String token = rule.createApiToken(u);
    JenkinsRule.WebClient api = rule.createWebClient();
    api.setJavaScriptEnabled(false);
    api.setThrowExceptionOnFailingStatusCode(false);

    WebRequest req = new WebRequest(href(base, "/job/" + job + "/api/json"));
    req.setAdditionalHeader("Authorization", "Bearer " + token);
    req.setAdditionalHeader(BearerTokenFilter.HEADER_USER, user);
    WebResponse resp;
    boolean was = api.isRedirectEnabled();
    api.setRedirectEnabled(false);
    try {
      resp = api.loadWebResponse(req);
    } catch (FailingHttpStatusCodeException e) {
      resp = e.getResponse();
    } finally {
      api.setRedirectEnabled(was);
    }
    assertEquals(200, resp.getStatusCode(),
        "a Bearer API-token request must reach the protected endpoint (200), "
            + "not be gated: " + resp.getStatusCode());
    String loc = resp.getResponseHeaderValue("Location");
    assertTrue(loc == null || !loc.contains("/mfa"),
        "a Bearer API-token request must NOT be redirected to the MFA page: " + loc);

    // ---- Fail-open (A21 step 6): a Bearer token presented for the WRONG
    // caller id must behave EXACTLY like a plain, no-headers anonymous request
    // — not 500, not a /mfa bounce, nothing the filter "did" to the request.
    //
    // jenkins-core 2.528.3 has no Bearer authenticator and the filter refuses
    // the O(n) every-user scan, so a Bearer with no (or a wrong) companion user
    // is "not a Bearer request" for this filter: it touches nothing (no attr, no
    // context change) and the request stays anonymous. The security load here is
    // the NO-ORACLE property — a caller probing with a wrong user id must see no
    // difference at all from sending no token (so there is nothing to signal a
    // valid token). In THIS harness the anonymous user has read access to the
    // job API, so "no token" is 200; the wrong-caller Bearer MUST be 200 exactly
    // like the no-token baseline, and must NOT be a 302 to /mfa (which would
    // mean the filter authenticated the enrolled user and the gate then bounced
    // — i.e. a wrong caller got treated as the real, enrolled caller).
    JenkinsRule.WebClient anon = rule.createWebClient();
    anon.setJavaScriptEnabled(false);
    anon.setThrowExceptionOnFailingStatusCode(false);

    WebRequest plain = new WebRequest(href(base, "/job/" + job + "/api/json"));
    WebResponse p2;
    boolean wasp = anon.isRedirectEnabled();
    anon.setRedirectEnabled(false);
    try {
      p2 = anon.loadWebResponse(plain);
    } catch (FailingHttpStatusCodeException e) {
      p2 = e.getResponse();
    } finally {
      anon.setRedirectEnabled(wasp);
    }

    WebRequest bad = new WebRequest(href(base, "/job/" + job + "/api/json"));
    bad.setAdditionalHeader("Authorization", "Bearer " + token);
    bad.setAdditionalHeader(BearerTokenFilter.HEADER_USER, "not-" + user);  // wrong caller
    WebResponse r2;
    boolean was2 = anon.isRedirectEnabled();
    anon.setRedirectEnabled(false);
    try {
      r2 = anon.loadWebResponse(bad);
    } catch (FailingHttpStatusCodeException e) {
      r2 = e.getResponse();
    } finally {
      anon.setRedirectEnabled(was2);
    }
    assertEquals(p2.getStatusCode(), r2.getStatusCode(),
        "a Bearer token named for the WRONG caller id must be indistinguishable "
            + "from a plain no-token request (no oracle, fail-open): "
            + "no-token=" + p2.getStatusCode() + " wrong-caller=" + r2.getStatusCode());
    String loc2 = r2.getResponseHeaderValue("Location");
    assertEquals(p2.getResponseHeaderValue("Location"), loc2,
        "a wrong-caller Bearer request must have the same Location as the no-token "
            + "baseline (i.e. the filter treated it as 'no Bearer' — not as the "
            + "enrolled caller being bounced to /mfa): " + loc2);
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
   * THEN  the JSON is {ok:false, error:"locked", retrySeconds&gt;0}
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
    rule.createProject(FreeStyleProject.class, "it-locked-job");
    String siteJob = "/job/it-locked-job/";
    URL base = rule.getURL();

    JenkinsRule.WebClient c = rule.createWebClient();
    c.setJavaScriptEnabled(false);
    c.setThrowExceptionOnFailingStatusCode(false);
    c.login(user, pw);
    HtmlPage page = mfaPage(c, base, siteJob);
    String crumb = crumbFromPage(page);

    // Five wrong codes. (Different values; the 6-digit shape routes to TOTP.)
    for (int i = 0; i < 5; i++) {
      JSONObject r = postMfaForm(c, base, "postVerify", crumb,
          new NameValuePair("code", String.format("00000%d", i)));
      assertFalse(r.optBoolean("ok"), "a wrong TOTP must not verify");
      assertEquals(VerifyOutcome.ERR_WRONG_CODE, r.optString("error"),
          "the first five wrong codes report wrong_code (the 5th trip is not an error): " + r);
    }

    // The 6th, with the CORRECT code, is refused as locked — the code is
    // never even compared (lockout check runs first).
    JSONObject locked = postMfaForm(c, base, "postVerify", crumb,
        new NameValuePair("code", Totp.codeAt(key, System.currentTimeMillis())));
    assertFalse(locked.optBoolean("ok"));
    assertEquals(VerifyOutcome.ERR_LOCKED, locked.optString("error"),
        "the 6th attempt (even correct) must be refused as locked: " + locked);
    assertTrue(locked.optLong("retrySeconds", 0L) > 0,
        "a live lockout must report a positive retry countdown: " + locked);

    // The gate still bounces a locked, unverified user (not a code oracle).
    WebResponse got = rawGet(c, base, siteJob);
    assertEquals(302, got.getStatusCode(), "a locked, unverified user is still gated (302)");
    assertTrue(got.getResponseHeaderValue("Location") != null
        && got.getResponseHeaderValue("Location").contains("/mfa"),
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
    String job = rule.createProject(FreeStyleProject.class, "it-kill-job").getFullName();
    String siteJob = "/job/" + job + "/";
    URL base = rule.getURL();

    JenkinsRule.WebClient c = rule.createWebClient();
    c.setJavaScriptEnabled(false);
    c.setThrowExceptionOnFailingStatusCode(false);
    c.login(user, pw);

    // Sanity: the gate is live before the flip (302).
    assertEquals(302, rawGet(c, base, siteJob).getStatusCode(),
        "precondition — the gate must be live (302) before the policy flip");

    DevcruMfaConfig cfg = DevcruMfaConfig.currentSafe();
    Policy original = cfg.getPolicy();
    try {
      cfg.setPolicy(Policy.OFF);
      cfg.save();

      WebResponse r = rawGet(c, base, siteJob);
      assertEquals(200, r.getStatusCode(),
          "with policy OFF, an enrolled unverified user reaches the protected path: "
              + r.getStatusCode());
      String loc = r.getResponseHeaderValue("Location");
      assertTrue(loc == null || !loc.contains("/mfa"),
          "policy OFF must not bounce to the MFA page: " + loc);
    } finally {
      cfg.setPolicy(original);
      cfg.save();
    }

    // Restored: the gate is live again for the same session.
    WebResponse r = rawGet(c, base, siteJob);
    assertEquals(302, r.getStatusCode(), "with policy restored the gate re-arms (302)");
    assertTrue(r.getResponseHeaderValue("Location") != null
        && r.getResponseHeaderValue("Location").contains("/mfa"),
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
   * THEN  the protected-path GET → 200 with NO 302 to /mfa
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
    String job = rule.createProject(FreeStyleProject.class, "it-trust-job").getFullName();
    String siteJob = "/job/" + job + "/";
    URL base = rule.getURL();

    // -- First browser: log in + verify (grants the trust record).
    JenkinsRule.WebClient first = rule.createWebClient();
    first.setJavaScriptEnabled(false);
    first.setThrowExceptionOnFailingStatusCode(false);
    first.login(user, pw);
    HtmlPage page = mfaPage(first, base, siteJob);
    String crumb = crumbFromPage(page);
    JSONObject ok = postMfaForm(first, base, "postVerify", crumb,
        new NameValuePair("code", Totp.codeAt(key, System.currentTimeMillis())));
    assertTrue(ok.optBoolean("ok"), "the first browser must verify (trust granted): " + ok);

    // -- Second browser: fresh everything; the persisted trust must carry
    //    it straight through.
    JenkinsRule.WebClient second = rule.createWebClient();
    second.setJavaScriptEnabled(false);
    second.setThrowExceptionOnFailingStatusCode(false);
    second.login(user, pw);
    WebResponse got = rawGet(second, base, siteJob);
    assertEquals(200, got.getStatusCode(),
        "a fresh session for a trusted (remembered) user must reach the protected "
            + "path directly — trustedUntilMs governs future logins (or-branch): "
            + got.getStatusCode());
    String loc = got.getResponseHeaderValue("Location");
    assertTrue(loc == null || !loc.contains("/mfa"),
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
   * THEN  the final response is NOT a 302 to /mfa
   *       (the core's own 4xx/error page is what renders — no loop)
   * </pre>
   *
   * <p>WHY/SOLVES: without the ERROR-dispatch pass, a broken URL for a
   * verified user would render as a core error page whose own resources
   * (and the error rendering itself) re-enter the filter as ERROR
   * dispatches — and if the MFA page or error page had a missing resource,
   * the chain 302 → 404 → 302 loops forever ("Too many redirects" in
   * {@code InjectedTest} is exactly that symptom). The decision-table half
   * is unit-pinned in {@code FilterLogicTest}; this is the boot-proof that
   * a real error dispatch flows through it. The assertion is scoped to the
   * safety property (no bounce to the MFA page); the exact 4xx status is a
   * core concern, not ours.
   */
  @Test
  void errorDispatchDoesNotLoopIntoTheGate(JenkinsRule rule) throws Exception {
    String user = "it-404";
    String pw = "secret123";
    String secret = Totp.newBase32Secret();
    byte[] key = Totp.decodeSecret(secret);
    enrollTotp(user, pw, secret);
    rule.createProject(FreeStyleProject.class, "it-404-job");
    String siteJob = "/job/it-404-job/";
    URL base = rule.getURL();

    JenkinsRule.WebClient c = rule.createWebClient();
    c.setJavaScriptEnabled(false);
    c.setThrowExceptionOnFailingStatusCode(false);
    c.login(user, pw);
    HtmlPage page = mfaPage(c, base, siteJob);
    String crumb = crumbFromPage(page);
    JSONObject ok = postMfaForm(c, base, "postVerify", crumb,
        new NameValuePair("code", Totp.codeAt(key, System.currentTimeMillis())));
    assertTrue(ok.optBoolean("ok"), "verify first so the request passes the gate: " + ok);

    // A sub-path with no view for this project: the core produces a 4xx
    // (sendError → ERROR dispatch on re-entry), not a normal response.
    WebResponse resp = follow(c, base, siteJob + "no-such-action");
    String loc = resp.getResponseHeaderValue("Location");
    assertTrue(loc == null || !loc.contains("/mfa"),
        "a core error dispatch must not be bounced into the gate (recursion guard): " + loc);
    assertTrue(resp.getStatusCode() != 302 || loc == null || !loc.contains("/mfa"),
        "no 302 into the MFA page off an error dispatch: status=" + resp.getStatusCode());
  }

  // ==================================================================
  // Helpers — URL construction, enrollment, raw I/O, crumb.
  // ==================================================================

  // ---- URL construction (context-path preserving) -----------------

  /**
   * Build a request URL under the booted base, preserving the context path.
   * The harness runs Jenkins at {@code http://host:PORT/jenkins/}; a naive
   * {@code new URL(base, "/x")} treats "/x" as path-absolute and drops the
   * context, landing at the server root (a 404). We therefore strip the
   * leading slash and <em>append</em> to a trailing-slash base.
   */
  private static URL href(URL base, String rel) throws Exception {
    String r = rel.startsWith("/") ? rel.substring(1) : rel;
    String b = base.toString();
    if (!b.endsWith("/")) {
      b = b + "/";
    }
    return new URL(b + r);
  }

  /**
   * Resolve an already context-absolute location (as emitted in a 302
   * {@code Location}) to an absolute URL, anchored at the host's authority —
   * NOT under the base's context (which would duplicate it).
   */
  private static URL hostAbs(URL base, String ctxAbsolutePath) throws Exception {
    String b = base.toString();
    int slash = b.indexOf("/", b.indexOf("//") + 2);
    String authority = (slash == -1) ? b : b.substring(0, slash);
    String p = ctxAbsolutePath.startsWith("/") ? ctxAbsolutePath : "/" + ctxAbsolutePath;
    return new URL(authority + p);
  }

  /** Context path of the booted base (e.g. "/jenkins"); "" for root deploy. */
  private static String ctxOf(URL base) {
    String b = base.toString();
    int slash = b.indexOf("/", b.indexOf("//") + 2);
    if (slash == -1) {
      return "";
    }
    String rest = b.substring(slash);
    if (rest.endsWith("/")) {
      rest = rest.substring(0, rest.length() - 1);
    }
    return rest;
  }

  /** Context-absolute form of an in-site path (e.g. /jenkins/job/x/). */
  private static String ctxAbs(String ctx, String sitePath) {
    String p = sitePath.startsWith("/") ? sitePath : "/" + sitePath;
    return (ctx.isEmpty() ? "" : ctx) + p;
  }

  /** The context root — the gate's no-carrier send-back target. */
  private static String ctxRoot(String ctx) {
    return (ctx.isEmpty()) ? "/" : ctx;
  }

  // ---- Enrollment (HPSR + per-user factor) ------------------------

  /** Ensure an HPSR realm + FCOL strategy are in place (idempotent). */
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

  /**
   * Create a password-backed user in the live HPSR and enrol the TOTP factor.
   * Enrolment goes through the realm's own {@code createAccount(login,
   * password)} (core's admin-side account creation) because
   * {@code Details.fromPlainPassword} is package-private and unreachable from
   * this package (verified against jenkins-core 2.528.3). The result is a
   * genuine HPSR password session — exactly what the live gate's
   * {@code Jenkins.getAuthentication2()}-based user resolution keys off.
   */
  private User enrollTotp(String name, String pw, String secret) throws Exception {
    User u = ensureRealm().createAccount(name, pw);
    MfaUserProperty p = MfaUserProperty.getOrCreate(u);
    p.setTotpSecret(Secret.fromString(secret));
    u.save();
    return u;
  }

  private User enrollEmailAndReturn(String name, String pw, String mail) throws Exception {
    User u = ensureRealm().createAccount(name, pw);
    MfaUserProperty p = MfaUserProperty.getOrCreate(u);
    p.setRegisteredEmail(mail);
    u.save();
    return u;
  }

  private void enrollEmail(String name, String pw, String mail) throws Exception {
    enrollEmailAndReturn(name, pw, mail);
  }

  // ---- Raw I/O ---------------------------------------------------

  /** A raw GET that truly stops at the first response — 302s are NOT
   *  followed, so {@code getStatusCode()/Location} describe the gate's own
   *  bounce, not the page behind it. (The client follows redirects by
   *  default; A19's defect was exactly that this helper's original
   *  "no redirect following" contract was never honoured, so the 404/500
   *  "gate" failures were in fact the *destination* page's status — the
   *  gate's 302 itself was correct on both counts. Restored here with an
   *  explicit toggle instead of a second client, so the session/cookies —
   *  and any state the case just set on this client — stay in play.) */
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

  /**
   * Follow 302s of a GET manually (one hop at a time, no client follow),
   * stopping at a non-302 or after 5 hops. Used where a final-status check
   * is the point (not the raw bounce).
   */
  private WebResponse follow(JenkinsRule.WebClient c, URL base, String path) throws Exception {
    WebResponse resp = rawGet(c, base, path);
    for (int hops = 0; resp.getStatusCode() == 302 && hops++ < 5; ) {
      String loc = resp.getResponseHeaderValue("Location");
      WebRequest req = new WebRequest(hostAbs(base, loc));
      try {
        resp = c.loadWebResponse(req);
      } catch (FailingHttpStatusCodeException e) {
        resp = e.getResponse();
      }
    }
    return resp;
  }

  /** Navigate the client to the MFA gate-bounce page and return the HTML. */
  private HtmlPage mfaPage(JenkinsRule.WebClient c, URL base, String path) throws Exception {
    WebResponse bounce = rawGet(c, base, path);
    assertEquals(302, bounce.getStatusCode(),
        "the enrolled unverified user must be bounced (302) to the MFA page: "
            + bounce.getStatusCode());
    String loc = bounce.getResponseHeaderValue("Location");
    assertNotNull(loc, "the bounce must carry a Location header");
    return (HtmlPage) c.getPage(hostAbs(base, loc));
  }

  /** The value of the MFA page's single hidden (crumb) input; remembers its name. */
  private String crumbFromPage(HtmlPage page) {
    // The MFA page declares the form by id, not name
    // (index.jelly: <form id="verifyForm">) — HtmlUnit's name lookup would
    // miss it and every case would die on a missing-form exception at boot.
    HtmlForm form = (HtmlForm) page.getElementById("verifyForm");
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
    WebRequest req = new WebRequest(href(base, "mfa/" + endpoint), HttpMethod.POST);
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
      resp = e.getResponse();
    }
    assertEquals(200, resp.getStatusCode(),
        "the MFA endpoint must answer with its 200 JSON envelope: " + resp.getStatusCode());
    return JSONObject.fromObject(resp.getContentAsString());
  }

  // ---- Small pure helpers ----------------------------------------

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
        return cookie.getValue();
      }
    }
    return null;
  }
}
