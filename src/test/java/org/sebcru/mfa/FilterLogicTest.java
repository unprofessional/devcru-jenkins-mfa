package org.sebcru.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.sebcru.mfa.DevcruMfaConfig.Policy;
import org.sebcru.mfa.MfaFilter.MfaFilterDecision;

/**
 * TDD record for {@link MfaFilter#decision} (Task 7) — the gate's whole
 * security question in one pure function: "given this request's extracted
 * inputs, do we let it through, or bounce it to the second-factor page?"
 *
 * <h2>What this file pins down</h2>
 * <p>The decision chain (plan §Task 7, order 0–9) as a truth table, one
 * branch per test group, in a plain JVM — no Jenkins boot, no HTTP, no
 * clock (the trust check's result is an input boolean; {@code FilterLogicTest}
 * never reads the wall time). The {@code doFilter} glue that <em>extracts</em>
 * these inputs from a live {@code HttpServletRequest} is deliberately left to
 * Task 8's {@code MfaFilterIT} (recorded in {@code MfaFilter}'s class doc).
 * <p>Also pinned: {@link MfaFilter#off} (the kill-switch OR, unit-testable
 * without JVM env) and {@link MfaFilter#resolveTarget} (the A3 ruling — the
 * {@code ?redirect=} parameter is canonical over {@code Referer}, and both
 * flow through the ONE open-redirect validator, so a forged parameter can
 * never bounce a user off-site).
 *
 * <h2>Red → green history</h2>
 * <p>No red phase is claimed against production behaviour: the decision chain
 * is a fresh implementation in this same session. The honest value is the
 * <em>branch pinning</em> of a security gate — several of these tests would
 * have been impossible to write as "mirror of the implementation" tests,
 * because their expectations come from the mads-signed security decisions
 * (unenrolled users are never hard-locked; API tokens are exempt; a verified
 * session is trusted for its life; OR-not-AND at step 9) and from the
 * plan's step ORDER (apiToken beats everything but the kill switch;
 * the allow-list is a security property, not a convenience). Where a test
 * encodes a signed decision it says which one, in WHY/SOLVES.
 */
class FilterLogicTest {

  // -----------------------------------------------------------------------
  // Step 0 — the kill switch (off()).
  // -----------------------------------------------------------------------

  /**
   * WHAT: the kill-switch OR semantics of {@code MfaFilter.off} — the gate is
   * inert if EITHER input trips it, and active only if both are clear.
   *
   * <p>BDD:
   * <pre>
   * GIVEN the env var DEVCRU_MFA_OFF is unset (null)
   * WHEN  the policy is REQUIRED
   * THEN  off() is false — the gate runs its full chain
   * GIVEN the env var is unset
   * WHEN  the policy is OFF
   * THEN  off() is true — the admin kill switch passes everything
   * GIVEN the env var is "1"
   * WHEN  the policy is REQUIRED  (env trips alone)
   * THEN  off() is true — the incident path works even with a healthy config
   * GIVEN the env var is "1"
   * WHEN  the policy is null     (a wedged / unreadable config)
   * THEN  off() is true — unreadable config degrades to the kill switch,
   *                   NOT to "gate everything"
   * GIVEN the env var is "0" (set to an inactive value)
   * WHEN  the policy is REQUIRED
   * THEN  off() is false — "0" is not a trip; only "1" is
   * </pre>
   *
   * <p>WHY/SOLVES: the README's "disabling the whole gate is a setting, not
   * an uninstall" is enforced by this one OR. The null-policy branch is the
   * load-bearing one: if an unreadable config meant "gate everything", a
   * corrupted DevcruMfaConfig.xml would lock every user out of Jenkins
   * (including the admin who has to fix it) — the incident case the env var
   * exists for becomes a footgun.
   */
  @Test
  void killSwitchIsEitherHalfAndNullPolicyDegradesToOff() {
    assertFalse(MfaFilter.off(null, Policy.REQUIRED));
    assertTrue(MfaFilter.off(null, Policy.OFF));
    assertTrue(MfaFilter.off("1", Policy.REQUIRED));
    assertTrue(MfaFilter.off("1", null));
    assertFalse(MfaFilter.off("0", Policy.REQUIRED));
  }

  /**
   * WHAT: a policy-OFF request never reaches REDIRECT, regardless of every
   * other input being "the worst case for passing".
   *
   * <p>BDD:
   * <pre>
   * GIVEN policy = OFF
   * AND   a user who is NOT exempt, IS enrolled, has NO verified session,
   *       has NO live trust, on a protected path, not an API token,
   *       not an error dispatch
   * WHEN  the full decision chain is evaluated
   * THEN  the outcome is PASS
   * </pre>
   *
   * <p>WHY/SOLVES: the same kill-switch guarantee at the decision level as
   * {@code off()} provides at the filter level — defense in depth against a
   * future regression that reorders step 0 below the other steps. "An admin
   * who turned MFA off must not be gated" is a signed expectation (README's
   * corner-cases section), so its violation is a support ticket, not a
   * nitpick.
   */
  @Test
  void policyOffPassesEvenWithEveryOtherInputWorstCase() {
    assertEquals(MfaFilterDecision.PASS,
        MfaFilter.decision(Policy.OFF,
            false,   // not exempt
            false,   // enrolled (worst case for passing)
            false,   // no verified session
            false,   // no live trust
            false,   // not an error dispatch
            "/job/web/",
            false)); // not an API token
  }

  // -----------------------------------------------------------------------
  // Step 2 — API tokens (CI).
  // -----------------------------------------------------------------------

  /**
   * WHAT: API-token requests PASS the gate with every other input worst-case
   * — the exemption does not depend on the user's enrolment, session, or
   * trust state.
   *
   * <p>BDD:
   * <pre>
   * GIVEN policy = REQUIRED, the request IS API-token-authenticated
   * AND   the underlying user is enrolled, NOT exempt, unverified session,
   *       no live trust, on a protected path ("/job/web/")
   * WHEN  the full decision chain is evaluated
   * THEN  the outcome is PASS
   * GIVEN the same inputs but apiToken = false
   * WHEN  the same chain is evaluated
   * THEN  the outcome is REDIRECT (the gate still works when the token
   *                   flag is absent)
   * </pre>
   *
   * <p>WHY/SOLVES: security decision 1 — "API tokens are exempt; gating
   * them breaks CI." The second branch (token flag absent ⇒ REDIRECT)
   * protects against a regression that makes the exemption unconditional —
   * an always-PASS gate is no gate at all, and only the paired
   * token-true/token-false inputs would catch that here.
   */
  @Test
  void apiTokenPassesAndOnlyThen() {
    assertEquals(MfaFilterDecision.PASS,
        MfaFilter.decision(Policy.REQUIRED,
            false, false, false, false, false, "/job/web/", true));
    assertEquals(MfaFilterDecision.REDIRECT,
        MfaFilter.decision(Policy.REQUIRED,
            false, false, false, false, false, "/job/web/", false));
  }

  // -----------------------------------------------------------------------
  // Step 4 — ERROR dispatch.
  // -----------------------------------------------------------------------

  /**
   * WHAT: core ERROR dispatches PASS the gate — the error page is not a
   * gated resource, and a failure in the gate's own path must not recurse.
   *
   * <p>BDD:
   * <pre>
   * GIVEN policy = REQUIRED, an enrolled non-exempt user, no verified
   *       session, no live trust
   * WHEN  the request is a core ERROR dispatch on a protected path
   * THEN  the outcome is PASS
   * GIVEN the same inputs but errorDispatch = false
   * WHEN  the chain is evaluated
   * THEN  the outcome is REDIRECT (normal dispatches are still gated)
   * </pre>
   *
   * <p>WHY/SOLVES: without this pass, every 404 (a user typing a URL wrong)
   * and every 500 (any bug anywhere in Jenkins) would 302 to the MFA page
   * first — turning a harmless typo into an MFA challenge, and turning any
   * server-side error in the MFA page's own dependency tree into a
   * 302→404→302 loop the user can never escape. The paired
   * error-true/error-false inputs pin that the pass is specific to ERROR
   * dispatches, not a blanket hole.
   */
  @Test
  void errorDispatchPassesAndOnlyThen() {
    assertEquals(MfaFilterDecision.PASS,
        MfaFilter.decision(Policy.REQUIRED,
            false, false, false, false, true, "/job/web/", false));
    assertEquals(MfaFilterDecision.REDIRECT,
        MfaFilter.decision(Policy.REQUIRED,
            false, false, false, false, false, "/job/web/", false));
  }

  // -----------------------------------------------------------------------
  // Step 5 — the path allow-list.
  // -----------------------------------------------------------------------

  /**
   * WHAT: the authentication flow, the MFA page, static assets, and the
   * crumb endpoint are all allowed through ungated; everything else (and a
   * null path) is not.
   *
   * <p>BDD:
   * <pre>
   * GIVEN policy = REQUIRED, a non-exempt enrolled user, no session, no trust
   * WHEN  the request path is any of: /login, /j_acegi_securityCheck,
   *       /mfa, /images/logo.png,
   *       /static/2.528/js/core.js
   * THEN  each is PASS (the login flow and the MFA page itself must be
   *                   reachable for the user to ever get verified)
   * WHEN  the request path is /, /job/web/, /user/mads, /configure
   * THEN  each is REDIRECT (ordinary pages ARE the gated resource)
   * WHEN  the request path is null (no path could be extracted)
   * THEN  the outcome is REDIRECT — fail closed on unknown shape
   * </pre>
   *
   * <p>WHY/SOLVES: the allow-list is the "the user can actually complete
   * MFA" half of the gate — a regression that drops /mfa
   * breaks the entire plugin (the bounce target itself gets bounced); a
   * regression that widens the allow-list past login/static assets quietly
   * ungates real pages. The null case pins the fail-closed posture: when we
   * can't identify the resource, we don't let it through.
   */
  @Nested
  class PathAllowList {
    private static final Object[] ALLOWED = {"/login", "/j_acegi_securityCheck",
        "/mfa", "/images/logo.png",
        "/static/2.528/js/core.js", "/scripts/something.js", "/css/theme.css",
        "/adjuncts/123/xyz", "/logout"};

    @Test
    void loginFlowAndStaticAssetsPass() {
      for (Object path : ALLOWED) {
        assertEquals(MfaFilterDecision.PASS,
            MfaFilter.decision(Policy.REQUIRED,
                false, false, false, false, false, (String) path, false),
            "expected PASS for allowed path: " + path);
      }
    }

    @Test
    void protectedPathsRedirect() {
      for (String path : new String[]{"/", "/job/web/", "/user/mads",
          "/configure", "/about"}) {
        assertEquals(MfaFilterDecision.REDIRECT,
            MfaFilter.decision(Policy.REQUIRED,
                false, false, false, false, false, path, false),
            "expected REDIRECT for protected path: " + path);
      }
    }

    /**
     * WHAT: a null request path (the extraction produced nothing) is not
     * allowed — the gate fails closed on an unidentifiable resource.
     *
     * <p>BDD:
     * <pre>
     * GIVEN policy = REQUIRED, an enrolled non-exempt user, no session, no trust
     * WHEN  the request path is null
     * THEN  the outcome is REDIRECT
     * </pre>
     *
     * <p>WHY/SOLVES: the null path is not "we don't know, let it through" —
     * it is "we don't know, gate it." A user-facing 302 (one code to type)
     * is a far smaller price than an ungated page whose URL we failed to
     * extract, which is exactly the fail-closed rule the class doc commits to.
     */
    @Test
    void nullPathFailsClosed() {
      assertEquals(MfaFilterDecision.REDIRECT,
          MfaFilter.decision(Policy.REQUIRED,
              false, false, false, false, false, null, false));
    }
  }

  // -----------------------------------------------------------------------
  // Step 7 — the exemption list (service accounts).
  // -----------------------------------------------------------------------

  /**
   * WHAT: a user on the exemption list PASSes even when enrolled, unverified,
   * and untrusted — the exemption is absolute (it is for service accounts
   * that cannot MFA).
   *
   * <p>BDD:
   * <pre>
   * GIVEN policy = REQUIRED, an EXEMPT user, enrolled, no session, no trust,
   *       on a protected path
   * WHEN  the chain is evaluated
   * THEN  the outcome is PASS
   * GIVEN the same inputs but exempt = false
   * WHEN  the chain is evaluated
   * THEN  the outcome is REDIRECT
   * </pre>
   *
   * <p>WHY/SOLVES: README corner-case "unenrolled users and service
   * accounts … an exemption list for service accounts." If the exemption
   * were narrower than absolute (e.g. only unenrolled users), a headless
   * service account that somehow carries a stale MfaUserProperty would be
   * locked out of Jenkins forever — with no UI to fix it from, because the
   * admin recovery path requires a logged-in session. The paired
   * exempt-true/exempt-false inputs pin the width of the exemption.
   */
  @Test
  void exemptUserPassesAndOnlyThen() {
    assertEquals(MfaFilterDecision.PASS,
        MfaFilter.decision(Policy.REQUIRED,
            true, false, false, false, false, "/job/web/", false));
    assertEquals(MfaFilterDecision.REDIRECT,
        MfaFilter.decision(Policy.REQUIRED,
            false, false, false, false, false, "/job/web/", false));
  }

  // -----------------------------------------------------------------------
  // Step 8 — unenrolled users are never hard-locked.
  // -----------------------------------------------------------------------

  /**
   * WHAT: a user with no MFA factors enrolled PASSes — MFA is mandatory
   * once enrolled, not mandatory in general.
   *
   * <p>BDD:
   * <pre>
   * GIVEN policy = REQUIRED, a NON-EXEMPT user who is NOT enrolled
   *       (no TOTP secret, no registered email), no session, no trust
   * WHEN  the chain is evaluated
   * THEN  the outcome is PASS
   * GIVEN the same user but now enrolled (notEnrolled = false)
   * WHEN  the chain is evaluated
   * THEN  the outcome is REDIRECT (enrolment is what turns the gate on)
   * </pre>
   *
   * <p>WHY/SOLVES: the mads-signed decision "unenrolled users are NOT
   * hard-locked." On a fresh instance where nobody has enrolled yet,
   * notEnrolled=true for everyone — a regression that flips this to
   * REDIRECT would lock every user out of Jenkins on day one (the classic
   * "mandatory MFA plugin that nobody can log in to because nobody could
   * enrol"). The paired inputs pin that enrolment is the switch that
   * flips the decision, not policy=REQUIRED.
   */
  @Test
  void unenrolledPassesEnrolledRedirects() {
    assertEquals(MfaFilterDecision.PASS,
        MfaFilter.decision(Policy.REQUIRED,
            false, true, false, false, false, "/job/web/", false));
    assertEquals(MfaFilterDecision.REDIRECT,
        MfaFilter.decision(Policy.REQUIRED,
            false, false, false, false, false, "/job/web/", false));
  }

  // -----------------------------------------------------------------------
  // Step 9 — the session flag OR the remembered-device trust.
  // -----------------------------------------------------------------------

  /**
   * WHAT: step 9 is a DISJUNCTION — each of the two trust instruments is
   * sufficient on its own, and their combination is also sufficient. This
   * deliberately rejects the plan line-559 sketch's "AND" reading (see
   * {@code MfaFilter}'s class doc for the two mads-signed semantics).
   *
   * <p>BDD:
   * <pre>
   * GIVEN policy = REQUIRED, an enrolled non-exempt user, protected path
   * WHEN  sessionVerified = true  AND trustLive = false   (live session,
   *       the trust window having expired mid-session)
   * THEN  PASS — a session that already proved the factor is trusted for
   *                   its lifetime; there is no per-request expiry (signed)
   * GIVEN the same user, WHEN sessionVerified = false AND trustLive = true
   *       (fresh browser inside the remember-window, no session flag yet)
   * THEN  PASS — the remembered-device path IS the disjunction's reason to
   *                   exist; AND-ing the inputs deletes this entire feature
   * GIVEN the same user, WHEN both are true
   * THEN  PASS (trivially — the OR of two trues)
   * GIVEN the same user, WHEN both are false
   * THEN  REDIRECT — the gate's whole reason to be
   * </pre>
   *
   * <p>WHY/SOLVES: the two signed decisions are (a) "a live session that
   * logged in is trusted for its lifetime" (no re-auth churn — the replaced
   * plugin's exact UX sin) and (b) "a future login from a remembered
   * browser inside the window skips the code." (a) is the
   * sessionVerified-only branch; (b) is the trustLive-only branch — the
   * fresh-login case where NO session flag can exist yet. A regression to
   * AND-logic breaks (b) entirely (the "re-login within 30 d → no second
   * prompt" acceptance line) and adds churn to (a). All four quadrants are
   * pinned so either branch can't regress silently behind the other.
   */
  @Test
  void step9IsADisjunction() {
    assertEquals(MfaFilterDecision.PASS,
        MfaFilter.decision(Policy.REQUIRED,
            false, false, true, false, false, "/job/web/", false),
        "verified session alone must pass (no per-request expiry — signed)");
    assertEquals(MfaFilterDecision.PASS,
        MfaFilter.decision(Policy.REQUIRED,
            false, false, false, true, false, "/job/web/", false),
        "live trust alone must pass (remembered device on a fresh login)");
    assertEquals(MfaFilterDecision.PASS,
        MfaFilter.decision(Policy.REQUIRED,
            false, false, true, true, false, "/job/web/", false),
        "both instruments live must pass");
    assertEquals(MfaFilterDecision.REDIRECT,
        MfaFilter.decision(Policy.REQUIRED,
            false, false, false, false, false, "/job/web/", false),
        "neither instrument live must redirect (the gate's job)");
  }

  // -----------------------------------------------------------------------
  // Ordering — earlier steps beat later ones.
  // -----------------------------------------------------------------------

  /**
   * WHAT: the plan's step order is load-bearing — API-token, error-dispatch,
   * and allow-list passes all take precedence over steps 6–9, and the
   * exemption/unenrolled passes beat step 9.
   *
   * <p>BDD:
   * <pre>
   * GIVEN an enrolled, non-exempt, unverified, untrusted user (everything
   *       that would REDIRECT at step 9)
   * WHEN  they are an API token (step 2)
   * THEN  PASS — even though they are enrolled
   * WHEN  the request is on /mfa (step 5)
   * THEN  PASS — the MFA page is reachable for the very user who needs it
   * GIVEN the same user but NOT an API token and NOT on an allowed path
   * WHEN  they are exempt (step 7)
   * THEN  PASS — even though enrolled + unverified + untrusted
   * WHEN  they are not exempt but not enrolled (step 8)
   * THEN  PASS — even though unverified + untrusted
   * </pre>
   *
   * <p>WHY/SOLVES: if a later step's condition could override an earlier
   * step's pass, the exempt service account would be gated on a page it has
   * no way to get past, the API token would break CI, and the MFA page it
   * 302s users to would 302 users away — each a silent, total failure.
   * Pinning the order (not just the outcomes) is what keeps a future
   * "reorder for clarity" from silently breaking a signed property.
   */
  @Test
  void earlierStepsBeLaterSteps() {
    // API token beats enrolment (2 before 7/8/9).
    assertEquals(MfaFilterDecision.PASS,
        MfaFilter.decision(Policy.REQUIRED,
            false, false, false, false, false, "/job/web/", true));
    // Allow-list beats enrolment (5 before 7/9).
    assertEquals(MfaFilterDecision.PASS,
        MfaFilter.decision(Policy.REQUIRED,
            false, false, false, false, false, "/mfa", false));
    // Exemption beats enrolment + step 9 (7 before 9).
    assertEquals(MfaFilterDecision.PASS,
        MfaFilter.decision(Policy.REQUIRED,
            true, false, false, false, false, "/job/web/", false));
    // Unenrolled beats step 9 (8 before 9).
    assertEquals(MfaFilterDecision.PASS,
        MfaFilter.decision(Policy.REQUIRED,
            false, true, false, false, false, "/job/web/", false));
  }

  // -----------------------------------------------------------------------
  // The A3 seam — ?redirect= canonical over Referer, one validator.
  // -----------------------------------------------------------------------

  /**
   * WHAT: {@code resolveTarget} gives the {@code ?redirect=} parameter
   * precedence over the {@code Referer} header, and falls back to Referer
   * when the parameter is absent/blank — the A3 ruling (mads, 2026-08-18),
   * pinned at the seam so the gate's bounce URL and the controller's
   * post-verify target can never drift into two shaped validators.
   *
   * <p>BDD:
   * <pre>
   * GIVEN a site at host "jenkins.dev", root context
   * WHEN  the parameter is the in-site path  /job/web/
   * AND   the Referer is the MFA page's own URL  https://jenkins.dev/mfa
   *       (the form-POST shape — Referer alone would re-prompt the user)
   * THEN  the resolved target is /job/web/ — the PARAMETER wins, not the
   *                   Referer
   * GIVEN a site at host "jenkins.dev", root context
   * WHEN  the parameter is absent (null) AND the Referer is /job/web
   * THEN  the resolved target is /job/web — the header fallback still works
   * GIVEN a site at host "jenkins.dev", root context
   * WHEN  the parameter is present but blank ("  ") AND the Referer is /job/web
   * THEN  the resolved target is /job/web — a blank parameter is treated as
   *                   absent, not as a valid (empty) target
   * </pre>
   *
   * <p>WHY/SOLVES: this is the entire "back to where you were" fix. The
   * form-POST shape (branch 1) is the one that makes the fix real: the
   * MFA page's own URL as the Referer is what a browser actually hands us,
   * so a Referer-only implementation would land a verified user back on
   * the MFA page (an immediate re-prompt loop) — the A5 audit finding this
   * closes. Branches 2 and 3 protect the fallback so a page opened without
   * the parameter (e.g. a user bookmarking /mfa) still gets
   * a sensible send-back.
   */
  /**
   * WHAT: the A3 ruling's input-selection half — the {@code ?redirect=}
   * query parameter is canonical over the {@code Referer} header, and a
   * blank parameter is treated exactly like an absent one.
   *
   * <p>BDD:
   * <pre>
   * GIVEN the site host "jenkins.dev":8080, root context
   * AND   a form-POST shape: the parameter present ("/job/web/") and the
   *       Referer being the MFA page's OWN url (the A5 failure mode)
   * WHEN  resolveTarget selects its input
   * THEN  the PARAMETER wins — the target is /job/web/, not the MFA page
   * GIVEN the same site
   * WHEN  the parameter is absent (null) and the Referer is "/job/web"
   * THEN  the Referer fallback applies — the target is /job/web
   * GIVEN the same site
   * WHEN  the parameter is present but blank ("   ") and the Referer is
   *       "/job/web"
   * THEN  the blank parameter is treated as absent — the Referer applies
   * </pre>
   *
   * <p>WHY/SOLVES: without the parameter-first rule the normal browser flow
   * (the A5 audit finding) re-prompts in a loop — the form POST carries the
   * MFA page's own URL as its Referer, so a Referer-first selection sends
   * the user back to the very page they just finished. The blank-parameter
   * branch keeps a defensively-emptied parameter (a future form field, a
   * stripped URL) from silently defeating the fallback. The security half
   * of this seam (a *forged* parameter cannot escape the site) is the next
   * test, {@code resolveTargetRefusesOffSiteParameter}.
   */
  @Test
  void resolveTargetPrefersCanonicalParameter() {
    // 1. The form-POST shape: parameter present, Referer = the MFA page.
    assertEquals("/job/web/",
        MfaFilter.resolveTarget("/job/web/",
            "https://jenkins.dev/mfa",
            "jenkins.dev", "8080", ""));
    // 2. Parameter absent → Referer fallback.
    assertEquals("/job/web",
        MfaFilter.resolveTarget(null, "/job/web",
            "jenkins.dev", "8080", ""));
    // 3. Blank parameter → Referer fallback (treated as absent).
    assertEquals("/job/web",
        MfaFilter.resolveTarget("   ", "/job/web",
            "jenkins.dev", "8080", ""));
  }

  /**
   * WHAT: a forged {@code ?redirect=} parameter CANNOT bounce a user
   * off-site — the parameter goes through the SAME open-redirect validator
   * as the Referer, so a malicious parameter degrades to the site root
   * exactly the way a malicious Referer does.
   *
   * <p>BDD:
   * <pre>
   * GIVEN a site at host "jenkins.dev", root context
   * WHEN  the parameter is   https://evil.com/phish      (cross-origin)
   * AND   the parameter is   //evil.com/phish            (protocol-relative)
   * AND   the parameter is   /login                      (security path)
   * THEN  each resolves to the site root "/" — NEVER the raw parameter
   * GIVEN the same site
   * WHEN  the parameter is   /job/web/  (a legitimate in-site path)
   * THEN  it resolves to /job/web/  (the happy path still works after the
   *                   above branches are pinned)
   * </pre>
   *
   * <p>WHY/SOLVES: the parameter is attacker-controllable in a way the
   * Referer is also attacker-controllable — an attacker can set a victim's
   * browser to GET /mfa?redirect=https://evil.com/ and have
   * the victim's successful MFA send them to the attacker's site. Routing
   * the parameter through the one existing validator (rather than a
   * second, looser, "parameters are probably fine" path) is what makes the
   * open-redirect guarantee hold for the new input as well. This is the
   * security property A3's implementation must not trade away for
   * convenience.
   */
  @Test
  void resolveTargetRefusesOffSiteParameter() {
    assertEquals("/",
        MfaFilter.resolveTarget("https://evil.com/phish", null,
            "jenkins.dev", "8080", ""));
    assertEquals("/",
        MfaFilter.resolveTarget("//evil.com/phish", null,
            "jenkins.dev", "8080", ""));
    assertEquals("/",
        MfaFilter.resolveTarget("/login", null,
            "jenkins.dev", "8080", ""));
    // Happy path after the refusals — the parameter is not uniformly blocked.
    assertEquals("/job/web/",
        MfaFilter.resolveTarget("/job/web/", null,
            "jenkins.dev", "8080", ""));
  }

  // -----------------------------------------------------------------------
  // The full "default fresh-login" case — the gate's raison d'être.
  // -----------------------------------------------------------------------

  /**
   * WHAT: the canonical gated case — a password-authenticated, enrolled,
   * non-exempt user on a fresh session (no verified flag, no live trust)
   * on an ordinary page — is REDIRECTed to the MFA page. This is the one
   * row of the table the whole plugin exists to produce, and it is pinned
   * on its own so a regression that makes the gate uniformly pass (or
   * uniformly redirect) is one assertion's width from being caught.
   *
   * <p>BDD:
   * <pre>
   * GIVEN policy = REQUIRED
   * AND   a NON-EXEMPT user who IS enrolled
   * AND   NO verified session flag, NO live trust
   * AND   a normal (non-error) dispatch on a protected path ("/")
   * AND   NOT an API-token request
   * WHEN  the full decision chain is evaluated
   * THEN  the outcome is REDIRECT
   * </pre>
   *
   * <p>WHY/SOLVES: if this single row ever became PASS, the gate would be
   * decorative — a TOTP/email enrolment that changes nothing, and every
   * acceptance line in the plan's Task 10 (mads logs in → lands on the MFA
   * page) would fail. The row is also the one most likely to be "fixed"
   * away by a future "simplify the decision" pass that drops step 9's
   * redirect branch, believing the per-input tests above cover it — they
   * cover the branches, but only this row pins the default outcome.
   */
  @Test
  void canonicalGatedCaseRedirects() {
    assertEquals(MfaFilterDecision.REDIRECT,
        MfaFilter.decision(Policy.REQUIRED,
            false,   // not exempt
            false,   // enrolled
            false,   // no verified session
            false,   // no live trust
            false,   // normal dispatch
            "/",     // protected path
            false)); // not an API token
  }
}
