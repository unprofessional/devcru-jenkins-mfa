package org.sebcru.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import hudson.util.Secret;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.sebcru.mfa.MfaController.Factor;

/**
 * TDD record for the pure seams of {@link MfaController} (Task 6) — the
 * security-relevant decisions extracted as package-private statics exactly so
 * this file can pin them in a plain JVM with no running Jenkins, no HTTP, and
 * no clock.
 *
 * <h2>What this file pins down</h2>
 * <ol>
 *   <li>{@code resolveRedirectTarget} — the "no dead redirect / no open
 *       redirect" validator: same-origin non-login referers are honoured, and
 *       everything else (missing, cross-origin, protocol-relative, security
 *       paths, non-"/"-relative) degrades to the site root. This is the seam
 *       whose failure modes are either "MFA works but lands on a black page"
 *       (the SaaS-legacy behaviour we are replacing) or "verified user bounced
 *       to attacker's site" (open redirect) — both are real defects, in
 *       opposite directions, of the same decision.</li>
 *   <li>{@code classifyFactor} — shape-based factor selection: a 6-digit
 *       string is only ever tried as TOTP, an 8-char alphabet string only
 *       ever as email code, everything else is a failed attempt (counted by
 *       the rate limiter), never a 500.</li>
 *   <li>{@code maskEmail} — the registered mailbox shown on the page is
 *       masked to first-char + domain, so the not-yet-verified viewer cannot
 *       read the full address off the MFA page.</li>
 * </ol>
 *
 * <h2>Red → green history</h2>
 * <p>No red phase is claimed: these were written as spec-pins in the same
 * session as the implementation (the independent-oracle opportunity —
 * published vectors — applies to the crypto, locked in by TotpTest). The
 * honest value of this file is boundary-branch pinning for a pure
 * security-relevant validator that the Task 8 Jenkins boot test will not
 * branch-cover, plus the regression guard on the two flagged deviations
 * (RootAction URL path; shape-based factor routing).
 */
class MfaControllerTest {

  // =====================================================================
  // resolveRedirectTarget — no dead redirect / no open redirect
  // =====================================================================

  /**
   * WHAT: the happy path of resolveRedirectTarget — an in-site target is
   * honoured, so a user MFA-ing on a job page lands back on that job page
   * instead of a blank/dead page (the legacy SaaS plugin's failure mode).
   *
   * <p>BDD:
   * <pre>
   * GIVEN a site at host "jenkins.dev" (port ignored unless in URL), root context
   * WHEN  the referer is the same-site absolute URL  https://jenkins.dev/job/web/
   * AND  the referer is the same-site relative path  /job/web/
   * THEN  both resolve to /job/web/ — the exact in-site path the user came from
   * WHEN  there is no referer at all (null / blank)
   * THEN  the result is the site root "/" — still a live page, never an error URL
   * </pre>
   *
   * <p>WHY/SOLVES: the whole point of this plugin over the SaaS thing it
   * replaces is "MFA returns you to where you were, not a black page." A
   * regression that drops the honours-in-site case regresses the plugin to
   * the thing we left; a regression that drops the missing-referer fallback
   * produces an empty/404 post-login. Both directions are pinned here.
   */
  @Test
  void honoursInSiteRefererAndFallsBackToRoot() {
    assertEquals("/job/web/",
        MfaController.resolveRedirectTarget("https://jenkins.dev/job/web/",
            "jenkins.dev", "8080", ""));
    assertEquals("/job/web/",
        MfaController.resolveRedirectTarget("/job/web/",
            "jenkins.dev", "8080", ""));
    assertEquals("/",
        MfaController.resolveRedirectTarget(null, "jenkins.dev", "8080", ""));
    assertEquals("/",
        MfaController.resolveRedirectTarget("   ", "jenkins.dev", "8080", ""));
  }

  /**
   * WHAT: the open-redirect refusals of resolveRedirectTarget — every
   * off-site target shape degrades to the site root, so a forged
   * Referer header can never bounce a just-verified user off the site.
   *
   * <p>BDD:
   * <pre>
   * GIVEN the same site as above
   * WHEN  the referer is protocol-relative      //evil.com/phish
   * AND  the referer is cross-origin absolute   https://evil.com/phish
   * AND  the referer is a non-http scheme       javascript:alert(1)
   * AND  the referer is a bare relative         evil.com/phish (no leading /)
   * THEN  every one of them resolves to "/" — the site root
   * WHEN  the referer is same-host but a WRONG PORT  https://jenkins.dev:9443/
   *       on a site listening on 8080
   * THEN  it resolves to "/" (origin, not just host, must match)
   * </pre>
   *
   * <p>WHY/SOLVES: this is the direct opposite failure of the previous test —
   * the same validator that makes back-navigation helpful must make
   * Referer-forging useless. The four shapes are the four classic open-
   * redirect carriers: protocol-relative (looks same-origin to a naive
   * startsWith check), absolute cross-origin, non-HTTP scheme, and bare-
   * relative (browser resolves against the current ORIGIN — but our resolver
   * cannot vouch for that, so it must refuse). The port case pins that
   * "origin" means scheme+host+port: a same-host different-port referer is a
   * different security zone on a mis-configured box.
   */
  @Test
  void refusesOpenRedirectShapes() {
    assertEquals("/",
        MfaController.resolveRedirectTarget("//evil.com/phish",
            "jenkins.dev", "8080", ""));
    assertEquals("/",
        MfaController.resolveRedirectTarget("https://evil.com/phish",
            "jenkins.dev", "8080", ""));
    assertEquals("/",
        MfaController.resolveRedirectTarget("javascript:alert(1)",
            "jenkins.dev", "8080", ""));
    assertEquals("/",
        MfaController.resolveRedirectTarget("evil.com/phish",
            "jenkins.dev", "8080", ""));
    assertEquals("/",
        MfaController.resolveRedirectTarget("https://jenkins.dev:9443/",
            "jenkins.dev", "8080", ""));
    // And the positive control: same origin WITH an explicit matching port
    // is honoured — pins that the port check is compared, not blanket-refused.
    assertEquals("/job/web/",
        MfaController.resolveRedirectTarget("https://jenkins.dev:8080/job/web/",
            "jenkins.dev", "8080", ""));
  }

  /**
   * WHAT: the security-path exclusion of resolveRedirectTarget — verified
   * users are never redirected into the login flow or back onto the MFA
   * page itself.
   *
   * <p>BDD:
   * <pre>
   * GIVEN the same site
   * WHEN  the referer points at /login, /logout, /signup, /securityRealm/mfa
   * THEN  each resolves to "/" — not to the security flow
   * WHEN  the referer is an ordinary page that merely CONTAINS a security word
   *       mid-path (/jobs/security-review/)
   * THEN  it is honoured — the exclusion tests the first path segment, not
   *       substring containment
   * </pre>
   *
   * <p>WHY/SOLVES: redirecting a just-verified user to /login drops the
   * completed authentication (Spring sees a logged-out user and re-auths);
   * redirecting to the MFA page itself is an infinite re-prompt loop — the
   * user can prove a factor forever and never get in. Both were the
   * "MFA works but login never completes" family the plan calls out. The
   * first-segment (not substring) pin matters because real Jenkins trees
   * frequently contain jobs named "security-review" etc.; a substring rule
   * would silently break back-navigation for them while feeling perfectly
   * safe in review.
   */
  @Test
  void refusesSecurityPathsButHonoursLookalikes() {
    for (String p : new String[] {
        "/login", "/logout", "/signup", "/securityRealm/mfa", "/security/realms"}) {
      assertEquals("/", MfaController.resolveRedirectTarget(p,
          "jenkins.dev", "8080", ""),
          "security path must fall back to root: " + p);
    }
    assertEquals("/jobs/security-review/",
        MfaController.resolveRedirectTarget("/jobs/security-review/",
            "jenkins.dev", "8080", ""));
  }

  /**
   * WHAT: the context-path handling of resolveRedirectTarget — Jenkins
   * installed under /jenkins must keep the mount path in both the honoured
   * target and the fallback root.
   *
   * <p>BDD:
   * <pre>
   * GIVEN a site under context path /jenkins (root-installed sites use "")
   * WHEN  the referer is /jenkins/job/web/
   * THEN  the result is /jenkins/job/web/ — mount preserved, path honoured
   * WHEN  the referer is /jenkins/securityRealm/mfa
   * THEN  the result is /jenkins — the ROOT with mount, not a bare "/"
   * </pre>
   *
   * <p>WHY/SOLVES: a root-installed Jenkins is the easy test case; sub-path
   * deployments (/jenkins, /ci) are where redirect bugs hide because the
   * security-path check must run on the IN-SITE path (mount stripped) while
   * the emitted target carries the mount back. Getting either half wrong
   * gives either a 404 after MFA (mount dropped) or a redirect into the
   * wrong mount (security check run on the raw path, e.g. "/jenkins/login"
   * not recognised as a security page, and handed back verbatim).
   */
  @Test
  void preservesContextPathInTargetAndFallback() {
    assertEquals("/jenkins/job/web/",
        MfaController.resolveRedirectTarget("/jenkins/job/web/",
            "jenkins.dev", "8080", "/jenkins"));
    assertEquals("/jenkins",
        MfaController.resolveRedirectTarget("/jenkins/securityRealm/mfa",
            "jenkins.dev", "8080", "/jenkins"));
    assertEquals("/jenkins",
        MfaController.resolveRedirectTarget(null,
            "jenkins.dev", "8080", "/jenkins"));
  }

  // =====================================================================
  // classifyFactor — shape-based factor selection
  // =====================================================================

  /**
   * WHAT: classifyFactor's positive branches — the shape→factor routing that
   * drives attempt order in postVerify.
   *
   * <p>BDD:
   * <pre>
   * GIVEN any submitted string
   * WHEN  it is exactly 6 ASCII digits               (123456)
   * THEN  it classifies as TOTP
   * WHEN  it is an 8-char email-code alphabet word,
   *       in any case mix                            (aB3dEfGh)
   * THEN  it classifies as EMAIL
   * WHEN  it carries surrounding whitespace          (" 123456 ")
   * THEN  it classifies by its trimmed shape         (TOTP)
   * </pre>
   *
   * <p>WHY/SOLVES: the controller feeds raw form input here, and the factor
   * that gets tried FIRST is decided by this function (with a fallback to
   * the other enrolled factor). Routing a 6-digit TOTP into the email check
   * would spend the user's attempt against the wrong pending state — the
   * failure mode is "I typed the right code and it said wrong," which on the
   * third repeat trips the lockout and the user is out. Length-disjoint
   * alphabets (6 vs 8) are what make the routing unambiguous; this test pins
   * the disjointness contract itself.
   */
  @Test
  void classifiesWellFormedCodes() {
    assertEquals(Factor.TOTP, MfaController.classifyFactor("123456"));
    assertEquals(Factor.TOTP, MfaController.classifyFactor(" 123456 "));
    assertEquals(Factor.EMAIL, MfaController.classifyFactor("23456789"));
    assertEquals(Factor.EMAIL, MfaController.classifyFactor("aB3dEfGh"));
    assertEquals(Factor.EMAIL, MfaController.classifyFactor("AB3DEFGH"));
  }

  /**
   * WHAT: classifyFactor's rejection branches — anything that is neither a
   * TOTP shape nor an email-code shape lands in UNKNOWN (→ counted as one
   * failed attempt by the rate limiter), never an exception.
   *
   * <p>BDD:
   * <pre>
   * GIVEN any malformed submission
   * WHEN  it is 5 or 7 digits, or 8 chars containing 0/1/I/O
   *       (ambiguous glyphs the email alphabet excludes)
   * AND  when it is null, blank, or "abcdefgh" (outside the 2-9A-HJ-NP-Z
   *       alphabet on an 8-char length — note 'a','b' etc. ARE in the
   *       alphabet; the reject cases below are the genuinely foreign ones)
   * THEN  each classifies as UNKNOWN and nothing is thrown
   * </pre>
   *
   * <p>WHY/SOLVES: UNKNOWN is the fail-closed bucket. If malformed input
   * instead threw, the auth path returns a 500 to a half-logged-in user —
   * "site broken" — and the rate limiter counts nothing, so a pure-flood of
   * garbage is not throttled. If it instead silently routed to a factor, a
   * 7-char paste could be "fixed up" into a live check against the wrong
   * state. The 0/1/I/O cases pin the alphabet contract shared with
   * {@code EmailCodeIssuer.CODE_ALPHABET}: a string containing an excluded
   * glyph could never have been issued, so routing it to UNKNOWN costs the
   * user one counted attempt and gives the limiter something to see.
   */
  @Test
  void classifiesMalformedAsUnknownWithoutThrowing() {
    assertEquals(Factor.UNKNOWN, MfaController.classifyFactor(null));
    assertEquals(Factor.UNKNOWN, MfaController.classifyFactor(""));
    assertEquals(Factor.UNKNOWN, MfaController.classifyFactor("12345"));
    assertEquals(Factor.UNKNOWN, MfaController.classifyFactor("1234567"));
    // 8-char but containing alphabet-excluded glyphs 0/1/I/O:
    assertEquals(Factor.UNKNOWN, MfaController.classifyFactor("A1BCDEFG"));
    assertEquals(Factor.UNKNOWN, MfaController.classifyFactor("0BCDEFGH"));
    // 6 chars but not digits:
    assertEquals(Factor.UNKNOWN, MfaController.classifyFactor("12345a"));
    // 8 chars but containing the alphabet-excluded digits 0/1: a string with
    // "10" in it can never have been issued, so it is not email-shaped.
    assertEquals(Factor.UNKNOWN, MfaController.classifyFactor("ABCDEFGH10".substring(0, 8)
        .replace("H", "0").replace("G", "1")));
  }

  // =====================================================================
  // maskEmail — display masking of the registered mailbox
  // =====================================================================

  /**
   * WHAT: the masking contract of maskEmail — enough visible to confirm "yes,
   * my inbox," not enough to harvest the full address.
   *
   * <p>BDD:
   * <pre>
   * GIVEN a registered address
   * WHEN  it is a normal address            mads@devcru.org
   * THEN  it masks to first-char + ***      m***@devcru.org  (domain intact)
   * WHEN  it is a single-letter local part  a@x.com
   * THEN  it masks to a***@x.com — the shape holds, no special case
   * WHEN  it is blank/null/whitespace
   * THEN  it masks to "" — the page renders nothing, never a placeholder address
   * WHEN  it has no @ sign at all
   * THEN  it masks to "***" — the raw input is never echoed back
   * </pre>
   *
   * <p>WHY/SOLVES: the MFA page is reachable by a password-authenticated,
   * MFA-unverified user — the exact principal an attacker who has just
   * brute-forced a password is. If the full mailbox renders there, that
   * principal has a free directory lookup (account takeover confirmation,
   * phishing seed, and the confirmed target for the "send me a code" race).
   * The mask keeps the affordance honest — "we will send to m…@devcru.org"
   * still lets the owner confirm it is their inbox — while denying the
   * attacker the string. The no-@ → "***" pin matters because it forbids any
   * fallback that echoes input.
   */
  @Test
  void masksToLocalFirstCharPlusDomain() {
    assertEquals("m***@devcru.org", MfaController.maskEmail("mads@devcru.org"));
    assertEquals("a***@x.com", MfaController.maskEmail("a@x.com"));
    assertEquals("***@x.com", MfaController.maskEmail("@x.com"));
    assertEquals("", MfaController.maskEmail(null));
    assertEquals("", MfaController.maskEmail("   "));
    assertEquals("***", MfaController.maskEmail("no-at-sign"));
    assertEquals("m***@devcru.org", MfaController.maskEmail("  mads@devcru.org  "));
  }

  // =====================================================================
  // ensureEmailCodeSecret — per-user HMAC key lazy-mint (A2 ruling, 2026-08-18)
  // =====================================================================

  /**
   * WHAT: the per-user email-code HMAC key is provisioned on first use and
   * never after — the A2 audit finding said the controller fed a
   * *blank-string* key to {@code EmailCodeIssuer} because nothing ever minted
   * the key. This seam mints exactly once (when the property holds none) and
   * returns the already-stored key unchanged otherwise, so every user's
   * pending codes are hashed under a unique, high-entropy, persisted key
   * rather than a shared empty one.
   *
   * <p>BDD:
   * <pre>
   * GIVEN an email-enrolled user whose property has NO emailCodeSecret yet
   * WHEN  ensureEmailCodeSecret(p) runs
   * THEN  it returns a non-blank key,
   * AND   the property is now holding a non-null Secret whose plaintext ==
   *       the returned key (persisted, master-key encrypted at save time)
   * WHEN  ensureEmailCodeSecret(p) runs a second time
   * THEN  it returns the SAME key — it is NOT re-minted (idempotent)
   * GIVEN a user whose property ALREADY has a key stored
   * WHEN  ensureEmailCodeSecret(p) runs
   * THEN  it returns that exact key, unchanged (never clobbers an existing one)
   * </pre>
   *
   * <p>WHY/SOLVES: the mads-signed confidentiality story is
   * "per-user HMAC key, master-key encrypted at rest, two users' states cannot
   * be correlated." With a blank string as the key every account's pending
   * code hashes under *the same* key, so that story is false. Minting on first
   * use (rather than waiting for the Task 9 enrolment UI) closes that gap
   * before any enrol screen exists — the lazy-mint is the first of the two
   * minting paths mads ruled (A2); the enrolment UI is the second. Idempotency
   * matters because both {@code postResendEmail} and the TOTP-fallback
   * {@code verifyEmail} call this on the hot path — a re-mint would invalidate
   * a code that was just issued under the previous key, turning a resend into
   * a "wrong code."
   */
  @Test
  void lazilyMintsPerUserEmailCodeHmacKeyExactlyOnce() {
    // Fresh property, no key yet.
    MfaUserProperty p = new MfaUserProperty();
    p.setRegisteredEmail("mads@devcru.org");
    assertNull(p.getEmailCodeSecret(), "precondition: no key provisioned yet");

    String first = MfaController.ensureEmailCodeSecret(p);
    assertFalse(first == null || first.isBlank(),
        "minted key must be non-blank (a blank HMAC key is the A2 defect)");
    notNullSecretWithPlain(p, first);

    // Idempotent: a second call must NOT re-mint.
    String second = MfaController.ensureEmailCodeSecret(p);
    assertEquals(first, second,
        "lazy-mint must be idempotent — re-minting would invalidate a code "
            + "just issued under the previous key");

    // A pre-existing key is returned unchanged, never clobbered.
    MfaUserProperty pre = new MfaUserProperty();
    pre.setRegisteredEmail("mads@devcru.org");
    String existing = "pre-provisioned-key-0123456789";
    pre.setEmailCodeSecret(Secret.fromString(existing));
    assertEquals(existing, MfaController.ensureEmailCodeSecret(pre),
        "an already-stored key must be returned unchanged");
  }

  private static void notNullSecretWithPlain(MfaUserProperty p, String expected) {
    assertNotNull(p.getEmailCodeSecret(),
        "the minted key must be stored on the property (persisted at u.save())");
    assertArrayEquals(
        expected.getBytes(StandardCharsets.US_ASCII),
        p.getEmailCodeSecret().getPlainText().getBytes(StandardCharsets.US_ASCII),
        "stored Secret plaintext must equal the returned key");
  }

  // =====================================================================
  // A3 (mads ruling 2026-08-18): ?redirect= canonical over Referer —
  // the post-verify target composition, pinned at the controller seam.
  // =====================================================================

  /**
   * WHAT: the post-verify redirect composition — the controller reads the
   * {@code ?redirect=} parameter (the value the gate's 302 carried into the
   * MFA page URL) and only falls back to {@code Referer} when it is absent.
   * Both flow through the one shared validator ({@code MfaFilter.
   * resolveTarget} → {@code resolveRedirectTarget}); this test pins that
   * exact input selection at the site that consumes it.
   *
   * <p>BDD:
   * <pre>
   * GIVEN a site at host "jenkins.dev", root context
   * AND   the gate's bounce URL carried  ?redirect=/job/web/
   * AND   the browser's form POST carries Referer = the MFA page's own URL
   *       (https://jenkins.dev/securityRealm/mfa) — the form-POST shape,
   *       where Referer alone would re-prompt the user
   * WHEN  the post-verify composition resolves the send-back target
   *       (parameter first, Referer fallback, one validator)
   * THEN  the target is /job/web/ — the PRE-LOGIN destination the user
   *       actually wanted, not the MFA page
   * GIVEN the same site, the gate's bounce carried NO parameter (a user who
   *       bookmarked /securityRealm/mfa directly)
   * AND   the page was opened via Referer = https://jenkins.dev/job/web/
   * WHEN  the same composition runs
   * THEN  the target is /job/web/ — the Referer fallback still works
   *       for the parameter-less entry
   * </pre>
   *
   * <p>WHY/SOLVES: this is the controller half of the A3/A5 pair. The
   * audit finding (A5) was that the Referer-only contract lands a verified
   * user back on the MFA page (immediate re-prompt loop) because a same-
   * origin form POST's Referer is the page that issued it. The parameter
   * exists to carry the pre-login destination across the gate's 302; if the
   * controller reads the Referer first (or ignores the parameter), the fix
   * is dead on arrival and every "MFA completed" bounces users into the
   * prompt again. The end-to-end IT (Task 8, A5's owner) asserts the full
   * round trip against a booted Jenkins; this unit test pins the input
   * selection it depends on without the boot.
   */
  @Test
  void postVerifyTargetUsesCanonicalParameterThenReferer() {
    // The form-POST shape: parameter present (the pre-login destination),
    // Referer = the MFA page's own URL. The parameter must win.
    String formPostShape = MfaFilter.resolveTarget(
        "/job/web/",                                  // ?redirect= (canonical)
        "https://jenkins.dev/securityRealm/mfa",      // Referer (the MFA page)
        "jenkins.dev", "8080", "");
    assertEquals("/job/web/", formPostShape,
        "the gate's ?redirect= parameter is canonical over the MFA-page Referer");

    // The parameter-less entry: no ?redirect= on the page URL; the Referer
    // (a normal in-site page) is the fallback source.
    String paramLess = MfaFilter.resolveTarget(
        null,                                         // no ?redirect= parameter
        "https://jenkins.dev/job/web/",               // Referer (an in-site page)
        "jenkins.dev", "8080", "");
    assertEquals("/job/web/", paramLess,
        "the Referer fallback must still work when the parameter is absent");
  }
}
