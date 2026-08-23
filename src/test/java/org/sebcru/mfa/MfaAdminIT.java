package org.sebcru.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.FullControlOnceLoggedInAuthorizationStrategy;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.Permission;
import hudson.security.SidACL;
import hudson.security.AuthorizationStrategy;
import hudson.util.Secret;
import java.io.File;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.acegisecurity.acls.sid.Sid;
import org.acegisecurity.acls.sid.PrincipalSid;
import org.htmlunit.FailingHttpStatusCodeException;
import org.htmlunit.HttpMethod;
import org.htmlunit.WebRequest;
import org.htmlunit.WebResponse;
import org.htmlunit.html.HtmlPage;
import org.htmlunit.util.NameValuePair;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * A22-b — the booted proof that the admin factor-management surface
 * exists, and the red→green pin that it can never be an A23-shaped hole.
 *
 * <h2>What this pins (spec §7, the integration legs, wired per the carve-out)</h2>
 * <p>Ruling 1 + spec case 7 make {@code /mfaAdmin} NOT gate allow-listed, so
 * the first control an enrolled-unverified session meets is the GATE (a 302
 * to the MFA page). The controller's own 403 seam stands behind the gate. The
 * legs below pin both controls at the wire:
 * <ol>
 *   <li><b>The gate carve-out + A23-analogue (spec cases 3 + 7).</b> A
 *       logged-in, enrolled (ADMINISTER under FCOL), NOT-verified, no-trust
 *       session GETs and POSTs {@code clearFactors} against a NAMED, enrolled
 *       victim. Both are 302'd to the MFA page by the gate — the admin
 *       surface is not allow-listed, so the password-only attacker is bounced
 *       OFF the mutation, not handed to it — and the victim's factor state is
 *       BYTE-IDENTICAL. This is the wire truth of the A23-analogue; the
 *       controller's 403 is the backstop the next leg proves.</li>
 *   <li><b>The Ruling-3 edge at the wire (spec case 3's 403 shape).</b> An
 *       UNENROLLED ADMIN (password account, no factor of its own) passes the
 *       gate (unenrolled = exempt) and CAN read the roster — but POST
 *       {@code clearFactors} answers 403
 *       {@code admin_verification_required}, because an unenrolled actor can
 *       hold neither session-verify nor trust. This is the credential axis,
 *       pinned at the wire; the FCOL strategy alone can't produce a verified
 *       admin without a factor, so this is the leg that carries case 3's
 *       stable 403 reason.</li>
 *   <li><b>The self-strike pin (spec case 5).</b> A verified admin POSTs
 *       {@code clearFactors?userId=<self>} → 200
 *       {@code admin_self_management_forbidden}; the admin's own factors are
 *       untouched. Without this pin the §4 load-bearing rule is a comment.</li>
 *   <li><b>Non-admin denied at the wire (spec case 6 — the privilege slot).</b>
 *       Under a LEAST-PRIVILEGE strategy (the admin user granted
 *       {@code ADMINISTER}; everyone else READ-only) an UNENROLLED non-admin
 *       → GET {@code /mfaAdmin} 403 and POST {@code clearFactors} 403
 *       {@code admin_permission_required}, and a VERIFIED non-admin (enrolled
 *       + TOTP-verified, no ADMINISTER) ALSO gets the PERMISSION reason — the
 *       check-order probe that only the Defect-2 fix survives. The privilege
 *       slot of the breadth list: the elevated probe is not the subordinate
 *       probe.</li>
 *   <li><b>The admin journey (spec case 2 + the README's documented recovery
 *       path).</b> A verified ADMINISTER session reads the roster (enrolled-only
 *       per Ruling 4, masked display address per A16, no raw mailbox in the DOM)
 *       and clears the locked-out victim's factors; a second clear is
 *       idempotent ({@code not_enrolled}) and the admin's OWN factors survive.</li>
 *   <li><b>The restart-survival leg (spec §7 case 3 + §10 — the postmortem's
 *       restart lesson applied to a credential-clearing op).</b> A verified
 *       admin clears the locked-out victim, then the Jenkins instance is
 *       RESTARTED ({@code rule.restart()} — reload from disk). The cleared
 *       state must reload, not resurrect, the gate must now pass the victim
 *       (password-only login), the victim must re-enrol through the documented
 *       self-service path end to end, and the ADMIN's own factors must survive
 *       with no collateral loss. The on-disk {@code config.xml} is probed as
 *       the anti-vacuity anchor: the clear really persisted to disk, so the
 *       post-restart assertions read disk truth, not a never-persisted
 *       in-memory state.</li>
 * </ol>
 *
 * <p>Legs 1–3 run under {@code FullControlOnceLoggedInAuthorizationStrategy}
 * (every logged-in user is ADMINISTER — the credential axis is what they
 * exercise). Leg 4 swaps in a least-privilege {@link SidACL} so a genuine
 * non-admin exists to probe the permission axis — the one axis the FCOL
 * strategy cannot produce (it makes everyone an admin). {@code
 * MatrixAuthorizationStrategy} is not on this build's offline classpath, so
 * the strategy is a minimal hand-rolled ACL (admin-user gets ADMINISTER; else
 * READ) rather than the matrix UI.
 *
 * <p>Both users are enrolled + unverified at their respective entry points,
 * and the endpoints are NOT gate allow-listed — the gate still stands in
 * front of this surface (decision 4), so what is being tested is the
 * surface's own authorization chain, not a filter pass.
 *
 * <p>JUnit 5 + {@code @WithJenkins}, rule injected per method (house IT
 * shape — {@link MfaProfileIT}/{@link MfaFilterIT}).
 *
 * <h2>Red → green history (honest — per run; handoff §"proven red" is the
 * source of the run-1/run-3 mapping)</h2>
 * <ol>
 *   <li>Handoff state: 5 legs, 3 red / 2 green. The 2 green (run 3, by
 *       exclusion): the carve-out 302 leg and the self-strike pin — BOTH
 *       failed in run 1. Two defects drove the reds:
 *       <b>Defect 1</b> rendered the admin page 404 — a {@code doIndex}
 *       forward had no rule to land on; run 1 additionally surfaced a jelly
 *       500 (the view itself failing) and a redirect-following issue in the
 *       raw-GET helper. <b>Defect 2</b> (bytecode-proven this session):
 *       {@code User.getACL()} self-grants for the actor's own account
 *       BEFORE consulting the strategy, so the least-privilege SidACL never
 *       ran and the non-admin leg was testing a false world.</li>
 *   <li>Defect 1 fix round 1 — remove {@code doIndex}, let Stapler resolve
 *       the class-dir {@code index.jelly}, and gate the render on
 *       {@code adminPageAllowed()} (403 {@code admin_permission_required}
 *       body; {@code no-store}/{@code nosniff} headers). Run 4 exposed that
 *       the 404 survived: the log finally said why —
 *       {@code SAXParseException ... lineNumber: 231 ... Attribute name
 *       "j:out" associated with an element type "td"}: two roster cells
 *       written {@code <td class="mono" j:out value="..."/>} are invalid
 *       XML ({@code j:out} is an element tag, not an attribute), so
 *       {@code JellyFacet#buildIndexDispatchers} dropped the view and
 *       Stapler had no index dispatcher — a silent 404 instead of a loud
 *       500. Rewrote them as standalone {@code <j:out value="..."/>}
 *       elements.</li>
 *   <li>Run 5: 4/5 green; case {@code (c)} cast the {@code HtmlPage} from
 *       {@code WebClient.getPage} to {@code WebResponse} →
 *       {@code ClassCastException}. Fixed: {@code victimHome
 *       .getWebResponse().getStatusCode()}.</li>
 *   <li>Defect 2 implemented (same session): seam swapped from
 *       {@code actor.hasPermission(Jenkins.ADMINISTER)} on the actor's own
 *       {@code User} to the Jenkins root-ACL check (see
 *       {@code MfaAdminController.hasAdminister} for the finding). That is
 *       the production-seam change flagged to mads for sign-off — the
 *       sign-off was given 2026-08-23 pending Moldy's review cycle, and the
 *       change is parked uncommitted (working branch only) until that review
 *       lands.</li>
 *   <li>Run 6 and the {@code mvn -o -B clean verify} mirror: 5/5 green,
 *       unit suites 112 green, SpotBugs 0, {@code .hpi} built.</li>
 *   <li>Leg 6 (the restart-survival leg, spec §7 case 3 + §10) landed in a
 *       LATER commit on the reviewed (APPROVED, v3) branch — the Moldy
 *       review's one open item. It extended leg 5 (clear a locked-out
 *       victim), added {@code rule.restart()}, and asserted the post-restart
 *       state. First two runs were COMPILE failures of this leg's own
 *       mechanics (a typo referencing the {@code java.util.regex} package
 *       where the {@code Pattern.DOTALL} flag was meant; and
 *       {@code JenkinsRule.restart()} declares {@code Throwable}, so the leg
 *       widened to {@code throws Throwable}). The first RUNNING signal:
 *       <b>6/6 green</b> — the restart leg exposed NO persistence defect,
 *       which is an honest confirmation rather than a proven red (the
 *       on-disk {@code config.xml} probe is the anti-vacuity anchor: it
 *       proves the clear really wrote to disk, so the surviving clear is
 *       read back from disk, not from a never-persisted in-memory state). A
 *       red that surfaces later (e.g. a persistence change regressing the
 *       round-trip) is exactly what this leg exists to catch — the
 *       postmortem's restart lesson applied to a credential-clearing op.</li>
 * </ol>
 *
 * <p>Test-only fixtures ({@code verified-sub}, TOTP seed
 * {@code LUPINPWPWPWPWPWP}, {@code vsub-pw-1}) are in-source literals for
 * the check-order probe, not credentials.
 */
@WithJenkins
class MfaAdminIT {

  private static final String ADMIN_PW = "admin-was-here-1";
  private static final String VICTIM_PW = "victim-stuck-1";

  private String crumbName = "Jenkins-Crumb"; // overwritten from the page below

  /** The production realm shape (Task 8/Task 9/A23's harness): HPSR +
   *  FCOL — every logged-in user is an ADMINISTER holder, so the cases
   *  below exercise the credential axis (verified-not-enrolled), not the
   *  ADMINISTER axis (which the page's layout gate owns and core pins).
   *  Called from the top of each test (house IT shape — no @BeforeEach). */
  private HudsonPrivateSecurityRealm ensureRealm(JenkinsRule rule) {
    Jenkins j = Jenkins.get();
    if (j.getSecurityRealm() instanceof HudsonPrivateSecurityRealm realm) {
      return realm;
    }
    HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false); // no signup
    j.setSecurityRealm(realm);
    j.setAuthorizationStrategy(new FullControlOnceLoggedInAuthorizationStrategy());
    return realm;
  }

  // ==================================================================
  // Case 1 — the gate carve-out + A23-analogue: an enrolled, password-only
  //   (unverified, untrusted) admin session is BOUNCED OFF the admin surface
  //   by the gate itself (spec §7 cases 3 + 7) — the surface is not
  //   allow-listed, so the mutation is unreachable pre-verify, at every layer.
  // ==================================================================

  /**
   * WHAT — the GATE (not the controller's 403) is the first control an
   * enrolled-unverified session meets at {@code /mfaAdmin}: this leg pins
   * spec cases 3 + 7 at the wire — both the page GET and the verb POST are
   * bounced.
   *
   * <pre>
   * GIVEN  HPSR + FCOL; "victim" enrolled (TOTP + registered mail, trust 0);
   *        "attacker" enrolled, logged in, NOT TOTP-verified, no trusted
   *        device (password-only session)
   * WHEN   GET  /mfaAdmin            -> 302, Location targets the MFA page
   * WHEN   POST /mfaAdmin/clearFactors?victim -> 302, also to the MFA page
   * THEN   the victim's factor state is byte-identical (TOTP factor, email
   *        factor, registered mailbox, TOTP seed, trust) — bounce mutated
   *        nothing
   * </pre>
   *
   * WHY — the surface is deliberately NOT gate allow-listed; the A23-analogue
   * (password-only attacker reaching a mutation) must fail at the door, at
   * every layer, with the victim untouched. If this regressed, an
   * unverified session could strip another user's MFA before proving a
   * factor.
   */
  @Test
  void enrolledPasswordOnlySessionIsBouncedByTheGateOffTheAdminSurface(JenkinsRule rule)
      throws Exception {
    ensureRealm(rule);
    User victim = enroll(rule, "victim", VICTIM_PW, "JBSWY3DPEHPK3PXP");
    MfaUserProperty p = victim.getProperty(MfaUserProperty.class);
    p.setRegisteredEmail("victim.example");
    p.setTrustedUntilMs(0L);
    victim.save();
    // The attacker: enrolled + logged in + NOT verified + no trusted device.
    // Under FCOL they hold ADMINISTER, but the gate does not care about that —
    // an enrolled, unverified, untrusted session is REDIRECTed to /mfa.
    enroll(rule, "attacker", VICTIM_PW, "KRSXG5CTMVRXEZLU");
    JenkinsRule.WebClient c = rule.createWebClient();
    c.login("attacker", VICTIM_PW);

    // (a) GET the admin page: 302 to the MFA page (the gate stands in front —
    // the §4 invariant pinned at the wire). No roster HTML is served.
    WebResponse page = rawGet(c, rule, "mfaAdmin/");
    assertEquals(302, page.getStatusCode(),
        "an enrolled, password-only session must be redirected off /mfaAdmin: "
            + page.getStatusCode() + " " + page.getContentAsString());
    assertTrue(isMfaRedirect(page),
        "the gate bounce must target the MFA page: Location="
            + page.getResponseHeaderValue("Location"));

    // (b) POST clearFactors: ALSO 302 (the gate bounces the verb too — the
    // A23-analogue at the wire: the password-only attacker never reaches the
    // mutation, it is bounced off the door).
    WebResponse clear = rawPostAdmin(c, rule, "clearFactors", victim.getId());
    assertEquals(302, clear.getStatusCode(),
        "clearFactors from an enrolled, password-only session must be gated 302: "
            + clear.getStatusCode() + " " + clear.getContentAsString());
    assertTrue(isMfaRedirect(clear),
        "the verb bounce must target the MFA page: Location="
            + clear.getResponseHeaderValue("Location"));

    // (c) The victim's factor state is BYTE-IDENTICAL — the gate bounced the
    // request, nothing was mutated.
    MfaUserProperty after = victim.getProperty(MfaUserProperty.class);
    assertTrue(after.hasTotpFactor(), "gate-bounce must not touch the victim's TOTP factor");
    assertTrue(after.hasEmailFactor(), "gate-bounce must not touch the victim's email factor");
    assertEquals("victim.example", after.getRegisteredEmail(),
        "gate-bounce must not touch the registered email");
    assertEquals(p.getTotpSecret().getPlainText(), after.getTotpSecret().getPlainText(),
        "gate-bounce must not touch the victim's TOTP seed");
    assertEquals(0L, after.getTrustedUntilMs(), "gate-bounce must not touch the victim's trust");
  }

  // ==================================================================
  // Case 2 — the Ruling-3 edge at the wire (spec case 3's 403 shape): an
  //   UNENROLLED admin (ADMINISTER) reads the roster fine, but POST
  //   clearFactors is 403 admin_verification_required — an unenrolled actor
  //   holds neither session-verify nor trust.
  // ==================================================================

  /**
   * WHAT — the Ruling-3 edge (spec case 3): an UNENROLLED ADMIN passes the
   * gate, may READ the roster, but the mutation is denied on the CREDENTIAL
   * axis before any factor state changes.
   *
   * <pre>
   * GIVEN  HPSR + FCOL; "victim" enrolled; "admin-nounroll" is an ADMINISTER
   *        holder with NO factor of its own (unenrolled), logged in
   * WHEN   the admin GETs the page                 -> roster renders; victim
   *        listed; raw mailbox absent from the DOM (A16 masked display)
   * WHEN   the admin POSTs clearFactors?victim     -> 403
   *        admin_verification_required (ok=false)
   * THEN   the victim's TOTP factor is untouched
   * </pre>
   *
   * WHY — read != mutation. Ruling 3 holds that an admin may see the roster
   * without a factor of their own, but an unenrolled actor holds neither
   * session-verify nor trust, so the verb must fail CLOSED. This leg is the
   * only one that can produce FCOL's stable 403 credential reason (FCOL
   * can't make a verified-unenrolled admin by itself, so the strategy alone
   * can't pin it).
   */
  @Test
  void unenrolledAdminCanReadRosterButNotMutate(JenkinsRule rule) throws Exception {
    ensureRealm(rule);
    User victim = enroll(rule, "victim", VICTIM_PW, "JBSWY3DPEHPK3PXP");
    victim.getProperty(MfaUserProperty.class).setRegisteredEmail("victim.example");
    victim.save();
    // An ADMINISTER user with NO factor of their own.
    HudsonPrivateSecurityRealm realm = (HudsonPrivateSecurityRealm) rule.jenkins.getSecurityRealm();
    User admin = realm.createAccount("admin-nounroll", ADMIN_PW);

    JenkinsRule.WebClient c = rule.createWebClient();
    c.login("admin-nounroll", ADMIN_PW);

    // (a) The roster renders (unenrolled admins pass the gate; ADMINISTER is
    // the read-side gate), and it lists the enrolled victim.
    String page = pageHtml(c, rule);
    assertTrue(page.contains("victim"), "roster must list the enrolled victim: " + page);
    assertFalse(page.contains("victim.example"),
        "the raw mailbox must not reach the DOM: " + page);

    // (b) POST clearFactors: 403 admin_verification_required — the credential
    // axis (Ruling 3): unenrolled ⇒ no verify, no trust.
    JSONObject clear = postAdmin(rule, c, "clearFactors", victim.getId(), 403);
    assertFalse(clear.optBoolean("ok"),
        "clearFactors from an unenrolled admin must be DENIED: " + clear);
    assertEquals(VerifyOutcome.ERR_ADMIN_VERIFICATION_REQUIRED, clear.optString("error"),
        "the denial must carry the stable credential reason: " + clear);

    // (c) The victim is untouched.
    assertTrue(victim.getProperty(MfaUserProperty.class).hasTotpFactor(),
        "the 403 must not touch the victim's TOTP factor");
  }

  // ==================================================================
  // Case 3 — the self-strike pin (spec §7 case 5): a verified admin POSTs
  //   clearFactors against their OWN id → 200 admin_self_management_forbidden;
  //   their own factors are untouched. Without this the load-bearing rule is
  //   a comment.
  // ==================================================================

  /**
   * WHAT — the self-strike pin (spec §7 case 5): clearing is a recovery verb
   * for OTHERS, and the actor's own id must be refused before any state
   * change, even by a fully verified admin.
   *
   * <pre>
   * GIVEN  HPSR + FCOL; "admin2" enrolled (TOTP + mail) and TOTP-verified
   *        this session (permission + credential axes both live)
   * WHEN   POST clearFactors?victim=<own admin2 id>
   * THEN   200 ok=false, error=admin_self_management_forbidden; the actor's
   *        own TOTP factor and registered mailbox are byte-identical
   * </pre>
   *
   * WHY — §4's load-bearing rule: an admin can never use this verb on
   * themselves. If this regressed, a verified admin (or any session holding
   * their id) could clear their own MFA out of band — the verb becomes a
   * self-disable switch.
   */
  @Test
  void verifiedAdminCannotClearTheirOwnFactorsSelfStrikePin(JenkinsRule rule) throws Exception {
    ensureRealm(rule);
    User administered = enroll(rule, "admin2", ADMIN_PW, "KRSXG5CTMVRXEZLU");
    administered.getProperty(MfaUserProperty.class).setRegisteredEmail("admin2.example");
    administered.save();
    JenkinsRule.WebClient c = rule.createWebClient();
    c.login("admin2", ADMIN_PW);
    verifyTotp(c, rule, "admin2", "KRSXG5CTMVRXEZLU");

    JSONObject self = postAdmin(rule, c, "clearFactors", administered.getId(), 200);
    assertFalse(self.optBoolean("ok"),
        "clearFactors against the actor's own id must be DENIED: " + self);
    assertEquals(VerifyOutcome.ERR_ADMIN_SELF_MANAGEMENT, self.optString("error"),
        "self-strike must carry the load-bearing reason: " + self);

    MfaUserProperty after = administered.getProperty(MfaUserProperty.class);
    assertTrue(after.hasTotpFactor(), "self-strike must not touch the actor's TOTP factor");
    assertEquals("admin2.example", after.getRegisteredEmail(),
        "self-strike must not touch the actor's mailbox");
  }

  // ==================================================================
  // Case 4 — non-admin denied at the wire (spec §7 case 6, the privilege
  //   slot): under a least-privilege strategy (the admin user holds ADMINISTER,
  //   everyone else READ) an UNENROLLED non-admin GETs 403 and POSTs
  //   clearFactors 403 admin_permission_required. The elevated probe (case 2)
  //   is not the subordinate probe.
  // ==================================================================

  /**
   * WHAT — non-admin denied at the wire (spec §7 case 6, the privilege slot).
   * Two probes: (a–c) a plain non-admin, and (d) a <b>verified</b> non-admin
   * who has already proven a credential — the check-order probe that only
   * the Defect-2 fix survives.
   *
   * <pre>
   * GIVEN  least-privilege strategy: only "admin-user" holds ADMINISTER, all
   *        others READ; "victim" enrolled;
   *        probe A: "lowly" — plain account, no factor, no ADMINISTER
   *        probe B: "verified-sub" — enrolled + TOTP-verified this session,
   *                  still NO ADMINISTER
   * WHEN   A GETs /mfaAdmin            -> 403
   * WHEN   A POSTs clearFactors?victim -> 403 admin_permission_required
   * WHEN   B POSTs clearFactors?victim -> 403 admin_permission_required (the
   *        PERMISSION reason, even though B's credential is live — order!)
   * THEN   victim factor + mailbox byte-identical after every probe
   * </pre>
   *
   * WHY — the breadth list's privilege slot: the elevated probe (case 2) is
   * not the subordinate probe, and a proven credential is not a permission.
   * Probe B is the one that catches the Defect-2 hole: under the old
   * {@code User.hasPermission} seam the verified non-admin self-granted
   * through and would have CLEARed the victim (MFA stripped by a
   * non-admin). It is red under the pre-fix seam and green only when the
   * permission check is honest and fires first.
   */
  @Test
  void nonAdminIsDeniedTheAdminSurfaceAtTheWire(JenkinsRule rule) throws Exception {
    HudsonPrivateSecurityRealm realm = ensureRealm(rule);
    // Swap FCOL for a least-privilege strategy so a genuine non-admin exists.
    rule.jenkins.setAuthorizationStrategy(new LeastPrivilegeAdministerStrategy("admin-user"));

    User victim = enroll(rule, "victim", VICTIM_PW, "JBSWY3DPEHPK3PXP");
    victim.getProperty(MfaUserProperty.class).setRegisteredEmail("victim.example");
    victim.save();
    // The non-admin: a plain account, no factor, no ADMINISTER.
    User lowly = realm.createAccount("lowly", "lowly-pw-1");

    JenkinsRule.WebClient c = rule.createWebClient();
    c.login("lowly", "lowly-pw-1");

    // (a) GET /mfaAdmin → 403 (permission axis, page GET — the layout is not
    // the control; the controller answers the 403).
    WebResponse page = rawGet(c, rule, "mfaAdmin/");
    assertEquals(403, page.getStatusCode(),
        "a non-admin's GET /mfaAdmin must be 403: " + page.getStatusCode()
            + " " + page.getContentAsString());

    // (b) POST clearFactors → 403 admin_permission_required (the privilege
    // slot). The target's state is irrelevant — permission is checked first.
    JSONObject clear = postAdmin(rule, c, "clearFactors", victim.getId(), 403);
    assertFalse(clear.optBoolean("ok"),
        "clearFactors by a non-admin must be DENIED: " + clear);
    assertEquals(VerifyOutcome.ERR_ADMIN_PERMISSION, clear.optString("error"),
        "the non-admin denial must carry admin_permission_required: " + clear);

    // (c) The victim is untouched.
    assertTrue(victim.getProperty(MfaUserProperty.class).hasTotpFactor(),
        "the non-admin 403 must not touch the victim's TOTP factor");

    // (d) THE ORDER PROBE — the one only the honest seam survives: a
    // non-admin who HAS already proved a credential (enrolled + verified
    // this session). Under the Defect-2 self-grant seam this actor
    // ("verified-sub": a verified subordinate, no ADMINISTER) would pass
    // BOTH axes (permission "granted" by the self-grant, credential
    // proven) and succeed in clearing the victim's factors — a verified
    // non-admin stripping another user's MFA. The permission axis must
    // fire FIRST and win, so the answer is the PERMISSION reason even
    // though the credential is live. Red under the old seam (200 ok,
    // victim cleared); green only when the permission check is honest.
    User vsub = enroll(rule, "verified-sub", "vsub-pw-1", "LUPINPWPWPWPWPWP");
    JenkinsRule.WebClient vsubClient = rule.createWebClient();
    vsubClient.login("verified-sub", "vsub-pw-1");
    verifyTotp(vsubClient, rule, "verified-sub", "LUPINPWPWPWPWPWP");
    JSONObject vsubClear = postAdmin(rule, vsubClient, "clearFactors", victim.getId(), 403);
    assertFalse(vsubClear.optBoolean("ok"),
        "a verified NON-admin must be DENIED regardless of credential: " + vsubClear);
    assertEquals(VerifyOutcome.ERR_ADMIN_PERMISSION, vsubClear.optString("error"),
        "a proven-credential non-admin must be denied on PERMISSION, not "
            + "credential — the check order must privilege the axis over the factor: "
            + vsubClear);
    MfaUserProperty vsubAfter = victim.getProperty(MfaUserProperty.class);
    assertTrue(vsubAfter.hasTotpFactor(),
        "the verified-non-admin denial must not touch the victim's TOTP factor");
    assertEquals("victim.example", vsubAfter.getRegisteredEmail(),
        "the verified-non-admin denial must not touch the victim's mailbox");
  }

  // ==================================================================
  // Case 5 — the admin journey: verified admin clears a locked-out victim
  //   (spec §7 case 2 + the README's documented recovery path).
  // ==================================================================

  /**
   * WHAT — the admin journey (spec §7 case 2 + the README's documented
   * recovery path): a fully verified admin recovers a locked-out victim,
   * idempotently, without ever touching their own factors.
   *
   * <pre>
   * GIVEN  HPSR + FCOL; "victim" enrolled + mail (locked out); "admin"
   *        enrolled + mail, TOTP-verified this session
   * WHEN   the admin GETs the roster          -> 200; victim AND admin listed
   *        (Ruling 4 enrolled-only); raw mailboxes absent from the DOM (A16)
   * WHEN   POST clearFactors?victim           -> 200 ok=true; victim fully
   *        unenrolled (enabled flag, TOTP factor, registered mail all null/
   *        false)
   * WHEN   the victim logs in fresh           -> 200 dashboard, no gate bounce
   * WHEN   POST clearFactors?victim (again)   -> 200 error=not_enrolled
   *        (idempotent-healthy, not an error state)
   * WHEN   POST revokeTrust?victim            -> 200 error=not_enrolled, trust
   *        axis alone never mutates factors
   * THEN   the admin's OWN TOTP factor + registered mail survive every step
   *        (no self-strike by accident)
   * </pre>
   *
   * WHY — this is the documented recovery path itself; if it failed, a
   * locked-out user could not self-recover and an admin could not help, or
   * the clear would spill onto the actor (a verified admin who recovers one
   * victim loses their own MFA). The privacy pin (no raw mailbox in the DOM)
   * rides here because the roster is the only surface where mailboxes
   * appear.
   */
  @Test
  void verifiedAdminClearsLockedOutVictimAndOwnFactorsSurvive(JenkinsRule rule) throws Exception {
    ensureRealm(rule);
    User victim = enroll(rule, "victim", VICTIM_PW, "JBSWY3DPEHPK3PXP");
    victim.getProperty(MfaUserProperty.class).setRegisteredEmail("victim.example");
    victim.save();
    User admin = enroll(rule, "admin", ADMIN_PW, "KRSXG5CTMVRXEZLU");
    admin.getProperty(MfaUserProperty.class).setRegisteredEmail("admin.example");
    admin.save();

    // The admin's own natural flow: login → verify TOTP (passing the gate
    // AND setting the session credential the guard seam demands).
    JenkinsRule.WebClient c = rule.createWebClient();
    c.login("admin", ADMIN_PW);
    verifyTotp(c, rule, "admin", "KRSXG5CTMVRXEZLU");

    // (a) The page renders for them with the enrolled-only roster:
    // both enrolled users present…
    String page = pageHtml(c, rule);
    assertTrue(page.contains("victim"), "roster must include the enrolled victim: " + page);
    assertTrue(page.contains("admin"), "roster must include the enrolled admin: " + page);
    // …but the raw plaintext mailbox must never reach the DOM (A16/privacy):
    assertFalse(page.contains("victim.example"),
        "the raw registered mailbox must not appear in the admin page DOM");
    assertFalse(page.contains("admin.example"),
        "the raw registered mailbox must not appear in the admin page DOM");

    // (b) The recovery op: clear the locked-out victim's factors.
    JSONObject clear = postAdmin(rule, c, "clearFactors", victim.getId(), 200);
    assertTrue(clear.optBoolean("ok"),
        "a verified admin's clearFactors must succeed: " + clear);
    MfaUserProperty after = victim.getProperty(MfaUserProperty.class);
    assertFalse(after.isMfaEnabled(), "the clear must remove the victim's enrolled state");
    assertFalse(after.hasTotpFactor(), "the clear must remove the TOTP factor");
    assertNull(after.getRegisteredEmail(), "the clear must remove the registered mailbox");

    // (c) The victim is now unenrolled — the gate passes them (no
    // factors, no lockout): the documented recovery actually recovered.
    JenkinsRule.WebClient victimClient = rule.createWebClient();
    victimClient.login("victim", VICTIM_PW);
    HtmlPage victimHome = victimClient.getPage(rule.getURL());
    int victimHomeStatus = victimHome.getWebResponse().getStatusCode();
    assertEquals(200, victimHomeStatus,
        "after the clear the victim must reach the dashboard without a gate bounce");

    // (d) A second clear is idempotent-healthy: not_enrolled, not an error.
    JSONObject second = postAdmin(rule, c, "clearFactors", victim.getId(), 200);
    assertEquals(VerifyOutcome.ERR_NOT_ENROLLED, second.optString("error"),
        "clearing an already-unenrolled user must answer not_enrolled: " + second);

    // (e) The admin's OWN factors survive every operation — clearing
    // another user never touches the actor.
    MfaUserProperty adminAfter = admin.getProperty(MfaUserProperty.class);
    assertTrue(adminAfter.hasTotpFactor(), "the clear must not touch the actor's TOTP factor");
    assertEquals("admin.example", adminAfter.getRegisteredEmail(),
        "the clear must not touch the actor's registered mailbox");

    // (f) revokeTrust works the same way: the victim's trust goes to 0,
    // factors untouched by that verb alone.
    JSONObject revoke = postAdmin(rule, c, "revokeTrust", victim.getId(), 200);
    assertEquals(VerifyOutcome.ERR_NOT_ENROLLED, revoke.optString("error"),
        "revokeTrust on a cleared (unenrolled) user must answer not_enrolled: " + revoke);
  }

  // ==================================================================
  // Case 6 — the restart-survival leg (spec §7 case 3 + §10): the
  //   credential-clear's persistence round-trip. The clear is proven at the
  //   seam (leg 5 + AdminManageAllowedTest byte-for-byte) and target.save()
  //   is called — this leg proves the persisted clear reloads from disk
  //   after a REAL restart: no resurrection of the victim's factors, the
  //   recovery path works end to end after the restart (gate passes,
  //   re-enrolment closes the loop), and the admin's own factors suffer no
  //   collateral loss.
  // ==================================================================

  /**
   * WHAT — the persistence round-trip (spec §7 case 3 + §10, the
   * postmortem's restart lesson applied to a credential-clearing op): after
   * a verified admin clears the locked-out victim's factors and the Jenkins
   * instance RESTARTS (reload from disk), the clear must reload as a clear —
   * not resurrect — and the documented recovery must complete end to end.
   *
   * <pre>
   * GIVEN  HPSR + FCOL; "victim" enrolled (TOTP + registered mail, trust 0)
   *        — a total lockout shape; "admin" enrolled + mail, TOTP-verified
   *        this session
   * WHEN   the admin POSTs clearFactors?victim -> 200 ok=true (the same
   *        verified op leg 5 proves)
   * AND    the on-disk users/&lt;victim&gt;/config.xml exists and carries NO
   *        totpSecret element — the anti-vacuity anchor: the clear really
   *        reached disk, so the post-restart assertions read disk truth
   * WHEN   rule.restart() — the Jenkins instance restarts and reloads from
   *        disk
   * THEN   (a) the victim's reloaded MfaUserProperty is STILL cleared:
   *        totpSecret null, emailCodeSecret null, registeredEmail null,
   *        trust 0 — the unenrolled state SURVIVED, it was NOT resurrected;
   *        AND the victim's on-disk config.xml still carries no totpSecret
   *        (the round-trip wrote the cleared state back, or wrote nothing
   *        new — either way, no factor on disk)
   * THEN   (b) a FRESH password-only session for the victim reaches the
   *        dashboard 200 — the reloaded gate passes an unenrolled user (no
   *        bounce); if the clear had not persisted, the victim's factors
   *        would reload and the gate would bounce them to the MFA page
   * THEN   (c) the victim RE-ENROLLS through the documented self-service
   *        path (postEnroll — unenrolled users are exempt from the
   *        management guard — then postEnrollConfirm with a live code):
   *        the recovery described in the README completes, end to end,
   *        after the restart
   * THEN   (d) the ADMIN's own factors survived the restart byte-for-byte
   *        (seed + mailbox, no collateral loss) and are LIVE — a fresh
   *        verified admin session clears a second sacrificial victim
   *        through the same verb, proving the admin's cleared-state
   *        survives is not an accident of the admin never being touched
   * </pre>
   *
   * WHY — the credential-clear's persistence is seam-proven (leg 5 +
   * {@code AdminManageAllowedTest} byte-for-byte) and {@code target.save()}
   * is called, but nothing upstream proved the persisted clear SURVIVES a
   * restart. For an operation that DESTROYS credentials, an unproven
   * round-trip is the postmortem's restart lesson in its purest form: a
   * victim whose "recovered" factors silently resurrect after a restart is
   * locked out again at the worst moment, and an admin who "cleared" a
   * user believes the lockout is over when it is not. This leg is what
   * spec §7 case 3 called "not negotiable for a credential-clearing op"
   * and §10 item 2 requires as the definition of done. The on-disk
   * {@code config.xml} probe is what makes (a)–(d) non-vacuous: without a
   * disk anchor, an in-memory clear that was never persisted would pass (a)
   * trivially — the anchor proves the clear wrote, so the reload is the
   * round-trip being tested.
   */
  @Test
  void clearedVictimSurvivesRestartAndRecoveryCompletes(JenkinsRule rule) throws Throwable {
    ensureRealm(rule);
    User victim = enroll(rule, "victim", VICTIM_PW, "JBSWY3DPEHPK3PXP");
    victim.getProperty(MfaUserProperty.class).setRegisteredEmail("victim.example");
    victim.save();
    User admin = enroll(rule, "admin", ADMIN_PW, "KRSXG5CTMVRXEZLU");
    admin.getProperty(MfaUserProperty.class).setRegisteredEmail("admin.example");
    admin.save();

    // The admin's natural flow (as leg 5): login → verify TOTP, then the
    // credential-clear on the locked-out victim.
    JenkinsRule.WebClient c = rule.createWebClient();
    c.login("admin", ADMIN_PW);
    verifyTotp(c, rule, "admin", "KRSXG5CTMVRXEZLU");

    // (0) The clear succeeds (the verified op leg 5 proves in flight).
    JSONObject clear = postAdmin(rule, c, "clearFactors", victim.getId(), 200);
    assertTrue(clear.optBoolean("ok"), "the verified admin's clear must succeed: " + clear);

    // (0a) ANTI-VACUITY ANCHOR — the clear persisted to DISK before the
    // restart, so the post-restart assertions read round-trip truth rather
    // than a never-persisted in-memory state. The victim's on-disk
    // config.xml must be present (the clear path saved it) and must carry
    // no totpSecret element (the factor is gone from disk).
    File victimDir = userDir(rule.jenkins.getRootDir(), "victim");
    File victimXml = new File(victimDir, "config.xml");
    assertTrue(victimXml.exists(),
        "the clear's save() must have materialised the victim's config.xml on disk: "
            + victimXml);
    assertFalse(diskXmlHasTotpSecret(victimXml),
        "the cleared victim's on-disk config.xml must carry NO totpSecret element "
            + "(the factor is gone from disk, not just from memory)");

    // The RESTART — the round-trip leg proper: reload Jenkins from disk.
    rule.restart();

    // Resolve the reloaded users. User.getById re-resolves against the
    // reloaded realm; the property is what the restart actually reloaded
    // from config.xml.
    User victimAfter = User.getById("victim", true);
    User adminAfter = User.getById("admin", true);
    assertNotNull(victimAfter, "the victim user must survive the restart");
    assertNotNull(adminAfter, "the admin user must survive the restart");

    // (a) The victim's reloaded state is STILL cleared — NOT resurrected.
    MfaUserProperty victimP = victimAfter.getProperty(MfaUserProperty.class);
    assertNotNull(victimP, "the victim's MfaUserProperty must be present (getOrCreate-safe)");
    assertFalse(victimP.hasTotpFactor(),
        "the victim's TOTP factor must NOT have resurrected across the restart");
    assertFalse(victimP.hasEmailFactor(),
        "the victim's email factor must NOT have resurrected across the restart");
    assertNull(victimP.getRegisteredEmail(),
        "the victim's registered mailbox must NOT have resurrected across the restart");
    assertEquals(0L, victimP.getTrustedUntilMs(),
        "the victim's trust must be 0 after the restart (the clear's trust reset survived)");
    // The on-disk config.xml after the restart: the round-trip wrote the
    // cleared state back (or wrote nothing new) — either way, NO factor
    // element is on disk.
    assertFalse(diskXmlHasTotpSecret(new File(victimDir, "config.xml")),
        "after the restart the victim's on-disk config.xml must still carry NO totpSecret");

    // (b) The reloaded gate passes the victim (unenrolled = exempt): a FRESH
    // password-only session reaches the dashboard with no bounce. If the
    // clear had not persisted, the victim's factors would reload and the
    // gate would bounce them to the MFA page.
    JenkinsRule.WebClient victimClient = rule.createWebClient();
    victimClient.login("victim", VICTIM_PW);
    HtmlPage victimHome = victimClient.getPage(rule.getURL());
    int victimHomeStatus = victimHome.getWebResponse().getStatusCode();
    assertEquals(200, victimHomeStatus,
        "after the restart the UNENROLLED victim must reach the dashboard 200 "
            + "without a gate bounce: " + victimHomeStatus);

    // (c) The victim RE-ENROLLS through the documented self-service path,
    // end to end, AFTER the restart (the README's recovery paragraph is
    // completed: clear → restart → victim re-enrolls → round trip closes).
    // An unenrolled user is EXEMPT from the management guard (the A23 guard
    // only challenges ENROLLED-unverified sessions), so postEnroll is
    // reachable password-only.
    String crumb = mfaCrumb(victimClient, rule);
    JSONObject gen = postMfaProfile(rule, victimClient, "postEnroll", crumb);
    assertTrue(gen.optBoolean("ok"), "postEnroll must return a fresh seed: " + gen);
    String newSeed = gen.optString("seed");
    byte[] key = org.sebcru.mfa.crypto.Totp.decodeSecret(newSeed);
    String code = org.sebcru.mfa.crypto.Totp.codeAt(key, System.currentTimeMillis());
    JSONObject confirm = postMfaProfile(rule, victimClient, "postEnrollConfirm", crumb,
        new NameValuePair("seed", newSeed), new NameValuePair("code", code));
    assertTrue(confirm.optBoolean("ok"),
        "postEnrollConfirm must commit the re-enrolment: " + confirm);
    // The re-enrolled factor is LIVE and PERSISTED (the save in the confirm
    // path wrote it) — the recovery path actually recovered.
    MfaUserProperty victimRe = User.getById("victim", true).getProperty(MfaUserProperty.class);
    assertTrue(victimRe.hasTotpFactor(),
        "the victim must be re-enrolled after the restart (factor present in memory)");
    assertEquals(newSeed, victimRe.getTotpSecret().getPlainText(),
        "the re-enrolled factor must be the fresh seed the victim committed");

    // (d) The ADMIN's own factors survived the restart with no collateral
    // loss — the seed and mailbox reload identical, and the factors are
    // LIVE (a fresh verified admin can clear a second sacrificial victim
    // through the same verb, proving the admin's survival is real, not an
    // accident of the admin never being touched in this test).
    MfaUserProperty adminP = adminAfter.getProperty(MfaUserProperty.class);
    assertTrue(adminP.hasTotpFactor(), "the admin's TOTP factor must survive the restart");
    assertEquals("KRSXG5CTMVRXEZLU", adminP.getTotpSecret().getPlainText(),
        "the admin's TOTP seed must reload byte-for-byte across the restart");
    assertEquals("admin.example", adminP.getRegisteredEmail(),
        "the admin's registered mailbox must survive the restart");

    // A sacrificial second victim proves the admin's factors are LIVE after
    // the restart (not merely present): the admin logs in fresh, verifies
    // TOTP, and clears the sacrificial victim through the same verb.
    User sacrificial = enroll(rule, "sacrificial", "sac-pw-1", "QWERTYUIOP12345678");
    sacrificial.getProperty(MfaUserProperty.class).setRegisteredEmail("sac.example");
    sacrificial.save();
    JenkinsRule.WebClient adminFresh = rule.createWebClient();
    adminFresh.login("admin", ADMIN_PW);
    verifyTotp(adminFresh, rule, "admin", "KRSXG5CTMVRXEZLU");
    JSONObject sacClear = postAdmin(rule, adminFresh, "clearFactors", sacrificial.getId(), 200);
    assertTrue(sacClear.optBoolean("ok"),
        "the post-restart verified admin must be able to clear via the same verb: "
            + sacClear);
    assertFalse(User.getById("sacrificial", true)
            .getProperty(MfaUserProperty.class).hasTotpFactor(),
        "the sacrificial victim's factor must be cleared by the post-restart admin");
  }

  /**
   * Resolve the on-disk user directory for the given id. Jenkins sanitises
   * the id for the directory name (hyphens dropped, a hash appended), so
   * match the sanitised prefix rather than the raw id.
   */
  private static File userDir(File jenkinsRoot, String userId) {
    String sanitized = userId.replaceAll("[^A-Za-z0-9_]", "");
    File usersRoot = new File(jenkinsRoot, "users");
    File[] dirs = usersRoot.listFiles((d, n) -> n.startsWith(sanitized + "_"));
    assertNotNull(dirs, "the users directory must exist");
    assertEquals(1, dirs.length,
        "exactly one user directory for " + userId + ": " + Arrays.toString(dirs));
    return dirs[0];
  }

  /**
   * True iff the user's on-disk {@code config.xml} carries a non-empty
   * {@code totpSecret} element. The anti-vacuity probe: before the restart
   * it proves the clear WROTE to disk (so the post-restart assertions read
   * round-trip truth); after the restart it proves the persisted state did
   * NOT resurrect a factor.
   */
  private static boolean diskXmlHasTotpSecret(File xml) throws java.io.IOException {
    if (!xml.exists()) {
      return false; // no file, no factor element
    }
    String content = java.nio.file.Files.readString(xml.toPath());
    // A present, non-empty totpSecret carries the base32 seed between the
    // tags: <hudson.util.Secret>…base32…</hudson.util.Secret>. A cleared
    // factor writes no element at all (or an empty one). Match the element
    // name and require non-whitespace content between its tags.
    java.util.regex.Matcher m = java.util.regex.Pattern
        .compile("<totpSecret>\\s*([^<\\s].*?)</totpSecret>", java.util.regex.Pattern.DOTALL)
        .matcher(content);
    return m.find() && !m.group(1).trim().isEmpty();
  }

  /**
   * POST a crumb-bearing self-service {@code /mfa} profile endpoint
   * (postEnroll / postEnrollConfirm / …) and assert its 200 JSON envelope.
   * The MfaAdminIT shape of the MfaProfileIT helper — context-relative
   * under the rule's URL, A19's redirect discipline is irrelevant here
   * (profile endpoints answer 200 JSON, never a 302).
   */
  private JSONObject postMfaProfile(JenkinsRule rule, JenkinsRule.WebClient c, String endpoint,
      String crumb, NameValuePair... fields) throws Exception {
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

  // ==================================================================
  // Helpers (house IT mechanics — MfaProfileIT-compatible shapes).
  // ==================================================================

  /** Create a password user and enrol TOTP (the property the verbs act on). */
  private User enroll(JenkinsRule rule, String name, String pw, String secret) throws Exception {
    HudsonPrivateSecurityRealm realm =
        (HudsonPrivateSecurityRealm) rule.jenkins.getSecurityRealm();
    User u = realm.createAccount(name, pw);
    MfaUserProperty p = MfaUserProperty.getOrCreate(u);
    p.setTotpSecret(Secret.fromString(secret));
    u.save();
    return u;
  }

  /** Verify TOTP so the session holds the verified credential. */
  private void verifyTotp(JenkinsRule.WebClient c, JenkinsRule rule, String user, String secret)
      throws Exception {
    String crumb = mfaCrumb(c, rule);
    byte[] key = org.sebcru.mfa.crypto.Totp.decodeSecret(secret);
    String code = org.sebcru.mfa.crypto.Totp.codeAt(key, System.currentTimeMillis());
    WebRequest req = new WebRequest(new URL(rule.getURL(), "mfa/postVerify"), HttpMethod.POST);
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
    assertTrue(j.optBoolean("ok"), "the admin's TOTP verify must succeed: " + j);
  }

  /** The MFA page is always allow-listed: crumb source for any session. */
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

  /** POST a crumb-bearing verb to the admin surface; assert the expected
   *  HTTP STATUS and return the envelope. The A23 contract lives in the
   *  status: a denial is a 403 (never a silent 200), a processed request
   *  is a 200 whose envelope carries the stable ok/error shape. The
   *  crumb is sourced from the MFA page — the one page that renders for
   *  EVERY session shape, including the unverified attacker's. */
  private JSONObject postAdmin(JenkinsRule rule, JenkinsRule.WebClient c, String endpoint,
      String userId, int expectedStatus) throws Exception {
    String crumb = mfaCrumb(c, rule);
    WebRequest req = new WebRequest(new URL(rule.getURL(), "mfaAdmin/" + endpoint),
        HttpMethod.POST);
    List<NameValuePair> params = new ArrayList<>();
    params.add(new NameValuePair(this.crumbName, crumb));
    params.add(new NameValuePair("userId", userId));
    params.add(new NameValuePair("confirmUserId", userId));
    req.setRequestParameters(params);
    WebResponse resp;
    try {
      resp = c.loadWebResponse(req);
    } catch (FailingHttpStatusCodeException e) {
      resp = e.getResponse();
    }
    assertEquals(expectedStatus, resp.getStatusCode(),
        endpoint + " must answer status " + expectedStatus + ": "
            + resp.getStatusCode() + " body=" + resp.getContentAsString());
    return JSONObject.fromObject(resp.getContentAsString());
  }

  /** GET the rendered /mfaAdmin page's HTML (following redirects). */
  private String pageHtml(JenkinsRule.WebClient c, JenkinsRule rule) throws Exception {
    WebResponse r = rawGet(c, rule, "/mfaAdmin/");
    List<String> hops = new ArrayList<>();
    for (int h = 0; r.getStatusCode() == 302 && h++ < 3; ) {
      String loc = r.getResponseHeaderValue("Location");
      hops.add(r.getStatusCode() + " -> " + loc);
      r = c.loadWebResponse(new WebRequest(hostAbs(rule, loc)));
    }
    assertEquals(200, r.getStatusCode(),
        "the admin page must render 200; chain: "
            + (hops.isEmpty() ? "(direct " + r.getStatusCode() + ")"
               : String.join("; ", hops) + "; final " + r.getStatusCode()));
    return r.getContentAsString();
  }

  /** A raw GET that stops at the first response (302 not followed). */
  private WebResponse rawGet(JenkinsRule.WebClient c, JenkinsRule rule, String path)
      throws Exception {
    // path is CONTEXT-RELATIVE: strip a leading "/" so the reference
    // resolves UNDER the context (rule.getURL() carries /jenkins/) — a
    // leading-slash reference resolves at the server root and 404s.
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

  /** Resolve an already context-absolute Location to an absolute URL at the
   *  host authority (NOT under the context, which would duplicate it). */
  private static URL hostAbs(JenkinsRule rule, String ctxAbsolutePath) throws Exception {
    String b = rule.getURL().toString();
    int slash = b.indexOf("/", b.indexOf("//") + 2);
    String authority = (slash == -1) ? b : b.substring(0, slash);
    String p = ctxAbsolutePath.startsWith("/") ? ctxAbsolutePath : "/" + ctxAbsolutePath;
    return new URL(authority + p);
  }

  /** A raw POST to an admin verb that stops at the first response (302 not
   *  followed) and returns the response. Unlike {@link #postAdmin} it
   *  asserts nothing about the status or body — it is for the legs where the
   *  interesting assertion is the STATUS itself (the gate-bounce 302).
   *  The crumb is carried nonetheless so the pin is honest: even WITH a
   *  valid CSRF crumb, an enrolled, password-only session is bounced.
   *  The redirect is explicitly DISABLED for this one request (the A19
   *  lesson: the harness web client follows redirects by default, which
   *  would turn the gate's 302 into the MFA page's 200 and swallow the pin)
   *  and restored afterwards, exactly as {@link #rawGet} does. */
  private WebResponse rawPostAdmin(JenkinsRule.WebClient c, JenkinsRule rule, String endpoint,
      String userId) throws Exception {
    String crumb = mfaCrumb(c, rule);
    WebRequest req = new WebRequest(new URL(rule.getURL(), "mfaAdmin/" + endpoint),
        HttpMethod.POST);
    List<NameValuePair> params = new ArrayList<>();
    params.add(new NameValuePair(this.crumbName, crumb));
    params.add(new NameValuePair("userId", userId));
    params.add(new NameValuePair("confirmUserId", userId));
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

  /** True iff the response is a 302 whose Location targets the MFA page
   *  (the gate's bounce, {@code <ctx>/mfa?redirect=…}). The {@code /mfa?}
   *  (page + redirect param) is precise: it matches the MFA page and NOT a
   *  hypothetical {@code /mfaAdmin} location. */
  private static boolean isMfaRedirect(WebResponse r) {
    String loc = r.getResponseHeaderValue("Location");
    return loc != null && loc.contains("/mfa?");
  }

  /**
   * The LEAST-PRIVILEGE authorization strategy the privilege-slot leg (case 4)
   * needs: exactly one user ({code adminUser}) holds {@code ADMINISTER};
   * everyone else is fail-closed (no permission at all). This is the one shape
   * the {@code FullControlOnceLoggedInAuthorizationStrategy} used by the
   * other legs cannot produce — FCOL makes every logged-in user an admin, so
   * a genuine non-admin simply does not exist under it, and the privilege
   * axis (spec §7 case 6: a non-admin denied at the wire) is untestable.
   *
   * <p>{@code MatrixAuthorizationStrategy} (the natural tool) is not on this
   * build's offline classpath (it left jenkins-core in this core lineage), so
   * this is a minimal hand-rolled strategy: its root ACL is a
   * {@code SidACL} that grants ADMINISTER to one named principal and returns
   * {@code null} for every other sid + permission, which {@code SidACL}
   * resolves to a FAIL-CLOSED {@code false} (verified from the bytecode: no
   * matching entry → {@code Boolean.FALSE}). A non-null grant is therefore
   * the ONLY way to hold ADMINISTER, which is exactly the "elevated vs.
   * subordinate probe" contrast the leg pins. (Note:
   * {@code AuthorizationStrategy} is a CLASS in this core — the strategy and
   * the ACL are different types, so the strategy holds the ACL rather than
   * BEING one.)
   */
  static final class LeastPrivilegeAdministerStrategy extends AuthorizationStrategy {
    private final String adminUser;

    LeastPrivilegeAdministerStrategy(String adminUser) {
      this.adminUser = adminUser;
    }

    /** THE root ACL: every root-level permission check flows through this
     *  SidACL. The grant table is deliberately minimal and realistic:
     *  <ul>
     *    <li>{@code ADMINISTER} → exactly the one named user (the "elevated
     *        probe" for contrast on the other legs);</li>
     *    <li>{@code READ} (global) → every *authenticated* principal — the
     *        ordinary-user baseline, without which even the harness's
     *        post-login landing page 403s and the login helper itself
     *        cannot complete, conflating login with authorization;</li>
     *    <li>everything else → {@code null} → SidACL fails CLOSED.
     *  </ul>
     *  Anonymous is never granted anything. Item/user-level ACLs are not
     *  probed by this leg — the two probes target the root object only. */
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

    /**
     * Programmatic descriptor — NOT an {@code @Extension}. Nothing in this
     * leg renders the strategy in a form (no security-configure page is
     * loaded), so no descriptor registry entry is needed; a lazily-shared
     * instance keeps the {@code Describable} contract satisfiable if
     * anything ever asks, without risking harness extension scanning.
     */
    private static final Descriptor<AuthorizationStrategy> DESCRIPTOR =
        new Descriptor<AuthorizationStrategy>(AuthorizationStrategy.class) {
          @Override
          public String getDisplayName() {
            return "Test least-privilege: one admin user";
          }

          @Override
          public String getId() {
            return "test-least-privilege-administer";
          }
        };

    @Override
    public Descriptor<AuthorizationStrategy> getDescriptor() {
      return DESCRIPTOR;
    }
  }
}
