package org.sebcru.mfa;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

/**
 * §1-D D2 — the admin face is an island until the back link exists. mads's
 * production walk (2026-08-24) found the roster page with NO cancel/back
 * affordance: "once you're there you're stranded." The settled ruling keeps
 * the roster on its own page (it is a mutation surface — its own POST
 * endpoints, crumb, typed-confirmation dialog, CSP-clean JS — and inlining
 * it into the single-submit configureSecurity form would mix form-submit
 * semantics; Jenkins convention agrees: action surfaces get their own
 * page). The island feeling is fixed by a BACK LINK, not by a transplant.
 *
 * <p>Contract pinned here (one commit per task — this class is D2's):
 * <ul>
 *   <li>the link exists on BOTH rendered arms — the roster AND the 403
 *       denial arm. The denial page is exactly where "stranded" bites
 *       hardest: an authenticated non-admin bounced from a surface they
 *       can't use has no way home on the page itself.</li>
 *   <li>the link is ABSOLUTE-rooted ({@code /manage/configureSecurity/}),
 *       never relative — the context-safe script-URL defect (Defect
 *       record, §5) proved that a relative resource dies under a
 *       non-root context path; a navigation target has the identical
 *       failure mode.</li>
 *   <li>the link declares its own colour for BASE (dark) rules AND for the
 *       light block on both arms — the round-7 lesson ("never inherit /
 *       guess colours", postmortem rule 12) applied to the new element, on
 *       the light axis where it is hardest to see (an inherited dark
 *       link on a white page is an off-theme island no full-page
 *       screenshot obviously shows).</li>
 *   <li>the text carries the target's name ("Security configuration") —
 *       the settings page is the admin's MFA front door and the one the
 *       walk used to reach this face, so "back" means there.</li>
 * </ul>
 *
 * <p>Honest red phase: written against the current (pre-fix) document and
 * run BEFORE the jelly got the links — "no back link on the roster arm"
 * and "no back link on the denial arm" failed with anchor=null for both
 * arms; only after the index.jelly fix did all legs go green.
 *
 * <p>WHY / SOLVES: navigation is a user-facing behaviour the harness never
 * renders — the IT's rawGet sees a 200 either way. If this regressed, the
 * admin surface would again leave every visitor (including one holding a
 * permission-denied 403) without a route off the page, and a future
 * "fixed the navigation" report could overclaim without pixels to prove
 * it, the way the theming overclaim went.
 */
class MfaAdminBackLinkTest {

  private static String doc;

  @BeforeAll
  static void loadAdminIndex() throws Exception {
    InputStream in =
        MfaAdminBackLinkTest.class.getResourceAsStream(
            "/org/sebcru/mfa/MfaAdminController/index.jelly");
    assertNotNull(in,
        "the admin index view resource must be on the test classpath");
    try (in) {
      doc = new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }
  }

  /** The 403 denial arm's text (from its open to the roster arm). */
  private static String denialArm() {
    return doc.substring(
        doc.indexOf("<j:when test=\"${!it.adminPageAllowed()}\">"),
        doc.indexOf("<j:otherwise>"));
  }

  /** The roster arm's text (from the j:otherwise open to document end). */
  private static String rosterArm() {
    return doc.substring(doc.indexOf("<j:otherwise>"));
  }

  /** The {@code <a class="back" ...>} element inside {@code arm}, or null. */
  private static String backLinkIn(String arm) {
    int start = arm.indexOf("<a class=\"back\"");
    if (start < 0) {
      return null;
    }
    int end = arm.indexOf("</a>", start);
    assertTrue(end > start, "the back anchor in this arm is not closed");
    return arm.substring(start, end);
  }

  @Test
  @DisplayName("roster arm: back link present, absolute-rooted, named")
  void rosterArmCarriesTheBackLink() {
    String arm = rosterArm();
    String link = backLinkIn(arm);
    assertNotNull(
        link,
        "the roster arm must offer a back link — the production walk's"
            + " defect: the admin page is an island with no route off it");
    assertTrue(
        link.contains("href=\"/manage/configureSecurity/\""),
        "the back link must target /manage/configureSecurity/ ABSOLUTE — a"
            + " relative href dies under a non-root context path (the"
            + " script-URL defect class): " + link);
    // Whitespace is collapsed in the HTML source but not in the file text;
    // the rendered NAME is what the pin protects.
    String renderedName = link.replaceAll("<[^>]+>", " ").replaceAll("\\s+", " ");
    assertTrue(
        renderedName.toLowerCase().contains("security configuration"),
        "the back link must name its destination (the settings page is the"
            + " face's front door): " + link);
  }

  @Test
  @DisplayName("denial arm: back link present, absolute-rooted, named")
  void denialArmCarriesTheBackLink() {
    String arm = denialArm();
    String link = backLinkIn(arm);
    assertNotNull(
        link,
        "the 403 denial arm must offer a back link TOO — a visitor bounced"
            + " from a surface they cannot use is the STRANDEST case; the"
            + " denial page is part of the face, not an afterthought");
    // Arm-aware target (ruling documented in the commit): the denial arm's
    // audience is an authenticated NON-admin, and
    // /manage/configureSecurity/ is itself ADMINISTER-gated — sending them
    // there only hands them core's 403 page. The handoff left the target
    // open ("or a Manage Jenkins breadcrumb"); their reachable home is the
    // admin console root, so THAT arm points at /manage/, while the roster
    // arm (whose audience CAN reach the front door) points at the security
    // config page. Both absolute-rooted; both named.
    assertTrue(
        link.contains("href=\"/manage/\""),
        "the denial arm's back link must target /manage/ (the admin console"
            + " root) absolute — /manage/configureSecurity/ would 403 for"
            + " this arm's non-admin audience: " + link);
    assertTrue(
        !link.contains("configureSecurity"),
        "the denial arm must NOT link to configureSecurity — it is"
            + " ADMINISTER-gated and this arm's audience does not hold it:"
            + " " + link);
  }

  @Test
  @DisplayName("both arms: the link colour is declared for BOTH schemes")
  void backLinkColourIsDeclaredInBothSchemes() {
    // Shared css-slicing, so the document is cut one way in both test
    // classes (MfaAdminIndexThemeTest owns the implementation).
    String baseDark = MfaAdminIndexThemeTest.rosterBaseCss();
    String light = MfaAdminIndexThemeTest.rosterLightCss();
    assertNotNull(light, "the roster arm's stylesheet has no light block");

    assertTrue(
        MfaAdminIndexThemeTest.selectorColoured(baseDark, ".back"),
        "the back link must declare its own colour in the BASE (dark)"
            + " rules — never inherit a neighbouring rule (round 7)");
    assertTrue(
        MfaAdminIndexThemeTest.selectorColoured(light, ".back"),
        "the back link must declare its own colour in the LIGHT block — an"
            + " inherited dark-coloured link on a white page is an"
            + " off-theme island (postmortem rule 12)");
    // The two declarations must DIFFER — one colour serving both schemes
    // is the theming-overclaim pattern this project has burned on before.
    String dark = MfaAdminIndexThemeTest.colourOf(baseDark, ".back");
    String lightColour = MfaAdminIndexThemeTest.colourOf(light, ".back");
    assertTrue(
        !dark.equalsIgnoreCase(lightColour),
        "the back link's light colour (" + lightColour + ") must differ"
            + " from its dark colour (" + dark + ") — a shared colour means"
            + " one scheme is borrowing the other's theme");

    // The denial arm carries its own small stylesheet; same contract there.
    int dStart = doc.indexOf("<style>");
    int dEnd = doc.indexOf("</style>", dStart);
    String denialCss = doc.substring(dStart, dEnd);
    String dBase = MfaAdminIndexThemeTest.baseBlockOf(denialCss);
    String dLight = MfaAdminIndexThemeTest.lightBlockOf(denialCss);
    assertNotNull(dLight, "the denial arm's stylesheet has no light block");
    assertTrue(
        MfaAdminIndexThemeTest.selectorColoured(dBase, ".back"),
        "the denial arm's back link needs its own base-scheme colour too");
    assertTrue(
        MfaAdminIndexThemeTest.selectorColoured(dLight, ".back"),
        "the denial arm's back link needs its own light-scheme colour too");
  }
}
