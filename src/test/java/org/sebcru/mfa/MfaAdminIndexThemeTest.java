package org.sebcru.mfa;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * A22-b §1-B — the theming contract for the standalone admin page
 * ({@code MfaAdminController/index.jelly}), pinned the way the context-safe
 * script-URL defect was pinned: against the RENDERED source the user's
 * browser receives, because the defect this test exists for is one only a
 * rendered page can show.
 *
 * <p>Honest red-phase history (2026-08-23): the real-browser walk captured
 * "dark" and "light" renders of the roster that were BYTE-IDENTICAL
 * (same md5, screenshots 03/04 of the A22-b record). The page had long
 * declared {@code color-scheme: light dark;} in the hope that the UA and
 * controls would follow the user's preference — but every rule in the
 * stylesheet was a hardcoded dark literal, and there was no light theme at
 * all. A page that claims both schemes and renders one is not "both themes
 * verified"; it silently lies to light-preferring admins. These pins make
 * the claim true instead:
 * <ul>
 *   <li>a {@code @media (prefers-color-scheme: light)} block exists and is
 *       substantive;</li>
 *   <li>every coloured surface of the roster card AND of the typed-
 *       confirmation dialog gets an explicit light declaration (the
 *       round-7 lesson, "never inherit / guess button colours", applied to
 *       the light axis as well);</li>
 *   <li>the light body background is actually different from the dark one —
 *       the screenshot-md5 acceptance criterion, checked in source rather
 *       than only in pixels;</li>
 *   <li>the 403 denial body — the other rendered surface of this face — is
 *       theme-aware instead of permanently dark.</li>
 * </ul>
 *
 * <p>WHY / SOLVES: light is a first-class Jenkins theme (mads's instance
 * runs light-preferring browsers; the sister MFA surfaces follow the user's
 * theme). If this regressed, a light-preferring admin reading the roster
 * would hit a dark hole in a light UI — and, worse, a future "fixed the
 * theming" report could overclaim both themes verified again (the v3
 * overclaim this task corrects), because the byte-identical screenshot
 * pair would come back and no test would stop it.
 */
class MfaAdminIndexThemeTest {

  /** The rendered admin document, read exactly as the classpath ships it. */
  private static String doc;

  @BeforeAll
  static void loadAdminIndex() throws Exception {
    InputStream in =
        MfaAdminIndexThemeTest.class.getResourceAsStream(
            "/org/sebcru/mfa/MfaAdminController/index.jelly");
    assertNotNull(in,
        "the admin index view resource must be on the test classpath — "
            + "a move that orphans it would make these pins vacuous");
    try (in) {
      doc = new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }
  }

  /**
   * WHAT: the page's scheme declaration survives — it opts in to BOTH UA
   * schemes rather than forcing one.
   * <pre>
   * GIVEN the rendered admin document
   * WHEN  its :root rule is inspected
   * THEN  it declares `color-scheme: light dark` (both, not `dark` only) —
   *       the UA controls and form widgets are told the page serves both
   *       themes, which is only true once the light block below exists
   * </pre>
   * WHY / SOLVES: a future "simplification" to a dark-only declaration would
   * re-create exactly the overclaim this class exists to kill.
   */
  @Test
  void rootDeclaresBothSchemes() {
    assertTrue(doc.contains("color-scheme: light dark"),
        "the admin page must declare `color-scheme: light dark` — "
            + "dark-only or light-only declarations would make the "
            + "prefers-color-scheme pins below moot");
  }

  /**
   * WHAT: a light media block exists and every coloured surface declares it
   * explicitly (no inheritance, no guessing — the round-7 lesson on the
   * light axis).
   * <pre>
   * GIVEN the rendered admin document
   * WHEN  extracted under `@media (prefers-color-scheme: light)`
   * THEN  the block exists and re-declares each surface that the base
   *       (dark) rules paint: body, .card, h1, .sub, th, td, .none,
   *       .factor-totp, .factor-email, .btn, .btn-danger, .veil, .dialog,
   *       .dialog input, .result-ok, .result-err, noscript
   * </pre>
   * WHY / SOLVES: the A22-b dark render was proven element-by-element in
   * postmortem round 7 (white-on-white ghost buttons); an equally explicit
   * light rule set is the only shape in which "light works" is not a hope.
   * If one surface were left to inherit, it would render as a dark island
   * inside the light card — a defect no screenshot of the WHOLE page
   * obviously shows and a test is the only thing that pins per-surface.
   */
  @Test
  void lightBlockExistsAndCoversEveryPaintedSurface() {
    String light = extractLightBlock(cardCss());
    assertNotNull(light,
        "the admin page must contain a `@media (prefers-color-scheme: light)`"
            + " block — before the §1-B fix it rendered byte-identical dark"
            + " under a light preference");
    String[] required = {
        "body", ".card", "h1", ".sub", "th", "td", ".none",
        ".factor-totp", ".factor-email", ".btn", ".btn-danger",
        ".veil", ".dialog", ".dialog input", ".result-ok", ".result-err",
        "noscript",
    };
    List<String> missing = new ArrayList<>();
    for (String sel : required) {
      if (!selectorPresent(light, sel)) {
        missing.add(sel);
      }
    }
    assertTrue(missing.isEmpty(),
        "light block missing declarations for: " + missing
            + " — every surface the dark rules paint must be re-painted in"
            + " light, or that surface renders as a dark island");
  }

  /**
   * WHAT: the two schemes are GENUINELY different documents, not one
   * document wearing two labels.
   * <pre>
   * GIVEN the rendered admin document
   * WHEN  the base body background and the light-block body background are
   *       compared
   * THEN  they are different colours — the source-level form of the
   *       acceptance criterion "two screenshots with different md5"
   * </pre>
   * WHY / SOLVES: the byte-identical-md5 screenshots of the A22-b "both
   * themes" walk were the defect; this assertion catches the regression at
   * the source, before it ever reaches a browser, for either scheme.
   */
  @Test
  void lightBodyBackgroundDiffersFromDarkBodyBackground() {
    String css = cardCss();
    String darkBody = bodyBackgroundOf(css);
    assertNotNull(darkBody, "base body rule without a background colour");
    String lightBlock = extractLightBlock(css);
    assertNotNull(lightBlock,
        "the light block must exist — without it there is no light body");
    String lightBody = bodyBackgroundOf(lightBlock);
    assertNotNull(lightBody,
        "the light block must declare its own body background — "
            + "inheriting the dark one is the exact bug under test");
    assertTrue(!darkBody.equalsIgnoreCase(lightBody),
        "light body background " + lightBody + " must differ from the dark "
            + "body background " + darkBody + " — identical bodies would "
            + "render byte-identical pages under both schemes");
  }

  /**
   * WHAT: the 403 denial body — the FACE's other rendered surface (the
   * permission-denial page a strict consumer and an unauthorised browser
   * both receive) — is theme-aware too.
   * <pre>
   * GIVEN the rendered admin document's 403 branch
   * WHEN  that branch is inspected (its window opens with the 403 status
   *       code and ends at the roster arm's &lt;j:otherwise&gt;)
   * THEN  it contains a prefers-color-scheme media rule and the stable
   *       admin_permission_required token — the denial page stops being a
   *       permanently dark sheet inside a light UI
   * </pre>
   * WHY / SOLVES: theming only the roster card while the denial page stays
   * dark leaves the same "dark hole in a light UI" on the most common
   * visitor to this face (anyone without ADMINISTER). The acceptance for
   * this task is "light and dark are genuinely distinct" for the face,
   * not for one happy path of it.
   */
  @Test
  void denialBodyIsThemeAware() {
    String denialStyle = doc.substring(
        doc.indexOf("<st:statusCode value=\"403\"/>"),
        doc.indexOf("<j:otherwise>"));
    assertTrue(denialStyle.contains("@media (prefers-color-scheme: light)"),
        "the 403 denial body must carry a light scheme rule — it is a "
            + "rendered surface of the admin face, not an off-theme "
            + "afterthought (the window above is the 403 arm only)");
    // The denial vocabulary must remain in the document regardless of
    // theming — a strict consumer matches on it.
    assertTrue(denialStyle.contains("admin_permission_required"));
  }

  // ------------------------------------------------------------
  // minimal CSS text helpers (the document is ours; no parser needed)
  // ------------------------------------------------------------

  /**
   * The roster arm's card stylesheet — the text between its
   * {@code <style>} opening and its {@code </style>} closing. The 403
   * denial arm (which precedes the roster arm in the document) carries
   * its own small stylesheet, so this helper must start AFTER the
   * roster arm's {@code <j:otherwise>} open, not at the document's first
   * {@code <style>}.
   */
  private static String cardCss() {
    int arm = doc.indexOf("<j:otherwise>");
    int start = doc.indexOf("<style>", arm);
    int end = doc.indexOf("</style>", start);
    if (arm < 0 || start < 0 || end < 0 || end < start) {
      throw new AssertionError("the card document has no <style> block");
    }
    return doc.substring(start, end);
  }

  /** The text inside {@code css}'s light media block, or null if absent. */
  private static String extractLightBlock(String css) {
    int start = css.indexOf("@media (prefers-color-scheme: light)");
    if (start < 0) {
      return null;
    }
    int open = css.indexOf('{', start);
    int depth = 0;
    for (int i = open; i < css.length(); i++) {
      char c = css.charAt(i);
      if (c == '{') {
        depth++;
      } else if (c == '}') {
        depth--;
        if (depth == 0) {
          return css.substring(open + 1, i);
        }
      }
    }
    throw new AssertionError("unbalanced braces after the light media rule");
  }

  /**
   * True if {@code sel} appears as a CSS selector with its own rule
   * opening inside {@code css} — so a selector merely mentioned in a
   * comment, or as a substring (.dialog inside ".dialog input"), does not
   * count.
   */
  private static boolean selectorPresent(String css, String sel) {
    int i = 0;
    while ((i = css.indexOf(sel, i)) >= 0) {
      if (!isSelectorStart(css, i)) {
        i += sel.length();
        continue;
      }
      // The selector's rule must open (a '{') before that run of text
      // closes ('}'), and nothing may sit between selector and brace
      // except whitespace or a selector-group comma.
      int brace = css.indexOf('{', i);
      int close = css.indexOf('}', i);
      if (brace >= 0 && (close < 0 || brace < close)) {
        String between = css.substring(i + sel.length(), brace).trim();
        if (between.isEmpty() || between.endsWith(",")) {
          return true;
        }
      }
      i += sel.length();
    }
    return false;
  }

  /**
   * The first hex background colour declared by any {@code body} rule in
   * {@code css} (or null). A "body" hit only counts when it starts a
   * selector, so the token buried in a property value never matches; the
   * rule's closing brace is found by brace-MATCHING, because a bare
   * forward `indexOf('}')` lands on the PREVIOUS rule's closing brace
   * (the selector run is checked between the selector and the NEXT rule
   * opening — which must come after the rule that closes this one).
   */
  private static String bodyBackgroundOf(String css) {
    int i = 0;
    String needle = "body";
    while ((i = css.indexOf(needle, i)) >= 0) {
      if (!isSelectorStart(css, i)) {
        i += needle.length();
        continue;
      }
      int open = css.indexOf('{', i);
      if (open < 0) {
        break;
      }
      String between = css.substring(i + needle.length(), open).trim();
      if (!between.isEmpty() && !between.endsWith(",")) {
        i += needle.length();
        continue;
      }
      int close = matchingClose(css, open);
      String bg = firstHexAfter(css, open, close, "background");
      if (bg != null) {
        return bg;
      }
      // A body rule without a colour (e.g. the `html, body` margin reset)
      // does not answer the question — keep scanning.
      i += needle.length();
    }
    return null;
  }

  /**
   * The index of the {@code '}'} matching the {@code '{'} at
   * {@code open} (or -1). Nesting-aware.
   */
  private static int matchingClose(String css, int open) {
    int depth = 0;
    for (int i = open; i < css.length(); i++) {
      char c = css.charAt(i);
      if (c == '{') {
        depth++;
      } else if (c == '}') {
        depth--;
        if (depth == 0) {
          return i;
        }
      }
    }
    return -1;
  }

  /**
   * True when the needle starting at {@code i} begins a CSS selector: the
   * previous significant character is line-start, whitespace, one of
   * {@code {(,:}, or a combinator character — never an identifier
   * character (which would mean a substring hit like "body" inside
   * "font-family" or in a selector's tail).
   */
  private static boolean isSelectorStart(String css, int i) {
    if (i == 0) {
      return true;
    }
    char before = css.charAt(i - 1);
    return before == '\n' || before == '\r' || before == '\t' || before == ' '
        || before == '{' || before == '(' || before == ':'
        || before == '+' || before == '>';
  }

  /**
   * The first {@code <property>: #hex...} declaration inside
   * {@code [open, close]}, or null.
   */
  private static String firstHexAfter(String css, int open, int close,
      String property) {
    String blockText = css.substring(open, Math.max(open, close));
    int prop = blockText.indexOf(property + ":");
    if (prop < 0) {
      return null;
    }
    int hex = blockText.indexOf("#", prop);
    if (hex < 0) {
      return null;
    }
    StringBuilder sb = new StringBuilder("#");
    for (int i = hex + 1; i < blockText.length() && i - hex < 7; i++) {
      char c = blockText.charAt(i);
      if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
        break;
      }
      sb.append(c);
    }
    return sb.length() >= 4 ? sb.toString() : null;
  }
}
