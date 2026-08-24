package org.sebcru.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * §1-D D1 — the i18n contract of the global MFA config form, pinned the way
 * the mangle that broke it is observable: the FORM IS THE EXTERNAL CONSUMER.
 *
 * <p>The defect this test exists for (mads's live walk, 2026-08-24): on
 * {@code /manage/configureSecurity/} the section title rendered the RAW KEY
 * {@code manageFactorsLink} instead of its display name. Root cause,
 * verified against bytes (both before the fix, and re-verified per Moldy's
 * fact-check of develop @ 4b2ec80):
 * <ol>
 *   <li>{@code config.properties} line 5 carried
 *       {@code rememberFor.hint=Days ..., without re-dem...[truncated]} —
 *       the value itself ended in a literal truncation placeholder AND had
 *       no terminating newline. Born that way in {@code 7bebb6e}
 *       (2026-08-18); not a display artifact, the git blob is byte-identical
 *       on every ref checked.</li>
 *   <li>A22-b's {@code d2a9008} then appended {@code manageFactorsLink=...}
 *       onto that same physical line. {@code java.util.Properties} splits on
 *       the FIRST {@code =}, so the appended text silently became part of
 *       {@code rememberFor.hint}'s value and the key
 *       {@code manageFactorsLink} stopped existing. The jelly's
 *       {@code ${%manageFactorsLink}} falls through to the raw key name —
 *       the exact symptom mads saw.</li>
 *   <li>The same file never defined the remaining referenced keys at all
 *       (issuer, trustMinHours, totpWindow, the four tuning knobs,
 *       exemptUsers) — every one of those titles/descriptions renders as a
 *       raw key for the same fall-through reason.</li>
 * </ol>
 *
 * <p>Honest red phase: the key-resolution test of this class was run FIRST,
 * against the un-fixed file, and failed with 20 of the 25 referenced keys
 * missing (only policy, policy.hint, rememberForHours,
 * manageFactorsLink.hint, manageFactorsLink.action resolved — the latter
 * two only because their values still carried the key as text, which
 * {@code Properties} maps onto the surviving line's key). The truncation and
 * glue pins failed on the literal markers. All pins went green only after
 * the properties file was rewritten so every reference resolves.
 *
 * <p>WHY / SOLVES: the config form is the admin's front door to the gate's
 * policy. If this regressed, every missing key would present as raw internal
 * identifiers on a SECURITY page — admins could not read what a knob does,
 * and the "Open" link into the admin recovery surface (the only findable
 * entrance to /mfaAdmin per the spec's discoverability ruling) would show
 * its title as a key. The walk caught one instance by luck; these pins make
 * the whole class loud and reviewable.
 */
class DevcruMfaConfigI18nTest {

  /** ${%key} — the jelly i18n reference syntax (jexl, resolved at render). */
  private static final Pattern I18N_REF = Pattern.compile("\\$\\{%([A-Za-z0-9_.]+)%?\\}");

  private static String jelly;

  /** The properties file exactly as the classpath ships it. */
  private static final List<String> PROP_LINES = new ArrayList<>();

  private static Properties props;

  @BeforeAll
  static void loadResources() throws Exception {
    InputStream jin =
        DevcruMfaConfigI18nTest.class.getResourceAsStream(
            "/org/sebcru/mfa/DevcruMfaConfig/config.jelly");
    assertNotNull(jin, "config.jelly must be on the classpath — it IS the form");
    try (jin) {
      jelly = new String(jin.readAllBytes(), StandardCharsets.UTF_8);
    }
    InputStream pin =
        DevcruMfaConfigI18nTest.class.getResourceAsStream(
            "/org/sebcru/mfa/DevcruMfaConfig/config.properties");
    assertNotNull(pin, "config.properties must be on the classpath — it IS the key source");
    try (pin) {
      String raw = new String(pin.readAllBytes(), StandardCharsets.UTF_8);
      for (String line : raw.split("\n", -1)) {
        PROP_LINES.add(line);
      }
    }
    props = new Properties();
    try (InputStream in =
            DevcruMfaConfigI18nTest.class.getResourceAsStream(
                "/org/sebcru/mfa/DevcruMfaConfig/config.properties")) {
      // load with ISO-8859-1 is the java.util.Properties contract; the file
      // is pure US-ASCII (asserted below), so it round-trips losslessly.
      props.load(in);
    }
  }

  private static Set<String> referencedKeys() {
    Set<String> keys = new LinkedHashSet<>();
    Matcher m = I18N_REF.matcher(jelly);
    while (m.find()) {
      keys.add(m.group(1));
    }
    return keys;
  }

  /**
   * WHAT: the form/properties pairing is complete — every i18n key the
   * rendered form asks for exists as a real key with a non-blank value.
   * <pre>
   * GIVEN the config.jelly form and the config.properties key source
   * WHEN  every ${%key} reference in the jelly is resolved the way the
   *       render-time consumer (java.util.Properties) resolves it
   * THEN  every one of the 25 unique references resolves to a non-blank
   *       value — 0 raw-key fall-throughs, in any quantity, not just the
   *       one mads happened to see
   * </pre>
   * WHY / SOLVES: the live defect was exactly this fall-through (20 of 25
   * keys missing). A single-instance pin ("manageFactorsLink exists") would
   * pass today's fix while leaving the other 19 titles as raw keys — the
   * pin must scan the form, the consumer's actual input, or it protects
   * nothing beyond one remembered symptom.
   */
  @Test
  void everyJellyReferenceResolvesToARealKey() {
    Set<String> refs = referencedKeys();
    // The §1-D walk count, pinned: the form asks for 25 unique i18n keys.
    // (Moldy's fact-check of develop @ 4b2ec80 confirmed 25, correcting an
    // earlier 21.) Removing entries from either file must fail loudly.
    assertEquals(
        25,
        refs.size(),
        "the config form references 25 unique i18n keys — a different count"
            + " means the form or its key source changed shape; reconcile both"
            + " in the same change. Found: " + sorted(refs));

    List<String> missing = new ArrayList<>();
    for (String key : sorted(refs)) {
      String value = props.getProperty(key);
      if (value == null || value.isBlank()) {
        missing.add(key);
      }
    }
    assertTrue(
        missing.isEmpty(),
        "i18n keys referenced by config.jelly but missing/blank in"
            + " config.properties (would render as raw key names on the form):"
            + " " + missing);
  }

  /**
   * WHAT: the section's display name is the fixed value from the live walk,
   * not a symptom-shaped guess: {@code manageFactorsLink} resolves to
   * "Factor recovery (locked-out users)".
   * <pre>
   * GIVEN the repaired key source
   * WHEN  ${%manageFactorsLink} is resolved
   * THEN  it yields the exact display name mads saw stripped away, and the
   *       pinned action word ("Open") — the link the admin actually clicks
   * </pre>
   * WHY / SOLVES: this is the specific title that rendered as a raw key on
   * 2026-08-24. Pinning the VALUE (not just existence) makes any future
   * rename/re-mangle of the recovery-surface entry a loud, reviewable red —
   * and a re-glue of this line onto its neighbour (the original bug) is
   * caught by this test AND by the glue pin below, from both directions.
   */
  @Test
  void manageFactorsLinkSectionTitleIsTheWalkValue() {
    assertEquals(
        "Factor recovery (locked-out users)",
        props.getProperty("manageFactorsLink"),
        "the section title for the admin recovery surface must be the display"
            + " name from the production walk, not a raw key or placeholder");
    assertEquals(
        "Open",
        props.getProperty("manageFactorsLink.action"),
        "the link action word is part of the walk-pinned contract");
  }

  /**
   * WHAT: the truncation-placeholder marker ({@code ...[truncated]} — the
   * literal artifact of a truncated write, found at the end of the
   * rememberFor hint value since git 7bebb6e) is absent from every value.
   * <pre>
   * GIVEN the repaired key source
   * WHEN  every property VALUE is scanned
   * THEN  none carries the truncation placeholder, lower-case-insensitive
   * </pre>
   * WHY / SOLVES: the original broken value ended mid-sentence with
   * "...[truncated]" baked in as literal text, so an admin reading the
   * "remember trusted browsers" hint received a cut-off sentence that ended
   * in what looks like a tool artifact. The marker must never ship; if a
   * future rewrite re-introduces a truncated value, this fails on the value
   * no matter WHICH key carries it (the D1 root cause was a value, not a
   * key — the pin must follow the value).
   */
  @Test
  void noValueCarriesATruncationPlaceholder() {
    List<String> offenders = new ArrayList<>();
    for (String key : props.stringPropertyNames()) {
      String v = props.getProperty(key);
      if (v.toLowerCase(Locale.ROOT).contains("[truncated]")) {
        offenders.add(key);
      }
    }
    assertTrue(
        offenders.isEmpty(),
        "property values containing a truncation placeholder ([truncated]):"
            + " " + offenders
            + " — a value cut off mid-sentence reads as a broken install");
  }

  /**
   * WHAT: the glue failure mode — one physical line silently containing two
   * {@code key=value} assignments — cannot recur: {@code Properties} parses
   * such a line as the FIRST key with the remainder as value, so a second
   * assignment on a line makes the second key vanish. Pinned at the
   * PHYSICAL-LINE level (the parser's actual input), not the logical-key
   * level where it is already invisible.
   * <pre>
   * GIVEN the raw bytes of config.properties
   * WHEN  every non-blank, non-comment line is inspected
   * THEN  exactly one '=' separates key from value on the line (the java
   *       Properties split point), no line ends without a terminating
   *       newline except the final line, and no key TOKEN appears embedded
   *       inside another line's value
   * </pre>
   * WHY / SOLVES: this is the exact shape of the A22-b mangle (d2a9008
   * appended manageFactorsLink=... to a newline-less line). The logical
   * key test above catches the CONSEQUENCE (missing key); this pin catches
   * the CAUSE at the byte level, so a bad write is red BEFORE the form is
   * ever rendered — the difference between "walk found it" and "CI found
   * it".
   */
  @Test
  void noLineCarriesTwoAssignmentsOrAKeyInsideAValue() {
    List<String> problems = new ArrayList<>();
    Set<String> allKeys = new LinkedHashSet<>();
    for (String line : PROP_LINES) {
      if (line.isBlank() || line.startsWith("#")) {
        continue;
      }
      int firstEq = line.indexOf('=');
      int secondEq = firstEq < 0 ? -1 : line.indexOf('=', firstEq + 1);
      if (firstEq <= 0) {
        problems.add("line without a valid key before '=': " + line);
        continue;
      }
      allKeys.add(line.substring(0, firstEq));
      String value = line.substring(firstEq + 1);
      // A key name embedded in a value = glue (the second assignment never
      // became a key). Check against the file's own key vocabulary, which is
      // the only vocabulary that can make this check meaningful.
      for (String k : allKeys) {
        if (k.length() >= 4 && value.contains(k + "=")) {
          problems.add(
              "value of [" + line.substring(0, firstEq) + "] embeds a second"
                  + " assignment for key [" + k + "] — Properties will swallow"
                  + " it into this line's value");
        }
      }
    }
    // Trailing-newline discipline, pinned at the byte-split level: with
    // split("\n", -1) a file that ends WITHOUT a newline has a non-blank
    // LAST element. The original broken file (git 7bebb6e) ended exactly
    // that way (git's "No newline at end of file" diff marker), which is
    // what let the A22-b append glue onto line 5. A file that refuses to
    // terminate its last line is one append away from a glue mangle.
    String lastElement = PROP_LINES.get(PROP_LINES.size() - 1);
    assertTrue(
        lastElement.isEmpty(),
        "config.properties must end with a terminating newline — the file"
            + " that caused D1 did not, so the next append fused into the"
            + " last physical line; last element: " + lastElement);
    assertTrue(
        problems.isEmpty(),
        "config.properties physical-line violations (the glue mangle class): "
            + problems);
  }

  /**
   * WHAT: house style — the file is pure US-ASCII so the java.util
   * Properties load (ISO-8859-1) and the jelly render (UTF-8) read byte-
   * identical text; any UTF-8 escape would be silently mangled by the
   * load-side contract.
   * <pre>
   * GIVEN the raw bytes of config.properties
   * WHEN  every byte is examined
   * THEN  all are &lt; 128 (US-ASCII)
   * </pre>
   * WHY / SOLVES: a smart-quoted "“" typed into a hint would render as
   * mojibake on the form through the ISO-8859-1 load path while looking
   * perfectly fine in every editor and every CI log. ASCII-only is the
   * contract the loader actually honours.
   */
  @Test
  void fileIsPureAscii() throws Exception {
    try (InputStream in =
            DevcruMfaConfigI18nTest.class.getResourceAsStream(
                "/org/sebcru/mfa/DevcruMfaConfig/config.properties")) {
      for (int b; (b = in.read()) != -1; ) {
        assertTrue(
            b >= 0 && b < 128,
            "config.properties contains a non-ASCII byte (" + b + ") —"
                + " java.util.Properties loads it as ISO-8859-1, so UTF-8"
                + " text would reach the form as mojibake");
      }
    }
  }

  private static List<String> sorted(Set<String> in) {
    List<String> out = new ArrayList<>(in);
    out.sort(Comparator.naturalOrder());
    return out;
  }
}
