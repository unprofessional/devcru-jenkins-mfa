package org.sebcru.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.util.Secret;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.sebcru.mfa.crypto.Totp;

/**
 * TDD record for the Task 9 pure seams of {@link MfaController} — the
 * enrolment-path decisions (what the six profile-page endpoints decide
 * before they commit anything) extracted package-private static exactly so
 * they are pinable in a plain JVM with no running Jenkins, no HTTP, no clock
 * (the clock arrives as an explicit parameter, house style), and no zxing
 * PNG round-trip beyond its own decoder.
 *
 * <h2>What this file pins down</h2>
 * <ol>
 *   <li>{@code buildOtpauthUri} — the exact {@code otpauth://totp/…} URI an
 *       enrolment QR encodes. This string is the interop contract with every
 *       RFC 6238 authenticator (Authy, Google Authenticator, 1Password); a
 *       wrong scheme, missing parameter, or unencoded character is a "your
 *       QR does not work in any app" defect for the user.</li>
 *   <li>{@code qrDataUri} — the zxing render step: URI in,
 *       {@code data:image/png;base64,….} string out for the section's
 *       {@code <img>}. Pinning it as a pure seam means the controller's
 *       endpoint glue stays one line, the PNG shape is asserted here without
 *       a booted Jenkins, and a zxing failure is contractually "no image"
 *       (blank), never a partial render or a 500.</li>
 *   <li>{@code confirmEnrollDecision} — the single-POST enrolment commit
 *       decision: is the presented seed valid Base32 at all, does the code
 *       verify against it (±window), and does the property end up with the
 *       seed committed — or, on any failure, exactly unchanged.</li>
 * </ol>
 *
 * <h2>Red → green history</h2>
 * <p>The QR seam had no red to catch (zxing is stable third-party); the
 * value there is the PNG-shape + fail-closed contract pinned before the
 * endpoint glue existed. The confirm seam was written against the plan's
 * endpoint table (success = commit; {@code wrong_code} = not committed) as
 * the first draft of this file, and failed with a plain
 * {@code cannot find symbol: method confirmEnrollDecision} — the genuine
 * red against nothing. It was turned green by implementing the seam to the
 * plan's table; the IT ({@code MfaProfileIT}) re-proves it over the wire on
 * a booted Jenkins in the same commit.
 */
class MfaProfileSeamTest {

  // =====================================================================
  // buildOtpauthUri — the interop contract with every RFC 6238 app
  // =====================================================================

  /**
   * WHAT: buildOtpauthUri's canonical shape — scheme {@code otpauth},
   * type {@code otp}, label {@code <issuer>:<account>}, and the standard
   * {@code secret}/{@code issuer}/{@code algorithm}/{@code digits}/
   * {@code period} parameters in the canonical order the major apps parse.
   *
   * <p>BDD:
   * <pre>
   * GIVEN an issuer "devcru Jenkins", an account "mads", and a Base32
   *       secret "JBSWY3DPEHPK3PXP"
   * WHEN  the URI is built
   * THEN  it is exactly
   *       "otpauth://totp/devcru Jenkins:mads?secret=JBSWY3DPEHPK3PXP&issuer=devcru Jenkins&algorithm=SHA1&digits=6&period=30"
   *       (label and issuer space-encoded as %20 — the apps' parser expects)
   * AND   it carries no trailing garbage, no padding '=' from the secret
   *       (the plugin stores unpadded Base32), and no newline
   * </pre>
   *
   * <p>WHY/SOLVES: this exact string is what every authenticator app scans.
   * A regression that dropped a parameter (apps fall back to defaults —
   * SHA-512, 8 digits, 60 s — and the user's codes stop verifying with no
   * error anywhere in Jenkins), swapped the label format ({@code issuer:account}
   * is the RFC 4648/OTPAuth convention; a bare account label works too but
   * loses the multi-tenancy grouping), or failed to encode the space in the
   * issuer (a raw space in a query is rejected by strict parsers — the QR
   * becomes garbage) each produce "MFA enrolment never works" for the user.
   * The independent-oracle style here: the expected string is the canonical
   * form, not the implementation's output.
   */
  @Test
  void buildsCanonicalOtpauthUri() {
    assertEquals(
        "otpauth://totp/devcru%20Jenkins:mads?secret=JBSWY3DPEHPK3PXP"
            + "&issuer=devcru%20Jenkins&algorithm=SHA1&digits=6&period=30",
        MfaController.buildOtpauthUri("devcru Jenkins", "mads", "JBSWY3DPEHPK3PXP"));
  }

  /**
   * WHAT: buildOtpauthUri's encoding discipline — hostile/edge values
   * (ampersands, equals, plus signs, percent signs in issuer or account)
   * are percent-encoded so they cannot be parsed as URI structure by the
   * app scanning the QR.
   *
   * <p>BDD:
   * <pre>
   * GIVEN an issuer containing '&', '=', '%', ' ' and a plus, and an
   *       account containing the same set
   * WHEN  the URI is built
   * THEN  the label and the issuer parameter carry those characters
   *       percent-encoded (ampersand → %26 so it cannot inject a new
   *       parameter; '=' → %3D; '%' itself → %25 so it cannot spoof an
   *       escape sequence; space → %20; '+' → %2B — a raw '+' in a URI
   *       query decodes to a space)
   * AND   the 'algorithm' parameter is still present exactly once — i.e.
   *       none of those characters leaked out and created a second
   *       parameter named after part of the issuer
   * </pre>
   *
   * <p>WHY/SOLVES: the issuer is admin-configured, the account is derived
   * from the username — both are not user-chosen per QR, but both are
   * writable by someone with the corresponding privilege, and both reach an
   * external parser (the authenticator app) verbatim. Unpercented ampersand
   * or '=' would turn "issuer=a&secret=EVIL" into a QR whose decoded secret
   * differs from what the server enrolled — enrolment succeeds, then every
   * code fails. Encoding discipline is the cheapest guarantee that the
   * string the app sees IS the string we enrolled against.
   */
  @Test
  void encodesHostileLabelAndIssuerCharacters() {
    String uri = MfaController.buildOtpauthUri(
        "a&b=c%d+e f", "m%a+d&z=e", "JBSWY3DPEHPK3PXP");
    // Label: space → %20, & → %26, = → %3D, % → %25, + → %2B.
    assertTrue(uri.startsWith("otpauth://totp/a%26b%3Dc%25d%2Be%20f:m%25a%2Bd%26z%3De?"), uri);
    // The hostile issuer could not inject a parameter: exactly one secret=.
    assertEquals(1, uri.split("secret=", -1).length - 1, uri);
    assertEquals(1, uri.split("issuer=", -1).length - 1, uri);
    // Digits/period/algorithm are untouched fixed values.
    assertTrue(uri.endsWith("algorithm=SHA1&digits=6&period=30"), uri);
  }

  // =====================================================================
  // qrDataUri — the zxing render seam (URI in, <img> src out)
  // =====================================================================

  /**
   * WHAT: qrDataUri's happy path — a valid otpauth URI becomes a 300×300
   * QR PNG as a data URI the section's {@code <img>} can render directly,
   * and decoding the Base64 back through zxing recovers the EXACT original
   * URI (round trip, not just "some PNG").
   *
   * <p>BDD:
   * <pre>
   * GIVEN a canonical otpauth URI from buildOtpauthUri
   * WHEN  qrDataUri(uri) is called
   * THEN  the result starts with "data:image/png;base64,"
   * AND   the Base64 payload decodes to a byte array whose leading bytes
   *       are the PNG signature (89 50 4E 47 …)
   * AND   zxing's own MultiFormatReader decodes the PNG to EXACTLY the
   *       input URI string (round trip — a render that silently dropped
   *       characters would be a working QR for a different secret)
   * </pre>
   *
   * <p>WHY/SOLVES: the whole enrolment UX is "scan this". A PNG that is
   * valid-look but encodes a truncated URI would pass a "looks like an
   * image" check and still fail in every app; only the round-trip decode
   * pins that the image IS the URI. Keeping zxing inside this one seam also
   * means the endpoint cannot have a second, divergent render path (the
   * A2 "one mint seam" discipline applied to rendering).
   */
  @Test
  void rendersRoundTripping300x300QrPng() throws Exception {
    String uri = MfaController.buildOtpauthUri("devcru Jenkins", "mads", "JBSWY3DPEHPK3PXP");
    String dataUri = MfaController.qrDataUri(uri);
    assertNotNull(dataUri);
    assertTrue(dataUri.startsWith("data:image/png;base64,"),
        "the data URI must be a PNG for the <img> tag: " + dataUri.substring(0, 20));
    byte[] png = Base64.getDecoder().decode(dataUri.substring("data:image/png;base64,".length()));
    assertEquals((byte) 0x89, png[0], "PNG signature byte 1");
    assertEquals((byte) 0x50, png[1], "PNG signature byte 2");
    assertEquals((byte) 0x4E, png[2], "PNG signature byte 3");
    assertEquals((byte) 0x47, png[3], "PNG signature byte 4");
    String decoded = deQr(png);
    assertEquals(uri, decoded,
        "the QR must decode back to EXACTLY the URI that was encoded (round trip)");
  }

  /**
   * WHAT: qrDataUri's fail-closed contract — absent input (empty, null)
   * yields an <em>empty string</em> (the section then renders no image, and
   * the manual-entry path still works), never a partial PNG, never an
   * exception propagating into the endpoint.
   *
   * <p>(The first draft of this test also asserted that a 2000-char string
   * is unrenderable — that premise is false: 2000 bytes fit a 300×300 QR
   * at v24, and zxing renders it. The contract pins the blank-input branch
   * that the endpoint actually relies on, and the catch in {@code
   * qrDataUri} stays as the guard for a genuinely unencodable input.)
   *
   * <p>BDD:
   * <pre>
   * GIVEN the inputs "" and null
   * WHEN  qrDataUri is called with each
   * THEN  each returns "" (no image) — no exception escapes, no partial
   *       data URI
   * </pre>
   *
   * <p>WHY/SOLVES: the QR is a convenience; the manual-secret entry field
   * is the fallback. A zxing {@code WriterException} escaping into the
   * endpoint would 500 the whole enrolment POST for a one-off render
   * hiccup — the fallback is one line further down, and the 500 hides
   * both. Fail-to-blank keeps the POST answering JSON and the manual path
   * reachable.
   */
  @Test
  void returnsBlankForAbsentInput() {
    assertEquals("", MfaController.qrDataUri(""));
    assertEquals("", MfaController.qrDataUri(null));
  }

  // =====================================================================
  // confirmEnrollDecision — the single-POST enrolment commit decision
  // =====================================================================

  /**
   * WHAT: confirmEnrollDecision's success branch — a valid Base32 seed plus
   * a code that verifies against it (within the window) commits the seed to
   * the property, and the decision reports ok.
   *
   * <p>BDD:
   * <pre>
   * GIVEN a fresh MfaUserProperty (no factors), a fresh Base32 secret, and
   *       a window of ±1 step
   * WHEN  confirmEnrollDecision(p, secret, codeAt(now), now, 1) is called,
   *       where codeAt(now) is the correct TOTP for secret at instant now
   * THEN  the decision is ok (no error)
   * AND   the property now hasTotpFactor()
   * AND   the committed seed's plaintext is EXACTLY the presented seed
   *       (not uppercased-down-mangled: the canonical unpadded form is what
   *       buildOtpauthUri already put in the QR, so app and server agree)
   * </pre>
   *
   * <p>WHY/SOLVES: this is the enrolment's trust anchor — the seed only
   * reaches user-land storage (encrypted {@code Secret} on the property)
   * AFTER a correct code for THAT seed is presented in the same POST
   * (plan's single-POST commit; no pre-commit session state). A regression
   * that committed before verifying, or verified against a different seed
   * than it stored, would let a user (or a crafted profile submit) pin a
   * TOTP factor they cannot actually prove — MFA on, gate passing, factor
   * useless. The "committed == presented" assertion is the exact pin.
   */
  @Test
  void commitsSeedOnCorrectCode() {
    MfaUserProperty p = new MfaUserProperty();
    String seed = Totp.newBase32Secret();
    long now = 1_700_000_000_000L; // pinned instant: no wall-clock flake
    String code = Totp.codeAt(Totp.decodeSecret(seed), now);
    MfaController.EnrollDecision d =
        MfaController.confirmEnrollDecision(p, seed, code, now, 1);
    assertNull(d.error(), "a correct code must commit without error: " + d);
    assertTrue(p.hasTotpFactor(), "the seed is committed after the correct code");
    assertEquals(seed, p.getTotpSecret().getPlainText(),
        "the committed seed is the EXACT seed the QR encoded / the code proved");
  }

  /**
   * WHAT: confirmEnrollDecision's failure branches and the no-commit
   * guarantee — each bad shape reports its stable reason AND leaves the
   * property's TOTP factor exactly as it was (in particular: an
   * already-enrolled user's ACTUAL seed is never clobbered by a failed
   * confirm of a different seed).
   *
   * <p>BDD:
   * <pre>
   * GIVEN a fresh property, a valid base seed, a fixed instant, window 1
   * WHEN  the presented seed is "" / "!!!" / "AAA" (invalid Base32 chars)
   * THEN  the decision is error "invalid_seed" AND hasTotpFactor() is
   *       still false (nothing committed)
   * WHEN  the seed is valid but the code is a wrong 6-digit string
   * THEN  the decision is error "wrong_code" AND still not committed
   * WHEN  the property ALREADY has a different enrolled seed "JBSWY3DPEHPK3PXP"
   *       and a wrong code is presented for a new seed
   * THEN  the decision is error "wrong_code" AND the property's seed is
   *       still the ORIGINAL enrolled one (not the new one, not blank)
   * </pre>
   *
   * <p>WHY/SOLVES: the no-commit-on-failure half is the whole point of the
   * single-POST design — the seed arrives over a JSON field anyone with a
   * session cookie can set, and only a live code for that seed is the
   * credential that makes it safe to store. Clobbering an enrolled seed on
   * a failed confirm of a second (regenerated) candidate is a lost-authy
   * lockout for the user; storing a seed whose code was never proven is MFA
   * that gates nobody — both are exactly the failures this table exists to
   * refuse. The wrong_code-on-already-enrolled case is what protects
   * "regenerate then type a wrong code" from destroying the working factor.
   */
  @Test
  void refusesBadSeedsAndCodesWithoutCommitting() {
    long now = 1_700_000_000_000L;

    // ---- invalid seed shapes: nothing is ever committed.
    for (String badSeed : new String[] {"", "!!!", "AAA"}) {
      MfaUserProperty p = new MfaUserProperty();
      MfaController.EnrollDecision d =
          MfaController.confirmEnrollDecision(p, badSeed, "123456", now, 1);
      assertEquals(MfaController.ERR_INVALID_SEED, d.error(), "bad seed: " + badSeed);
      assertFalse(p.hasTotpFactor(), "no commit on an invalid seed: " + badSeed);
    }

    // ---- valid seed, wrong code: not committed.
    String seed = Totp.newBase32Secret();
    MfaUserProperty p2 = new MfaUserProperty();
    MfaController.EnrollDecision d2 =
        MfaController.confirmEnrollDecision(p2, seed, "000001", now, 1);
    assertEquals(VerifyOutcome.ERR_WRONG_CODE, d2.error(), "wrong code reports wrong_code");
    assertFalse(p2.hasTotpFactor(), "wrong code must not commit the seed");

    // ---- already enrolled: a failed confirm of a DIFFERENT seed must not
    //      touch the working one.
    String enrolled = "JBSWY3DPEHPK3PXP"; // the RFC 4648 test vector seed
    MfaUserProperty p3 = new MfaUserProperty();
    p3.setTotpSecret(Secret.fromString(enrolled));
    MfaController.EnrollDecision d3 =
        MfaController.confirmEnrollDecision(p3, seed, "000001", now, 1);
    assertEquals(VerifyOutcome.ERR_WRONG_CODE, d3.error());
    assertEquals(enrolled, p3.getTotpSecret().getPlainText(),
        "the enrolled seed survives a failed confirm of a different seed");
  }

  // =====================================================================
  // A23 — the management-authorization seam (pure; all four quadrants)
  // =====================================================================

  /**
   * WHAT: the A23 authorization decision for the six factor-management
   * endpoints, pinned as pure booleans across all four quadrants of
   * (enrolled × verified × trust). (TECH_DEBT A23, external review
   * 2026-08-19; the wire-level attack chain is pinned by MfaProfileIT case
   * e — this is the unit-level pin of the decision itself, so a refactor
   * cannot move a clause without a red here.)
   *
   * <p>BDD:
   * <pre>
   * GIVEN the three inputs to MfaController.managementAllowed
   * WHEN  enrolled=false (no factor at all, any session shape)
   * THEN  ALLOW — unenrolled users are passed by the gate and must keep
   *       self-enrolment access (their sessions never carry VERIFIED_ATTR,
   *       so requiring the flag would lock every fresh user out of the
   *       enrolment UI)
   * WHEN  enrolled + verified-this-session
   * THEN  ALLOW (the natural self-service flow: login → verify → manage) —
   *       regardless of trust state
   * WHEN  enrolled + verified-this-session + live trust
   * THEN  ALLOW (both instruments present; the OR is idempotent)
   * WHEN  enrolled + unverified + no live trust
   * THEN  DENY — the password-only attacker's exact state: the flag is set
   *       only by a postVerify success, trust only granted by a prior
   *       successful verify, and the attacker has neither
   * WHEN  enrolled + unverified + LIVE trust
   * THEN  ALLOW — a remembered-device login already proved a factor within
   *       the trust window; without this clause the guard breaks the
   *       legitimate disable/re-enrol flow from a remembered browser
   * </pre>
   *
   * <p>WHY/SOLVES: the gate's {@code /mfa} allow-list (needed for
   * postVerify) passes all six management endpoints to a pre-verify
   * session, so the gate is NOT the protection these endpoints rely on —
   * this decision is. Pinning all four quadrants (not just the deny) is
   * what keeps the fix from over-correcting into a self-inflicted lockout
   * of fresh users (unenrolled) or of trusted-device sessions. The
   * contract constant the deny answers with (verification_required) is
   * pinned in the same test below, and the stable 403 JSON shape is pinned
   * by the IT's wire assertions.
   */
  @Test
  void managementAuthorizationAllFourQuadrants() {
    // Unenrolled: always allow, regardless of session shape (fresh users
    // must keep self-enrolment; their sessions never carry the flag).
    assertTrue(MfaController.managementAllowed(false, false, false),
        "a fresh user must keep enrolment access (no flag, no trust)");
    assertTrue(MfaController.managementAllowed(false, true, false),
        "an unenrolled+verified session (e.g. right after a gate pass) may also manage");

    // Enrolled + verified this session: allow, with or without trust.
    assertTrue(MfaController.managementAllowed(true, true, false),
        "enrolled + verified-this-session → allow (the natural self-service flow)");
    assertTrue(MfaController.managementAllowed(true, true, true),
        "enrolled + verified + trust → allow (both instruments, OR is idempotent)");

    // Enrolled + unverified + no trust: DENY — the password-only attacker.
    assertFalse(MfaController.managementAllowed(true, false, false),
        "enrolled + unverified + no trust → deny (the A23 attack shape: the "
            + "password holder alone must not manage factors)");

    // Enrolled + unverified but live trust: allow — a remembered-device
    // login already proved a factor within the window.
    assertTrue(MfaController.managementAllowed(true, false, true),
        "enrolled + unverified + live remembered trust → allow (a trusted "
            + "device login already proved a factor; denying would break the "
            + "legitimate disable/re-enrol flow from a remembered browser)");

    // The stable error reason the deny answers with: the UI maps it to a
    // user-visible "complete verification first" message (config.jelly's
    // MESSAGES table), so the constant is part of the wire contract.
    assertEquals("verification_required", VerifyOutcome.ERR_VERIFICATION_REQUIRED,
        "the deny's stable error code is the UI-facing wire contract");
  }

  // ---- helper: decode a PNG back to its QR payload with zxing (the
  //      independent read-back the round-trip test needs). A 300x300 QR
  //      with version ~5-6 decodes cleanly with no special hints.
  private static String deQr(byte[] png) throws Exception {
    java.awt.image.BufferedImage img =
        javax.imageio.ImageIO.read(new java.io.ByteArrayInputStream(png));
    com.google.zxing.common.HybridBinarizer hb = new com.google.zxing.common.HybridBinarizer(
        new com.google.zxing.client.j2se.BufferedImageLuminanceSource(img));
    com.google.zxing.BinaryBitmap bmp = new com.google.zxing.BinaryBitmap(hb);
    com.google.zxing.Result r = new com.google.zxing.MultiFormatReader().decode(bmp);
    return r.getText();
  }
}
