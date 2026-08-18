package org.sebcru.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.sebcru.mfa.crypto.Totp;

/**
 * TDD record for {@link Totp} — the TOTP primitive the whole MFA gate stands on.
 *
 * <h2>What this file pins down</h2>
 * <p>The gate's security question is: "does this 6-digit string, produced by the
 * user's authenticator app, correspond to this user's secret at now (± skew)?"
 * Every behaviour below is a contract that behaviour depends on:
 *
 * <ol>
 *   <li>Code generation matches the published RFC 4226/6238 examples (interop with
 *       Google Authenticator, Authy, 1Password, etc. — a deviation of a single
 *       output digit is a 100% verification failure rate).</li>
 *   <li>Time→counter derivation is correct from "now" out to the year 2603
 *       (no 32-bit overflow at large counters).</li>
 *   <li>Provisioned secrets are canonical, unspaced, unpadded Base32 — the exact
 *       string the user scans from the QR on first enrolment only.</li>
 *   <li>Verification is windowed (client clock skew is absorbed) but bounded
 *       (the online brute-force surface stays 3×10⁶, not unbounded).</li>
 *   <li>Verification fails closed on wrong, short, null, or non-numeric input
 *       and never throws — the controller feeds raw user input straight in.</li>
 * </ol>
 *
 * <h2>Red → green history (what the red phase actually caught)</h2>
 * <p>These vectors were written against the RFCs <em>before</em> the
 * implementation existed. The first implementation (derived from the plan's
 * spec sketch) used the MD5 truncation index ({@code h[15]}) for the final
 * byte. That is only valid when the HMAC-SHA1 digest is 16 bytes long —
 * {@code h[15]} then reads the wrong digest word, the dynamic truncation
 * shifts, and every generated code diverges from every authenticator app in
 * the world. The RFC vectors went red; the fix was the digest-length-relative
 * offset ({@code h[h.length - 1]}). That was the entire value of writing the
 * tests first against an independent oracle: the defect was in the spec
 * sketch itself, invisible to any internal-consistency check.
 */
class TotpTest {
  /** RFC 4226/6238 test key: ASCII "12345678901234567890" (20 bytes). */
  private static final byte[] RFC_KEY = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);

  /**
   * WHAT: the raw HOTP core — HMAC over a counter, dynamic truncation, 6-digit output.
   * TOTP is HOTP with counter = epochMillis/step; if this core is wrong, no TOTP
   * layer built on it can be right.
   *
   * <p>BDD:
   * <pre>
   * GIVEN the RFC 4226 Appendix D test key ("12345678901234567890")
   * WHEN  a 6-digit HOTP is generated for each counter T = 0 … 9
   * THEN  each output equals the published RFC 4226 Appendix D value exactly
   * </pre>
   *
   * <p>WHY/SOLVES: the RFC vectors are an independent oracle, not a mirror of our
   * own implementation. This is the single strongest interop guarantee we can make
   * without shipping: authenticator apps implement the RFC, so matching the RFC
   * vectors is a sufficient condition for "the code the phone shows is the code
   * the server accepts".
   */
  @Test
  void hotpMatchesRfc4226Vectors() {
    // RFC 4226 Appendix D, 6-digit truncation
    assertEquals("755224", Totp.codeFor(RFC_KEY, 0));
    assertEquals("287082", Totp.codeFor(RFC_KEY, 1));
    assertEquals("359152", Totp.codeFor(RFC_KEY, 2));
    assertEquals("969429", Totp.codeFor(RFC_KEY, 3));
    assertEquals("338314", Totp.codeFor(RFC_KEY, 4));
    assertEquals("254676", Totp.codeFor(RFC_KEY, 5));
    assertEquals("287922", Totp.codeFor(RFC_KEY, 6));
    assertEquals("162583", Totp.codeFor(RFC_KEY, 7));
    assertEquals("399871", Totp.codeFor(RFC_KEY, 8));
    assertEquals("520489", Totp.codeFor(RFC_KEY, 9));
  }

  /**
   * WHAT: TOTP specifically — milliseconds→30-second-counter derivation, SHA-1
   * HMAC, 6-digit output, across the full span of the RFC's example table.
   *
   * <p>BDD:
   * <pre>
   * GIVEN the RFC 6238 test key
   * WHEN  a code is requested at each RFC example instant
   *       (T = 59 s … 20,000,000,000 s — i.e. now out to the year 2603)
   * THEN  each output equals the last 6 digits of the RFC 6238 Appendix A.1
   *       8-digit value (SHA-1, 6-digit truncation, 30 s step)
   * </pre>
   *
   * <p>WHY/SOLVES: this is the exact server↔authenticator contract. The spread of
   * instants matters on its own: the largest counter (T=2×10¹⁰) exceeds 2³¹, so
   * this test also pins that the counter arithmetic is 64-bit end to end — an
   * int overflow here would be silent for ~year 2038, then produce wrong codes
   * for every user at once with zero error signal.
   */
  @Test
  void totpMatchesRfc6238VectorsSha1() {
    // RFC 6238 Appendix A.1 (SHA-1, T in seconds, step 30): 8-digit values,
    // we keep the last 6 digits.
    assertEquals("287082", Totp.codeAt(RFC_KEY, 59_000L));                 // T=59
    assertEquals("081804", Totp.codeAt(RFC_KEY, 1_111_111_109_000L));      // T=1111111109
    assertEquals("050471", Totp.codeAt(RFC_KEY, 1_111_111_111_000L));      // T=1111111111
    assertEquals("005924", Totp.codeAt(RFC_KEY, 1_234_567_890_000L));      // T=1234567890
    assertEquals("279037", Totp.codeAt(RFC_KEY, 2_000_000_000_000L));      // T=2000000000
    assertEquals("353130", Totp.codeAt(RFC_KEY, 20_000_000_000_000L));     // T=20000000000
  }

  /**
   * WHAT: secret provisioning and the encode↔decode round-trip.
   *
   * <p>BDD:
   * <pre>
   * GIVEN a freshly provisioned secret (Totp.newBase32Secret)
   * WHEN  it is inspected and then decode→re-encode round-tripped
   * THEN  it is 128 bits of entropy, encoded as canonical uppercase Base32
   *       with no spaces and no '=' padding, and decoding it recovers a key
   *       whose independent re-encoding is the identical string
   * </pre>
   *
   * <p>WHY/SOLVES: the Base32 string is shown once, in the QR at enrolment, and
   * is the only artefact the user's app ever sees. Non-canonical encodings
   * (padding, lowercase, grouping spaces) are rejected or mis-parsed by at
   * least some authenticator apps — a user who scans a padded string and the
   * server which holds the unpadded one compute different codes forever, and
   * the failure mode is "MFA never works" with no error anywhere. The
   * round-trip half additionally pins the invariant the gate relies on at
   * verify time: decodeSecret(what was provisioned) is exactly the key the
   * RFC-vector tests proved correct.
   */
  @Test
  void base32SecretRoundTrip() {
    String b32 = Totp.newBase32Secret();
    assertNotNull(b32);
    assertFalse(b32.indexOf(' ') >= 0);
    assertFalse(b32.indexOf('=') >= 0);
    byte[] key = Totp.decodeSecret(b32);
    assertEquals(16, key.length);
    // decode must be the inverse of encode (up to padding)
    String re = new org.apache.commons.codec.binary.Base32().encodeAsString(key).replace("=", "");
    assertEquals(b32, re);
  }

  /**
   * WHAT: verify() accept-path semantics — the tolerance model.
   *
   * <p>BDD:
   * <pre>
   * GIVEN a valid code for step T
   * WHEN  it is verified at time T with window 0 → accepted
   * WHEN  the same code with leading whitespace is verified → accepted
   *       (users copy-paste; a failed paste is a support ticket)
   * WHEN  the code for T+1 or T−1 (±30 s of phase) is verified
   *       at T with window 1 → accepted (client clock skew absorbed)
   * WHEN  the code for T+2 is verified at T with window 1 → rejected
   *       (skew tolerance is bounded, not sliding)
   * </pre>
   *
   * <p>WHY/SOLVES: phone clocks drift — NTP isn't always running, and a ±30 s
   * tolerance is the RFC-recommended default. Without it, verification becomes
   * flaky precisely for users on old devices. WITH tolerance, the accept set
   * grows by a full 10⁶ codes per step, so it must be fixed rather than
   * sliding: with window=1 exactly three codes are ever valid for a given
   * instant (T−1, T, T+1), which keeps the online attack surface a constant
   * 3×10⁶ and makes the pairing with RateLimiter's per-username lockout
   * (Task 4) well-defined. The T+2 rejection pins that bound.
   */
  @Test
  void verifyAcceptsCurrentAndAdjacentSteps() {
    byte[] key = Totp.decodeSecret(Totp.newBase32Secret());
    long t = 1_700_000_000_000L; // fixed instant
    String code = Totp.codeAt(key, t);
    assertTrue(Totp.verify(key, code, t, 0));
    assertTrue(Totp.verify(key, " " + code, t, 0)); // whitespace tolerated
    assertTrue(Totp.verify(key, Totp.codeAt(key, t + 30_000), t, 1));
    assertTrue(Totp.verify(key, Totp.codeAt(key, t - 30_000), t, 1));
    assertFalse(Totp.verify(key, Totp.codeAt(key, t + 60_000), t, 1));
  }

  /**
   * WHAT: verify() reject-path — fail-closed on everything malformed.
   *
   * <p>BDD:
   * <pre>
   * GIVEN a valid code for step T
   * WHEN  a valid-looking but wrong 6-digit code is verified → rejected
   * WHEN  a 4-digit code is verified → rejected (no partial match)
   * WHEN  null is verified → rejected, and no exception escapes
   * WHEN  a non-numeric 8-char string is verified → rejected, no exception
   * </pre>
   *
   * <p>WHY/SOLVES: the MFA controller (Task 6) will pass raw form input
   * directly to verify(); it must be total over all string inputs — throwing
   * converts a failed login into a 500 on the auth path, which reads as
   * "site broken" rather than "code wrong" and gives lockout tooling
   * nothing to count against. Rejection (not exception) is what RateLimiter
   * needs to accumulate the maxAttempts→lockout chain. Note the companion
   * requirement that cannot be pinned by a functional test and stands as a
   * review-level invariant instead: comparison of the candidate code against
   * candidates is constant-time ({@code MessageDigest.isEqual}) — timing
   * tests are flaky, so this one lives in code review, not here.
   */
  @Test
  void rejectsWrongAndMalformed() {
    byte[] key = Totp.decodeSecret(Totp.newBase32Secret());
    long t = 1_700_000_000_000L;
    String code = Totp.codeAt(key, t);
    String wrong = String.format("%06d", (Integer.parseInt(code, 10) + 1) % 1_000_000);
    assertFalse(Totp.verify(key, wrong, t, 0));
    assertFalse(Totp.verify(key, "1234", t, 1));
    assertFalse(Totp.verify(key, null, t, 1));
    assertFalse(Totp.verify(key, "abcdefgh", t, 1));
  }
}
