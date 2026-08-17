package org.sebcru.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.sebcru.mfa.crypto.Totp;

class TotpTest {
  /** RFC 4226/6238 test key: ASCII "12345678901234567890". */
  private static final byte[] RFC_KEY = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);

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
