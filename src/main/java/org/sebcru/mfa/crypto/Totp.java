package org.sebcru.mfa.crypto;

import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base32;

/**
 * RFC 6238 TOTP. Pure JDK crypto. Time step 30s, 6 digits, HMAC-SHA1
 * (Authy / Google Authenticator / 1Password compatible).
 */
public final class Totp {
  public static final int STEP_SECONDS = 30;
  public static final int DIGITS = 6;
  private static final SecureRandom RANDOM = new SecureRandom();

  private Totp() {}

  /** New random Base32 secret (128 bits, unpadded). */
  public static String newBase32Secret() {
    byte[] b = new byte[16];
    RANDOM.nextBytes(b);
    return new Base32().encodeAsString(b).replace("=", "");
  }

  public static byte[] decodeSecret(String base32) {
    return new Base32().decode(base32.toUpperCase());
  }

  /** Core HOTP (RFC 4226): counter-based, 6 digits. */
  public static String codeFor(byte[] key, long counter) {
    byte[] msg = new byte[8];
    for (int i = 7; i >= 0; i--) { msg[i] = (byte) (counter & 0xff); counter >>= 8; }
    try {
      Mac mac = Mac.getInstance("HmacSHA1");
      mac.init(new SecretKeySpec(key, "HmacSHA1"));
      byte[] h = mac.doFinal(msg);
      int off = h[h.length - 1] & 0x0f;
      int bin = ((h[off] & 0x7f) << 24) | ((h[off + 1] & 0xff) << 16)
              | ((h[off + 2] & 0xff) << 8) | (h[off + 3] & 0xff);
      int mod = bin % (int) Math.pow(10, DIGITS);
      return String.format("%06d", mod);
    } catch (Exception e) {
      throw new IllegalStateException("HMAC-SHA1 unavailable", e);
    }
  }

  /** TOTP code at a specific instant (epoch millis). */
  public static String codeAt(byte[] key, long epochMillis) {
    return codeFor(key, epochMillis / 1000 / STEP_SECONDS);
  }

  /**
   * Verify with ±window step tolerance (clock skew). Constant-time compare
   * per candidate; returns true on first match.
   * Whitespace in the input is stripped (mobile keyboards love it).
   */
  public static boolean verify(byte[] key, String input, long epochMillis, int window) {
    if (input == null) return false;
    String cleaned = input.replaceAll("\\s+", "");
    if (cleaned.length() != DIGITS) return false;
    long step = epochMillis / 1000 / STEP_SECONDS;
    for (long c = step - window; c <= step + window; c++) {
      if (constEq(codeFor(key, c), cleaned)) return true;
    }
    return false;
  }

  /** Constant-time equality on the 6-digit strings. */
  private static boolean constEq(String a, String b) {
    return MessageDigest.isEqual(a.getBytes(), b.getBytes());
  }
}
