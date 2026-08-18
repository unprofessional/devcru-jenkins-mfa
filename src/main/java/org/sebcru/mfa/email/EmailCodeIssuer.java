package org.sebcru.mfa.email;

import hudson.util.Secret;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.sebcru.mfa.MfaUserProperty;

/**
 * Issues, stores, and verifies email one-time codes.
 *
 * <h2>Confidentiality model</h2>
 * <p>The plaintext code exists only in three places: the return value of
 * {@link #issue}/{@link #resend} (handed to the {@link EmailSender} exactly
 * once), the rendered mail body, and — during {@link #verify} — a local
 * variable that is dropped at method end. What is persisted in
 * {@link MfaUserProperty} is {@code sha256(HmacSHA256(code, perUserCodeSecret))},
 * so a stolen {@code config.xml} (or filesystem access) yields no usable
 * codes, and two users' states cannot be correlated through code material.
 * The per-user HMAC key is itself a Jenkins {@link Secret}, encrypted at
 * rest with the master key.
 *
 * <h2>Code alphabet</h2>
 * <p>8 chars from {@code A–Z0–9} minus {@code 0 O 1 I}: no ambiguous glyph
 * pairs, no case confusion, and — because the code goes into a human
 * email — no characters a tired user must disambiguate. 32⁸ ≈ 1.1×10¹²
 * candidates; with a 5-minute TTL and the gate's per-user lockout, offline
 * or online brute force is not a realistic path.
 *
 * <h2>Single-use and expiry</h2>
 * <p>A pending code is valid iff its stored hash constant-time-matches the
 * attempt's hash AND it is within TTL. On success the pending state is
 * cleared <em>before</em> returning, so the code cannot be replayed —
 * including replay by the same user a second time, and including any
 * in-flight duplicate (Jenkins is single-threaded per request pipeline,
 * but a retried POST must not double-consume). Case-insensitive matching
 * means a user pasting a lowercase code (or a phone auto-capitalization
 * glitch) still matches; the comparison is over the hashed forms, so this
 * adds no timing signal.
 *
 * <h2>Resend cooldown</h2>
 * <p>{@link #resend} refuses while {@code now − lastResendAt < cooldown} —
 * this throttles mail-bombing a victim's inbox (the code is emailed to the
 * account's registered address, not the attacker's; the cooldown bounds
 * how fast an attacker who just brute-forced a password can flood it).
 * After the cooldown, a fresh code replaces the old one: the old hash is
 * overwritten, so only one code can ever be live at a time per user.
 *
 * <h2>Testability</h2>
 * <p>{@link #nowMs(Secret, ...)} / the {@code nowMs} parameter on
 * {@link #verify} and {@link #resend} take an explicit instant so the test
 * suite pins TTL and cooldown behaviour against fixed clocks, with no
 * wall-clock flake. Production callers pass {@code System.currentTimeMillis()}.
 */
public final class EmailCodeIssuer {

  /** A–Z0–9 minus 0 O 1 I. Order is fixed; the tests depend on it. */
  public static final String CODE_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

  public static final int CODE_LENGTH = 8;
  private static final String HMAC_ALGO = "HmacSHA256";

  private final SecureRandom random;

  public EmailCodeIssuer() {
    this.random = new SecureRandom();
  }

  /**
   * Generate a one-time code.
   *
   * @return CODE_LENGTH characters drawn from {@link #CODE_ALPHABET}; the
   *         only place the plaintext exists is this return value and (later)
   *         the mail body.
   */
  public String newCode() {
    StringBuilder sb = new StringBuilder(CODE_LENGTH);
    for (int i = 0; i < CODE_LENGTH; i++) {
      sb.append(CODE_ALPHABET.charAt(random.nextInt(CODE_ALPHABET.length())));
    }
    return sb.toString();
  }

  /**
   * Store the HMAC of an already-generated code (see class doc for the
   * hash chain). Factored out from {@link #issue} so the tests can pin the
   * stored-value construction independently of generation.
   */
  public static Secret hashOf(String code, String perUserCodeSecret) {
    byte[] mac = hmac(code, perUserCodeSecret);
    byte[] digest = sha256(mac);
    byte[] b64 = java.util.Base64.getEncoder().encode(digest);
    return Secret.fromString(new String(b64, StandardCharsets.US_ASCII));
  }

  /**
   * Issue a fresh code: generate, store its hash + issued-at + resend-at,
   * then hand the plaintext to the sender. Exactly one code is live per
   * user afterwards — a prior live code (if any) is invalidated by
   * overwrite.
   *
   * @return the plaintext code that {@code sender} received.
   */
  public String issue(MfaUserProperty user, String perUserCodeSecret, long nowMs, long ttlSeconds, EmailSender sender) {
    String code = newCode();
    user.setPendingCodeHash(hashOf(code, perUserCodeSecret));
    user.setCodeIssuedAt(nowMs);
    user.setLastResendAt(nowMs);
    sender.send(user.getRegisteredEmail(), code, ttlSeconds);
    return code;
  }

  /** Result of {@link #verify}: the decision and a stable machine reason. */
  public enum VerifyResult {
    /** Code hash matched, within TTL; pending state has been consumed. */
    CONSUMED,
    /** No code is currently pending (never issued, or already consumed). */
    NO_PENDING,
    /** Submitted hash does not match the pending hash. */
    WRONG_CODE,
    /** Pending code exists and matched, but TTL has elapsed. */
    EXPIRED
  }

  /**
   * Verify a submitted code against the user's pending state.
   *
   * <p>Ordering note: the hash comparison happens before the TTL check,
   * so an attacker observing only accept/reject gets no distinction
   * between "wrong code while one is pending" and "expired code" beyond
   * the final boolean — both surface to the UI as a failed attempt, and
   * the RateLimiter (Task 4) is what converts repeated failures into a
   * lockout. The fine-grained {@link VerifyResult} returned here is for
   * the controller's messaging, not for an external oracle.
   *
   * <p><b>On {@link VerifyResult#CONSUMED}, the pending state is cleared
   * on the user property before this returns</b>; a second call with the
   * same code returns {@link VerifyResult#NO_PENDING}.
   */
  public VerifyResult verify(MfaUserProperty user, String perUserCodeSecret, String submitted, long nowMs, long ttlSeconds) {
    Secret stored = user.getPendingCodeHash();
    if (stored == null || submitted == null) {
      return VerifyResult.NO_PENDING;
    }
    // Codes are generated uppercase; the submitted form may not be.
    // Locale.ROOT: ASCII-only alphabet, immune to locale quirks (Turkish i, etc.).
    Secret candidate = hashOf(submitted.toUpperCase(java.util.Locale.ROOT), perUserCodeSecret);
    if (MessageDigest.isEqual(
        stored.getPlainText().getBytes(StandardCharsets.US_ASCII),
        candidate.getPlainText().getBytes(StandardCharsets.US_ASCII))) {
      // Matched. Check TTL before consuming the match.
      long issuedAt = user.getCodeIssuedAt();
      if (issuedAt > 0 && nowMs - issuedAt > ttlSeconds * 1000L) {
        // Expired: keep the state (a resend is the recovery) but reject.
        user.setPendingCodeHash(null);
        user.setCodeIssuedAt(0L);
        return VerifyResult.EXPIRED;
      }
      user.setPendingCodeHash(null);
      user.setCodeIssuedAt(0L);
      return VerifyResult.CONSUMED;
    }
    return VerifyResult.WRONG_CODE;
  }

  /**
   * Resend (i.e. re-issue) a code for {@code user}.
   *
   * @param nowMs      the current instant (tests pin this).
   * @param cooldownSeconds seconds since {@code lastResendAt} required before
   *                        a re-issue is permitted.
   * @param ttlSeconds TTL the new code will carry (recorded for the mail
   *                   body; enforcement is in {@link #verify}).
   * @param sender delivery boundary.
   * @return the new plaintext code, or {@code null} if the cooldown has not
   *         elapsed. A blocked resend does not touch user state.
   */
  public String resend(MfaUserProperty user, String perUserCodeSecret, long nowMs, long cooldownSeconds, long ttlSeconds, EmailSender sender) {
    long last = user.getLastResendAt();
    if (last > 0 && nowMs - last < cooldownSeconds * 1000L) {
      return null;
    }
    return issue(user, perUserCodeSecret, nowMs, ttlSeconds, sender);
  }

  // ---- crypto primitives (pure, package-static for reuse/tests) ----

  private static byte[] hmac(String code, String perUserCodeSecret) {
    try {
      Mac mac = Mac.getInstance(HMAC_ALGO);
      mac.init(new SecretKeySpec(perUserCodeSecret.getBytes(StandardCharsets.UTF_8), HMAC_ALGO));
      return mac.doFinal(code.getBytes(StandardCharsets.UTF_8));
    } catch (java.security.GeneralSecurityException e) {
      // HmacSHA256 is mandatory in every JRE; unreachable.
      throw new IllegalStateException("HmacSHA256 unavailable", e);
    }
  }

  private static byte[] sha256(byte[] input) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(input);
    } catch (java.security.NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }
}
