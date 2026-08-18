package org.sebcru.mfa.email;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.sebcru.mfa.MfaUserProperty;

/**
 * Unit tests for {@link EmailCodeIssuer} — hashed, single-use, TTL-bound
 * email one-time codes.
 *
 * <h2>What this file pins down</h2>
 * <ul>
 *   <li>Code material: 8 chars from the unambiguous alphabet, two draws
 *       differ, codes never land in stored state (only their hash does).</li>
 *   <li>The stored-value chain: deterministic per (code, per-user key),
 *       independent of key, base64-stable, case-insensitive on verify.</li>
 *   <li>Single-use: a consumed code is dead, including identical resubmit;
 *       wrong codes don't consume.</li>
 *   <li>TTL: valid strictly inside the window, EXPIRED just past it, and an
 *       expired pending code cannot be "rescued" by re-verifying.</li>
 *   <li>Resend: cooldown blocks (state untouched), then replaces — exactly
 *       one code live at a time.</li>
 *   <li>Fail-closed on null/absent state: never throws, returns a
 *       structured negative result the controller can map to messaging.</li>
 * </ul>
 *
 * <h2>Why no Jenkins harness</h2>
 * <p>{@code MfaUserProperty} is a plain record outside of a Jenkins VM and
 * {@link hudson.util.Secret} is constructible without the master key (XStream
 * encryption only happens on {@code save()}). The issuer is pure crypto +
 * record mutation, so the whole contract is testable synchronously against a
 * pinned clock — no wall-clock flake, no mail round trip (a recording
 * {@link EmailSender} double stands in).
 *
 * <h2>Red → green note</h2>
 * <p>One red on first run, recorded honestly per AGENTS.md: the alphabet
 * test asserted membership with {@code ALPHABET.contains(code)} — substring
 * semantics, so it rejected every generated code. The code under test was
 * innocent; the assertion was. Fixed to per-character {@code indexOf}
 * checks; the rest of the suite (single-use, TTL, cooldown, hashed storage)
 * was green on first run. Its defensive value is pinning the
 * consume-before-return and cooldown semantics <em>before</em> Task 6 wires
 * them to the login endpoint, where a replayable code would be exploitable,
 * not merely flaky.
 */
class EmailCodeIssuerTest {

  private static final String KEY = "test-per-user-hmac-key";
  private static final String EMAIL = "mads@devcru.org";
  private static final long NOW = 1_700_000_000_000L;
  private static final long TTL_S = 300;
  private static final long COOLDOWN_S = 60;

  /** Recording double: captures exactly what would land in the mailbox. */
  private static final class RecordingSender implements EmailSender {
    final List<String> codes = new ArrayList<>();
    final List<String> to = new ArrayList<>();
    boolean threw = false;

    @Override
    public void send(String to, String code, long ttlSeconds) {
      this.to.add(to);
      this.codes.add(code);
    }
  }

  private static MfaUserProperty enrolled() {
    MfaUserProperty p = new MfaUserProperty();
    p.setRegisteredEmail(EMAIL);
    return p;
  }

  /**
   * WHAT: the code is human-deliverable and unpredictable in shape.
   * BDD:
   * GIVEN a fresh issuer
   * WHEN  a code is generated
   * THEN  it is 8 chars, every char from the unambiguous alphabet
   *       (A–Z0–9 minus 0 O 1 I), uppercase, and two consecutive draws differ
   * WHY/SOLVES: the code is typed/transcribed by a human from an email;
   *       ambiguous glyph pairs (0/O, 1/I) would turn into wrong-code
   *       failures the user blames on MFA, not their own eyes. Different
   *       draws per call confirms real entropy, not a constant.
   */
  @Test
  void codesAreEightCharsFromUnambiguousAlphabet() {
    EmailCodeIssuer issuer = new EmailCodeIssuer();
    for (int i = 0; i < 50; i++) {
      String code = issuer.newCode();
      assertEquals(8, code.length());
      for (int j = 0; j < code.length(); j++) {
        assertTrue(
            EmailCodeIssuer.CODE_ALPHABET.indexOf(code.charAt(j)) >= 0,
            "code " + code + " has non-alphabet char at " + j);
      }
    }
    assertNotEquals(issuer.newCode(), issuer.newCode());
  }

  /**
   * WHAT: issuance is atomic — stored hash + clocks + exactly one mail.
   * BDD:
   * GIVEN an email-enrolled user
   * WHEN  issue() runs at a pinned instant
   * THEN  the plaintext code returned is the one handed to the sender,
   *       addressed to the registered mailbox,
   *       the stored value is the code's hash (not the code itself),
   *       and issued-at / resend-at are pinned to the given instant
   * WHY/SOLVES: proves confidentiality-at-rest by construction — the
   *       stored value must differ from the plaintext and equal
   *       {@code hashOf(code, key)}. If the plaintext ever leaked into
   *       state, a stolen config.xml would hand an attacker a live code.
   */
  @Test
  void issueStoresHashNotPlainAndSendsExactlyOnce() {
    MfaUserProperty user = enrolled();
    RecordingSender sender = new RecordingSender();
    String code = new EmailCodeIssuer().issue(user, KEY, NOW, TTL_S, sender);

    assertEquals(1, sender.to.size());
    assertEquals(EMAIL, sender.to.get(0));
    assertEquals(code, sender.codes.get(0));
    assertNotNull(user.getPendingCodeHash());
    assertNotEquals(code, user.getPendingCodeHash().getPlainText());
    assertEquals(EmailCodeIssuer.hashOf(code, KEY).getPlainText(),
        user.getPendingCodeHash().getPlainText());
    assertEquals(NOW, user.getCodeIssuedAt());
    assertEquals(NOW, user.getLastResendAt());
  }

  /**
   * WHAT: the stored hash is a proper MAC-of-hash chain.
   * BDD:
   * GIVEN a code and two different per-user keys
   * WHEN  hashOf() is applied
   * THEN  the result is deterministic for the same (code, key) pair,
   *       differs across keys, and is stable base64
   * WHY/SOLVES: per-user keying means a breach of one user's state never
   *       validates against another's (no cross-user code reuse), and
   *       determinism is what makes "recompute and compare" verification
   *       possible at all.
   */
  @Test
  void hashIsDeterministicPerKeyAndDiffersAcrossKeys() {
    String code = "ABC123DE";
    String key2 = "another-per-user-hmac-key";
    assertEquals(EmailCodeIssuer.hashOf(code, KEY).getPlainText(),
        EmailCodeIssuer.hashOf(code, KEY).getPlainText());
    assertNotEquals(EmailCodeIssuer.hashOf(code, KEY).getPlainText(),
        EmailCodeIssuer.hashOf(code, key2).getPlainText());
    // base64 of a 32-byte sha256 digest → 44 chars, no whitespace
    String stored = EmailCodeIssuer.hashOf(code, KEY).getPlainText();
    assertEquals(44, stored.length());
    assertFalse(stored.contains(" "));
  }

  /**
   * WHAT: the happy verify path consumes exactly once.
   * BDD:
   * GIVEN a user with one live code at NOW
   * WHEN  verify() receives the correct code at NOW+5s
   * THEN  CONSUMED is returned and the pending state is cleared
   * WHEN  the identical code is submitted again
   * THEN  NO_PENDING — the code is dead, even for its owner
   * WHY/SOLVES: single-use is the whole point — a code sitting in an
   *       already-sent email (spoofed reply, mailbox shared with the
   *       family, a browser back-button resubmit) must be worthless the
   *       moment it's used.
   */
  @Test
  void verifyConsumesExactlyOnce() {
    MfaUserProperty user = enrolled();
    EmailCodeIssuer issuer = new EmailCodeIssuer();
    String code = issuer.issue(user, KEY, NOW, TTL_S, new RecordingSender());

    assertEquals(EmailCodeIssuer.VerifyResult.CONSUMED,
        issuer.verify(user, KEY, code, NOW + 5_000, TTL_S));
    assertNull(user.getPendingCodeHash());
    assertEquals(0L, user.getCodeIssuedAt());

    assertEquals(EmailCodeIssuer.VerifyResult.NO_PENDING,
        issuer.verify(user, KEY, code, NOW + 6_000, TTL_S));
  }

  /**
   * WHAT: case insensitivity of comparison.
   * BDD:
   * GIVEN a live code
   * WHEN  verify() receives it lower-cased
   * THEN  CONSUMED — the user's device/phone/copy-paste may normalize case
   * WHY/SOLVES: codes arrive via email clients that may fold case, voice
   *       readback, or manual re-entry. Matching over hashed normalized
   *       forms adds no extra timing surface (the comparison is always
   *       constant-time over the fixed-length digest).
   */
  @Test
  void verifyIsCaseInsensitive() {
    MfaUserProperty user = enrolled();
    EmailCodeIssuer issuer = new EmailCodeIssuer();
    String code = issuer.issue(user, KEY, NOW, TTL_S, new RecordingSender());

    assertEquals(EmailCodeIssuer.VerifyResult.CONSUMED,
        issuer.verify(user, KEY, code.toLowerCase(), NOW + 5_000, TTL_S));
  }

  /**
   * WHAT: a wrong code is rejected without consuming the live one.
   * BDD:
   * GIVEN a live code
   * WHEN  verify() receives a different 8-char code
   * THEN  WRONG_CODE, and the correct code still verifies CONSUMED next
   * WHEN  verify() receives short/garbage/null inputs
   * THEN  a structured negative (WRONG_CODE or NO_PENDING), never a throw
   * WHY/SOLVES: rejecting-without-consuming is what lets the user retry
   *       with the real code — and it's the counter the Task 4 RateLimiter
   *       will increment toward lockout. Total-over-strings guarantees the
   *       Task 6 endpoint never 500s on hostile input.
   */
  @Test
  void wrongCodeDoesNotConsumeAndMalformedFailsClosed() {
    MfaUserProperty user = enrolled();
    EmailCodeIssuer issuer = new EmailCodeIssuer();
    String code = issuer.issue(user, KEY, NOW, TTL_S, new RecordingSender());
    String wrong = "ZZZZZ999".equals(code) ? "ZZZZZ998" : "ZZZZZ999";

    assertEquals(EmailCodeIssuer.VerifyResult.WRONG_CODE,
        issuer.verify(user, KEY, wrong, NOW + 5_000, TTL_S));
    assertNotNull(user.getPendingCodeHash(), "live code must survive a wrong attempt");

    assertEquals(EmailCodeIssuer.VerifyResult.WRONG_CODE,
        issuer.verify(user, KEY, "1234", NOW + 5_000, TTL_S));
    assertEquals(EmailCodeIssuer.VerifyResult.NO_PENDING,
        issuer.verify(user, KEY, null, NOW + 5_000, TTL_S));

    // the live code is still good
    assertEquals(EmailCodeIssuer.VerifyResult.CONSUMED,
        issuer.verify(user, KEY, code, NOW + 5_000, TTL_S));
  }

  /**
   * WHAT: TTL boundary behaviour.
   * BDD:
   * GIVEN a code issued at NOW with a 300 s TTL
   * WHEN  verify() runs at NOW+300 s (inclusive boundary)
   * THEN  CONSUMED
   * WHEN  a second code is issued and verify() runs at NOW+300.001 s
   * THEN  EXPIRED, and the pending state is invalidated — re-verifying the
   *       same expired code yields NO_PENDING, not a late CONSUMED
   * WHY/SOLVES: expired codes are not "old but valid" — the pending state
   *       is cleared so a replayed stale email is worthless, and recovery
   *       is exactly one resend (cooldown permitting), not a retry.
   */
  @Test
  void ttlIsEnforcedAndExpiredStateIsCleared() {
    MfaUserProperty user = enrolled();
    EmailCodeIssuer issuer = new EmailCodeIssuer();
    String code = issuer.issue(user, KEY, NOW, TTL_S, new RecordingSender());

    // just inside the window
    assertEquals(EmailCodeIssuer.VerifyResult.CONSUMED,
        issuer.verify(user, KEY, code, NOW + 300_000, TTL_S));

    // fresh code, just past the window
    String code2 = issuer.issue(user, KEY, NOW, TTL_S, new RecordingSender());
    assertEquals(EmailCodeIssuer.VerifyResult.EXPIRED,
        issuer.verify(user, KEY, code2, NOW + 300_001, TTL_S));
    assertNull(user.getPendingCodeHash());

    // the expired code cannot be resurrected
    assertEquals(EmailCodeIssuer.VerifyResult.NO_PENDING,
        issuer.verify(user, KEY, code2, NOW + 400_000, TTL_S));
  }

  /**
   * WHAT: the resend cooldown and replacement semantics.
   * BDD:
   * GIVEN a user with a code issued at NOW
   * WHEN  resend() is called at NOW+30 s with a 60 s cooldown
   * THEN  it returns null, sends nothing, and touches no state
   * WHEN  resend() is called at NOW+60 s
   * THEN  a new code is issued and sent; the old code is dead (its hash
   *       was overwritten) and the new one verifies
   * WHY/SOLVES: the cooldown bounds how fast anyone who just got in can
   *       mail-bomb the registered inbox; single-live-code means a
   *       "resend" click on the login page can never leave two valid
   *       accept paths in play.
   */
  @Test
  void resendRespectsCooldownThenReplacesOldCode() {
    MfaUserProperty user = enrolled();
    EmailCodeIssuer issuer = new EmailCodeIssuer();
    RecordingSender sender = new RecordingSender();
    String code1 = issuer.issue(user, KEY, NOW, TTL_S, sender);

    // inside the cooldown
    assertNull(issuer.resend(user, KEY, NOW + 30_000, COOLDOWN_S, TTL_S, sender));
    assertEquals(1, sender.codes.size(), "no mail during cooldown");
    assertEquals(NOW, user.getLastResendAt(), "state untouched during cooldown");

    // after the cooldown: replaced, old dead, new live
    String code2 = issuer.resend(user, KEY, NOW + 60_000, COOLDOWN_S, TTL_S, sender);
    assertNotNull(code2);
    assertNotEquals(code1, code2);
    assertEquals(2, sender.codes.size());

    assertEquals(EmailCodeIssuer.VerifyResult.WRONG_CODE,
        issuer.verify(user, KEY, code1, NOW + 61_000, TTL_S));
    assertEquals(EmailCodeIssuer.VerifyResult.CONSUMED,
        issuer.verify(user, KEY, code2, NOW + 61_000, TTL_S));
  }

  /**
   * WHAT: fail-closed on missing state.
   * BDD:
   * GIVEN a user who never enrolled an email factor (or never had a code
   *       issued)
   * WHEN  verify() is called with a plausible 8-char code
   * THEN  NO_PENDING — no throw, no crash, structured negative
   * WHY/SOLVES: the Task 6 endpoint will call verify on the email path
   *       before checking much else; this keeps a never-enrolled (or
   *       never-sent-to) state from surfacing as a 500, and gives the
   *       controller a distinct reason to say "request a new code"
   *       instead of "wrong code".
   */
  @Test
  void verifyWithNoPendingStateFailsClosed() {
    MfaUserProperty user = enrolled();
    EmailCodeIssuer issuer = new EmailCodeIssuer();
    assertEquals(EmailCodeIssuer.VerifyResult.NO_PENDING,
        issuer.verify(user, KEY, "ABC123DE", NOW, TTL_S));
    // even for a fully blank user
    assertEquals(EmailCodeIssuer.VerifyResult.NO_PENDING,
        new EmailCodeIssuer().verify(new MfaUserProperty(), KEY, "ABC123DE", NOW, TTL_S));
  }
}
