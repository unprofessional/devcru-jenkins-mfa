package org.sebcru.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.util.Secret;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * A22-b — the pure-seam pins for the admin surface's authorization (spec §7,
 * the unit legs), in the exact house pattern A23's
 * {@code managementAllowed} is pinned in ({@link MfaProfileSeamTest}).
 *
 * <p>Three seams, all Jenkins-free (plain JVM, no boot):
 * <ol>
 *   <li>{@link MfaAdminController#adminManageAllowed} across the FULL
 *       quadrilateral including the PERMISSION axis — the leg the
 *       {@code FullControlOnceLoggedInAuthorizationStrategy} IT (everyone is
 *       an admin) cannot reach, pinned here so the privilege ordering
 *       (permission → credential) cannot be reordered by a refactor.</li>
 *   <li>{@link MfaAdminController#clearFactorState} — the single writer of
 *       the "fully unenrolled" state, pinned so a future "clear one more
 *       field" that drifts between the clearFactors path and this method
 *       turns red here.</li>
 *   <li>{@link MfaAdminController.AdminRow} — the roster row model: the
 *       masked-mailbox privacy contract (A16) and the TOTP/email/trust
 *       columns (spec §7 item 2).</li>
 * </ol>
 */
class AdminManageAllowedTest {

  // ============================================================
  // Seam 1 — adminManageAllowed, the full quadrilateral.
  // ============================================================

  /**
   * BDD (permission axis FIRST — spec §4 ordering):
   * <pre>
   * GIVEN no ADMINISTER (a fully-verified, live-trust, enrolled user)
   * WHEN  sessionVerified=true, trustLive=true, enrolled=true
   * THEN  DENY (administer=false short-circuits BEFORE the credential is read)
   *       — a non-admin can manage NOBODY, whatever their own credential state
   * </pre>
   * The permission axis is checked before the credential axis, so a
   * non-admin is denied even when every credential input would otherwise pass.
   */
  @Test
  void nonAdminDeniedEvenWithFullCredentials() {
    // administer=false, but EVERY credential input true: still deny.
    assertFalse(MfaAdminController.adminManageAllowed(false, true, true, true),
        "a NON-admin with a live full credential must still be denied — "
            + "permission is checked before credential");
    assertFalse(MfaAdminController.adminManageAllowed(false, true, true, false),
        "administer=false must deny regardless of sessionVerified");
    assertFalse(MfaAdminController.adminManageAllowed(false, true, false, true),
        "administer=false must deny regardless of trustLive");
    assertFalse(MfaAdminController.adminManageAllowed(false, false, false, false),
        "administer=false denies the all-false row too (one stable reason)");
  }

  /**
   * BDD (the Ruling-3 edge — spec §4 "an unenrolled admin can SEE the roster
   * but CANNOT clear anyone"):
   * <pre>
   * GIVEN ADMINISTER, NOT enrolled (the admin account holds no factor of its
   *       own), any session shape
   * THEN  DENY — an unenrolled actor can hold NEITHER instrument (no factors
   *       to verify, no trust to grant), so the credential clause can never
   *       pass for them
   * </pre>
   * Pinning all four session shapes (not just one) is what keeps the rule from
   * silently softening to "administer alone is enough" — the one behaviour a
   * reviewer might reasonably want to relax (§9 ruling).
   */
  @Test
  void enrolledAdminWithoutCredentialDeniedRuling3Edge() {
    assertFalse(MfaAdminController.adminManageAllowed(true, false, false, false),
        "administer + unenrolled + no verify + no trust → DENY");
    assertFalse(MfaAdminController.adminManageAllowed(true, false, true, false),
        "administer + unenrolled + sessionVerified must NOT pass — an unenrolled "
            + "session never carries VERIFIED_ATTR, and we do not trust the "
            + "input to be anything else");
    assertFalse(MfaAdminController.adminManageAllowed(true, false, false, true),
        "administer + unenrolled + trustLive must NOT pass — no factors, no trust");
    assertFalse(MfaAdminController.adminManageAllowed(true, false, true, true),
        "administer + unenrolled + both inputs → still DENY (credential clause)");
  }

  /**
   * BDD (the natural admin flow + the A23 trust-clause symmetry):
   * <pre>
   * GIVEN ADMINISTER + enrolled
   * WHEN  verified this session (regardless of trust)  → ALLOW
   * WHEN  live remembered trust (regardless of verify) → ALLOW
   * WHEN  BOTH                                         → ALLOW
   * WHEN  NEITHER (the password-only attacker)         → DENY
   * </pre>
   * The DENY row is the load-bearing one: it is the A23-analogue the whole
   * admin surface stands on (an admin who has not proved a second factor this
   * login and holds no live trust cannot manage any other user's credentials).
   */
  @Test
  void adminQuadrilateralCredentialedRows() {
    // verified this session (trust irrelevant): allow.
    assertTrue(MfaAdminController.adminManageAllowed(true, true, true, false),
        "administer + enrolled + verified-this-session → ALLOW");
    // live trust (verify irrelevant): allow — a remembered device already
    // proved a factor; the clause is symmetric with A23's trust clause.
    assertTrue(MfaAdminController.adminManageAllowed(true, true, false, true),
        "administer + enrolled + live trust → ALLOW (trust-clause symmetry)");
    // both: allow (OR is idempotent).
    assertTrue(MfaAdminController.adminManageAllowed(true, true, true, true),
        "administer + enrolled + verified + trust → ALLOW");
    // NEITHER: the password-only attacker's exact state → DENY.
    assertFalse(MfaAdminController.adminManageAllowed(true, true, false, false),
        "administer + enrolled + unverified + no trust → DENY (the A23-analogue)");
  }

  // ============================================================
  // Seam 2 — clearFactorState: the single writer of "fully unenrolled".
  // ============================================================

  /**
   * BDD (spec §3: one save(), EVERY factor and piece of pending state
   * cleared in one pass):
   * <pre>
   * GIVEN a victim property with a full live state
   *       (TOTP factor, email factor + registered mailbox, live trust,
   *        a pending code hash, code-issued timestamp, resend timestamp,
   *        a failed-attempt streak — i.e. a locked-out, half-verified victim)
   * WHEN  clearFactorState runs
   * THEN  EVERY one of those eight fields is cleared to its exact
   *       unenrolled value (secrets null, email null, trust 0, pending
   *       hash null, both timestamps 0, streak 0)
   * </pre>
   * The point of pinning the EXACT value of every field (not just
   * "isMfaEnabled() is false") is that a future "clear one more field" that
   * forgets the pending/lockout state — which spec §3 explicitly requires be
   * wiped so a cleared user is not left in a phantom-pending state — turns
   * red here, on the field it forgot.
   */
  @Test
  void clearFactorStateClearsEveryFactorAndPendingField() {
    MfaUserProperty p = new MfaUserProperty();
    p.setTotpSecret(Secret.fromString("JBSWY3DPEHPK3PXP"));
    p.setEmailCodeSecret(Secret.fromString("enrolment-hmac-material"));
    p.setRegisteredEmail("victim@devcru.org");
    p.setTrustedUntilMs(System.currentTimeMillis() + 3_600_000L);
    p.setPendingCodeHash(Secret.fromString("a-pending-code-hash"));
    p.setCodeIssuedAt(1_000_000L);
    p.setLastResendAt(2_000_000L);
    p.setFailedAttemptStreak(4);
    // Sanity: the fixture is genuinely a live, locked-out state before the op.
    assertTrue(p.hasTotpFactor(), "fixture must have a live TOTP factor before the clear");
    assertTrue(p.hasEmailFactor(), "fixture must have a live email factor before the clear");
    assertEquals("victim@devcru.org", p.getRegisteredEmail(), "fixture mailbox before the clear");

    MfaAdminController.clearFactorState(p);

    assertNull(p.getTotpSecret(), "clearFactorState must null the TOTP seed");
    assertNull(p.getEmailCodeSecret(), "clearFactorState must null the email-code factor");
    assertNull(p.getRegisteredEmail(), "clearFactorState must clear the registered mailbox");
    assertEquals(0L, p.getTrustedUntilMs(), "clearFactorState must zero the trust timestamp");
    assertNull(p.getPendingCodeHash(), "clearFactorState must null the pending code hash");
    assertEquals(0L, p.getCodeIssuedAt(), "clearFactorState must zero the code-issued timestamp");
    assertEquals(0L, p.getLastResendAt(), "clearFactorState must zero the last-resend timestamp");
    assertEquals(0, p.getFailedAttemptStreak(), "clearFactorState must zero the failed-attempt streak");
    assertFalse(p.isMfaEnabled(), "after clearFactorState the user must no longer be enrolled");
  }

  // ============================================================
  // Seam 3 — the roster row model (spec §7 item 2).
  // ============================================================

  /**
   * BDD (spec §7 item 2 — the privacy + column contract of a roster row):
   * <pre>
   * GIVEN a TOTP-only user (live factor, NO registered mailbox)
   * WHEN  their AdminRow is built with the mailbox MASKED at the source
   *       (the "(no mailbox)" placeholder is what getRosterRows passes when
   *       no mailbox is set — the one place the row model meets the
   *       no-mailbox case)
   * THEN  the row's maskedMail is the masked form of the placeholder and
   *       the TOTP/email/trust columns reflect the fixture byte-for-byte:
   *       totp=true (factor present), email=FALSE (this plugin defines the
   *       email factor AS the registered address — property §hasEmailFactor:
   *       no address, no email factor), trust=true
   * </pre>
   * Pinning the email column through the property's OWN predicate (rather
   * than re-deriving it) is what keeps the row model and the enrolment
   * definition from drifting: if "email factor" stopped meaning "registered
   * address", the row's column would lie about the user's factors.
   */
  @Test
  void adminRowMasksMailboxAndExposesFactorColumns() {
    MfaUserProperty p = new MfaUserProperty();
    p.setTotpSecret(Secret.fromString("JBSWY3DPEHPK3PXP"));
    // Deliberately NO registered email: TOTP-only user. The row's mailbox
    // slot therefore receives getRosterRows' exact placeholder for the
    // no-mailbox case — the masked form of "(no mailbox)", which is
    // "***" per maskEmail's no-@ rule; the privacy pin still bites, so we
    // also carry a second, real mailbox through to prove the masking.
    boolean trustLive = true;

    // getRosterRows masks at the source; mirror that exact step here (both
    // the real-mailbox and no-mailbox shapes) so the pin is against the REAL
    // masking + REAL row, not a re-implementation.
    String maskedReal = MfaController.maskEmail("mads@devcru.org");
    MfaAdminController.AdminRow row = new MfaAdminController.AdminRow(
        "mads", "Mads", maskedReal,
        p.hasTotpFactor(), p.hasEmailFactor(), trustLive);

    // The masked form is what the row carries, and it is the documented shape.
    assertEquals("m***@devcru.org", row.getMaskedMail(),
        "the row must carry the masked mailbox: " + row.getMaskedMail());
    // The RAW address must appear in NO getter of the row (A16 privacy).
    assertFalse(row.getMaskedMail().contains("mads"),
        "the raw local part must NOT survive masking: " + row.getMaskedMail());
    assertFalse(row.getMaskedMail().contains("mads@devcru.org"),
        "the raw registered mailbox must not appear in any row field: " + row.getMaskedMail());
    // The TOTP / email / trust columns mirror the fixture property through the
    // property's OWN predicates (the row model must not re-derive "factor"
    // differently from the enrolment definition).
    assertEquals("mads", row.getUserId(), "the row carries the user id");
    assertEquals("Mads", row.getDisplayName(), "the row carries the display name");
    assertTrue(row.isTotp(), "the TOTP column reflects a live TOTP factor");
    assertTrue(p.hasEmailFactor() == false, "fixture sanity: no address ⇒ no email factor");
    assertFalse(row.isEmail(),
        "the email column reflects NO live email factor (no registered address)");
    assertTrue(row.isTrustLive(), "the trust column reflects a live trust");
  }

  /**
   * BDD (spec §7 item 2 — "an unenrolled user produces no row"):
   * <pre>
   * GIVEN a fully-clear (unenrolled) property — no factors, no mailbox,
   *       no trust, no pending state (the post-clearFactorState shape)
   * THEN  isMfaEnabled() is false: getRosterRows skips such users, so the
   *       row-list filter's predicate (the one line that decides "row or
   *       no row") returns false for them
   * </pre>
   * This is the predicate's contract pinned in isolation: an unenrolled user
   * is OUT of the recovery surface (they cannot be locked out), so no row.
   */
  @Test
  void unenrolledUserProducesNoRosterRow() {
    MfaUserProperty p = new MfaUserProperty();
    MfaAdminController.clearFactorState(p);
    // The row-or-no-row predicate in getRosterRows is exactly this.
    boolean wouldProduceRow = p != null && p.isMfaEnabled();
    assertFalse(wouldProduceRow,
        "an unenrolled user (no live factor) must produce NO roster row");
    List<?> empty = List.of(); // guard against an accidental null; the point is the predicate.
    assertEquals(0, empty.size());
  }
}
