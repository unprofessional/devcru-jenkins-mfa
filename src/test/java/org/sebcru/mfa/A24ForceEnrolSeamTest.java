package org.sebcru.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.util.Secret;
import org.junit.jupiter.api.Test;
import org.sebcru.mfa.MfaAdminController.ForceEnrolAction;
import org.sebcru.mfa.MfaAdminController.ForceEnrolDecision;
import org.sebcru.mfa.MfaAdminController.RolloutState;

/**
 * A24 — the pure seams of the force-enrol feature, pinned in a plain JVM
 * before any boot: the rollout-state classification behind the three roster
 * views (spec §3), the force-enrol TARGET-STATE decision table (spec §4.1/§4.3,
 * rulings D1/D5/D12/D14), the write applier's "obligation never proof"
 * guarantee, the D8 rollback semantics of clearFactors, and the D6
 * account-state labelling.
 *
 * <h2>What this file pins down</h2>
 * <ol>
 *   <li>A setup-pending user is NEVER miscounted as completed merely because
 *       the forced email makes {@code isMfaEnabled()} true (spec §7 criterion 2).</li>
 *   <li>The first-time signal is the persisted marker ALONE — a default/TOTP
 *       {@code lastVerifiedFactor} and expired trust cannot impersonate or
 *       suppress it (spec §7 criterion 3).</li>
 *   <li>Every deny is decided BEFORE any mutation: {@code decideForceEnrol}
 *       is pure and {@code applyForceEnrol} writes only mailbox + marker.</li>
 *   <li>Denials carry the stable error strings the IT and UI map on:
 *       {@code already_enrolled}, {@code invalid_email}, …</li>
 * </ol>
 */
class A24ForceEnrolSeamTest {

  // ------------------------------------------------------------------
  // Rollout-state classification (the roster view model)
  // ------------------------------------------------------------------

  /**
   * WHAT: the rollout classifier over a null property, a fresh property, an
   * ordinarily enrolled user, a forced-setup-pending user.
   *
   * <p>BDD:
   * <pre>
   * GIVEN no property at all (never-touched user)
   * WHEN  classified            THEN NOT_ENROLLED
   * GIVEN a fresh property with no factors and no marker
   * WHEN  classified            THEN NOT_ENROLLED
   * GIVEN a self-enrolled TOTP user (no marker)
   * WHEN  classified            THEN ENROLLED
   * GIVEN a forced email enrolment (marker set, email factor live)
   * WHEN  classified            THEN SETUP_PENDING — NOT ENROLLED, even though
   *                                   isMfaEnabled() is true
   * </pre>
   *
   * <p>WHY/SOLVES: spec §7 criterion 2. The forced email flips
   * {@code isMfaEnabled()}, so a naive "enrolled = enabled" read would move
   * the user off the worklist before they ever verified — the pending
   * population would silently vanish from every view. The marker outranks
   * factor presence; each user lands in exactly one view.
   */
  @Test
  void rolloutStatePutsEachUserInExactlyOneView() {
    assertEquals(RolloutState.NOT_ENROLLED, MfaAdminController.rolloutState(null));
    assertEquals(RolloutState.NOT_ENROLLED,
        MfaAdminController.rolloutState(new MfaUserProperty()));

    MfaUserProperty totp = new MfaUserProperty();
    totp.setTotpSecret(Secret.fromString("JBSWY3DPEHPK3PXP"));
    assertTrue(totp.isMfaEnabled());
    assertEquals(RolloutState.ENROLLED, MfaAdminController.rolloutState(totp));

    MfaUserProperty pending = new MfaUserProperty();
    pending.setRegisteredEmail("victim@example.com");
    pending.setForcedSetupPending(true);
    assertTrue(pending.isMfaEnabled(), "forced email makes isMfaEnabled true");
    assertEquals(RolloutState.SETUP_PENDING, MfaAdminController.rolloutState(pending));
  }

  /**
   * WHAT: the first-time-setup signal is the persisted marker alone.
   *
   * <p>BDD:
   * <pre>
   * GIVEN a brand-new property (Java defaults)
   * THEN  forcedSetupPending is false AND lastVerifiedFactor is 0 — proving
   *       the two states are independently encoded, so a default/TOTP-valued
   *       lastVerifiedFactor can neither impersonate nor suppress the marker
   * GIVEN expired trust (trustedUntilMs in the past) and no marker
   * THEN  nothing about the marker changed — expired trust is not "never verified"
   * </pre>
   *
   * <p>WHY/SOLVES: spec §6/§10-D10. The obvious-but-wrong design inferred
   * "first time" from {@code lastVerifiedFactor == 0}; that field defaults to
   * 0 (= TOTP) for users who verified by TOTP years ago only if it were never
   * written — but worse, its default is indistinguishable from a real prior
   * TOTP verification record of factor 0, and expired trust likewise does not
   * mean "never verified". The explicit marker is the honest signal, so the
   * default-value separation here is load-bearing, not incidental.
   */
  @Test
  void firstTimeSignalIsTheMarkerAloneNotLastVerifiedFactorOrTrust() {
    MfaUserProperty p = new MfaUserProperty();
    assertFalse(p.isForcedSetupPending(), "fresh property carries no marker");
    assertEquals(0L, p.getLastVerifiedFactor(), "default factor value is 0");
    p.setTrustedUntilMs(System.currentTimeMillis() - 1000); // expired trust
    assertFalse(p.isForcedSetupPending(),
        "expired trust must not create or clear the marker");
  }

  // ------------------------------------------------------------------
  // The force-enrol target-state decision (deny-before-mutation)
  // ------------------------------------------------------------------

  /**
   * WHAT: the decision table's DENY arms.
   *
   * <p>BDD:
   * <pre>
   * GIVEN any target state and a blank / null / malformed mailbox
   * THEN  DENY invalid_email — blank would silently un-enrol via the setter,
   *       which is clearFactors' single-writer job, not this verb's
   * GIVEN an ordinarily enrolled target (live factor, NO marker)
   * WHEN  a valid mailbox is submitted THEN DENY already_enrolled
   * </pre>
   *
   * <p>WHY/SOLVES: the stable error strings are contract (UI maps them, ITs
   * assert them). {@code already_enrolled} keeps force-enrol from ever
   * clobbering a self-service enrolment the user proved themselves; the
   * invalid_email arm keeps the verb from becoming an un-enrolment oracle.
   */
  @Test
  void decideForceEnrolDeniesInvalidMailboxAndAlreadyEnrolled() {
    ForceEnrolDecision blank =
        MfaAdminController.decideForceEnrol(new MfaUserProperty(), "   ");
    assertEquals(ForceEnrolAction.DENY, blank.action);
    assertEquals(VerifyOutcome.ERR_INVALID_EMAIL, blank.error);

    ForceEnrolDecision malformed =
        MfaAdminController.decideForceEnrol(null, "not-an-address");
    assertEquals(ForceEnrolAction.DENY, malformed.action);
    assertEquals(VerifyOutcome.ERR_INVALID_EMAIL, malformed.error);

    MfaUserProperty enrolled = new MfaUserProperty();
    enrolled.setTotpSecret(Secret.fromString("JBSWY3DPEHPK3PXP"));
    ForceEnrolDecision d =
        MfaAdminController.decideForceEnrol(enrolled, "victim@example.com");
    assertEquals(ForceEnrolAction.DENY, d.action);
    assertEquals(VerifyOutcome.ERR_ALREADY_ENROLLED, d.error);
  }

  /**
   * WHAT: the D5 idempotence + correction arms for an already-pending target.
   *
   * <p>BDD:
   * <pre>
   * GIVEN a setup-pending target registered at victim@example.com
   * WHEN  force-enrolled again with "victim@example.com" (same box, any case)
   * THEN  UNCHANGED — no second write, no second candidate minted
   * WHEN  force-enrolled with corrected@example.com
   * THEN  CORRECT carrying the new address
   * </pre>
   *
   * <p>WHY/SOLVES: ruling D5. Fixing an admin typo must neither require
   * clearFactors first (which would strip the obligation entirely) nor leave
   * the old mailbox's pending code live — the CORRECT action exists so the
   * applier can replace the address and invalidate old-code state in one save.
   */
  @Test
  void decideForceEnrolIdempotentOnSameMailboxCorrectsDifferentOne() {
    MfaUserProperty pending = new MfaUserProperty();
    pending.setRegisteredEmail("victim@example.com");
    pending.setForcedSetupPending(true);

    ForceEnrolDecision same =
        MfaAdminController.decideForceEnrol(pending, "Victim@Example.com");
    assertEquals(ForceEnrolAction.UNCHANGED, same.action);
    assertNull(same.error);

    ForceEnrolDecision corrected =
        MfaAdminController.decideForceEnrol(pending, "corrected@example.com");
    assertEquals(ForceEnrolAction.CORRECT, corrected.action);
    assertEquals("corrected@example.com", corrected.email);
    assertNull(corrected.error);
  }

  /**
   * WHAT: the ENROL arm for a never-enrolled target (including the null-
   * property shape most untouched users have).
   *
   * <p>BDD:
   * <pre>
   * GIVEN a null property or a fresh empty property
   * WHEN  a valid mailbox is submitted
   * THEN  ENROL carrying the trimmed mailbox, no error
   * </pre>
   *
   * <p>WHY/SOLVES: D14 — absent-property records are exactly the population
   * the complement exists to act on; the decision must not demand a
   * pre-existing property (and must not create one either — creating stays in
   * the endpoint glue, after every denial).
   */
  @Test
  void decideForceEnrolEnrollsNeverEnrolledTarget() {
    ForceEnrolDecision fromNull =
        MfaAdminController.decideForceEnrol(null, "  new@example.com ");
    assertEquals(ForceEnrolAction.ENROL, fromNull.action);
    assertEquals("new@example.com", fromNull.email);

    ForceEnrolDecision fromFresh =
        MfaAdminController.decideForceEnrol(new MfaUserProperty(), "new@example.com");
    assertEquals(ForceEnrolAction.ENROL, fromFresh.action);
  }

  // ------------------------------------------------------------------
  // The applier: obligation, never proof
  // ------------------------------------------------------------------

  /**
   * WHAT: applyForceEnrol(ENROL) writes ONLY the mailbox and the marker.
   *
   * <p>BDD:
   * <pre>
   * GIVEN a fresh property
   * WHEN  the ENROL decision is applied
   * THEN  registeredEmail = mailbox, forcedSetupPending = true, and
   *       totpSecret / trustedUntilMs / pendingCodeHash /
   *       codeIssuedAt / lastVerifiedFactor are all UNTOUCHED defaults
   * </pre>
   *
   * <p>WHY/SOLVES: the load-bearing security line (spec §4.1): force-enrol
   * creates an OBLIGATION to verify and can never create a PROOF of
   * verification. If this applier ever wrote a secret, trust, or a verified
   * marker, the admin's action would read as "the admin vouched for this
   * session" — the exact conflation the whole feature exists to refuse.
   */
  @Test
  void applyEnrolWritesOnlyMailboxAndMarkerNeverSecretOrTrust() {
    MfaUserProperty p = new MfaUserProperty();
    MfaAdminController.applyForceEnrol(p,
        MfaAdminController.decideForceEnrol(null, "victim@example.com"));
    assertEquals("victim@example.com", p.getRegisteredEmail());
    assertTrue(p.isForcedSetupPending());
    assertNull(p.getTotpSecret());
    assertNull(p.getEmailCodeSecret());
    assertEquals(0L, p.getTrustedUntilMs());
    assertNull(p.getPendingCodeHash());
    assertEquals(0L, p.getCodeIssuedAt());
    assertEquals(0L, p.getLastResendAt());
    assertEquals(0L, p.getLastVerifiedFactor());
  }

  /**
   * WHAT: applyForceEnrol(CORRECT) replaces the address, invalidates the old
   * mailbox's pending-code state, and KEEPS the marker.
   *
   * <p>BDD:
   * <pre>
   * GIVEN a setup-pending property with a live pending code issued for the
   *       OLD mailbox
   * WHEN  the CORRECT decision is applied
   * THEN  registeredEmail is the NEW mailbox, pendingCodeHash/codeIssuedAt/
   *       lastResendAt are cleared, forcedSetupPending stays TRUE, and no
   *       secret/trust field moved
   * </pre>
   *
   * <p>WHY/SOLVES: D5's rationale verbatim — fixing a typo must not leave an
   * old-address code able to complete setup, and must not drop the obligation
   * (a cleared marker would let the user straight into Jenkins unverified).
   */
  @Test
  void applyCorrectionReplacesAddressKillsOldCodeKeepsMarker() {
    MfaUserProperty p = new MfaUserProperty();
    p.setRegisteredEmail("old@example.com");
    p.setForcedSetupPending(true);
    p.setPendingCodeHash(Secret.fromString("deadbeefdeadbeef"));
    p.setCodeIssuedAt(123L);
    p.setLastResendAt(456L);

    MfaAdminController.applyForceEnrol(p,
        MfaAdminController.decideForceEnrol(p, "new@example.com"));
    assertEquals("new@example.com", p.getRegisteredEmail());
    assertTrue(p.isForcedSetupPending(), "correction keeps the obligation live");
    assertNull(p.getPendingCodeHash(), "old-address code state invalidated");
    assertEquals(0L, p.getCodeIssuedAt());
    assertEquals(0L, p.getLastResendAt());
    assertEquals(0L, p.getTrustedUntilMs());
    assertNull(p.getTotpSecret());
  }

  // ------------------------------------------------------------------
  // D8 rollback + D6 account labels + mailbox syntax seam
  // ------------------------------------------------------------------

  /**
   * WHAT: clearFactors also clears the forced-setup marker (D8 rollback).
   *
   * <p>BDD:
   * <pre>
   * GIVEN a forced-setup-pending property with an email factor and a pending code
   * WHEN  clearFactorState runs
   * THEN  forcedSetupPending is FALSE along with every factor/pending field —
   *       the per-user off switch removes the obligation with the factor
   * </pre>
   *
   * <p>WHY/SOLVES: D8's per-user rollback ruling. If clearFactors left the
   * marker set, a cleared user under REQUIRED would sit at the gate forever
   * with no factor to verify against — an unrecoverable lockout manufactured
   * by the recovery verb itself.
   */
  @Test
  void clearFactorsAlsoClearsTheForcedSetupMarker() {
    MfaUserProperty p = new MfaUserProperty();
    p.setRegisteredEmail("victim@example.com");
    p.setForcedSetupPending(true);
    p.setPendingCodeHash(Secret.fromString("deadbeefdeadbeef"));
    MfaAdminController.clearFactorState(p);
    assertFalse(p.isForcedSetupPending());
    assertNull(p.getRegisteredEmail());
    assertNull(p.getPendingCodeHash());
    assertFalse(p.isMfaEnabled());
  }

  /**
   * WHAT: the account-state label mapping (D6).
   *
   * <p>BDD:
   * <pre>
   * GIVEN a positively-enabled realm signal  THEN "active"
   * GIVEN a positively-disabled signal       THEN "disabled"
   * GIVEN an unresolvable signal (null)      THEN "unknown" — never guessed active
   * </pre>
   *
   * <p>WHY/SOLVES: D6's honesty rule. An unknown realm status rendered as
   * "active" would let an operator force-enrol a stranded/disabled account
   * believing the label blessed it; "unknown" forces the human decision.
   */
  @Test
  void accountStateLabelsAreHonestAboutUnknown() {
    assertEquals("active", MfaAdminController.accountState(Boolean.TRUE));
    assertEquals("disabled", MfaAdminController.accountState(Boolean.FALSE));
    assertEquals("unknown", MfaAdminController.accountState(null));
  }

  /**
   * WHAT: the endpoint-contract mailbox validator.
   *
   * <p>BDD:
   * <pre>
   * GIVEN "victim@example.com"          THEN valid
   * GIVEN null, "", "   ", "noat",      THEN invalid
   *       "a@b" (no dot), "a b@c.d", "a@b c.d"
   * </pre>
   *
   * <p>WHY/SOLVES: the property setter normalizes blank to null but validates
   * nothing (spec §4.3) — without this seam the verb would happily persist
   * garbage the mailer then cannot deliver, and the user would be gated with
   * no reachable code. Ownership is still proved only by delivered-code
   * verification; this check is syntax-only, deliberately.
   */
  @Test
  void mailboxValidationIsSyntaxOnly() {
    assertTrue(MfaAdminController.isValidEmail("victim@example.com"));
    assertFalse(MfaAdminController.isValidEmail(null));
    assertFalse(MfaAdminController.isValidEmail(""));
    assertFalse(MfaAdminController.isValidEmail("   "));
    assertFalse(MfaAdminController.isValidEmail("noat"));
    assertFalse(MfaAdminController.isValidEmail("a@b"));
    assertFalse(MfaAdminController.isValidEmail("a b@c.d"));
    assertFalse(MfaAdminController.isValidEmail("a@b c.d"));
  }
}
