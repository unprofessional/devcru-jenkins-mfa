package org.sebcru.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

/**
 * WHAT (TDD intent, per AGENTS.md):
 *   {@link DevcruMfaConfig} is the admin surface for the gate. Task 5 turns the
 *   Task 4 POJO into a Jenkins {@code GlobalConfiguration}. This suite pins the
 *   values that <em>every</em> other task relies on, so a later edit to a field
 *   name, default, or the {@code Policy} enum cannot silently drift the gate's
 *   behaviour without a loud red.
 *
 * <p>The concrete {@code GlobalConfiguration}/{@code descriptor} wiring
 * (persistence, {@code @Symbol}, the config.jelly round-trip) is exercised in
 * the Task 8 in-JVM integration test, where a real Jenkins boots. What is
 * testable in a plain JVM — and what the gate and its unit tests depend on — is
 * the <em>shape and defaults</em> of the POJO itself, which is what this file
 * covers.
 *
 * <h2>Red → green note</h2>
 * <p>Red by design on first run: at the time this file was written,
 * {@code DevcruMfaConfig} still carried only the six Task 4 fields and the
 * four Task 5 UI-only fields (issuer/totpWindow/emailTtl/resendCooldown/
 * exemptUsers) did not exist, so this file did not compile. That is the TDD
 * red — the missing fields. Green is reached by adding them.
 *
 * WHY/SOLVES:
 * <ul>
 *   <li>The plan's §defaults table is mads-signed; re-litigating a default here
 *       (e.g. "what's the trust floor?") would change the security contract.
 *       Pinning the defaults as assertions means a future "helpful" edit is
 *       caught at the boundary, not in production.</li>
 *   <li>The {@code trustMinHours} floor is a named mads requirement ("never
 *       below 24h"). Pinning it as a literal default prevents a regression
 *       where the floor is lowered, removed, or made configurable without
 *       review.</li>
 *   <li>{@code Policy} values are checked by the Task 7 filter by name. Renaming
 *       {@code REQUIRED} would break the filter; the test catches the rename
 *       at the compile boundary.</li>
 * </ul>
 */
class DevcruMfaConfigTest {

  // ---------------------------------------------------------------------
  // Defaults — the plan's §defaults table, pinned verbatim.
  // ---------------------------------------------------------------------

  /**
   * WHAT: a freshly-constructed config carries the plan's defaults.
   * BDD:
   * GIVEN a brand-new DevcruMfaConfig()
   * WHEN  every getter is read
   * THEN  each returns the plan's documented default
   * WHY/SOLVES: the gate and the unit tests (TrustStore, RateLimiter,
   *   EmailCodeIssuer) all call these getters. A default that drifts here
   *   (e.g. trustMinHours lowered from 24 to 1) silently weakens the
   *   24h trust floor that mads signed. This test is the boundary that
   *   catches that drift.
   */
  @Test
  void defaultsMatchThePlanTable() {
    DevcruMfaConfig c = new DevcruMfaConfig();

    assertEquals(DevcruMfaConfig.Policy.REQUIRED, c.getPolicy(),
        "policy defaults to REQUIRED (MFA mandatory once enrolled; unenrolled not hard-locked)");
    assertEquals(720, c.getRememberForHours(),
        "remember-for defaults to 720h = 30 days (the plan's documented default)");
    assertEquals(24, c.getTrustMinHours(),
        "trust floor is 24h — mads's named requirement, never below");
    assertEquals(5, c.getMaxAttempts(),
        "5 wrong codes per window trips the lockout (the plan's rate-limit default)");
    assertEquals(30, c.getAttemptWindowMinutes(),
        "30-minute sliding window for failures (the plan's rate-limit default)");
    assertEquals(15, c.getLockoutMinutes(),
        "15-minute lockout after maxAttempts (the plan's rate-limit default)");
    assertEquals("devcru Jenkins", c.getIssuer(),
        "issuer shown in authenticator apps is 'devcru Jenkins' (the plan's default)");
    assertEquals(1, c.getTotpWindow(),
        "±1 time-step TOTP tolerance covers a ~30s-skewed clock (the plan's default)");
    assertEquals(300, c.getEmailCodeTtlSeconds(),
        "email codes valid for 300s = 5 minutes (the plan's default)");
    assertEquals(60, c.getEmailResendCooldownSeconds(),
        "resend throttled to once per 60s (the plan's default)");
    assertEquals("", c.getExemptUsers(),
        "no users exempt by default (empty list)");
  }

  /**
   * WHAT: the Policy enum is exactly {OFF, REQUIRED} — no AUDIT/optional mode.
   * BDD:
   * GIVEN the Policy enum
   * WHEN  its values are enumerated
   * THEN  they are exactly OFF and REQUIRED, in that order
   * WHY/SOLVES: the Task 7 filter switches on Policy.OFF (kill switch) and
   *   treats anything else as "gate active". A third value (e.g. AUDIT)
   *   would need an explicit review decision, which this test forces by
   *   failing the moment a new value is added.
   */
  @Test
  void policyEnumIsExactlyOffAndRequired() {
    DevcruMfaConfig.Policy[] values = DevcruMfaConfig.Policy.values();
    assertEquals(2, values.length, "exactly two policy values");
    assertEquals(DevcruMfaConfig.Policy.OFF, values[0]);
    assertEquals(DevcruMfaConfig.Policy.REQUIRED, values[1]);
  }

  /**
   * WHAT: the 24h trust floor is non-negotiable in the default config.
   * BDD:
   * GIVEN the default config
   * WHEN  trustMinHours is read
   * THEN  it is 24, and is the MINIMUM (not a suggestion) — i.e. any value
   *       an admin sets below 24 is a regression this test's sibling
   *       (TrustStoreTest) would catch at the clamp, and this test catches
   *       at the default source
   * WHY/SOLVES: this is the single most load-bearing default in the plugin.
   *   mads's requirement is "never below 24h". Pinning the default here, and
   *   the clamp in TrustStoreTest, gives two independent boundaries against
   *   the same regression: a lowered default (caught here) vs. a bypassed
   *   clamp (caught there).
   */
  @Test
  void trustFloorDefaultsToTwentyFourHours() {
    DevcruMfaConfig c = new DevcruMfaConfig();
    assertEquals(24, c.getTrustMinHours());
    assertTrue(c.getTrustMinHours() >= 1, "floor is at least 1h and the default is 24h");
  }

  /**
   * WHAT: setters round-trip (get-after-set returns what was set).
   * BDD:
   * GIVEN a new config
   * WHEN  each field is set to a distinct non-default value and read back
   * THEN  the read value equals the written value
   * WHY/SOLVES: this exercises the field-setter pairing that {@code
   *   req.bindJSON} relies on in Task 5's configure(). A missing or
   *   misspelled setter would make bindJSON silently drop a value — the
   *   admin saves a value, it doesn't persist, and the gate runs on the
   *   default. This test catches the pairing mismatch.
   */
  @Test
  void settersRoundTrip() {
    DevcruMfaConfig c = new DevcruMfaConfig();
    c.setPolicy(DevcruMfaConfig.Policy.OFF);
    c.setRememberForHours(48);
    c.setTrustMinHours(48);
    c.setMaxAttempts(3);
    c.setAttemptWindowMinutes(10);
    c.setLockoutMinutes(5);
    c.setIssuer("Custom Issuer");
    c.setTotpWindow(2);
    c.setEmailCodeTtlSeconds(600);
    c.setEmailResendCooldownSeconds(120);
    c.setExemptUsers("svc-ci\nsvc-deploy");

    assertEquals(DevcruMfaConfig.Policy.OFF, c.getPolicy());
    assertEquals(48, c.getRememberForHours());
    assertEquals(48, c.getTrustMinHours());
    assertEquals(3, c.getMaxAttempts());
    assertEquals(10, c.getAttemptWindowMinutes());
    assertEquals(5, c.getLockoutMinutes());
    assertEquals("Custom Issuer", c.getIssuer());
    assertEquals(2, c.getTotpWindow());
    assertEquals(600, c.getEmailCodeTtlSeconds());
    assertEquals(120, c.getEmailResendCooldownSeconds());
    assertEquals("svc-ci\nsvc-deploy", c.getExemptUsers());
  }

  /**
   * WHAT: exemptUsers parses as newline-separated usernames (Task 7's filter
   *   checks membership against this).
   * BDD:
   * GIVEN a config with exemptUsers = "svc-ci\nsvc-deploy\n\n"
   * WHEN  the list of exempt names is derived
   * THEN  it is exactly [svc-ci, svc-deploy] — no blank entries, no leading
   *       whitespace
   * WHY/SOLVES: the Task 7 filter short-circuits gated users who appear in
   *   this list. If blank lines or whitespace leaked through, an admin
   *   could accidentally exempt " " (a non-existent user) or, worse, trim
   *   logic that breaks the exact match. Pinning the derivation here keeps
   *   the filter's parsing contract explicit.
   */
  @Test
  void exemptUsersDerivesToTrimmedNonBlankList() {
    DevcruMfaConfig c = new DevcruMfaConfig();
    c.setExemptUsers("svc-ci\n  svc-deploy  \n\n   \n");
    assertEquals(2, c.exemptUserList().size());
    assertEquals("svc-ci", c.exemptUserList().get(0));
    assertEquals("svc-deploy", c.exemptUserList().get(1));
  }

  /**
   * WHAT: an empty/blank exemptUsers yields an empty list (nobody exempt).
   * BDD:
   * GIVEN a config with getExemptUsers() = "" or "\n   \n"
   * WHEN  the list is derived
   * THEN  it is empty
   * WHY/SOLVES: the "nobody is exempt by default" guarantee depends on the
   *   derivation treating blank/whitespace as empty, not as one blank
   *   username. A blank-username match in Task 7's filter would be a
   *   foot-gun (exempting the empty string); this test keeps it impossible.
   */
  @Test
  void exemptUsersBlankYieldsEmptyList() {
    assertEquals(0, new DevcruMfaConfig().exemptUserList().size(), "default (empty) → no one exempt");
    DevcruMfaConfig c = new DevcruMfaConfig();
    c.setExemptUsers("\n   \n");
    assertEquals(0, c.exemptUserList().size(), "all-blank → no one exempt");
  }
}
