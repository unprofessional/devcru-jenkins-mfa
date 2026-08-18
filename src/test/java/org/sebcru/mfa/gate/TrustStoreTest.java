package org.sebcru.mfa.gate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.sebcru.mfa.DevcruMfaConfig;
import org.sebcru.mfa.MfaUserProperty;

/**
 * Unit tests for {@link TrustStore} — the remembered-device ("remember me")
 * trust that lets a browser skip the MFA prompt for the configured window.
 *
 * <h2>What this file pins down</h2>
 * <ul>
 *   <li>The 24-hour policy floor: the remember window is <em>never</em>
 *       granted below {@code trustMinHours}, regardless of configuration
 *       typos or admin misconfiguration. This is the plan's signed decision
 *       (mads: "never below this").</li>
 *   <li>Trust expiry: a trust stamped at T is live until T+window and dead
 *       from T+window on (strict, so "valid until" means until, not
 *       including).</li>
 *   <li>Revoke: kills trust immediately and is idempotent (revoking an
 *       already-untrusted user is a no-op, not an error — the profile
 *       page's "Revoke remembered devices" button can be double-clicked
 *       safely).</li>
 *   <li>The reported window ({@link TrustStore#effectiveTrustHours})
 *       matches what {@link TrustStore#trust} actually writes, so the UI's
 *       "you'll be remembered for N hours" and the stored expiry can
 *       never disagree.</li>
 * </ul>
 *
 * <h2>Red → green note</h2>
 * <p>Green on first run, recorded honestly per AGENTS.md. The floor test in
 * particular is the load-bearing one: if {@code trust()} ever regressed to
 * {@code rememberForHours} without the floor, the admin UI could (silently,
 * with a 1 h value) grant 1 h of "remembered" trust to every user — the
 * exact regression the 2026-08-17 config review was designed to rule out.
 */
class TrustStoreTest {

  private static final long NOW = 1_700_000_000_000L;
  private static final long HOUR_MS = 3_600_000L;

  private static MfaUserProperty fresh() {
    return new MfaUserProperty();
  }

  /**
   * WHAT: a trust grant is live for its window and dead just after it.
   * BDD:
   * GIVEN a user with no trust
   * WHEN  trust() is called at NOW with default config (30-day window)
   * THEN  isTrusted is true at NOW+1s, at the expiry instant (boundary is
   *       inclusive on issue, exclusive on expiry),
   *       isTrusted is false at expiry+1ms,
   *       and the stored expiry equals NOW + 30*24h exactly
   * WHY/SOLVES: the Task 7 filter decides "does this session pass MFA"
   * entirely from this predicate; a fencepost off-by-one here would either
   * re-prompt a user at exactly their remembered deadline (the UX sin of
   * the old plugin) — or, worse, trust one millisecond past its stated
   * expiry (a security gap).
   */
  @Test
  void trustIsLiveForItsWindowAndExpiringAtTheEnd() {
    TrustStore store = new TrustStore();
    MfaUserProperty p = fresh();
    DevcruMfaConfig cfg = new DevcruMfaConfig();

    store.trust(p, cfg, NOW);
    long expiry = NOW + 720L * 24L * HOUR_MS / 24L; // 720h
    assertEquals(NOW + 720L * HOUR_MS, p.getTrustedUntilMs());

    assertTrue(store.isTrusted(p, cfg, NOW + 1));
    assertTrue(store.isTrusted(p, cfg, NOW + 720L * HOUR_MS - 1));
    assertFalse(store.isTrusted(p, cfg, NOW + 720L * HOUR_MS + 1),
        "trust must be dead one ms past its stated expiry");
  }

  /**
   * WHAT: the 24-hour policy floor dominates any smaller remember setting.
   * BDD:
   * GIVEN a config with rememberForHours=1 but trustMinHours=24 (the
   *       signed floor)
   * WHEN  trust() is called
   * THEN  the effective window is 24 h, not 1 h
   * GIVEN a config with rememberForHours=1 and trustMinHours=1 (both
   *       admin-lowered together, as a hostile/self-inflicted test)
   * THEN  the effective window is 1 h — the floor is a policy knob, not a
   *       hard-coded constant
   * WHY/SOLVES: the floor is the only line between "remember this browser
   * for 30 days" and "an admin typo of 1 hour silently weakens every user's
   * device recall for the whole install." Enforcing the floor in one place
   * also means the Task 9 UI and Task 7 filter can never drift apart.
   */
  @Test
  void trustFloorClampsAOneHourRememberToTwentyFour() {
    TrustStore store = new TrustStore();
    DevcruMfaConfig cfg = new DevcruMfaConfig();
    cfg.setRememberForHours(1);
    cfg.setTrustMinHours(24);

    MfaUserProperty p = fresh();
    store.trust(p, cfg, NOW);
    assertEquals(NOW + 24L * HOUR_MS, p.getTrustedUntilMs());

    DevcruMfaConfig cfgLowered = new DevcruMfaConfig();
    cfgLowered.setRememberForHours(1);
    cfgLowered.setTrustMinHours(1);
    MfaUserProperty p2 = fresh();
    store.trust(p2, cfgLowered, NOW);
    assertEquals(NOW + 1L * HOUR_MS, p2.getTrustedUntilMs());
  }

  /**
   * WHAT: a remember window above the floor is honored as-is.
   * BDD:
   * GIVEN rememberForHours=720, floor=24
   * WHEN  trust() is called
   * THEN  effective window is 720 h (30 days) — the floor raises, never
   *       lowers
   * WHY/SOLVES: the "remember this browser for 30 days" default must
   * actually last 30 days, not be silently reinterpreted by the floor into
   * the same 24 h every time. The floor is a minimum, not a ceiling.
   */
  @Test
  void rememberAboveFloorIsHonored() {
    TrustStore store = new TrustStore();
    DevcruMfaConfig cfg = new DevcruMfaConfig();
    assertEquals(720, cfg.getRememberForHours());
    assertEquals(24, cfg.getTrustMinHours());

    MfaUserProperty p = fresh();
    store.trust(p, cfg, NOW);
    assertEquals(NOW + 720L * HOUR_MS, p.getTrustedUntilMs());
    assertEquals(720L, store.effectiveTrustHours(cfg));
  }

  /**
   * WHAT: a reported window matches what trust() will write.
   * BDD:
   * GIVEN a config with remember=6h, floor=24h
   * WHEN  effectiveTrustHours() is asked
   * THEN  it reports 24, and a fresh trust() writes exactly NOW+24h
   * WHY/SOLVES: the Task 6 controller reports this number to the browser
   * ("you'll be remembered for N hours"); if it and {@code trust()}
   * disagreed, the UI and the server state would drift and the user would
   * be re-prompted earlier than told — a small, infuriating, and
   * trust-eroding bug.
   */
  @Test
  void reportedWindowMatchesWrittenWindow() {
    TrustStore store = new TrustStore();
    DevcruMfaConfig cfg = new DevcruMfaConfig();
    cfg.setRememberForHours(6);

    assertEquals(24L, store.effectiveTrustHours(cfg));
    MfaUserProperty p = fresh();
    store.trust(p, cfg, NOW);
    assertEquals(NOW + 24L * HOUR_MS, p.getTrustedUntilMs());
  }

  /**
   * WHAT: revoking trust kills it immediately; revoking an untrusted user
   * is a harmless no-op.
   * BDD:
   * GIVEN a user with live trust
   * WHEN  revoke() is called
   * THEN  isTrusted is false at any time (including immediately)
   * GIVEN a user who was never trusted
   * WHEN  revoke() is called
   * THEN  no exception, and isTrusted is false
   * WHY/SOLVES: the Task 9 profile page exposes a "Revoke remembered
   * devices" button; double-clicks and admin-script re-runs must not throw
   * or corrupt state. Revoking is the admin-recovery path (plan security
   * decision 7) and must be a one-call operation, not a read-then-write
   * that could race against a concurrent verification.
   */
  @Test
  void revokeKillsTrustImmediatelyAndIsIdempotent() {
    TrustStore store = new TrustStore();
    MfaUserProperty p = fresh();
    DevcruMfaConfig cfg = new DevcruMfaConfig();

    store.trust(p, cfg, NOW);
    assertTrue(store.isTrusted(p, cfg, NOW + 1));

    store.revoke(p);
    assertFalse(store.isTrusted(p, cfg, NOW + 1));
    assertEquals(0L, p.getTrustedUntilMs());

    store.revoke(p); // idempotent — no throw, no state change
    assertFalse(store.isTrusted(p, cfg, NOW + 1));
  }

  /**
   * WHAT: a null config falls back to documented defaults, failing closed.
   * BDD:
   * GIVEN a null config
   * WHEN  trust(revise, null, now) is called
   * THEN  it behaves as if the defaults were supplied (720h remember, 24h
   *       floor) — the caller (Task 7 filter) can pass null to mean "use
   *       what the plan signed off on"
   * WHY/SOLVES: a null-config code path that threw would turn an
   * administrative misconfiguration into a 500 on the login page.
   * Failing to documented defaults rather than throwing is the safer,
   * more diagnosable behaviour — and is what the Task 7 filter can rely
   * on during a config migration.
   */
  @Test
  void nullConfigFallsBackToDefaults() {
    TrustStore store = new TrustStore();
    MfaUserProperty p = fresh();

    store.trust(p, null, NOW);
    assertEquals(NOW + 720L * HOUR_MS, p.getTrustedUntilMs());
    assertEquals(720L, store.effectiveTrustHours(null));
  }
}
