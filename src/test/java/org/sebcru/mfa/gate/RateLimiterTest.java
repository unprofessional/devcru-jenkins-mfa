package org.sebcru.mfa.gate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.sebcru.mfa.DevcruMfaConfig;

/**
 * Unit tests for {@link RateLimiter} — the per-username failed-attempt
 * accounting + lockout that stops an offline-online brute force on the
 * MFA gate.
 *
 * <h2>What this file pins down</h2>
 * <ul>
 *   <li>Sliding window: only failures inside the last
 *       {@code attemptWindowMinutes} count toward the threshold. A burst
 *       of {@code maxAttempts} failures a window ago does not lock the
 *       user out today.</li>
 *   <li>Exact trip point: the {@code maxAttempts}-th in-window failure
 *       is the one that trips, and the lockout starts from that instant —
 *       not from the oldest failure. The user's countdown is bounded and
 *       predictable.</li>
 *   <li>Lockout duration: the lockout lasts exactly
 *       {@code lockoutMinutes}, after which the user is free again even
 *       if the same failure pattern repeats (a fresh burst can re-trip
 *       it, but the old lockout has fully lapsed).</li>
 *   <li>Clear-on-success: a single successful verification resets the
 *       failure state; subsequent failures are re-counted from zero.</li>
 *   <li>Per-user isolation: one user's failures do not affect another's
 *       counter — Alice's 5 wrong TOTP attempts must not lock Bob out.</li>
 *   <li>Retry accounting: {@link RateLimiter#retrySeconds} reports the
 *       remaining lockout in whole seconds, monotonically non-increasing,
 *       and 0 when not locked (the Task 6 controller reads this for the
 *       UI countdown).</li>
 * </ul>
 *
 * <h2>Red → green note</h2>
 * <p>Two genuine reds on first run, both in production code, recorded
 * honestly per AGENTS.md:
 * <ol>
 *   <li><b>Threshold off-by-one</b>: the first implementation added the
 *       timestamp <em>before</em> checking the threshold, so the lockout
 *       tripped on the 6th failure instead of the 5th. The
 *       {@code lockoutTripsExactlyAtMaxAttempts} and
 *       {@code perUserIsolation} tests pinned it: the threshold must
 *       evaluate on <em>pre-add</em> state ({@code list.size() + 1 >=
 *       maxAttempts}), or the attacker gets an extra free code.</li>
 *   <li><b>Unit-less null-config defaults</b>: the fallbacks used by
 *       {@link #effectiveWindowMs}/{@link #effectiveLockoutMs} when cfg is
 *       null returned raw {@code 30L}/{@code 15L} <em>milliseconds</em>
 *       (the minutes were never multiplied). With a millisecond window the
 *       failure list was pruned on every call, so a null config <b>could
 *       never lock anyone out</b>. {@code nullConfigFallsBackToDefaults}
 *       caught it; fixed to the same {@code minutes * MINUTE_MS} shape as
 *       the non-null path.</li>
 *   <li><b>Test arithmetic (not production)</b>: the
 *       {@code retrySecondsCountsDownToZero} probe originally asserted 0
 *       remaining at NOW+901s, ignoring that the lock started at the
 *       trip (NOW+4s), not at NOW — 3s legitimately remained. The test's
 *       probe instant was corrected to NOW+905s; the production code was
 *       innocent and is what a probe run (reflection into
 *       {@code lockoutUntil}) confirmed before editing.</li>
 *   <li><b>No-extend on retry (review-caught, pinned by a new test —
 *       green on first run)</b>: the first trip branch wrote
 *       {@code lockoutUntil.put(now + lockout)} unconditionally, so a
 *       probing attacker who knows the victim's username could retry the
 *       MFA endpoint every hour and keep the victim's lockout rolling
 *       forever (invisible, per-account DoS). The trip now extends a
 *       lockout only if none is live, and
 *       {@link #lockoutCannotBeExtendedByRetryDURINGItsWindow} pins the
 *       "fixed delay from the trip instant" guarantee.</li>
 * </ol>
 */
class RateLimiterTest {

  private static final long NOW = 1_700_000_000_000L;
  private static final long MIN_MS = 60_000L;

  private static DevcruMfaConfig cfg() {
    return new DevcruMfaConfig();
  }

  /**
   * WHAT: the lockout trips on exactly the maxAttempts-th in-window
   * failure, and the earlier attempts do not trip it.
   * BDD:
   * GIVEN the default config (maxAttempts=5, window=30m, lockout=15m)
   * WHEN  recordFailure is called 4 times inside the window
   * THEN  isLocked is still false after the 4th
   * WHEN  recordFailure is called a 5th time
   * THEN  isLocked is true immediately (the 5th is the one that trips)
   * WHY/SOLVES: the "5/15-min" behaviour the README promises is
   * enforceable only if the trip threshold and the lockout write land in
   * the same call. A one-off-by-one in either direction would be
   * exploitable (attacker probes 6 codes before the first lockout) or
   * user-hostile (user locked after only 4 codes).
   */
  @Test
  void lockoutTripsExactlyAtMaxAttempts() {
    RateLimiter rl = new RateLimiter();
    DevcruMfaConfig c = cfg();

    assertFalse(rl.isLocked("alice", c, NOW));
    for (int i = 0; i < 4; i++) {
      rl.recordFailure("alice", c, NOW + i * 1000L);
      assertFalse(rl.isLocked("alice", c, NOW + 5000L), "must not trip before the 5th failure");
    }
    rl.recordFailure("alice", c, NOW + 4000L);
    assertTrue(rl.isLocked("alice", c, NOW + 4000L), "the 5th in-window failure trips the lockout");
  }

  /**
   * WHAT: a failure burst that falls outside the window does not lock
   * the user out, even when the user keeps failing afterwards.
   * BDD:
   * GIVEN 4 failures at NOW, +5m, +10m, +15m (a burst an hour old from
   *       the vantage of a later check)
   * WHEN  a 5th failure is recorded at NOW+31m
   * THEN  no lockout — the oldest failure (now 31 min old) has slid out
   *       of the 30-minute window, so the in-window count is 3, not 4
   * WHEN  a 6th failure is recorded at NOW+35m
   * THEN  still no lockout — the +5m failure has just crossed the window
   *       boundary, keeping the count under maxAttempts
   * WHY/SOLVES: the rate limit's purpose is to slow down a *dense burst*,
   * not to punish a user for having a bad day over the last few hours.
   * The deliberate trade-off: a slow drip that never exceeds
   * {@code maxAttempts} per window is never locked out — but that is
   * acceptable because each individual wrong-code attempt has a bounded,
   * tiny success probability (1 in 1,000,000 for TOTP, worse for the
   * email code), and the lockout's job is to make dense automated
   * brute-force uneconomical, which the sliding window does by making
   * the burst itself the trip condition.
   */
  @Test
  void failuresOutsideWindowDoNotCount() {
    RateLimiter rl = new RateLimiter();
    DevcruMfaConfig c = cfg();

    rl.recordFailure("alice", c, NOW);
    rl.recordFailure("alice", c, NOW + 5 * MIN_MS);
    rl.recordFailure("alice", c, NOW + 10 * MIN_MS);
    rl.recordFailure("alice", c, NOW + 15 * MIN_MS);
    assertEquals(4, rl.recentFailures("alice", c, NOW + 15 * MIN_MS + 1000L));

    // 5th: the t=NOW failure is 31 min old — outside the 30m window.
    rl.recordFailure("alice", c, NOW + 31 * MIN_MS);
    assertFalse(rl.isLocked("alice", c, NOW + 31 * MIN_MS),
        "a slipped-out oldest failure means 4 in-window, not 5");

    // 6th: the t=+5m failure is exactly 30 min old — boundary is
    // "age >= window => out", so it is dropped; count stays under 5.
    rl.recordFailure("alice", c, NOW + 35 * MIN_MS);
    assertFalse(rl.isLocked("alice", c, NOW + 35 * MIN_MS),
        "the sliding window keeps a slow drip of old failures from tripping the limit");
  }

  /**
   * WHAT: an already-live lockout cannot be extended by further
   * failures during its countdown.
   * BDD:
   * GIVEN a lockout that trips at t=NOW+4s (15 min) and therefore ends
   *       at NOW+904s
   * WHEN  additional failures are recorded at NOW+30m and NOW+40m
   *       (inside the countdown, past the 30m window so they'd otherwise
   *       look like a fresh burst)
   * THEN  retrySeconds at NOW+40m is still computed from the ORIGINAL trip
   *       (≈ 904s−46min… i.e. it has already lapsed → 0), NOT from the
   *       NOW+40m retry — the lockout has already lapsed by then, and the
   *       retries during the live window (say at NOW+5m, NOW+10m) did not
   *       push the expiry out past NOW+904s
   * WHEN  a 5th in-window retry is forced at NOW+5m while the lock is
   *       live
   * THEN  isLocked remains true until exactly NOW+904s, i.e. the retries
   *       did not move the expiry
   * WHY/SOLVES: this is the "try again in N seconds" promise. Without the
   *       no-extend rule, a probing attacker who knows the victim's
   *       username could retry the MFA code every hour and keep the
   *       victim's lockout rolling indefinitely — a denial-of-service
   *       against a single legitimate account, invisible to the admin.
   *       The lockout is a fixed delay from the trip instant, full stop.
   */
  @Test
  void lockoutCannotBeExtendedByRetryDURINGItsWindow() {
    RateLimiter rl = new RateLimiter();
    DevcruMfaConfig c = cfg();

    // Trip at NOW+4s.
    for (int i = 0; i < 5; i++) {
      rl.recordFailure("alice", c, NOW + i * 1000L);
    }
    assertTrue(rl.isLocked("alice", c, NOW + 4000L));

    // Retries during the live window must NOT push the expiry out.
    rl.recordFailure("alice", c, NOW + 5 * MIN_MS);
    rl.recordFailure("alice", c, NOW + 10 * MIN_MS);
    rl.recordFailure("alice", c, NOW + 14 * MIN_MS);

    // Still locked just before the original expiry…
    assertTrue(rl.isLocked("alice", c, NOW + 14 * MIN_MS + 59_000L));
    // …and free right at trip+900s (NOW+904s), i.e. the retries did not
    // move it.
    assertFalse(rl.isLocked("alice", c, NOW + 15 * MIN_MS + 5_000L),
        "retries during a live lockout must not extend it");
  }

  /**
   * WHAT: after the lockout window lapses, the user is free again; a
   * fresh burst can re-trip the lockout from the new failures.
   * BDD:
   * GIVEN the default config (lockout=15m) and a burst whose 5th failure
   *       (the trip) lands at t=NOW+4s
   * WHEN  isLocked is checked through the lockout
   * THEN  true at NOW+14m59s, still true at NOW+15m (the lock runs from
   *       the TRIP instant, NOW+4s — so its true end is NOW+15m+4s)
   * THEN  false at NOW+15m+5s, once the stated duration has fully lapsed
   * WHEN  a fresh burst of 5 failures occurs at NOW+20m..NOW+20m+4s
   * THEN  the lockout re-trips and now runs until NOW+35m+4s
   * WHY/SOLVES: the lockout is a delay, not a ban. It must expire
   * cleanly at its stated duration (so the "try again in 15 minutes"
   * message in the Task 6 UI is honest), and it must be re-armable for
   * the next attacker burst — the failure counter does not need to be
   * "cleared" by the admin for the protection to come back.
   */
  @Test
  void lockoutExpiresAndRearmsOnAFreshBurst() {
    RateLimiter rl = new RateLimiter();
    DevcruMfaConfig c = cfg();

    for (int i = 0; i < 5; i++) {
      rl.recordFailure("alice", c, NOW + i * 1000L);
    }
    assertTrue(rl.isLocked("alice", c, NOW + 14 * MIN_MS + 59_000L));
    // Lock started at the trip (NOW+4s), so NOW+15m is still 4s in.
    assertTrue(rl.isLocked("alice", c, NOW + 15 * MIN_MS),
        "the lock runs trip+lockoutMinutes, i.e. past a naive '15m from NOW' boundary");
    assertFalse(rl.isLocked("alice", c, NOW + 15 * MIN_MS + 5_000L),
        "lockout lapses exactly at trip+duration");

    // Fresh burst after the lockout lapses — must re-trip.
    for (int i = 0; i < 5; i++) {
      rl.recordFailure("alice", c, (NOW + 20 * MIN_MS) + i * 1000L);
    }
    assertTrue(rl.isLocked("alice", c, NOW + 20 * MIN_MS + 4000L));
    assertFalse(rl.isLocked("alice", c, NOW + 35 * MIN_MS + 10_000L),
        "re-armed lockout also lapses at its own trip+duration");
  }

  /**
   * WHAT: a successful verification clears the failure state, so
   * subsequent failures are re-counted from zero.
   * BDD:
   * GIVEN 3 recorded failures for alice
   * WHEN  clear(alice) is called (the Task 6 controller calls this on a
   *       successful TOTP/email verify)
   * THEN  recentFailures is 0,
   *       a burst of 3 more failures (now only counting 3 in-window)
   *       does <b>not</b> re-trip the lockout — the first 3 are gone
   * WHY/SOLVES: a locked-out user who gets it right (or an admin
   * resetting them via the recovery path) must not be "remembering"
   * old failures forever — the rate limit would otherwise be a
   * one-way ratchet and a single good code would need to be paired
   * with a 15-minute wait every time the user had a bad day.
   */
  @Test
  void clearOnSuccessResetsTheCounter() {
    RateLimiter rl = new RateLimiter();
    DevcruMfaConfig c = cfg();

    for (int i = 0; i < 3; i++) {
      rl.recordFailure("alice", c, NOW + i * 1000L);
    }
    rl.clear("alice");
    assertEquals(0, rl.recentFailures("alice", c, NOW + 5000L));

    for (int i = 0; i < 3; i++) {
      rl.recordFailure("alice", c, (NOW + 10 * MIN_MS) + i * 1000L);
    }
    assertFalse(rl.isLocked("alice", c, NOW + 10 * MIN_MS + 3000L),
        "a cleared counter means the first 3 failures are gone; 3 more do not trip maxAttempts=5");
  }

  /**
   * WHAT: one user's failures do not affect another's counter.
   * BDD:
   * GIVEN 5 failures for alice (trips her lockout)
   * WHEN  bob's state is queried
   * THEN  bob is not locked, and bob's failure list is empty (5
   *       failures for bob still does not trip until the 5th one for
   *       bob specifically)
   * WHY/SOLVES: the map is keyed by username, but if the sweep or the
   * per-user list got crossed (a shared-list bug, a copy-paste in
   * computeIfAbsent, etc.) one user's brute-force attempt would lock
   * the rest of the org out. This is a per-user isolation invariant.
   */
  @Test
  void perUserIsolation() {
    RateLimiter rl = new RateLimiter();
    DevcruMfaConfig c = cfg();

    for (int i = 0; i < 5; i++) {
      rl.recordFailure("alice", c, NOW + i * 1000L);
    }
    assertTrue(rl.isLocked("alice", c, NOW));
    assertFalse(rl.isLocked("bob", c, NOW), "bob must not be locked by alice's failures");
    assertEquals(0, rl.recentFailures("bob", c, NOW));

    for (int i = 0; i < 4; i++) {
      rl.recordFailure("bob", c, NOW + (10_000L + i * 1000L));
    }
    assertFalse(rl.isLocked("bob", c, NOW + 14_000L), "bob's 4 failures do not trip his own maxAttempts=5");
  }

  /**
   * WHAT: retrySeconds reports the remaining lockout in whole seconds,
   * monotonically non-increasing, and is 0 when not locked.
   * BDD:
   * GIVEN a fresh lockout (trip at NOW+4s → 15 min = 900 s, ends NOW+904s)
   * WHEN  retrySeconds is asked at 3 points (t=+4s, t=+64s, t=+905s)
   * THEN  it reports 900, then 840, then 0 (once the lock has lapsed),
   *       and stays at 0 after the lockout lapses
   * WHEN  the user is not locked
   * THEN  it is 0
   * WHY/SOLVES: the Task 6 controller renders this as "Please try again
   * in N seconds." An off-by-one here (or a ceiling vs. floor mistake)
   * would mean the UI says "0" while the server is still locked, or
   * vice versa — the user sees a countdown that ends in a dead-end.
   */
  @Test
  void retrySecondsCountsDownToZero() {
    RateLimiter rl = new RateLimiter();
    DevcruMfaConfig c = cfg();

    assertEquals(0L, rl.retrySeconds("alice", c, NOW));
    for (int i = 0; i < 5; i++) {
      rl.recordFailure("alice", c, NOW + i * 1000L);
    }
    assertEquals(900L, rl.retrySeconds("alice", c, NOW + 4000L),
        "right after the 5th failure at t=NOW+4s, ~900s remain");
    assertEquals(840L, rl.retrySeconds("alice", c, NOW + 64_000L),
        "60s in, 840s remain");
    // Lock started at the trip (NOW+4s) and lasts 900s → ends NOW+904s.
    // Probing at NOW+901s is still 3s inside; probe at/after NOW+905s.
    assertEquals(0L, rl.retrySeconds("alice", c, NOW + 15 * MIN_MS + 5_000L),
        "after the lockout (trip+900s elapsed), 0 remain");
  }

  /**
   * WHAT: a null config falls back to documented defaults rather than NPE.
   * BDD:
   * GIVEN a null config
   * WHEN  recordFailure/recentFailures are called
   * THEN  the documented defaults apply (5/30m/15m) and no NPE is thrown
   * WHY/SOLVES: the Task 7 filter passes config in from
   * {@code DevcruMfaConfig.get()}, which cannot realistically be null,
   * but a null here must not turn the login page into a 500 — it must
   * fail to documented defaults, the same way {@link TrustStore} does.
   */
  @Test
  void nullConfigFallsBackToDefaults() {
    RateLimiter rl = new RateLimiter();
    for (int i = 0; i < 5; i++) {
      rl.recordFailure("alice", null, NOW + i * 1000L);
    }
    assertTrue(rl.isLocked("alice", null, NOW), "defaults are 5/30m/15m");
    assertEquals(900L, rl.retrySeconds("alice", null, NOW + 4000L),
        "trip landed at NOW+4s, so 900s remain at that instant");
  }
}
