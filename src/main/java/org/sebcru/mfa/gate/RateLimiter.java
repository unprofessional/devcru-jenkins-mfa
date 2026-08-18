package org.sebcru.mfa.gate;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.sebcru.mfa.DevcruMfaConfig;

/**
 * Per-username failed-attempt accounting + lockout for the MFA gate.
 *
 * <p>Sliding window: failures recorded within the last
 * {@code attemptWindowMinutes} count toward {@code maxAttempts}; reaching
 * that trips a fixed {@code lockoutMinutes} lockout <em>starting from the
 * moment the threshold trips</em> (not from the oldest failure), so the
 * countdown the user sees is bounded and predictable. After the lockout
 * window closes, a fresh burst of {@code maxAttempts} fresh failures can
 * trip it again — the counter does not need to be "cleared" in the
 * success-only sense, just run out of in-window failures.
 *
 * <p>Deliberately in-memory (plan's security decision 5, matching
 * openmfa): a Jenkins restart resets all failure state. We accept that
 * trade in exchange for zero disk I/O in the request path, and for the
 * same restart-impersonation-reset behaviour as the plugin this one
 * replaces. Lockout is a delay measure, not a permanent ban — it must not
 * become a persistence dependency.
 *
 * <p>All methods take an explicit {@code now} (ms epoch); there is no
 * hidden clock, so the unit tests can pin the sliding window and the
 * lockout boundaries exactly.
 *
 * <p>State caps: per-user failure lists are trimmed to
 * {@link #MAX_TRACKED_FAILURES} entries by the sweep, and lockout entries
 * are dropped as they expire — both on every mutating call and lazily on
 * {@link #isLocked}, so a forgotten user leaves at most one (small) list
 * behind. No background thread, per plan decision 5.
 */
public final class RateLimiter {

  /** Defensive cap on how many timestamps per user we keep, even with a
   *  very long admin-configured window. */
  private static final int MAX_TRACKED_FAILURES = 100;
  private static final long MINUTE_MS = 60_000L;

  private final Map<String, List<Long>> failures = new ConcurrentHashMap<>();
  private final Map<String, Long> lockoutUntil = new ConcurrentHashMap<>();

  /**
   * @return true iff a live lockout has already been recorded for
   *         {@code user}. A lockout is (and stays) in force until
   *         {@code lockoutUntil} passes; after expiry the first fresh burst
   *         of {@code maxAttempts} failures can trip it again. All lockout
   *         state is written exclusively by {@link #recordFailure}, which
   *         holds the monitor; this read is lock-free on purpose.
   */
  public boolean isLocked(String user, DevcruMfaConfig cfg, long now) {
    Long until = lockoutUntil.get(user);
    return until != null && until > now;
  }

  /** Remaining lockout time in whole seconds, 0 if not locked. */
  public long retrySeconds(String user, DevcruMfaConfig cfg, long now) {
    Long until = lockoutUntil.get(user);
    if (until == null) {
      return 0L;
    }
    long remain = (until - now) / 1000;
    return Math.max(0L, remain);
  }

  /**
   * Record one failed verification for {@code user}. Trips the lockout
   * (from now) when this failure is the {@code maxAttempts}-th inside the
   * window. The sweep drops out-of-window timestamps and expired
   * lockouts in the same call, keeping state bounded (plan: "internal
   * sweep of expired entries on each call, cap list length at 100").
   */
  public void recordFailure(String user, DevcruMfaConfig cfg, long now) {
    long windowMs = effectiveWindowMs(cfg);
    long maxAttempts = effectiveMaxAttempts(cfg);
    synchronized (this) {
      List<Long> list = failures.computeIfAbsent(user, k -> new ArrayList<>());
      list.removeIf(ts -> now - ts >= windowMs);
      if (list.size() + 1 >= maxAttempts) {
        // This call is the maxAttempts-th failure inside the window: the
        // burst is complete, so trip the lockout from now. Two deliberate
        // choices:
        //  - We do NOT append the timestamp; the list holds
        //    maxAttempts-1 while the trip failure opens the lockout, and
        //    isLocked() (which reads lockoutUntil) is the authority during
        //    the lock.
        //  - We do NOT extend a lockout that is already live. The
        //    controller short-circuits locked users before they ever get
        //    here (Task 6), but even if an attempt slips through, a
        //    probing attacker must not be able to hold a legitimate user
        //    locked forever by retrying inside the countdown — the
        //    "try again in N seconds" promise must be true. A lockout
        //    gets its full duration once, from the instant it trips;
        //    after it lapses, a fresh burst arms a fresh lockout.
        Long existing = lockoutUntil.get(user);
        if (existing == null || existing <= now) {
          lockoutUntil.put(user, now + effectiveLockoutMs(cfg));
        }
      } else {
        // Below the threshold: record, and if an older lockout is still
        // live we keep it (don't restart the countdown on a retry that
        // lands during an active lockout — the lockout was already
        // announced).
        list.add(now);
      }
      // Cap the history (defensive against pathological admin windows).
      while (list.size() > MAX_TRACKED_FAILURES) {
        list.remove(0);
      }
      // Drop expired lockouts and empty lists lazily, in the same call.
      sweep(now);
    }
  }

  /**
   * Reset a user's failure state. Called on a successful verification
   * (the Task 6 controller), and reachable from the admin recovery path.
   *
   * <p>Success clears <em>and</em> does not restart any live lockout: if a
   * user somehow verifies successfully while locked (e.g. an admin
   * cleared the state server-side mid-lock), the failure history — and the
   * lockout — go with it. The next in-window failure burst re-arms
   * normally from zero.
   */
  public void clear(String user) {
    synchronized (this) {
      failures.remove(user);
      lockoutUntil.remove(user);
    }
  }

  /** @return the number of this user's failures currently inside the
   *  window — visible to tests and to the controller for UI hints, but
   *  otherwise only meaningful internally. */
  public int recentFailures(String user, DevcruMfaConfig cfg, long now) {
    long windowMs = effectiveWindowMs(cfg);
    List<Long> list = failures.get(user);
    if (list == null) {
      return 0;
    }
    int n = 0;
    for (long ts : list) {
      if (now - ts < windowMs) {
        n++;
      }
    }
    return n;
  }

  private void sweep(long now) {
    for (Map.Entry<String, Long> e : lockoutUntil.entrySet()) {
      if (e.getValue() <= now) {
        String user = e.getKey();
        Long expected = e.getValue();
        lockoutUntil.computeIfPresent(user, (k, v) -> v.equals(expected) ? null : v);
      }
    }
    for (Map.Entry<String, List<Long>> e : failures.entrySet()) {
      if (e.getValue().isEmpty()) {
        String user = e.getKey();
        List<Long> expected = e.getValue();
        failures.computeIfPresent(user, (k, v) -> v == expected ? null : v);
      }
    }
  }

  private static long effectiveWindowMs(DevcruMfaConfig cfg) {
    long minutes = cfg == null ? 30L : cfg.getAttemptWindowMinutes();
    return minutes * MINUTE_MS;
  }

  private static long effectiveLockoutMs(DevcruMfaConfig cfg) {
    long minutes = cfg == null ? 15L : cfg.getLockoutMinutes();
    return minutes * MINUTE_MS;
  }

  private static int effectiveMaxAttempts(DevcruMfaConfig cfg) {
    return cfg == null ? 5 : cfg.getMaxAttempts();
  }
}
