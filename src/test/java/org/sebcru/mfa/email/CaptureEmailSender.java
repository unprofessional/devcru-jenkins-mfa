package org.sebcru.mfa.email;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Test double for the {@link EmailSender} delivery boundary (Task 8).
 *
 * <p>Instead of talking to a mail server it records every delivery it is
 * asked to make, so the integration test can pin the <em>round trip</em> —
 * what the resend endpoint issued, where it went, and what the mail body
 * actually contained. The security-relevant properties under test are
 * delivery-shaped, not crypto-shaped: codes go to the <em>registered</em>
 * mailbox only, and the plaintext code reaches a human-readable body.
 * Both are exactly what an {@link EmailSender} double is the right seam
 * for; the hashing itself stays unit-tested against {@code EmailCodeIssuer}.
 *
 * <p>Thread-safe (the controller may deliver from a request thread); the
 * {@link #sent} list is a {@link CopyOnWriteArrayList}, and the test is
 * single-threaded anyway — cheap insurance, no synchronization noise.
 */
public final class CaptureEmailSender implements EmailSender {

  /** One recorded delivery: destination, code, the TTL it was told. */
  public record Sent(String to, String code, long ttlSeconds) {}

  private final List<Sent> sent = new CopyOnWriteArrayList<>();

  @Override
  public void send(String to, String code, long ttlSeconds) {
    sent.add(new Sent(to, code, ttlSeconds));
  }

  /** All deliveries so far, oldest first. */
  public List<Sent> sent() {
    return sent;
  }

  /** True iff exactly one delivery has been made so far. */
  public boolean exactlyOne() {
    return sent.size() == 1;
  }

  /** The most recent delivery (never null — the caller checks size first). */
  public Sent last() {
    return sent.get(sent.size() - 1);
  }

  /** Reset for a fresh test case (the IT does not reuse instances). */
  public void clear() {
    sent.clear();
  }
}
