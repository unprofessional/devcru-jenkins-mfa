package org.sebcru.mfa.email;

/**
 * Delivery boundary for email one-time codes.
 *
 * <p>The {@code EmailCodeIssuer} never knows how a code reaches the user's
 * inbox; the Jenkins-mailer implementation (Task 6) does. Keeping this an
 * interface keeps the crypto/state logic (the security-critical half)
 * unit-testable without a mail round trip, and lets a test double record
 * exactly what would have been sent.
 *
 * <p>Implementations must treat {@code code} as the only confidential
 * content: it must never be logged or included in a subject line.
 */
public interface EmailSender {

  /**
   * Deliver a one-time code.
   *
   * @param to        the registered mailbox
   * @param code      the plaintext one-time code (8 chars, uppercase alphanumeric)
   * @param ttlSeconds seconds the code remains valid
   */
  void send(String to, String code, long ttlSeconds);
}
