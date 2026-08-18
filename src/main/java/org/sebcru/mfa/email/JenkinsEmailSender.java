package org.sebcru.mfa.email;

import hudson.tasks.Mailer;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import java.io.UnsupportedEncodingException;
import jenkins.model.Jenkins;

/**
 * {@link EmailSender} that delivers through Jenkins' own Mailer — the same
 * global SMTP configuration an operator uses to mail build results. This is
 * the "Jenkins-mail implementation (Task 6)" the {@link EmailSender} contract
 * was written to be filled in by; once this exists, the crypto/state logic
 * (Task 3) and delivery share one boundary.
 *
 * <p>Deliberately thin: the security-critical half (hashing, single-use,
 * expiry, cooldown) lives in {@link EmailCodeIssuer}; this class only knows
 * "get a session from Jenkins' configured SMTP, put the code in the body,
 * send it." It exists so the real mail path is exercised (Task 8 wires it)
 * rather than left to a capture double.
 *
 * <p>Confidentiality: per the contract, {@code code} is the only sensitive
 * content — it is placed in the mail <em>body</em> only, never the subject
 * and never logged, so a forwarded/spoofed envelope does not leak the code to
 * a party other than the intended address.
 */
public final class JenkinsEmailSender implements EmailSender {

  @Override
  public void send(String to, String code, long ttlSeconds) {
    if (to == null || to.trim().isEmpty()) {
      // The address is enforced server-side (Task 6 always sends to the
      // registered mailbox). A blank here means the caller's invariant
      // broke; fail closed rather than mail nobody.
      throw new IllegalStateException("email code has no delivery address");
    }
    Session session = session();
    try {
      MimeMessage msg = new MimeMessage(session);
      msg.setFrom(from());
      msg.setRecipient(MimeMessage.RecipientType.TO,
          Mailer.stringToAddress(to, java.nio.charset.StandardCharsets.UTF_8.name()));
      msg.setSubject(subject());
      msg.setText(body(ttlSeconds, code), "UTF-8");
      msg.setSentDate(new java.util.Date());
      jakarta.mail.Transport.send(msg, msg.getAllRecipients());
    } catch (MessagingException | UnsupportedEncodingException e) {
      // A delivery failure must not throw a stack trace to the login page.
      // The issuer has already persisted the pending state, so the user's
      // remedy is a resend (cooldown permitting); swallowing here keeps the
      // "wrong code / server error" JSON contract intact.
      throw new IllegalStateException("email code delivery failed", e);
    }
  }

  /** Jenkins' configured SMTP session; null-safe for the no-descriptor path. */
  private static Session session() {
    Mailer.DescriptorImpl d = Mailer.descriptor();
    if (d == null) {
      return null;
    }
    return d.createSession();
  }

  /** The configured "From" address, or the admin address, or a fixed fallback. */
  private static String from() {
    Mailer.DescriptorImpl d = Mailer.descriptor();
    if (d != null) {
      String admin = d.getAdminAddress();
      if (admin != null && !admin.trim().isEmpty()) {
        return admin.trim();
      }
      String suffix = d.getDefaultSuffix();
      if (suffix != null && !suffix.trim().isEmpty()) {
        // "jenkins" + "@suffix" is the Mailer's own from-address shape when no
        // explicit admin address is set.
        return "jenkins@" + suffix.trim();
      }
    }
    return "no-reply@devcru.local";
  }

  private static String subject() {
    // The code is never in the subject.
    return "Your Jenkins MFA code";
  }

  private static String body(long ttlSeconds, String code) {
    long minutes = Math.max(1L, (ttlSeconds + 59) / 60);
    return "Your one-time verification code for Jenkins is:\n\n"
        + "    " + code + "\n\n"
        + "It is valid for the next " + minutes + " minute(s) and will be "
        + "invalidated the moment it is used or a new code is requested.\n\n"
        + "If you did not request this, ignore this message and, if you "
        + "want to be safe, contact an administrator.";
  }
}
