package org.sebcru.mfa;

import hudson.Extension;
import hudson.Util;
import jenkins.model.GlobalConfiguration;
import jenkins.model.GlobalConfigurationCategory;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.StaplerRequest2;

import java.util.ArrayList;
import java.util.List;

/**
 * Admin-configurable policy for the gate — the plugin's
 * <em>GlobalConfiguration</em>, editable at Manage Jenkins → Security.
 *
 * <p>This is the plan's {@code DevcruMfaConfig} as a Jenkins
 * {@code GlobalConfiguration}: an {@code @Extension} whose fields persist via
 * the standard descriptor {@code save()}/{@code load()} machinery
 * ({@code config/DevcruMfaConfig.xml}), with a {@code config.jelly} form
 * ({@code @Symbol("devcruMfa")} addresses it from Groovy / config-round-trip
 * tooling).
 *
 * <h2>Two deliberate refinements of the plan sketch</h2>
 * <ol>
 *   <li>The plan said {@code hudson/… GlobalConfiguration}; in Jenkins 2.528
 *       the class is {@code jenkins.model.GlobalConfiguration}. Same
 *       semantics, correct package — noted so nobody "fixes" it back.</li>
 *   <li>The plan said {@code getCategory() = SECURITY} referencing
 *       {@code jenkins/SecurityRealm}; Jenkins 2.528's
 *       {@code Descriptor#getCategory()} returns a
 *       {@code GlobalConfigurationCategory}, so this override returns the
 *       {@code Security} category via {@code
 *       GlobalConfigurationCategory.get(GlobalConfigurationCategory.Security.class)}
 *       — the same group, via the actual API shape (the same class of
 *       "plan named an old signature" that Task 2's {@code isSingle()}
 *       hit and the {@code @Symbol} omission above).</li>
 *   <li><b>Plan said {@code @Symbol("devcruMfa")}; not on the
 *       classpath.</b> The plan assumed {@code plugin-util-api} was
 *       available; on Jenkins 2.528 the {@code io.jenkins.plugins.Symbol}
 *       annotation lives in that plugin, which is not in the offline repo
 *       cache and would be a new transitive dep just for an identifier this
 *       private plugin never queries. A {@code GlobalConfiguration}
 *       descriptor without {@code @Symbol} still shows in Manage Jenkins
 *       → Security and its {@code config.jelly} is discovered by class
 *       name (see {@code MyViewsTabBar/GlobalConfigurationImpl} in core,
 *       which has no symbol). Dropped, no functionality lost.</li>
 * </ol>
 *
 * <h2>Instance resolution — the A1 ruling (mads, 2026-08-18)</h2>
 * <p>{@link #currentSafe()} is <em>authoritative for all runtime reads</em> —
 * the gate filter AND the controller. In a live Jenkins the persisted
 * descriptor instance <em>is</em> the config: admin form saves via
 * {@code configure()} land on it, and both runtime readers see the save in
 * the same request it was made in. {@link #get()} is the process-default
 * instance — the null-safe fallback {@link #currentSafe()} provides when no
 * descriptor is loaded (unit tests, pre-startup bootstrap) — and nothing
 * else. Wiring a runtime reader onto {@code get()} would reintroduce the
 * config-instance duality the ruling kills: admin-visible tuning (policy,
 * windows, exemptions) would reach the gate only by accident.
 *
 * <p>Defaults match the plan's §defaults table exactly, so a fresh install
 * behaves as documented even before an admin saves anything.
 *
 * <h2>Values are the plan's §defaults table — mads-signed.</h2>
 * Do not re-litigate them here; {@code DevcruMfaConfigTest} pins them as
 * assertions so any drift is a loud, reviewable red.
 */
@Extension
public final class DevcruMfaConfig extends GlobalConfiguration {

  /** Gate policy. Task 7's filter treats {@code OFF} as the kill-switch path. */
  public enum Policy {
    OFF, REQUIRED
  }

  // -------------------------------------------------------------------
  // Plan §defaults table — the only place defaults live.
  // -------------------------------------------------------------------
  private Policy policy = Policy.REQUIRED;
  /** Trust window after a successful MFA; default 30 days. */
  private int rememberForHours = 720;
  /** Policy floor — trust is never granted below this. mads: never below. */
  private int trustMinHours = 24;
  /** Shown in authenticator apps (otpauth URI label). */
  private String issuer = "devcru Jenkins";
  /** ± time-step TOTP tolerance (clock skew). */
  private int totpWindow = 1;
  /** Email code validity, seconds. */
  private int emailCodeTtlSeconds = 300;
  /** Resend throttle, seconds. */
  private int emailResendCooldownSeconds = 60;
  /** Failed attempts tolerated inside the window before lockout. */
  private int maxAttempts = 5;
  /** Sliding window over which failures accumulate, minutes. */
  private int attemptWindowMinutes = 30;
  /** Lockout duration after maxAttempts, minutes. */
  private int lockoutMinutes = 15;
  /** Newline-separated usernames fully exempt (e.g. service accounts). */
  private String exemptUsers = "";

  public GlobalConfigurationCategory getCategory() {
    return GlobalConfigurationCategory.get(GlobalConfigurationCategory.Security.class);
  }

  // -------------------------------------------------------------------
  // Persistence: bind the form's JSON into this instance, then save.
  // -------------------------------------------------------------------
  @Override
  public boolean configure(StaplerRequest2 req, JSONObject json) {
    req.bindJSON(this, json);
    // Clamp: the 24h policy floor is the one hard invariant an admin can
    // configure; everything else is a tuning knob. If the admin enters a
    // trustMinHours below the plan's floor, we raise it to the floor rather
    // than silently honouring a weaker policy. (rememberForHours is
    // clamped at *use* time by TrustStore, not here — the admin is allowed
    // to store a sub-24h remember value as long as the floor still applies.)
    if (getTrustMinHours() < 24) {
      setTrustMinHours(24);
    }
    // Coerce negative/zero tuning knobs to a floor of 1 to avoid nonsense
    // (0-minute window = "no failures ever count", 0s TTL = "no code is
    // ever valid"). These are not policy floors — they're just "don't
    // store a value that means the field disables itself".
    if (getMaxAttempts() < 1) {
      setMaxAttempts(1);
    }
    if (getAttemptWindowMinutes() < 1) {
      setAttemptWindowMinutes(1);
    }
    if (getLockoutMinutes() < 1) {
      setLockoutMinutes(1);
    }
    if (getEmailCodeTtlSeconds() < 1) {
      setEmailCodeTtlSeconds(1);
    }
    if (getEmailResendCooldownSeconds() < 1) {
      setEmailResendCooldownSeconds(1);
    }
    save();
    return true;
  }

  // -------------------------------------------------------------------
  // Accessors for the "live" instance.
  // -------------------------------------------------------------------

  /**
   * The persisted, Jenkins-served instance (descriptor loaded). At runtime the
   * gate filter, the controller, and every admin save land on <em>this</em>
   * object — there is one authoritative config for a live Jenkins. Falls
   * back to the process-default instance if no descriptor is loaded (unit
   * tests / pre-startup bootstrap) so callers never see null.
   *
   * <p>Prefer {@link #currentSafe()} from any code path that also runs in a
   * plain JVM or before Jenkins is up: this method's descriptor scan calls
   * {@code Jenkins.get()} internally, which throws before that moment.
   */
  public static DevcruMfaConfig current() {
    for (GlobalConfiguration c : GlobalConfiguration.all()) {
      if (c instanceof DevcruMfaConfig) {
        return (DevcruMfaConfig) c;
      }
    }
    return get();
  }

  /**
   * {@link #current()} with the pre-boot / plain-JVM edge closed: the
   * descriptor scan is wrapped in a try/catch, so a request that arrives
   * before (or without) a live Jenkins falls back to the process-default
   * instance instead of propagating {@code Jenkins.get()}'s
   * {@code IllegalArgumentException}. Runtime callers (filter, controller)
   * use this, never the bare {@link #get()}: a live Jenkins' descriptor
   * instance IS the authoritative config, and {@code get()} would be a
   * permanently-stale twin (audit A1 ruling — the instance duality this
   * kills).
   */
  public static DevcruMfaConfig currentSafe() {
    try {
      return current();
    } catch (RuntimeException preBoot) {
      return get();
    }
  }

  // -------------------------------------------------------------------
  // Unit-testability seam (plain JVM, no descriptor). The gate's two
  // brains and their tests construct DevcruMfaConfig() directly; this
  // returns a shared "process default" for any code path that wants one
  // without the Jenkins descriptor. Defaults are the plan's table.
  // -------------------------------------------------------------------
  private static volatile DevcruMfaConfig instance = new DevcruMfaConfig();

  public static DevcruMfaConfig get() {
    return instance;
  }

  /** Test seam: reset the shared process instance to a fresh default. */
  public static void setForTest(DevcruMfaConfig c) {
    instance = c == null ? new DevcruMfaConfig() : c;
  }

  // -------------------------------------------------------------------
  // Getters / setters (bindJSON round-trip requires these).
  // -------------------------------------------------------------------

  public Policy getPolicy() {
    return policy;
  }

  public void setPolicy(Policy policy) {
    this.policy = policy == null ? Policy.REQUIRED : policy;
  }

  public int getRememberForHours() {
    return rememberForHours;
  }

  public void setRememberForHours(int rememberForHours) {
    this.rememberForHours = rememberForHours;
  }

  public int getTrustMinHours() {
    return trustMinHours;
  }

  public void setTrustMinHours(int trustMinHours) {
    this.trustMinHours = trustMinHours;
  }

  public String getIssuer() {
    return issuer;
  }

  public void setIssuer(String issuer) {
    this.issuer = Util.fixNull(issuer);
  }

  public int getTotpWindow() {
    return totpWindow;
  }

  public void setTotpWindow(int totpWindow) {
    this.totpWindow = totpWindow;
  }

  public int getEmailCodeTtlSeconds() {
    return emailCodeTtlSeconds;
  }

  public void setEmailCodeTtlSeconds(int emailCodeTtlSeconds) {
    this.emailCodeTtlSeconds = emailCodeTtlSeconds;
  }

  public int getEmailResendCooldownSeconds() {
    return emailResendCooldownSeconds;
  }

  public void setEmailResendCooldownSeconds(int emailResendCooldownSeconds) {
    this.emailResendCooldownSeconds = emailResendCooldownSeconds;
  }

  public int getMaxAttempts() {
    return maxAttempts;
  }

  public void setMaxAttempts(int maxAttempts) {
    this.maxAttempts = maxAttempts;
  }

  public int getAttemptWindowMinutes() {
    return attemptWindowMinutes;
  }

  public void setAttemptWindowMinutes(int attemptWindowMinutes) {
    this.attemptWindowMinutes = attemptWindowMinutes;
  }

  public int getLockoutMinutes() {
    return lockoutMinutes;
  }

  public void setLockoutMinutes(int lockoutMinutes) {
    this.lockoutMinutes = lockoutMinutes;
  }

  public String getExemptUsers() {
    return exemptUsers;
  }

  public void setExemptUsers(String exemptUsers) {
    this.exemptUsers = Util.fixNull(exemptUsers);
  }

  // -------------------------------------------------------------------
  // Exemption helper — the Task 7 filter checks membership on this.
  // -------------------------------------------------------------------

  /**
   * Derive the exemption list from {@link #getExemptUsers()}: one username
   * per non-blank line, trimmed, order-preserving. Whitespace-only lines are
   * dropped, so a mis-entered trailing newline can't create a phantom
   * "exempt" user.
   */
  public List<String> exemptUserList() {
    List<String> out = new ArrayList<>();
    for (String line : getExemptUsers().split("\n|\r\n")) {
      String name = line.trim();
      if (!name.isEmpty()) {
        out.add(name);
      }
    }
    return out;
  }

  /** @return true iff {@code username} is in the exemption list. */
  public boolean isUserExempt(String username) {
    return username != null && exemptUserList().contains(username.trim());
  }
}
