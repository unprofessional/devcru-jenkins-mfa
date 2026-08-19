package org.sebcru.mfa;

import hudson.Extension;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import hudson.init.Terminator;
import hudson.util.PluginServletFilter;

/**
 * Devcru MFA — self-hosted MFA for Jenkins: TOTP (Authy/RFC 6238) and
 * email one-time codes, long remembered devices, no paywall.
 *
 * <p>Task 7's lifecycle owner (replaces the Task 0 placeholder): registers
 * the two servlet filters at {@link InitMilestone#EXTENSIONS_AUGMENTED} and
 * removes them at {@link Terminator @Terminator}, so a plugin reload or clean
 * shutdown leaves no dead filter in {@link PluginServletFilter}'s list.
 *
 * <h2>Filter order (A21)</h2>
 * <p>Two filters are registered, and the <em>order they are added</em> is
 * load-bearing: {@code hudson.util.PluginServletFilter} walks its filter
 * list in insertion order (a plain {@code List}, iterated head-to-tail at
 * serve time — verified against the 2.528.3 bytecode). {@link
 * #addBearerAuthenticator()} is called <em>before</em> {@link
 * #addGateFilter()} in {@link #addFilters()}, so for any request the
 * {@link BearerTokenFilter} runs first — it authenticates a Bearer API-token
 * request (setting the api-token request attribute + security context) — and
 * only then does the {@link MfaFilter} gate see the request and (correctly)
 * exempt it. If the gate ran first, a Bearer request would be bounced or
 * denied before it was ever recognised, defeating the A21 fix. Note the
 * Spring Security chain (which authenticates {@code Basic} API-token
 * requests and has no Bearer authenticator on this core) runs <em>outer</em>
 * of the entire plugin-filter list, so the two plugin filters' relative
 * order — Bearer before gate — is the only ordering we control and need.
 *
 * <h2>Why a plain {@code @Extension}, not a {@code hudson.Plugin} subclass — and
 * why {@code EXTENSIONS_AUGMENTED}, not {@code STARTED}</h2>
 * <p>Both are the same one lesson, learned the hard way this session. Jenkins
 * runs an {@code @Initializer} by calling
 * {@code Jenkins.getInjector().getInstance(<declaring class>)} (see
 * {@code hudson.init.TaskMethodFinder.lookUp}) — so the declaring class must be
 * Guice-creatable AND the injector must be fully built at the milestone the
 * task fires. A {@code hudson.Plugin} instance is created by its
 * {@code PluginWrapper}, not by that injector — so subclassing it fails the
 * lookup. And {@code after = STARTED} fires before the extension-augmented
 * injector is in place here, failing the same lookup with "Unable to inject
 * class …" (the {@code InjectedTest} harness boots a real Jenkins on every
 * build and caught both, which is what it is for).
 * <p>The fix is core's own idiom for exactly this class of registration
 * (JENKINS-60118 / the {@code UserLanguages} fix): an {@code @Extension}
 * class with a <strong>static</strong> initializer registered at
 * {@link InitMilestone#EXTENSIONS_AUGMENTED} — the milestone core uses for
 * its own {@code PluginServletFilter} registrations (e.g.
 * {@code ResourceDomainFilter}). As a plain extension singleton the injector
 * creates and caches the declaring class, and at {@code EXTENSIONS_AUGMENTED}
 * both the injector and its extension knowledge are ready. There is no
 * requirement for a Jenkins plugin's jar to contain a {@code hudson.Plugin}
 * subclass — the {@code @Extension}s are what make it a plugin.
 *
 * <p>One shared instance per filter class for the whole process.
 * {@code PluginServletFilter.removeFilter} matches by <em>identity</em>
 * (bytecode: a plain {@code List.remove(Object)}), so each
 * {@code static final} field the {@link Terminator}s tear down is the exact
 * object the {@code @Initializer}s added — a fresh {@code new BearerTokenFilter()}
 * in a remove call would never match and the filter would survive shutdown.
 * The instances are {@code static final} constants because both filters are
 * stateless (the gate's only shared state is its own {@code TrustStore}), so
 * a single process-wide instance per filter is correct and keeps add/remove
 * identity guaranteed regardless of how many times the extension is
 * (re)created.
 */
@Extension
public final class DevcruMfaPlugin {

  /** The single registered Bearer-authenticator instance — added FIRST so it
   *  runs first in the plugin-filter chain (see class doc, "Filter order").
   *  The SAME one at add and remove. */
  private static final BearerTokenFilter BEARER = new BearerTokenFilter();

  /** The single registered gate instance — added SECOND, so it runs after the
   *  Bearer authenticator (see class doc, "Filter order"). The SAME one at
   *  add and remove. */
  private static final MfaFilter GATE = new MfaFilter();

  @Initializer(after = InitMilestone.EXTENSIONS_AUGMENTED)
  public static void addFilters() throws jakarta.servlet.ServletException {
    // Order is contract: Bearer authenticator registered first, gate second.
    // The gate reads the api-token request attribute the bearer filter sets,
    // so the bearer filter must run first, and PluginServletFilter runs
    // filters in the order they were added.
    PluginServletFilter.addFilter(BEARER);
    PluginServletFilter.addFilter(GATE);
  }

  @Terminator
  public static void removeFilters() throws jakarta.servlet.ServletException {
    // Teardown order is the reverse of registration (gate first, bearer
    // second), but only for tidiness — removeFilter matches by identity, so
    // order does not affect correctness, and both must be removed.
    PluginServletFilter.removeFilter(GATE);
    PluginServletFilter.removeFilter(BEARER);
  }
}
