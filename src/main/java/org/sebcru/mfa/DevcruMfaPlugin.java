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
 * <p>Task 7's lifecycle owner (replaces the Task 0 placeholder): it
 * registers the gate — the {@link MfaFilter} servlet filter — at
 * {@link InitMilestone#STARTED} (after Jenkins is up and the security chain
 * + descriptors are loaded; earlier is wrong because the filter's config
 * read wants a live Jenkins) and removes it at
 * {@link Terminator @Terminator}, so a plugin reload or clean shutdown does
 * not leave a dead filter in {@link PluginServletFilter}'s list.
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
 * requirement for a Jenkins plugin's jar to contain a
 * {@code hudson.Plugin} subclass — the {@code @Extension}s are what make it
 * a plugin.
 *
 * <p>One shared filter instance for the whole process.
 * {@code PluginServletFilter.removeFilter} matches by <em>identity</em>
 * (bytecode: a plain {@code List.remove(Object)}), so the field the
 * {@link #removeFilter()} tears down is the exact object
 * {@link #addFilter()} added — a fresh {@code new MfaFilter()} in the remove
 * call would never match and the filter would survive shutdown. The
 * instance is a {@code static final} constant because {@link MfaFilter} is
 * stateless (its one brain, the {@code TrustStore}, is already shared), so a
 * single process-wide filter is correct and keeps add/remove identity
 * guaranteed regardless of how many times the extension is (re)created.
 */
@Extension
public final class DevcruMfaPlugin {

  /** The single registered instance — the SAME one at add and remove. */
  private static final MfaFilter FILTER = new MfaFilter();

  @Initializer(after = InitMilestone.EXTENSIONS_AUGMENTED)
  public static void addFilter() throws jakarta.servlet.ServletException {
    PluginServletFilter.addFilter(FILTER);
  }

  @Terminator
  public static void removeFilter() throws jakarta.servlet.ServletException {
    PluginServletFilter.removeFilter(FILTER);
  }
}
