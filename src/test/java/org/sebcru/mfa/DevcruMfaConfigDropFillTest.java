package org.sebcru.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import hudson.util.ListBoxModel;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

/**
 * §1-D D3 — the gate-policy drop-down must have a filler, or every render
 * of the config page spams the controller log.
 *
 * <p>The defect this test exists for (handoff §1-D, from the live
 * controller log post-A22-b deploy, 2026-08-24):
 *
 * <pre>
 * Caught exception evaluating:
 *   descriptor.calcFillSettings(field,attrs) in /manage/configureSecurity/.
 * Reason: java.lang.IllegalStateException:
 *   class org.sebcru.mfa.DevcruMfaConfig doesn't have the
 *   doFillPolicyItems method for filling a drop-down list
 * </pre>
 *
 * <p>Verified against core 2.528.3 bytecode (javap on the offline jar):
 * {@code Descriptor.calcFillSettings} looks the filler up by NAME
 * ({@code "doFill" + <field> + "Items"} — the constant is assembled at
 * runtime, so it is invisible as a token in the class file) via
 * {@code ReflectionUtils.getPublicMethodNamed}, and throws the
 * {@code IllegalStateException} on a null miss. The return type is NOT
 * checked by core — anything public no-arg would silence the throw — but
 * the core's own drop-down descriptors (e.g.
 * {@code TimeZoneProperty.DescriptorImpl}) all return
 * {@code hudson.util.ListBoxModel}, which is what
 * {@code <f:select/>} renders: value binds back through
 * {@code bindJSON}, name displays in the box. This test pins BOTH the
 * existence AND the contract (return type + contents), because a
 * filler that returns the wrong shape would silently render an empty or
 * bogus drop-down instead of throwing — a strictly quieter failure than
 * the log spam it replaces.
 *
 * <p>Honest red phase: {@code DevcruMfaConfig} has ZERO {@code doFill*}
 * methods (Moldy fact-check confirmed on develop @ 4b2ec80 — the same
 * defect class the handoff suspected). Written against that state, the
 * existence leg failed with the exact production exception shape
 * (NoSuchMethodException — the reflection probe is the same lookup core
 * performs), and the contents leg could not run until the method
 * existed; both went green together with the production method, in this
 * single run, before any other change.
 *
 * <p>WHY / SOLVES: the config page is rendered on EVERY request that
 * touches it (the walk's log trace shows the throw running through
 * {@code MfaFilter.passUnlessGated} — i.e. normal authenticated traffic),
 * so a missing filler is not a one-time startup warning: it is a
 * recurring controller-log event on an instance whose logs mads reads.
 * The pin makes "the select has a working filler" a build-level contract
 * so the class can never silently degrade back into log spam.
 */
class DevcruMfaConfigDropFillTest {

  private static boolean jellyDeclaresPolicySelect;

  @BeforeAll
  static void loadJelly() throws Exception {
    InputStream in =
        DevcruMfaConfigDropFillTest.class.getResourceAsStream(
            "/org/sebcru/mfa/DevcruMfaConfig/config.jelly");
    assertNotNull(in, "config.jelly must be on the test classpath");
    try (in) {
      String jelly = new String(in.readAllBytes(), StandardCharsets.UTF_8);
      int entry = jelly.indexOf("field=\"policy\"");
      assertTrue(entry >= 0, "config.jelly no longer declares a policy field");
      int nextEntry = jelly.indexOf("<f:entry", entry + 1);
      String policyEntry = jelly.substring(
          Math.max(0, entry - 200), nextEntry > 0 ? nextEntry : jelly.length());
      jellyDeclaresPolicySelect = policyEntry.contains("<f:select");
    }
  }

  @Test
  @DisplayName("the config jelly's policy field is a drop-down (why a filler is needed)")
  void jellyPolicyFieldIsASelect() {
    assertTrue(
        jellyDeclaresPolicySelect,
        "the policy field must be a <f:select/> on the config form — if the"
            + " form drops the drop-down, doFillPolicyItems is dead filler"
            + " and should be removed with it (the handoff's alternative:"
            + " filler and form are one contract)");
  }

  /**
   * WHAT: the production contract of the missing method, probed the SAME
   * way core probes it — a no-arg public method named
   * {@code doFillPolicyItems} on the descriptor, returning
   * {@link ListBoxModel} (the type core's own drop-down descriptors
   * return and {@code <f:select/>} renders).
   * <pre>
   * GIVEN the DevcruMfaConfig descriptor
   * WHEN  Descriptor.calcFillSettings' reflection lookup is simulated
   *      (public no-arg doFillPolicyItems)
   * THEN  the method exists and declares a ListBoxModel return — the
   *      IllegalStateException from the live log is gone at the source
   * </pre>
   * WHY / SOLVES: see class Javadoc — this is the exact production
   * exception, pinned at its exact lookup point.
   */
  @Test
  @DisplayName("doFillPolicyItems exists with the ListBoxModel return")
  void doFillPolicyItemsExistsWithContractedShape() {
    Method m;
    try {
      m = DevcruMfaConfig.class.getMethod("doFillPolicyItems");
    } catch (NoSuchMethodException e) {
      String msg =
          "DevcruMfaConfig is missing the doFillPolicyItems filler that"
              + " core's calcFillSettings resolves by name for the policy"
              + " drop-down — every render of"
              + " /manage/configureSecurity/ throws the production"
              + " IllegalStateException (log spam on an instance whose"
              + " logs mads reads). Core performs this same lookup via"
              + " ReflectionUtils.getPublicMethodNamed.";
      fail(msg);
      throw new AssertionError(msg, e); // unreachable; satisfies javac
    }
    assertEquals(
        ListBoxModel.class,
        m.getReturnType(),
        "doFillPolicyItems must return hudson.util.ListBoxModel — the type"
            + " core's own drop-down descriptors (TimeZoneProperty et"
            + " al.) return and <f:select/> renders; any other type would"
            + " silently render a broken box instead of throwing");
  }

  /**
   * WHAT: the filler's CONTENTS — exactly the two gate-policy values, as
   * the enum names that {@code bindJSON} round-trips (REQUIRED →
   * Policy.REQUIRED), each with a display label a human can read. The new
   * config's policy is not a third option — a fabricated value would 404
   * into bindJSON's enum coercion and the form would be unsavable.
   * <pre>
   * GIVEN a fresh DevcruMfaConfig descriptor instance
   * WHEN  doFillPolicyItems() is called
   * THEN  it returns exactly two options, one per Policy enum value, and
   *       each option's VALUE is the enum's name (the bindJSON
   *       round-trip contract) with a non-blank display label
   * </pre>
   * WHY / SOLVES: a filler that offers values the descriptor cannot
   * store is worse than no filler — the admin selects it, the form
   * submits, and the save either stores the wrong policy or fails. The
   * option set must be the enum, pinned value-by-value.
   */
  @Test
  @DisplayName("the filler offers exactly the two Policy values, bindable")
  void fillerOffersExactlyTheTwoPolicyValues() throws Exception {
    DevcruMfaConfig cfg = new DevcruMfaConfig();
    Object result =
        DevcruMfaConfig.class.getMethod("doFillPolicyItems").invoke(cfg);
    assertTrue(
        result instanceof ListBoxModel,
        "doFillPolicyItems must return a ListBoxModel at runtime, got: "
            + (result == null ? "null" : result.getClass().getName()));
    ListBoxModel model = (ListBoxModel) result;
    assertEquals(
        DevcruMfaConfig.Policy.values().length,
        model.size(),
        "one option per Policy enum value — more means a value the"
            + " descriptor cannot store, fewer means a policy with no UI");
    for (DevcruMfaConfig.Policy p : DevcruMfaConfig.Policy.values()) {
      String rendered = null;
      for (ListBoxModel.Option o : model) {
        if (p.name().equals(o.value)) {
          rendered = o.name;
          break;
        }
      }
      assertNotNull(
          rendered,
          "no option carries the bindable value [" + p.name() + "] —"
              + " bindJSON has nothing to coerce the form back into"
              + " Policy." + p.name());
      assertTrue(rendered.trim().length() > 0,
          "the option for " + p.name() + " has a blank display label");
    }
  }
}
