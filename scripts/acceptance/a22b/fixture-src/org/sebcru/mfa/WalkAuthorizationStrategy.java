package org.sebcru.mfa;

import hudson.model.Descriptor;
import hudson.security.ACL;
import hudson.security.AuthorizationStrategy;
import hudson.security.Permission;
import java.util.Collection;
import java.util.Collections;
import jenkins.model.Jenkins;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * Sandbox-only acceptance strategy ({@code fixture-src/} is the source of
 * truth; the {@code src/main/java} copy is produced by the README boot
 * recipe and is git-excluded — never commit it).
 *
 * <p>Grants exactly ONE Overall/Administer holder (the seeded admin) and
 * READ-level to every other authenticated user — the "A22-b sandbox: one
 * admin" the whole acceptance harness assumes.
 *
 * <h2>Red→green history (honest)</h2>
 * The 2026-08-23 incarnation was a {@code SidACL} that matched
 * {@code sid instanceof PrincipalSid}. On core 2.528.3 a plain
 * user-login {@code Authentication} carries no {@code PrincipalSid}, so
 * every check fell through to {@code null} → deny. An unsecured-boot
 * in-JVM probe (2026-08-25) pinned the shape precisely: strategy present
 * in memory, {@code adminUser} field set, admin in the realm, XStream
 * round-trip clean — yet {@code hasPermission(ADMINISTER)==false} AND
 * {@code hasPermission(READ)==false} (the double-false was the tell: a
 * working SidACL would at least have granted READ). The authoritative seam
 * in this core is {@code ACL.hasPermission2(Authentication2, Permission)}
 * — the same shape the production seam
 * ({@link MfaAdminController#hasAdminister}) deliberately checks against
 * {@code Jenkins.getACL()} per its Defect-2 doc — so this revision
 * overrides that method directly and no longer iterates Sids at all.
 *
 * <p>Third iteration (2026-08-25, in-request trace — honest): the literal
 * override above let the roster gate pass but 403'd the core
 * {@code /manage/configureSecurity/} page for the seeded admin. A
 * temporary decision+URI trace of {@code hasPermission2} (sandbox runtime
 * copy only, removed before commit) showed the page never asks about
 * {@code Administer} at all: core 2.528 gates the page on
 * {@link jenkins.model.Jenkins#SYSTEM_READ} and the {@code /manage/}
 * section on {@code Manage}, BOTH with {@code impliedBy = Administer},
 * and its own {@code ACL#checkPermission} walks {@code impliedBy} on a
 * miss — naming the walk's terminal {@code Administer} node in the thrown
 * message even though the failing boolean ran against SystemRead/Manage.
 * This revision mirrors that walk (the {@code for} loop at the bottom of
 * {@code hasPermission2}): admin passes any permission whose chain
 * reaches {@code Administer}, authenticated non-admin passes chains
 * reaching {@code Read}. The D2 denial arm is unaffected — {@code reader}
 * and {@code sac} still fail every admin-implied node, and
 * anonymous stays fully denied.
 */
public final class WalkAuthorizationStrategy extends AuthorizationStrategy {
  private String adminUser;

  public WalkAuthorizationStrategy() {
    this("admin");
  }

  public WalkAuthorizationStrategy(String adminUser) {
    this.adminUser = adminUser;
  }

  @Override
  public ACL getRootACL() {
    return new ACL() {
      @Override
      public boolean hasPermission2(Authentication auth, Permission permission) {
        if (auth == null
            || auth instanceof AnonymousAuthenticationToken
            || ACL.ANONYMOUS_USERNAME.equals(auth.getName())) {
          return false;
        }
        // Overall/Administer: the ONE sandbox admin, and only them. Every
        // other authenticated user (reader, sac) is denied here — that is
        // what keeps /mfaAdmin and configureSecurity locked to admin and
        // drives the D2 denial-arm leg.
        if (permission == Jenkins.ADMINISTER) {
          return adminUser.equals(auth.getName());
        }
        // READ-level for any authenticated user (admin included): instance
        // visibility is granted, administration is not. Grant READ
        // specifically (not "everything"), so least-privilege stays honest.
        if (permission == Jenkins.READ) {
          return true;
        }
        // Implication walk (the core ACL#checkPermission loop, mirrored):
        // a permission is held when any node its impliedBy chain reaches is
        // held. /manage/configureSecurity asks for SYSTEM_READ and the
        // /manage/ section asks for Manage — both impliedBy Administer — so
        // without this walk a literal-only grant 403s the very page the D1
        // labels render on, while still passing the Administer gate above.
        for (Permission implied = permission.impliedBy;
             implied != null;
             implied = implied.impliedBy) {
          if (implied == Jenkins.ADMINISTER) {
            return adminUser.equals(auth.getName());
          }
          if (implied == Jenkins.READ) {
            return true;
          }
        }
        return false;
      }
    };
  }

  @Override
  public Collection<String> getGroups() {
    return Collections.emptyList();
  }

  private static final Descriptor<AuthorizationStrategy> DESCRIPTOR =
      new Descriptor<AuthorizationStrategy>(AuthorizationStrategy.class) {
        @Override public String getDisplayName() { return "A22-b sandbox: one admin"; }
        @Override public String getId() { return "a22b-walk-one-admin"; }
      };

  @Override
  public Descriptor<AuthorizationStrategy> getDescriptor() {
    return DESCRIPTOR;
  }
}
