package org.sebcru.mfa;

import hudson.model.Descriptor;
import hudson.security.ACL;
import hudson.security.AuthorizationStrategy;
import hudson.security.Permission;
import hudson.security.SidACL;
import java.util.Collection;
import java.util.Collections;
import jenkins.model.Jenkins;
import org.acegisecurity.acls.sid.PrincipalSid;
import org.acegisecurity.acls.sid.Sid;

/** Sandbox-only acceptance strategy; source is ignored under .scratch/. */
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
    return new SidACL() {
      @Override
      protected Boolean hasPermission(Sid sid, Permission permission) {
        if (sid instanceof PrincipalSid principal) {
          String user = principal.getPrincipal();
          if (!ACL.ANONYMOUS_USERNAME.equals(user)) {
            if (Jenkins.ADMINISTER.equals(permission) && adminUser.equals(user)) {
              return Boolean.TRUE;
            }
            if (Jenkins.READ.equals(permission)) {
              return Boolean.TRUE;
            }
          }
        }
        return null;
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
