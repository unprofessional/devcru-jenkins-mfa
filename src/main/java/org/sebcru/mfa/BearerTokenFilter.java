package org.sebcru.mfa;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import jenkins.security.ApiTokenProperty;
import jenkins.security.BasicHeaderApiTokenAuthenticator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * A21 — Bearer-API-token authenticator (home-grown, no new dependency).
 * Registered FIRST in the plugin-filter list, ahead of the {@link MfaFilter}
 * gate, so a Bearer request is authenticated — and the api-token request
 * attribute set — before the gate reads it.
 *
 * <h2>Why this exists (A15 ruling, mads 2026-08-19)</h2>
 * <p>jenkins-core 2.528.3 has <em>no</em> Bearer token authenticator: its
 * Spring Security chain only carries the {@code Basic} header token classes
 * ({@code BasicHeaderApiTokenAuthenticator}). A client that authenticates an
 * API call with a Bearer-style {@code Authorization} header (the convention a
 * wide range of tooling, CI, and the rest of the ecosystem expects) is
 * therefore seen as anonymous by core and — once the gate is live and a
 * token user is enrolled — would be bounced to the MFA page or denied. The
 * ruling (mads, 2026-08-19): build it, home-grown, no third-party dependency
 * (Spring Security is a {@code provided} transitive and Jenkins does not run
 * its web filter chain; pulling any library for this is rejected).
 *
 * <h2>The one hard constraint: a token carries no identity</h2>
 * <p>Unlike GitHub-style tokens, a Jenkins API token is an opaque random
 * value with no embedded user id (verified against
 * {@code jenkins.security.ApiTokenProperty}: the token is a {@code uuid:hash}
 * pair; the plain legacy form is a raw random string). The only way to know
 * <em>which</em> user's token to check — without scanning every user's
 * property on each request, which we refuse to do per request — is a
 * <strong>companion header that names the caller</strong>. This is an
 * explicit, documented client contract of our making (A21): the client sends
 * <pre>
 *   Authorization: Bearer &...n;
 *   X-Jenkins-User: &lt;user-id&gt;
 * </pre>
 * {@link #HEADER_USER} is that contract. A Bearer header without it (or a
 * blank either) is ignored — we do not fall back to an O(n) scan.
 *
 * <h2>Success = behave exactly like core's Basic token path</h2>
 * <p>On a matching token the filter reproduces the effective outcome core's
 * {@code BasicHeaderApiTokenAuthenticator} produces for the same user over
 * {@code Basic}: it sets the <strong>api-token request attribute</strong>
 * ({@code jenkins.security.BasicHeaderApiTokenAuthenticator}, value
 * {@code Boolean.TRUE}) — the <em>same</em> attribute and value the gate
 * already exempts — so the {@link MfaFilter} decision chain needs zero
 * change and the exemption contract is identical for Basic and Bearer, as
 * A15's original note promised. It <em>also</em> stores the resulting
 * {@link Authentication} in the {@link SecurityContextHolder} — the single
 * job Spring's (absent) Bearer filter would normally do. Because core reads
 * the current user via {@code Jenkins.getAuthentication2()} =
 * {@code SecurityContextHolder.getContext().getAuthentication()}, this makes
 * a Bearer request read as <em>that user</em> to the rest of the request,
 * not merely "gate-exempt".
 *
 * <h2>The public-API constraint (AMC), and why {@code matchesPassword}</h2>
 * <p>The token check runs through the <em>public</em>
 * {@code User.getById(id,false) → getProperty(ApiTokenProperty.class) →
 * matchesPassword(bearer)} idiom, for two reasons. First, the
 * <strong>access-modifier-checker</strong> (bound into {@code verify})
 * rejects calls to core-internal helpers
 * ({@code jenkins.security.BasicApiTokenHelper}) and the
 * {@code User.impersonate(UserDetails)} overload — a plugin may only touch
 * approved {@code @ClientApi}/{@code @Restricted(Beta)} surface, and those
 * internal seams are not on it; a first draft that delegated to them failed
 * the build. Second, using only the public surface means the check does not
 * depend on an internal helper that could shift across core versions.
 * {@code matchesPassword} is the same primitive the Basic path ultimately
 * relies on, reached through the public door.
 *
 * <h2>Fail-open on ANY mismatch (A21 step 6)</h2>
 * <p>Missing Bearer header, missing {@link #HEADER_USER}, a blank either
 * value, an unknown user, a wrong/blank token — or any {@link RuntimeException}
 * resolving the token — the filter touches <strong>nothing</strong>: no
 * attribute, no context change, the request passes to the rest of the chain
 * as anonymous. The gate applies exactly as for any anonymous request. A
 * non-matching Bearer attempt therefore never 401s (which would break the
 * web UI or a non-Bearer client), never 500s, and never confers
 * authentication — it reads as "no Bearer, carry on". This is the
 * security-critical half: a wrong Bearer token must be indistinguishable
 * from no token (no oracle), and must never be mistaken for a success.
 *
 * <h2>Registration order (why FIRST)</h2>
 * <p>{@code hudson.util.PluginServletFilter} walks its filter list in
 * insertion order (a plain {@code List}, iterated head-to-tail at serve time).
 * {@link DevcruMfaPlugin} adds this filter BEFORE {@link MfaFilter}, so for
 * any request it runs first: it authenticates (if a Bearer token is present
 * and valid) and sets the attribute, and only then does the gate see the
 * request and (correctly) exempt it. The reverse order would gate a Bearer
 * request before it was ever recognised, defeating the point.
 */
public final class BearerTokenFilter implements Filter {

  /** The companion header that names the caller (A21's documented client
   *  contract). A Bearer header without it is ignored (a token alone cannot
   *  be attributed to a user without an O(n) user scan). */
  public static final String HEADER_USER = "X-Jenkins-User";

  /** The {@code Authorization} scheme value this filter recognises. */
  private static final String BEARER_PREFIX = "bearer ";

  @Override
  public void init(FilterConfig filterConfig) {}

  @Override
  public void doFilter(ServletRequest request, ServletResponse response,
      FilterChain chain) throws IOException, ServletException {
    if (request instanceof HttpServletRequest http) {
      BearerCredentials creds = parseBearing(http.getHeader("Authorization"),
          http.getHeader(HEADER_USER));
      if (creds != null) {
        authenticateAsTokenUser(http, creds.userId(), creds.token());
        // Whatever authenticateAsTokenUser decided (authenticated or not),
        // the request continues: on a match the attribute + context are set
        // and the gate will exempt; on a mismatch nothing was touched and
        // the request is anonymous to everything downstream (fail-open).
      }
    }
    chain.doFilter(request, response);
  }

  @Override
  public void destroy() {}

  // -----------------------------------------------------------------
  // Seam 1 — PURE header parse (unit-tested; no Jenkins, no Spring needed).
  // -----------------------------------------------------------------

  /**
   * Parse the Bearer credentials out of the two request headers.
   *
   * <p>This is the one part of A21 that is pure string logic and therefore
   * unit-testable without a booted Jenkins: it decides, from the raw header
   * values alone, whether <em>this request is a Bearer token request at all</em>
   * and (if so) which user + which opaque token it claims. Nothing here talks
   * to a {@link hudson.model.User} or a token store — those are
   * {@link #authenticateAsTokenUser}’s job. Keeping the parse pure is what
   * lets the edge cases below be pinned cheaply in a plain JVM.
   *
   * @return the parsed {@link BearerCredentials}, or {@code null} if the
   *     request is NOT a usable Bearer request — every one of: no
   *     {@code Authorization} header; an {@code Authorization} that is not a
   *     (case-insensitive) {@code Bearer } scheme; a blank token after the
   *     scheme; no {@code X-Jenkins-User} header; or a blank user id.
   */
  static BearerCredentials parseBearing(String authorization, String userHeader) {
    if (authorization == null) {
      return null;
    }
    // Case-insensitive scheme match, per the ruling. Everything after the
    // literal "bearer " (any case) is the opaque token.
    if (!authorization.toLowerCase(java.util.Locale.ROOT).startsWith(BEARER_PREFIX)) {
      return null; // not a Bearer request (e.g. "Basic …" or none) — leave
                   // the core Basic path alone.
    }
    String token = authorization.substring(BEARER_PREFIX.length());
    if (token.isBlank()) {
      return null; // "Bearer " with no token — treat as not a Bearer request.
    }
    if (userHeader == null || userHeader.isBlank()) {
      return null; // a token with no named caller: we refuse the O(n) scan,
                   // so a bare Bearer is not a Bearer request for this filter.
    }
    return new BearerCredentials(userHeader, token);
  }

  /** The parsed caller: which user (from {@link #HEADER_USER}) and which
   *  opaque token (from the {@code Bearer} scheme) to check. */
  record BearerCredentials(String userId, String token) {}

  // -----------------------------------------------------------------
  // Seam 2 — the core-backed authenticate (IT-tested: needs a real user +
  // a real token). Never throws; returns whether it authenticated.
  // -----------------------------------------------------------------

  /**
   * If {@code bearerToken} is {@code userId}’s API token, make this request
   * read as that user (api-token attribute + {@link SecurityContextHolder});
   * otherwise touch nothing.
   *
   * <p>The check is the public idiom {@code User.getById(id, false) →
   * getProperty(ApiTokenProperty.class) → matchesPassword(bearer)}.
   * {@code getById(…, false)} returns {@code null} for an unknown id rather
   * than creating a user row (we must not manufacture a user just because a
   * Bearer request names one). On a token mismatch — including
   * {@code matchesPassword} throwing (e.g. a user whose property state cannot
   * be read) — we return {@code false} and leave the request untouched.
   *
   * @return {@code true} if the token matched and the request now reads as
   *     {@code userId}; {@code false} on ANY mismatch (unknown user, or wrong/
   *     blank token, or a runtime failure resolving the token) — in which
   *     case nothing on the request was changed and the request is anonymous
   *     with no api-token attribute set.
   */
  static boolean authenticateAsTokenUser(HttpServletRequest http, String userId,
      String bearerToken) {
    try {
      hudson.model.User user = hudson.model.User.getById(userId, false);
      if (user == null || user.getProperty(ApiTokenProperty.class) == null
          || !user.getProperty(ApiTokenProperty.class).matchesPassword(bearerToken)) {
        // Unknown user, no token property, or the token didn't match —
        // fail open: leave the request anonymous, indistinguishable from
        // "no Bearer sent" (no oracle).
        return false;
      }
      // Match — set the api-token request attribute the MfaFilter gate
      // already exempts, the SAME attribute + value core sets for the Basic
      // path, so the exemption contract is identical for Basic and Bearer.
      http.setAttribute(BasicHeaderApiTokenAuthenticator.class.getName(),
          Boolean.TRUE);
      // And the one step Spring's (absent) Bearer filter would do: put an
      // Authentication in the context so Jenkins.getAuthentication2() reads
      // the request as this user (symmetric with how core resolves "who am I"
      // after the Basic path). impersonate2() is the public Spring-flavoured
      // impersonation seam (returns a UsernamePasswordAuthenticationToken
      // named for this user, no current-user permission assertion).
      Authentication authn = user.impersonate2();
      SecurityContextHolder.getContext().setAuthentication(authn);
      return true;
    } catch (RuntimeException notAuthenticatable) {
      // Any failure resolving the token or the user (NPE from a malformed
      // property, an impersonation lookup the realm can't satisfy, …) is a
      // mismatch, not an error: fail open, anonymous, no 500. This catch is
      // the security-critical boundary — a Bearer attempt must never surface
      // as a server error and must never be mistaken for a success.
      return false;
    }
  }
}
