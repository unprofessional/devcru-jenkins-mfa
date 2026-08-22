package org.sebcru.mfa;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import jenkins.security.BasicHeaderApiTokenAuthenticator;
import org.sebcru.mfa.DevcruMfaConfig.Policy;
import org.sebcru.mfa.gate.TrustStore;
import org.springframework.security.core.Authentication;

/**
 * The MFA gate (Task 7) — the servlet filter that bounces a
 * password-authenticated, still-MFA-unverified user to the second-factor
 * page at {@code <root>/mfa}.
 *
 * <h2>The decision chain (the plan's §Task 7, exact order)</h2>
 * <pre>
 *  0. kill switch: DEVCRU_MFA_OFF=1 env OR policy == OFF            → PASS
 *  1. not an HttpServletRequest                                     → PASS
 *  2. API-token request (BasicHeaderApiTokenAuthenticator attr)     → PASS
 *  3. no authenticated user (core login flow owns it)               → PASS
 *  4. ERROR dispatch (core error page)                              → PASS
 *  5. path allow-list (login/static/skins, incl. the MFA page)      → PASS
 *  6. policy == OFF (belt-and-braces with 0)                        → PASS
 *  7. user on the exemption list                                    → PASS
 *  8. no MfaUserProperty or factors not enrolled                    → PASS
 *  9. session is MFA-verified OR the remembered-device trust is live → PASS
 *  otherwise                                                        → 302 to the MFA page
 * </pre>
 *
 * <p>The plan numbers the allow-list "step 4" and the policy recheck "step 5";
 * this file inserts the ERROR-dispatch pass as its own step 4 (see below) and
 * keeps every other step in the plan's relative order. The ERROR pass is
 * required in practice: without it, every core error page (a 404 on a typo'd
 * URL, a 500 anywhere) would be 302'd to the MFA page, and the MFA page's own
 * failure states would recurse into the gate.
 *
 * <h2>Fail-closed on unknown request state</h2>
 * <p>If extracting the decision inputs throws an
 * {@link RuntimeException} that none of the named steps own (a half-booted
 * Jenkins, an unexpected request shape), the filter redirects to the MFA page
 * rather than passing the request through. A 302 to the second-factor page is
 * the worst-case inconvenience for a legitimate user (one code to type); a
 * silent pass is a hole in the gate, and the difference is the entire point
 * of the class.
 *
 * <h2>The two mads-signed trust semantics (do not re-litigate)</h2>
 * <ol>
 *   <li><b>A live, MFA-verified session is trusted for its
 *       lifetime.</b> There is deliberately <em>no</em> per-request expiry of
 *       an active session — "re-auth every N hours" churn was the exact UX sin
 *       of the plugin this one replaces. The session flag is therefore a pure
 *       PASS, not a freshness check.</li>
 *   <li><b>{@code trustedUntilMs} governs <em>future</em> logins only.</b>
 *       It is what lets a browser inside the remember-window skip the
 *       second-factor prompt on its <em>next</em> login. Step 9 is a
 *       <em>disjunction</em> — verified-this-session OR trusted-for-
 *       this-login — because each instrument covers a different moment:
 *       the flag covers the session a user is in, the trust record covers the
 *       sessions they have not started yet.</li>
 * </ol>
 *
 * <h2>API findings verified against jenkins-core 2.528.3 (2026-08-18)</h2>
 * <ul>
 *   <li><b>No {@code JenkinsUtil} exists in this core</b> (the plan sketch's
 *       {@code JenkinsUtil.getCurrentUser()} is unimplementable as written).
 *       The current-user idiom is {@code User.get2(Jenkins.getAuthentication2())},
 *       extracted here as the static {@link #findCurrentUser()} so the gate
 *       and the controller share one seam (see {@code MfaController}).
 *       {@code get2()} returns null for an {@code AnonymousAuthenticationToken}
 *       (verified via bytecode), which is exactly step 3's predicate.</li>
 *   <li><b>API-token detection:</b> the plan named
 *       {@code hudson.security.*}; in this LTS line the class is
 *       {@code jenkins.security.BasicHeaderApiTokenAuthenticator}, and it
 *       marks a token-authenticated request with a servlet attribute whose
 *       key is <em>its own class name</em>
 *       ({@code BasicHeaderApiTokenAuthenticator.class.getName()}) and whose
 *       value is {@link Boolean#TRUE} (verified against the bytecode:
 *       {@code ldc class; Class.getName; iconst_1; Boolean.valueOf;
 *       setAttribute}). The attribute is set <em>inside</em> Spring's security
 *       chain, which runs ahead of the plugin-filter position, so it is
 *       present by the time this filter sees the request. Task 8's IT re-
 *       pins this against a real boot.</li>
 *   <li><b>Registration is jakarta-only:</b> this core is post-javax
 *       (servlet 5.0), so the filter implements {@code jakarta.servlet.Filter}
 *       and is registered through
 *       {@code hudson.util.PluginServletFilter.addFilter(jakarta…)}.</li>
 * </ul>
 *
 * <h2>Unit-testability seam (deliberate, documented)</h2>
 * <p>The security-relevant logic is a pure function, {@link #decision}, over
 * plain data (policy, exempt flag, not-enrolled flag, session-verified flag,
 * trust-live flag, error-dispatch flag, path shape, api-token flag). It is
 * package-private so {@code FilterLogicTest} can pin the full table in a
 * plain JVM with no Jenkins, no HTTP, no clock, and no {@link TrustStore}.
 * Two inputs the decision depends on but must not <em>own</em> are
 * pre-computed by the {@code doFilter} glue and handed in as booleans: the
 * kill switch ({@link #off}, checked before {@code decision} is even called)
 * and the trust check (it needs a live {@link TrustStore} + a clock, so it is
 * computed once per request and passed as the {@code trustLive} argument).
 * The remaining glue — reading session/config/user/path off a live
 * {@code HttpServletRequest} and writing the 302 — is exercised for the happy
 * paths by the plugin's {@code InjectedTest} live-Jenkins boot (Task 7), with
 * the dedicated end-to-end {@code MfaFilterIT} (A5's redirect assertion and
 * the API-token attribute re-pin) landing in Task 8.
 */
public final class MfaFilter implements Filter {

  /** The {@code ?redirect=…} query parameter the gate hands to the MFA page. */
  static final String REDIRECT_PARAM = "redirect";

  // Path allow-list (step 4/5): the authentication flow itself, the MFA page,
  // Jenkins' own static resource routes, and the skins/plugins theme assets a
  // browser always fetches on first paint. Anything not covered stays gated.
  // Note: "/securityRealm" is NOT on this list any more (Task 8, Defect B):
  // under a ModelObject-backed local realm it is the realm's own mount tree,
  // which is already anonymous-reachable through step 3 — and the MFA page
  // moved to the free single segment "/mfa" precisely because that prefix
  // is squatted on every production local-realm deployment.
  private static final String[] ALLOWED_PREFIXES = {
    "/login", "/logout", "/postlogout", "/logoutpost",
    "/signup",
    "/j_acegi",
    "/mfa",                // the MFA page itself (Defect B: /securityRealm/*
                           // is the live realm's own mount, not ours)
    "/static/", "/images/", "/adjuncts/", "/scripts/", "/css/", "/crumbIssuer",
    // THIS plugin's own static assets (live incident 2026-08-22 round 4): the
    // gate page's verify-form JS is served from /plugin/devcru-mfa/ (CSP
    // script-src 'self' forbids inline scripts). Without this prefix a gated
    // session's request for mfa-gate.js 302s back to the gate page, the
    // "script" comes back as text/html, Chrome refuses to execute it, and the
    // Verify button is dead — the gate bricks its own key. Scoped to THIS
    // plugin's assets only; other plugins' paths stay gated.
    "/plugin/devcru-mfa/"
  };

  /** Stateless; one process-wide instance lives in {@link DevcruMfaPlugin}. */
  private static final TrustStore TRUST_STORE = new TrustStore();

  // ---------------------------------------------------------------------
  // The glue (Task 8 territory) — keep small and obvious.
  // ---------------------------------------------------------------------

  @Override
  public void init(FilterConfig filterConfig) {
    // Nothing to initialise: the filter is stateless and the trust store is
    // a shared static. Present so the Filter contract is explicit.
  }

  @Override
  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
      throws IOException, ServletException {
    // Step 0 — the kill switch is checked BEFORE any other work: a setting,
    // not an uninstall. The env half ("1" in DEVCRU_MFA_OFF) covers the
    // incident where even reading the config is unsafe; the policy half
    // covers the normal admin path.
    DevcruMfaConfig cfg = DevcruMfaConfig.currentSafe();
    if (off(System.getenv("DEVCRU_MFA_OFF"), cfg.getPolicy())) {
      chain.doFilter(req, res);
      return;
    }
    // Steps 1–9.
    passUnlessGated(req, res, chain, cfg);
  }

  /**
   * Step 0's pure half: the kill switch, as a function of its two inputs —
   * extracted so the OR semantics are unit-pinned without JVM env access
   * (plan line 581: "no JVM env in unit tests"; the seam is
   * tested-by-construction + this method).
   *
   * @param devcruMfaOffEnv the value of the env var (null when unset)
   * @param policy          the live policy
   * @return true iff the gate must let the request through untouched
   */
  static boolean off(String devcruMfaOffEnv, Policy policy) {
    return "1".equals(devcruMfaOffEnv)
        || policy == null || policy.equals(Policy.OFF);
  }

  private void passUnlessGated(ServletRequest req, ServletResponse res, FilterChain chain,
      DevcruMfaConfig cfg)
      throws IOException, ServletException {
    if (!(req instanceof HttpServletRequest http) || !(res instanceof HttpServletResponse rsp)) {
      // Step 1 — non-HTTP request (e.g. an internal servlet dispatch the
      // servlet spec routes through a Filter): nothing to gate.
      chain.doFilter(req, res);
      return;
    }
    // Step 2 — API-token request: CI keeps working (security decision 1).
    boolean apiToken = Boolean.TRUE.equals(http.getAttribute(
        BasicHeaderApiTokenAuthenticator.class.getName()));
    // Step 3 — no authenticated user: the core login flow owns that path.
    hudson.model.User user = findCurrentUser();
    // Step 4 — ERROR dispatch: core is rendering its own error page; the
    // error page is not a gated resource and must not be bounced (recursion
    // guard for "404 → MFA page → 404 → …").
    boolean errorDispatch = http.getDispatcherType() == DispatcherType.ERROR;
    String path = targetPath(http);
    String referer = http.getHeader("Referer");
    String explicitRedirect = http.getParameter(REDIRECT_PARAM);

    MfaFilterDecision d;
    try {
      Policy policy = cfg.getPolicy();
      long now = System.currentTimeMillis();
      // READ-ONLY: the hot path must never call getOrCreate() — that writes
      // config.xml on every gated request (audit §5 Domain-1 rule).
      MfaUserProperty prop = user == null ? null : user.getProperty(MfaUserProperty.class);
      boolean sessionVerified = Boolean.TRUE.equals(sessionVerified(http));
      // prop is null for an anonymous / no-User request: the trust check
      // must NOT run on a null property (TrustStore.isTrusted reads
      // prop.getTrustedUntilMs() — NPE otherwise). A null property always
      // means "no trust"; that case PASSes at step 8 as unenrolled.
      boolean trustLive = prop != null && TRUST_STORE.isTrusted(prop, cfg, now);
      d = decision(policy,
          cfg.isUserExempt(user == null ? null : user.getId()),
          prop == null || !prop.isMfaEnabled(), sessionVerified, trustLive,
          errorDispatch, path, apiToken);
    } catch (RuntimeException unknown) {
      // Fail closed — see class doc. A user-facing 302 beats a hole in the
      // gate when the request state is one the named steps do not cover.
      redirect(http, rsp, null);
      return;
    }
    if (d == MfaFilterDecision.PASS) {
      chain.doFilter(req, res);
    } else {
      // Step 9 — bounce to the second-factor page, carrying where the user
      // was actually going so post-verify can send them there (A3: the
      // ?redirect= parameter is the canonical carrier, not the Referer).
      redirect(http, rsp, resolveTarget(explicitRedirect, referer,
          http.getServerName(), String.valueOf(http.getServerPort()),
          http.getContextPath()));
    }
  }

  /**
   * The "back to where you were" carrier for the gate's 302. The
   * {@code ?redirect=} query parameter is canonical over {@code Referer}
   * (A3 ruling, 2026-08-18): a browser POSTing the MFA form carries the MFA
   * page's <em>own</em> URL as its Referer, so a Referer-only contract would
   * send the user back to the MFA page after a successful verify — an
   * immediate re-prompt loop. The parameter is present on the GET that
   * renders the page; both inputs flow through the single
   * {@link MfaController#resolveRedirectTarget} validator, so there is one
   * open-redirect boundary, not two.
   *
   * @param redirectParam the raw {@code ?redirect=…} value (may be null)
   * @param referer       the {@code Referer} header value (may be null)
   * @param host          the site's host name ({@code getServerName})
   * @param port          the site's port ({@code getServerPort})
   * @param contextPath   the Jenkins context path ("" for root-installed)
   * @return an already-validated in-site path (or the site root) — never the
   *         raw input, so this seam cannot be an open redirect by itself
   */
  static String resolveTarget(String redirectParam, String referer,
      String host, String port, String contextPath) {
    String input = (redirectParam == null || redirectParam.trim().isEmpty())
        ? referer : redirectParam;
    return MfaController.resolveRedirectTarget(input, host, port, contextPath);
  }

  // ---------------------------------------------------------------------
  // The pure decision (unit-tested: see FilterLogicTest).
  // ---------------------------------------------------------------------

  /** The gate's two outcomes. */
  enum MfaFilterDecision {
    /** The request proceeds to the application. */
    PASS,
    /** The request is 302'd to the MFA page. */
    REDIRECT
  }

  /**
   * The full decision table as a pure function.
   *
   * <p>Not modelled here (doFilter concerns, see their steps in the class
   * doc): step 0's kill-switch inputs (checked <em>before</em> this call —
   * the env-var and policy-OFF short-circuits), and step 1's HTTP-request
   * type check. Step 3 (no authenticated user) needs no input: a null user
   * has no {@code MfaUserProperty}, flows through as {@code notEnrolled},
   * and PASSes at step 8 — the core login flow owns the anonymous path.
   * The trust check is pre-computed by the caller (it needs a live
   * {@code TrustStore} + {@code now}); this function takes its boolean.
   *
   * @param policy          the live policy (OFF → step 0/6 pass)
   * @param exempt          the user is on the exemption list (step 7)
   * @param notEnrolled     the user has no MFA factors enrolled (step 8);
   *                        unenrolled users are never hard-locked
   * @param sessionVerified the session flag is set (step 9, first operand)
   * @param trustLive       the remembered-device trust is live at {@code now}
   *                        (step 9, second operand — OR, see class doc)
   * @param errorDispatch   this is a core ERROR dispatch (step 4)
   * @param requestPath     the request URI relative to the context path (step 5's
   *                        allow-list input; null/empty is not allowed)
   * @param apiToken        the API-token request attribute is Boolean.TRUE
   *                        (step 2)
   * @return PASS or REDIRECT
   */
  static MfaFilterDecision decision(Policy policy,
      boolean exempt, boolean notEnrolled, boolean sessionVerified,
      boolean trustLive, boolean errorDispatch, String requestPath,
      boolean apiToken) {
    // 0. kill switch — the policy-OFF half of step 0; the env-var half is
    //    short-circuited before this call in doFilter.
    if (policy == null || policy.equals(Policy.OFF)) {
      return MfaFilterDecision.PASS;
    }
    // 2. API token.
    if (apiToken) {
      return MfaFilterDecision.PASS;
    }
    // 4. ERROR dispatch.
    if (errorDispatch) {
      return MfaFilterDecision.PASS;
    }
    // 5. path allow-list.
    if (isAllowedPath(requestPath)) {
      return MfaFilterDecision.PASS;
    }
    // 6. policy recheck (belt-and-braces with 0 — a regression that reorders
    //    the chain still lands here, not in a gated request).
    if (!policy.equals(Policy.REQUIRED)) {
      return MfaFilterDecision.PASS;
    }
    // 7. exemption list.
    if (exempt) {
      return MfaFilterDecision.PASS;
    }
    // 8. no factors enrolled: nobody is hard-locked before they opt in.
    if (notEnrolled) {
      return MfaFilterDecision.PASS;
    }
    // 9. verified this session — OR — trusted for this login (see class doc
    //    for the two mads-signed semantics; this is the disjunction that
    //    makes both work at once).
    if (sessionVerified || trustLive) {
      return MfaFilterDecision.PASS;
    }
    // No pass condition held: gate it.
    return MfaFilterDecision.REDIRECT;
  }

  /** Step 5's prefix test. A null/blank path is not allowed (fail closed). */
  private static boolean isAllowedPath(String requestPath) {
    if (requestPath == null || requestPath.isEmpty()) {
      return false;
    }
    String p = requestPath;
    if (p.charAt(0) != '/') {
      p = "/" + p;
    }
    for (String prefix : ALLOWED_PREFIXES) {
      if (p.startsWith(prefix)) {
        return true;
      }
    }
    return false;
  }

  // ---------------------------------------------------------------------
  // doFilter-only helpers (not part of the pure decision).
  // ---------------------------------------------------------------------

  /**
   * The current authenticated user, or null. Extracted as a static so the
   * gate and the controller use the <em>same</em> seam — one definition of
   * "who is sitting in this request", shared. (A1: the controller's private
   * {@code currentUser()} is this method; the controller delegates to it.)
   * Mirrors {@code MfaController.currentUser()}: {@code getAuthentication2()}
   * is contractually non-null (System auth when nobody is logged in) and
   * {@code User.get2()} returns null for the anonymous token, so the
   * try/catch is the whole "bootstrap / no Jenkins" guard.
   */
  static hudson.model.User findCurrentUser() {
    try {
      Authentication authn = jenkins.model.Jenkins.getAuthentication2();
      return hudson.model.User.get2(authn);
    } catch (RuntimeException never) {
      // Early bootstrap / no Jenkins: treat as anonymous (step 3 → PASS).
      return null;
    }
  }

  private static Object sessionVerified(HttpServletRequest http) {
    HttpSession session = http.getSession(false);
    return session == null ? null : session.getAttribute(MfaController.VERIFIED_ATTR);
  }

  /**
   * The request's in-site path for the allow-list test: the request URI
   * minus the context path (e.g. "/jenkins/mfa" at ctx
   * "/jenkins" → "/mfa"), folded with the query string so a
   * "path?x=y" request is tested on its full form.
   *
   * <p><b>Why not {@code getServletPath()}:</b> on the Jenkins 2.528.3
   * servlet stack (embedded Jetty, Stapler dispatch) {@code getServletPath()}
   * returns an empty string for gated requests, so the allow-list test
   * would run against "/" and the MFA page itself would 302 to itself
   * forever ("Too many redirects" — caught by the Task 8 IT, 2026-08-19).
   * {@code getRequestURI()} − context path is the portable, spec-defined
   * decomposition and is what {@code MfaController} already resolves from.
   * A null/odd URI degrades to "/" — the fail-closed default.
   */
  private static String targetPath(HttpServletRequest http) {
    String uri = http.getRequestURI();
    String ctx = http.getContextPath();
    String base;
    if (uri == null || uri.isEmpty()) {
      base = "/";
    } else if (ctx != null && !ctx.isEmpty() && uri.startsWith(ctx)) {
      String rest = uri.substring(ctx.length());
      base = rest.isEmpty() ? "/" : rest;
    } else {
      base = uri;
    }
    String qs = http.getQueryString();
    return (qs == null || qs.isEmpty()) ? base : base + "?" + qs;
  }

  /**
   * The 302: Location = &lt;context&gt;/mfa?redirect=&lt;validated&gt;.
   * (Defect B, 2026-08-19: the page moved from /securityRealm/mfa to /mfa —
   * under HPSR the realm owns the top-level securityRealm mount.)
   * Terminal — the chain is deliberately not called past the redirect; the
   * request is consumed by it.
   */
  private static void redirect(HttpServletRequest http, HttpServletResponse rsp,
      String validatedTarget) throws IOException {
    String target = (validatedTarget == null) ? "/" : validatedTarget;
    String ctx = (http.getContextPath() == null) ? "" : http.getContextPath();
    rsp.setHeader("Cache-Control", "no-cache,no-store,must-revalidate");
    rsp.setStatus(HttpServletResponse.SC_FOUND);
    rsp.sendRedirect(ctx + "/mfa?" + REDIRECT_PARAM + "=" + encode(target));
  }

  /**
   * Percent-encode a URI component for the query string, but leave the
   * unreserved set and the "/" character as-is so a plain in-site path
   * ("/job/web/") stays human-readable and only genuinely special bytes get
   * encoded. Standard {@link URLEncoder} is form-encoded (space → '+'), so
   * convert '+' back to '%20' for URI correctness.
   */
  private static String encode(String s) {
    if (s == null || s.isEmpty()) {
      return "";
    }
    boolean needsEncoding = false;
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      boolean unreserved = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
          || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '/' || c == '~';
      if (!unreserved) {
        needsEncoding = true;
        break;
      }
    }
    if (!needsEncoding) {
      return s;
    }
    return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
  }

  @Override
  public void destroy() {
    // Stateless; nothing to release. The registration itself (the filter's
    // slot in PluginServletFilter's list) is owned by DevcruMfaPlugin's
    // @Terminator, which calls removeFilter with an equivalent instance.
  }
}
