package org.sebcru.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link BearerTokenFilter#parseBearing(String, String)} — the
 * <em>pure</em> half of A21: deciding, from the two raw header values alone,
 * whether a request is a usable Bearer token request and (if so) which user
 * and which opaque token it claims.
 *
 * <h2>Why this file exists (and why it's a plain JVM test, no Jenkins)</h2>
 * <p>The A21 spec splits the Bearer authenticator into a pure header parse and
 * a core-backed check. The parse is pure string logic — it needs no {@link
 * hudson.model.User}, no token store, no booted Jenkins — so it is unit-tested
 * here in a plain JVM. The check (does this token actually belong to this
 * user) is <em>not</em> unit-testable in a plain JVM: {@code
 * ApiTokenProperty.matchesPassword} dereferences a {@code tokenStore} that is
 * only populated once a token has been generated for a saved user, which needs
 * a booted Jenkins — that half is locked down in the booted IT
 * ({@code MfaFilterIT.bearerTokenExemptFromGate}, real token via
 * {@code rule.createApiToken}). Pinning the parse here keeps the branchy,
 * edge-case-heavy logic (scheme casing, blank tokens, the missing-companion
 * rule) cheap to test and cheap to reason about, independently of the
 * expensive boot.
 *
 * <h2>The contract these tests pin (A21 step 1–2, step 6)</h2>
 * <p>
 * <ul>
 *   <li>A request is a Bearer request only when BOTH the {@code
 *       Authorization} header is a (case-insensitive) {@code Bearer <token>}
 *       with a non-blank token AND the companion {@code X-Jenkins-User} header
 *       names a non-blank user. Otherwise {@code parseBearing} returns
 *       {@code null} and the filter must leave the request exactly as it found
 *       it (fail-open, anonymous, no oracle) — see the IT for the wire
 *       consequence.</li>
 *   <li>The token is exactly the bytes after the literal {@code Bearer }
 *       (any case) — never trimmed, never re-parsed. The user id is exactly
 *       the raw companion header — never trimmed. This is what makes a wrong
 *       or blank token fail the later {@code matchesPassword} cleanly (no
 *       oracle) rather than being "corrected" into something it isn't.</li>
 *   <li>A {@code Basic} (or any non-Bearer) {@code Authorization} header is
 *       NOT a Bearer request for this filter — core's own Basic authenticator
 *       owns that path, and this filter must not touch it.</li>
 * </ul>
 *
 * <h2>Red → green note</h2>
 * <p>No defect was caught here (green on first run) — the value is pinning the
 * non-trivial branch logic of the parse (the case-sensitive prefix edge cases,
 * the blank-token and blank-user rules that implement "we refuse an O(n)
 * scan") before the booted IT exercises it, so the IT can trust the parse
 * contract instead of re-deriving it. Recorded honestly per AGENTS.md; a red
 * phase is not backfilled.
 */
class BearerTokenFilterTest {

  @Nested
  class ParseSeam {

    /**
     * WHAT: the happy path — a well-formed Bearer header plus a named caller
     * parses to exactly that user + token, with neither value altered.
     * <p>BDD:
     * <pre>
     * GIVEN an Authorization header "Bearer <40-hex-looking token>" and a
     *       companion X-Jenkins-User header naming a real-looking id
     * WHEN  parseBearing is applied to both
     * THEN  it returns a BearerCredentials whose userId is exactly the
     *       companion header and whose token is exactly the bytes after
     *       "Bearer " — unchanged, not trimmed, not re-parsed
     * </pre>
     * <p>WHY/SOLVES: the later {@code matchesPassword} check relies on the
     * token being the <em>exact</em> client-supplied string. If the parse
     * trimmed or otherwise mangled it, a legitimately-valid token could fail
     * (a working token mysteriously stops working) — or worse, a malformed
     * one could be "corrected" into a match. Pinning raw pass-through makes
     * the parse a pure extractor, nothing more.
     */
    @Test
    void wellFormedBearerWithCompanionParsesToUserAndToken() {
      BearerTokenFilter.BearerCredentials c =
          BearerTokenFilter.parseBearing("Bearer abcdef0123456789", "mads-user");
      assertEquals("mads-user", c.userId());
      assertEquals("abcdef0123456789", c.token());
    }

    /**
     * WHAT: the scheme match is case-insensitive, per the ruling.
     * <p>BDD:
     * <pre>
     * GIVEN an Authorization header whose scheme is "BEARER " (all caps),
     *       "bEarEr " (mixed), or "bearer " (lower), each with a token and a
     *       companion user
     * WHEN  parseBearing is applied
     * THEN  all three parse to the same BearerCredentials (same user, same
     *       token) — only the scheme case differs
     * </pre>
     * <p>WHY/SOLVES: real clients don't agree on the case of the scheme
     * (many emit {@code Bearer }, some {@code BEARER }). A case-sensitive
     * prefix check would silently treat a valid, differently-cased Bearer
     * request as "not a Bearer request" and drop it to the gate — exactly the
     * "MFA never works for this client, and there's no error anywhere"
     * failure the MFA doc warns about. The ruling says case-insensitive; this
     * pins it for every case a client actually emits.
     */
    @Test
    void schemeMatchIsCaseInsensitive() {
      BearerTokenFilter.BearerCredentials lower =
          BearerTokenFilter.parseBearing("bearer abc", "u");
      BearerTokenFilter.BearerCredentials upper =
          BearerTokenFilter.parseBearing("BEARER abc", "u");
      BearerTokenFilter.BearerCredentials mixed =
          BearerTokenFilter.parseBearing("bEarEr abc", "u");
      assertEquals("abc", lower.token());
      assertEquals("abc", upper.token());
      assertEquals("abc", mixed.token());
      assertEquals(lower.userId(), upper.userId());
      assertEquals(lower.userId(), mixed.userId());
    }

    /**
     * WHAT: a {@code Basic} (or any non-Bearer) {@code Authorization} is NOT
     * a Bearer request for this filter and is returned as {@code null}.
     * <p>BDD:
     * <pre>
     * GIVEN an Authorization header using the Basic scheme (the one core's
     *       own BasicHeaderApiTokenAuthenticator owns) and a companion user
     * WHEN  parseBearing is applied
     * THEN  it returns null — this filter claims no interest in a Basic request
     * </pre>
     * <p>WHY/SOLVES: core already authenticates Basic API-token requests and
     * sets the api-token attribute itself (the green {@code
     * apiTokenExemptFromGate} IT proof). If this filter also tried to parse a
     * Basic header as Bearer, it would mis-attribute the Basic credentials
     * (treating the base64 blob as a "Bearer token" for the companion user)
     * and, worse, set the api-token attribute on a request where Basic auth
     * should fail — turning a genuine Basic-auth <em>rejection</em> into a
     * false {@code 200}. The cleanest guarantee is "this filter only ever
     * claims Bearer"; everything else is someone else's job.
     */
    @Test
    void basicSchemeIsNotABearerRequest() {
      assertNull(BearerTokenFilter.parseBearing("Basic dWFzZXI6cGFzcw==", "mads-user"));
    }

    /**
     * WHAT: a {@code Bearer } scheme with a blank token is not a usable Bearer
     * request (null).
     * <p>BDD:
     * <pre>
     * GIVEN an Authorization header "Bearer   " (scheme + only whitespace)
     *       and a companion user header
     * WHEN  parseBearing is applied
     * THEN  it returns null — there is no token to check
     * </pre>
     * <p>WHY/SOLVES: a bare {@code "Bearer "} is a malformed or stripped
     * header. If it were treated as a Bearer request with an empty token, the
     * later {@code matchesPassword("")} would be called — a needless trip to
     * the user/token lookups, and a subtle "is an empty string a valid API
     * token?" question. Returning null here sidesteps both: the request is
     * simply not a Bearer request, and the gate/client behaves as if no Bearer
     * was sent (fail-open, no oracle).
     */
    @Test
    void bearerWithBlankTokenIsNotABearerRequest() {
      assertNull(BearerTokenFilter.parseBearing("Bearer   ", "mads-user"));
    }

    /**
     * WHAT: the missing-companion rule — a Bearer header with NO
     * {@code X-Jenkins-User} header is not a Bearer request for this filter
     * (null).
     * <p>BDD:
     * <pre>
     * GIVEN an Authorization header "Bearer <token>" and a NULL X-Jenkins-User
     *       header (the client did not name a caller)
     * WHEN  parseBearing is applied
     * THEN  it returns null — a token with no named caller cannot be attributed
     *       without an O(n) scan of every user, which the ruling forbids
     * </pre>
     * <p>WHY/SOLVES: this is the load-bearing decision that makes A21
     * implementable at all. A Jenkins token carries no embedded identity, so
     * without the companion header the only way to find its owner is to scan
     * every {@code User} on every request — O(n) per request, which the ruling
     * explicitly refuses to do. The correct behaviour is to treat
     * "a Bearer with no named caller" as "not a Bearer request" (null), so the
     * request falls through to the gate as anonymous, and the client gets no
     * success and no error — it just isn't authenticated. This is the "no
     * oracle" guarantee: a client can't probe for a valid token by observing
     * whether a missing-companion request is treated differently.
     */
    @Test
    void bearerWithoutCompanionIsNotABearerRequest() {
      assertNull(BearerTokenFilter.parseBearing("Bearer abcdef0123", null));
      // And a blank companion is the same as no companion (we don't trim).
      assertNull(BearerTokenFilter.parseBearing("Bearer abcdef0123", "   "));
    }

    /**
     * WHAT: no {@code Authorization} header at all is not a Bearer request
     * (null) — regardless of the companion header.
     * <p>BDD:
     * <pre>
     * GIVEN a NULL Authorization header (a plain unauthenticated request) and
     *       a non-blank companion user header
     * WHEN  parseBearing is applied
     * THEN  it returns null — there is no Authorization to parse
     * </pre>
     * <p>WHY/SOLVES: the overwhelming majority of requests to Jenkins are
     * plain browser/form POSTs with no {@code Authorization} header at all.
     * This filter must treat them as "not a Bearer request" in O(1) and do
     * nothing (no user lookup, no context read) so the hot path stays free and
     * the gate sees exactly the anonymous request it would have seen if this
     * filter didn't exist. If this returned non-null on a plain request, the
     * filter would start touching the security context on every unauthenticated
     * request — a needless per-request cost and a real risk of disturbing
     * anonymous request handling.
     */
    @Test
    void missingAuthorizationHeaderIsNotABearerRequest() {
      assertNull(BearerTokenFilter.parseBearing(null, "mads-user"));
    }

    /**
     * WHAT: the companion user id is passed through raw, not trimmed or
     * otherwise altered.
     * <p>BDD:
     * <pre>
     * GIVEN a valid Bearer token and a companion header " mads " (with
     *       surrounding whitespace — a real, if sloppy, client)
     * WHEN  parseBearing is applied
     * THEN  the BearerCredentials.userId is exactly " mads " — the raw header,
     *       not "mads" — so the later User.getById is called with the
     *       client's exact bytes and an id that doesn't exist resolves to the
     *       unknown-user path (fail-open), never to a silently-different user
     * </pre>
     * <p>WHY/SOLVES: this matters for the "no oracle" and "no
     * mis-attribution" invariants. If the parse trimmed the user id, a client
     * sending {@code " mads "} would be silently checked against {@code mads}
     * — and could <em>succeed</em> at authenticating as {@code mads} despite
     * never having named the user correctly. That's a mis-attribution: a
     * request that did not correctly identify its caller ends up acting as a
     * real user. Pinning raw pass-through means only an exact match on the
     * user id (as {@code User.getById} sees it) authenticates; anything else
     * is a clean unknown-user fail, with no silent "close enough" success.
     */
    @Test
    void userIdIsPassedThroughRawNotTrimmed() {
      BearerTokenFilter.BearerCredentials c =
          BearerTokenFilter.parseBearing("Bearer abc", " mads ");
      assertEquals(" mads ", c.userId());
    }
  }
}
