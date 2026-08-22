# Post-rollout report: devcru-mfa live fixes (2026-08-22)

**Audience:** Seb — read this as analysis, not as a scorecard.
**From:** Moldy (deployer + the eight rounds of fixes below)
**Subject:** Everything that had to be fixed *after* your work passed review, and what each one says about the design process that produced it.

---

## The headline

Your plugin shipped with **99 green tests, SpotBugs clean, an approved review, and a CI-artifact build** — and it was **unusable in a real browser until four rounds of live hotfixes**, with four more defects after that. mads found every single one by clicking around for a few minutes.

That is not a testing failure. The tests did exactly what they were asked to do. It is a **coverage-of-reality failure**: every defect lived in a layer your process never touched — a real browser, a real CSP, a real theme, a real authenticator app, a real gated session, a real restart. Your harness was hermetically sealed from every dimension where the bugs existed.

Also be clear-eyed about what held: the gate's core logic, the fail-closed posture, the seam architecture, the kill switch, the error-code contracts, the A23 authorization work — all sound. Nothing below is "the security design was bad." The security design was good. What was missing is everything between the security design and a human being looking at a screen.

---

## Round-by-round, organized by concern layer

### Layer 1 — Integration with core: you tested your code, not your contract with Jenkins

**Round 1a — SAVE 500 (`NoStaplerConstructorException`).** `MfaUserProperty`'s no-arg constructor had no `@DataBoundConstructor`. Fresh-user SAVE goes through core's descriptor databinding — a path your tests never submitted. One annotation fixed it.

**Round 1b — Generate button dead.** `config.jelly` read `${it.mfaCrumbField}` etc., but core's security include binds `it=targetUser, descriptor=descriptor`. The page rendered the literal string `"mfaBaseUrl"` and your JS fetched garbage URLs. Your IT asserted the page *renders*. It never asserted the bindings *resolve* — render-presence is not render-correctness.

**Round 1c — Latent data loss.** Core's default `reconfigure()` rebuilds the property from form JSON, which would have wiped an enrolled user's TOTP seed on any profile SAVE. You never asked: *what does core do with my property when the user saves unrelated settings?* A plugin property is not an island; core has opinions about it that you must read before you write yours.

**The layer lesson:** Integration bugs don't live in your code. They live in the handshake between your code and the host. You verified your side of the handshake by reading your own code. The only way to verify the other side is to exercise it: submit the real form, through the real page, the way core actually dispatches it.

### Layer 2 — Browser security policy: you assumed the browser was a blank page

**Round 2 — CSP killed all inline JS.** Jenkins ships `script-src 'report-sample' 'self'`. Both your section and your gate page used inline `<script>` blocks, so neither ever executed. The gate one was a **lockout at first real verification** — the plugin would have bricked itself in production the moment anyone needed it, because the form's JS never loaded.

The question you never asked: *what security policy does the host page run under?* You wrote JS as if you owned the page. You don't — you're a guest inside Jenkins' CSP, and Jenkins' CSP is not negotiable. Static files under `webapp/` were the only legal path, and they were the only path you didn't try.

### Layer 3 — HTTP contract: self-contained means self-responsible

**Round 3 — the gate page had no Content-Type.** Core pages get theirs from `l:layout` → `l:view`'s `<st:contentType>`. Your gate page deliberately skipped `l:view` (a fine design decision — a standalone doc), but then inherited **nothing**: no Content-Type, and with `nosniff` set, the browser rendered your beautiful gate page as raw HTML source, `text/plain`.

The pattern: when you step outside a framework's conventions, you inherit its responsibilities too. Skipping the layout means declaring *everything* the layout used to give you. Your tests fetched the page and checked its body — no real browser ever rendered it, so nothing ever noticed the header was missing. This defect shipped the day the page was written and waited, dormant, for the first enrolled user.

### Layer 4 — Gate architecture: the gate did not know it had a body

**Round 4 — the gate bounced its own JavaScript.** CSP forced your JS into a static file at `/plugin/devcru-mfa/mfa-gate.js`. Your gate's `ALLOWED_PREFIXES` allow-listed `/static/`, `/adjuncts/`, `/mfa`, the auth flow — but not `/plugin/devcru-mfa/`. So a gated session's request for the gate's *own verify-form script* 302'd back to the gate page; the "script" arrived as `text/html`; Chrome's strict MIME check refused to execute it; the Verify button was dead.

This is the most architectural one of the eight. The allow-list was designed against an abstract list of "paths a login flow needs" — never against the question *what does my gate itself need to function?* The gate's JS is part of the gate. A filter that can't load its own UI is not a gate, it's a lock with no keyhole.

Diagnostic note for your analysis: this one was invisible to me too, at first — my curl probes used an API token, which is gate-exempt. It only reproduced in a genuinely gated browser session. Remember that asymmetry: **a probe with elevated privileges cannot reproduce a subordinate's problem.**

### Layer 5 — UX state machine: one timer, two meanings

**Round 5 — the resend cooldown locked the Verify button.** After Send-code, your JS armed one shared `lockUntil` timer that disabled *both* buttons for the ~60s resend cooldown. Verifying doesn't issue a code — it consumes one. But the user who received the email in two seconds typed the code and stared at a dead Verify button for the rest of the minute.

The thoughtlessness is not "off by one button." It is that two different lock semantics — *rate-limit the issuance of new codes* and *block verification attempts* — were modeled as one mechanism because one variable was convenient. Every shared piece of state is a claim that the things sharing it mean the same thing. Here they didn't, and the user paid for the conflation.

You also never walked the journey in real time: *email arrives instantly → user types code → clicks Verify.* Walk your user journeys with a stopwatch, not just a state diagram.

### Layer 6 — External interop: the phone is the oracle, not the test suite

**Round 6 — `otpauth://otp/` instead of `otpauth://totp/`.** Authy validates the URI type and refused to import; Google Authenticator is lenient and would have hidden it. mads hit the strict one.

Here is the part to sit with: **the wrong string was pinned in three tests.** `MfaProfileSeamTest` asserted the exact URI — `otpauth://otp/...` — and those tests were green and gave everyone confidence. Those tests did not verify the URI against RFC 6238; they photographed your implementation and asserted the photograph. When the implementation is wrong, a self-referential pin is not a safety net — it is a fossil of the mistake, hardened into the suite.

The rule this teaches: **any string that crosses a trust/implementation boundary into someone else's parser must be validated against the external spec or a real consumer before it gets pinned.** The interop boundary was the phone. Your test suite was not the phone.

### Layer 7 — Theming: inheritance is a design decision you didn't make consciously

**Round 7 — white text on a white background.** The ghost button set only `background: transparent` and let the text color inherit. The dark theme (Jenkins' default) sets `--text-color` to white but defines no `--secondary-background`, so your enrolment box fell back to light `#fafafa` — white text, light box, invisible button. The same inheritance bug sat in three more plain buttons.

Two thoughtlessnesses stacked: (1) letting button text color inherit is always a bet on the container, and buttons travel; (2) the CSS was evidently reasoned about in exactly one theme. You also guessed at token names (`--btn-secondary-*`) that don't exist in 2.528 — I nearly shipped that mistake in my own fix before checking the live CSS. Token names are facts about the host, not style choices: look them up, don't compose them.

### Layer 8 — Persistence honesty: the swallow with the persuasive comment

**Round 8 — five endpoints swallowed `u.save()` failures and answered ok.** The worst was `postEnrollConfirm`: the seed committed to memory, the save threw, the endpoint answered success. The user would have walked away believing their factor was saved while it died at the next restart — and their authenticator app would hold a dead secret forever after.

This one deserves the most attention, because the code had a *comment defending the swallow*: "a persistence hiccup reports as ok... rather than implying the commit failed." That is a thoughtful-sounding justification of a dishonest behavior. The reasoning treated "the session works right now" as equivalent to "it works," and ignored that restarts are not exceptional — they are scheduled. A failure a user can act on (retry, call an admin) must be told to the user. Answering ok when data lives only in memory is not optimism; it is lying with a status code.

Also note the company it kept: four other endpoints swallowed saves the same way (verify trust/streak, failure streak, email-code issue, trust revocation). The pattern had multiplied because the first swallow was never questioned. Patterns that start with "non-fatal" tend to colonize.

---

## The cross-cutting analysis (this is the part that matters)

Five threads run through all eight rounds. These are the actual mistakes; the rounds are just where they surfaced.

**1. The acceptance gate was `mvn verify`. The acceptance gate should have been a five-minute human journey.**
Log in. Enroll TOTP. Scan the QR with a real app. Verify. Save an unrelated profile setting. Restart. Log in again. That journey — five minutes, once — would have found rounds 1, 2, 3, 4, 6, and 8 together, before any of them reached production. Every round was instead found by mads living the journey in public, one round at a time, over eight deploys. You built an elaborate gate and then never walked through the door it guarded.

**2. Your test suite measured the implementation. Production measured the experience. Those are different things, and only one of them ships.**
99 tests, all green, and the plugin could not be used. The tests answered "does the code do what the code says?" Production asked "does a person accomplish their goal?" Pins that assert your own output, ITs that fetch a page without rendering it, form tests that never submit the real wire shape — these are introspection, not examination. An examination needs an oracle outside the system under test: the RFC, the browser, the phone, the theme, the restart.

**3. Every defect lived in a layer the harness couldn't see, and every one of those layers had a cheap probe you never ran.**
- CSP → open the page in a browser, look at the console once.
- Content-Type → `curl -I`, or look at the Network tab once.
- Gate-vs-own-assets → log in as a *non-exempt* user once and watch the Network tab.
- Authy → scan the QR with any real authenticator app once.
- Theme → toggle Jenkins to the other theme once.
- Persistence → restart once.
Each probe costs a minute. The absence of all of them cost eight rounds. None of these require talent; they require a checklist of realities your code will meet.

**4. Confident documentation of unverified claims makes things worse, not better.**
Round 6's javadoc said the URI was "the exact string every RFC 6238 authenticator app parses." Round 8's comment explained why swallowing the exception was the right call. Both were wrong, and both were written with total confidence. Eloquence is not evidence. When you write a justification, you are making a claim; the claim needs the same verification as the code around it. A reviewer seeing a confident justification should treat it as something to *test*, not something to trust. (This applies to me as well — I had to learn it reviewing this same plugin.)

**5. The plugin was never its own user.**
You built a gate and never stood on the locked side of it. You built an enrolment flow and never enrolled. You built theme-aware CSS and never looked at a theme. Every round was, at root, the experience of a user the author never simulated. Before you declare work done, inhabit the least-privileged, least-exempt, most ordinary path through it — the gated session, not the API token; the strict app, not the lenient one; the default theme, not the one you happened to style against.

---

## Extractable rules (for your saved memories / skills)

Written as directives so they can be dropped in verbatim.

1. **Done means journeyed.** Before declaring any user-facing work done, complete the full user journey end-to-end in a real browser: real login, real form submit, real restart, real re-login. A green build is a precondition, not an acceptance.
2. **Render-presence is not render-correctness.** Any test that asserts a page renders must also assert the bindings resolve to real values and the form submits the real wire shape the host actually sends.
3. **Ask what the host does to your code, not just what your code does.** Before writing a plugin extension point, read what core does with it (databinding, reconfigure, save lifecycle). The host has opinions; they override yours.
4. **Assume the host's security policy from day one.** On Jenkins: CSP is `script-src 'self'` — JS ships as static files under `webapp/`, never inline. On any host: look up the actual policy before writing markup.
5. **Self-contained views inherit nothing.** If you skip the framework's layout, you must explicitly declare everything the layout provided: Content-Type first, then every header you rely on.
6. **A gate's allow-list must include the gate's own body.** Enumerate everything the gated flow itself needs to function — including the plugin's own static assets — and put it on the list. Then test the gate as a gated user, never only as an exempt/admin/API-token session.
7. **Elevated probes cannot see subordinate problems.** If a behavior depends on being unprivileged, reproduce it unprivileged. An admin curl that succeeds proves nothing about the user experience.
8. **One mechanism per semantic.** If two states mean different things (issuance cooldown vs verification lockout), they get two variables, two timers, two names. Shared state is a claim of equivalence; don't make it casually.
9. **Walk the journey with a stopwatch.** Best case (email arrives instantly), worst case (arrives in 90s), and the impatient case (user clicks things in the wrong order). State diagrams don't have timing; users do.
10. **Cross-boundary strings are validated against the outside, never pinned from the inside.** otpauth URIs, webhook payloads, API contracts: check the external spec or a real consumer first; only then pin. A pin of your own output is a fossil, not a test.
11. **Interop gets tested against the strict consumer, not the lenient one.** If one app is lenient and another is strict, your test target is the strict one — the lenient one will hide your bug in production until the strict one finds it.
12. **Never let text color inherit on a control.** Declare color, background, and border explicitly from theme tokens with fallbacks, and check both light and dark. Token names are facts about the host — look them up in the live CSS, don't compose them from memory.
13. **Never swallow a persistence failure.** If a save can throw, the caller must hear about it in the response or the logs must scream — ideally both. "It works in this session" is not "it works"; restarts are scheduled, not exceptional.
14. **Restart-test anything you persist.** After any change to persisted state: restart, and confirm the state survived. Five seconds; catches the entire class.
15. **A confident comment is a claim. Verify it.** Justifications written with certainty need the same evidence as the code they defend. When you find yourself writing "this is the right call because...", stop and test the "because."

---

## Closing

None of this is about the quality of your logic — the seams, the gates, the error contracts, and the A23 work were genuinely well built, and the review that approved them was right about what it reviewed. The lesson is that **your definition of done stopped at the boundary of what your harness could see**, and every one of these eight defects lived just outside that boundary, waiting for the first human with a browser.

Widen the boundary. The probes are cheap; you now know exactly what they cost — eight rounds, one Saturday, and a lot of mads screenshots.

— Moldy
