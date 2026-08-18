# AGENTS.md — devcru-jenkins-mfa

Standing rules for any agent (or human) working in this repository. These are
**required**, not aspirational. mads owns acceptance; violating a rule below
means the work is not done, however green the build is.

## Test documentation requirement (mads, 2026-08-17)

**Every test in this project must document its TDD as BDD, even if only
through comments.** `src/test/java/org/sebcru/mfa/TotpTest.java` is the
reference implementation of this standard — follow its shape exactly.

For **each test method**, the Javadoc (or in-body comments) must contain all
three parts, in this order:

1. **WHAT** — one or two sentences: which behaviour/contract of the unit under
   test this test pins down. Name the class and the specific concern (e.g.
   "verify() reject-path", "secret provisioning round-trip").
2. **BDD block** — a `GIVEN / WHEN / THEN` description of the observed
   contract, in a `<pre>` fence so it stays aligned:
   - `GIVEN` the preconditions/fixtures (key, instant, config state…)
   - `WHEN` the exercised action, one branch per assertion group
   - `THEN` the expected outcome, exactly what each assertion checks
3. **WHY / SOLVES** — what downstream behaviour this contract protects.
   Answer one of: *why would the system break, and for whom, if this
   behaviour regressed?* Interop guarantees, security properties (attack
   surface size, fail-closed semantics, lockout accounting), or user-facing
   failure modes ("MFA never works with no error anywhere"). Do not write
   "documents expected behaviour" filler — name the concrete consequence.

### Red → green history

Where a test genuinely caught a defect (or where the red phase mattered),
record the red→green story — class level in the file's Javadoc, or inline if
it belongs to one test: what was written first, what failed, what the
failure revealed, and the fix. The canonical example: the RFC 4226/6238
vectors caught the digest-length truncation bug (`h[15]` vs
`h[h.length-1]`) **in the plan's own spec sketch**, before any production
code existed. Honest history only — never backfill a red phase that
happened.

### What does NOT count

- Assertions alone, even with descriptive method names (`verifyRejectsNull`
  without a doc block is a violation).
- Restating the RFC number without saying what it guarantees us.
- Copy-pasted BDD blocks where the GIVEN/WHEN/THEN differ between tests.

### Review gate

A test commit without its documentation blocks review, even when the build
is green. When adding tests to an existing file, match the style already
present in that file (TotpTest is the house standard).

## General

- Work branch `develop`; `master` advances only on explicit mads per-step
  approval. No force-push, ever.
- **Every task that lands, the README's "Practical usage — what end users
  should expect" section is updated in the same commit** (mads, 2026-08-17):
  new user-facing behaviour, new corner cases covered, and the honest
  "implemented vs. in progress" note kept current. The section stays a
  behaviour contract an end user could actually read — no internals, no
  jargon, every claim traceable to code/tests or a named plan task.
- **CI runs on every PR open/update and on pushes to `develop`/`master`**
  (`.github/workflows/ci.yml`): one job = `mvn clean verify` on JDK 21
  (SpotBugs `check` + enforcer + unit tests + `.hpi` packaging).
- **Local validation must mirror CI: use `mvn clean verify`, not `mvn test`.**
  The Jenkins plugin parent POM binds SpotBugs into the `verify` phase, so
  `mvn test` silently skips the linter. (This exact gap shipped a
  default-charset bug that only CI caught — see `Totp.constEq` history.)
- TDD throughout: the plan's independent oracles (RFC vectors, published
  examples, known-good fixtures) beat internal-consistency tests whenever
  one exists.
- Security decisions live in the plan (`/home/hunter/docs/plans/2026-08-17-jenkins-mfa-plugin.md`,
  "Security model decisions") — implement them as written; re-litigating them
  in a diff is out of scope.
