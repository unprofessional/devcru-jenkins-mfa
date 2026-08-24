package org.sebcru.mfa;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

/**
 * TDD record for the root {@code Jenkinsfile} — the self-deploy pipeline that
 * ships this very plugin to the controller running the job.
 *
 * <h2>What this file pins down</h2>
 * <p>The pipeline runs on an isolated CI user whose {@code sh} steps execute
 * under {@code /bin/sh} (dash on the agent host), NOT bash. The contract
 * pinned here is: <em>every pipeline {@code sh} block is dash-safe</em>. The
 * historical shape of this defect is not hypothetical — build #5 (2026-08-24)
 * died on exactly this axis: {@code set -o pipefail} inside the Snapshot
 * stage made dash exit with {@code Illegal option -o pipefail} (exit 2)
 * BEFORE the ssh ever ran, silently aborting a run that had just passed
 * Verify. The same class of bug hides in any future bashism (process
 * substitution, arrays, {@code [[ }} …): a bash-only syntax in a sh block is
 * a deploy blocker discovered only by a green-to-red production merge.
 *
 * <h2>Red → green history</h2>
 * <p>This test was written AFTER build #5 (the handoff orders §1-PIPELINE
 * first, so the defect lived as a production failure, not a red test). The
 * honest record: build #5's stage view + console showed the Snapshot stage
 * dying on the pipefail line; the fix made the stage dash-native (dropped the
 * bashism) and replaced the failure-detection role of pipefail with an
 * explicit, dash-safe integrity gate ({@code gzip -t} + entry-count floor +
 * sha256 sidecar). This test then goes green and keeps that class of
 * regression visible at the CI mirror instead of at a live deploy.
 *
 * <p>WHY/SOLVES: the definition of done for this pipeline is one end-to-end
 * green run fired by a real merge. Every bashism is one more doomed build,
 * one more 10-minute Verify, and one more merge mads has to approve only to
 * watch it die in Snapshot. A test that compiles every sh block under dash
 * ({@dash -n}) and executes the pure ones locally is the cheapest possible
 * guardrail short of running Jenkins itself.
 */
class JenkinsfilePipelineTest {

  /** Read the root Jenkinsfile from the working tree (module root). */
  private static String readJenkinsfile() throws IOException {
    Path jf = Path.of("Jenkinsfile");
    if (!Files.exists(jf)) {
      jf = Path.of("..", "Jenkinsfile");
    }
    return new String(Files.readAllBytes(jf), StandardCharsets.UTF_8);
  }

  /**
   * WHAT: the Snapshot stage is the crash site of build #5 and carries the
   * most shell logic of any stage — it must be parseable by dash AND must not
   * contain the known-unsafe bashisms that Pipeline's sh steps reject.
   *
   * <p>BDD:
   * <pre>
   * GIVEN the root Jenkinsfile contains a Snapshot stage with an sh '''...''' body
   * WHEN  that body is syntax-checked by dash (dash -n) and scanned for the
   *       bash-only constructs proven to kill this pipeline
   * THEN  dash accepts the syntax and none of the forbidden constructs appear
   * </pre>
   *
   * <p>WHY/SOLVES: {@code set -o pipefail}, process substitution
   * ({@code <( } / {@code >( }), arrays, and {@code [[ } conditional tests all
   * run fine in bash and die in dash — the exact failure mode shipped in
   * build #5. Catching them at verify time makes "merge to master → green
   * deploy" a reliable statement again.
   */
  @Test
  @Timeout(value = 60, unit = TimeUnit.SECONDS)
  @DisplayName("snapshot stage body is dash-parseable and free of known bashisms")
  void snapshotStageIsDashSafe(@TempDir Path tmp) throws Exception {
    String body = extractStageBody("Snapshot (pre-deploy, mandatory)");
    assertNotNull(body, "Snapshot stage with an sh block must exist");

    // 1) Scanned: the constructs dash demonstrably rejects on this host.
    assertFalse(body.contains("set -o pipefail"),
        "build #5 killer: dash exits 2 on `set -o pipefail` — use the explicit integrity gate");
    assertFalse(body.contains("<(") || body.contains(">("),
        "process substitution is bash-only and never runs in a Pipeline sh step");
    assertFalse(body.contains("[[ "), "double-bracket test is bash-only");

    // 2) Executed: dash itself must parse the body (syntax check, no run).
    //    The body references pipeline env vars; `dash -n` only parses, which
    //    is exactly the layer where bashisms die.
    Path script = tmp.resolve("snapshot-stage.sh");
    Files.write(script, body.getBytes(StandardCharsets.UTF_8));
    Path dash = findDash();
    if (dash == null) {
      System.out.println("no POSIX-shell probe available here; parse check skipped (static scan ran)");
      return;
    }
    Process p = new ProcessBuilder(dash.toString(), "-n", script.toString())
        .redirectErrorStream(true)
        .start();
    String output = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    int rc = p.waitFor();
    assertTrue(rc == 0, "dash -n must accept the Snapshot body (rc=" + rc + "): " + output);
  }

  /**
   * WHAT: the other sh-stage bodies of the pipeline are dash-safe too — the
   * build-#5 lesson is a class of defect, not a single line.
   *
   * <p>BDD:
   * <pre>
   * GIVEN every sh '''...''' body in the root Jenkinsfile
   *       (Toolchain, Compare, Install+restart, Wait for ready, Smoke)
   * WHEN  each body is syntax-checked by dash (dash -n)
   * THEN  every body parses
   * </pre>
   *
   * <p>WHY/SOLVES: the same regression class can land in ANY stage — a
   * "harmless" bashism in the Smoke stage would still fire at deploy time and
   * cost a real controller restart's worth of trust to recover. Parsing every
   * stage body under dash here costs seconds in the CI mirror and removes
   * that whole axis from the production surface.
   */
  @Test
  @Timeout(value = 60, unit = TimeUnit.SECONDS)
  @DisplayName("every pipeline sh block parses under dash")
  void allShBlocksAreDashParseable(@TempDir Path tmp) throws Exception {
    String jenkinsfile = readJenkinsfile();
    Path dash = findDash();

    java.util.regex.Matcher m =
        java.util.regex.Pattern.compile("sh\\s*'''(.*?)'''", java.util.regex.Pattern.DOTALL)
            .matcher(jenkinsfile);
    int blocks = 0;
    while (m.find()) {
      blocks++;
      String body = m.group(1);
      // Static scan: the constructs this pipeline has actually died on.
      assertFalse(
          body.contains("set -o pipefail"),
          "sh block #" + blocks + ": `set -o pipefail` is a bashism — build #5 killer");
      assertFalse(
          body.contains("<(") || body.contains(">("),
          "sh block #" + blocks + ": process substitution is bash-only");
      if (dash != null) {
        Path script = tmp.resolve("stage-" + blocks + ".sh");
        Files.write(script, body.getBytes(StandardCharsets.UTF_8));
        Process p =
            new ProcessBuilder(dash.toString(), "-n", script.toString())
                .redirectErrorStream(true)
                .start();
        String output =
            new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int rc = p.waitFor();
        assertTrue(
            rc == 0,
            "sh block #" + blocks + " must parse under dash (rc=" + rc + "): " + output);
      }
    }
    assertTrue(blocks >= 5, "expected at least 5 sh blocks in the Jenkinsfile, found " + blocks);
  }

  /**
   * WHAT: the Snapshot stage replaces pipefail's failure detection with an
   * explicit integrity gate — a corrupt or truncated snapshot must ABORT the
   * build, not become the rollback rung.
   *
   * <p>BDD:
   * <pre>
   * GIVEN the Snapshot stage body
   * WHEN  the gate is inspected
   * THEN  it verifies the artifact with `gzip -t` AND enforces a minimum
   *       entry count via `tar tzf`, and writes a sha256 sidecar
   * </pre>
   *
   * <p>WHY/SOLVES: without pipefail, a mid-stream ssh death would be masked
   * by pigz's exit 0 — the stage would "succeed" with a truncated archive and
   * the pipeline would deploy on top of it, with the snapshot as the only
   * rollback rung. The explicit gate (valid gzip + ≥100 entries + sha sidecar)
   * makes that failure path loud and pre-deploy. These are external
   * consumers of the safety model, so they are pinned here, postmortem rule 10.
   */
  @Test
  @DisplayName("snapshot stage carries an explicit integrity gate in place of pipefail")
  void snapshotStageHasExplicitIntegrityGate() throws IOException {
    String body = extractStageBody("Snapshot (pre-deploy, mandatory)");
    assertNotNull(body, "Snapshot stage must exist");
    assertTrue(body.contains("gzip -t"),
        "snapshot must be gzip-verified before deploy (replaces pipefail); body: " + body);
    assertTrue(body.contains("tar tzf"),
        "snapshot must carry an entry-count floor so a dead stream cannot look valid");
    assertTrue(body.contains("sha256sum") && body.contains(".sha256"),
        "snapshot must write a sha256 sidecar (retention + restore provenance)");
  }

  /** Extract the sh '''...''' body of the named stage. Null if absent. */
  private static String extractStageBody(String stageName) throws IOException {
    String jenkinsfile = readJenkinsfile();
    int stage = jenkinsfile.indexOf("stage('" + stageName + "')");
    if (stage < 0) {
      return null;
    }
    int block = jenkinsfile.indexOf("sh '''", stage);
    if (block < 0) {
      return null;
    }
    int start = block + "sh '''".length();
    int end = jenkinsfile.indexOf("'''", start);
    if (end < 0) {
      return null;
    }
    return jenkinsfile.substring(start, end);
  }

  /**
   * Locate a POSIX-shell executable for the parse-level check, or null where
   * none is available (a GitHub-hosted runner may lack it). On the dev and
   * agent hosts /bin/sh resolves to dash — exactly the shell Pipeline's sh
   * steps use at deploy time. When null, the parse check is skipped and the
   * static bashism scan (which runs everywhere) carries the guard.
   */
  private static Path findDash() {
    try {
      Path p = Path.of("/bin/sh");
      if (!Files.exists(p) || !Files.isExecutable(p)) {
        return null;
      }
      return p;
    } catch (Exception e) {
      return null;
    }
  }
}
