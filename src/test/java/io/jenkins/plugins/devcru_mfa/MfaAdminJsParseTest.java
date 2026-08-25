package io.jenkins.plugins.devcru_mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * Parse gate for src/main/webapp/mfa-admin.js: the A24 review round shipped
 * a syntactically broken edit to this file because nothing in `mvn verify`
 * ever executed it. This test runs `node --check` on it so a broken splice
 * fails the build.
 *
 * If node is not on PATH (CI environments without it), the check degrades
 * to a no-op rather than failing the build; when node IS present, a parse
 * failure fails loudly.
 */
class MfaAdminJsParseTest {

    @Test
    void mfaAdminJsParses() throws Exception {
        Path js = Path.of("src", "main", "webapp", "mfa-admin.js");
        assertTrue(Files.isRegularFile(js), "missing " + js);
        String node = findNode();
        if (node == null) {
            // No node available: cannot syntax-check here. Skip gracefully
            // (the file-exists assertion above still guards gross deletion).
            return;
        }
        Process p = new ProcessBuilder(node, "--check", js.toAbsolutePath().toString())
                .redirectErrorStream(true)
                .start();
        String out;
        try (var is = p.getInputStream()) {
            out = new String(is.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        }
        assertTrue(p.waitFor(60, TimeUnit.SECONDS), "node --check timed out");
        assertEquals(0, p.exitValue(),
                () -> "mfa-admin.js does not parse:\n" + out);
    }

    private static String findNode() throws IOException {
        for (String dir : System.getenv("PATH").split(File.pathSeparator)) {
            File f = new File(dir, "node");
            if (f.canExecute()) {
                return f.getAbsolutePath();
            }
        }
        return null;
    }
}
