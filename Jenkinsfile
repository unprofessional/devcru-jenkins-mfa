// devcru-mfa self-deploy pipeline — merges to master ship the plugin to the
// Jenkins instance that runs this very job (dogfood).
//
// Shape (mirrors the validated manual cutover of 2026-08-24):
//   verify (offline mvn, CI-mirror) -> artifact vs live sha compare
//   -> [changed?] off-host hot snapshot -> jenkins-cli install-plugin
//   -> immediate restart -> wait for ready -> smoke battery.
//
// Why immediate `restart` and not `safeRestart`: safeRestart waits for ALL
// running builds — including this one — so a self-deploying build can never
// live to see the restart it fired (deadlock). Immediate restart + Pipeline
// durability is the working shape: the run's state is persisted, and after
// the controller comes back the build resumes and runs the smoke stages.
//
// Rollback (if smoke fails): manual ladder — rung 1 `DEVCRU_MFA_OFF=1`,
// rung 2 uninstall, rung 3 restore the snapshot this pipeline just took
// (kept on the yharnam agent host, latest 2). Do not automate rung 3 here:
// if this pipeline broke the deploy, this pipeline is not the recovery tool.
//
// Requires on the yharnam agent (it runs as user `jenkins`, NOT hunter —
// /home/hunter is 750 and unreachable from CI):
//   - JDK 21:      /opt/jdk-21.0.12+8 (Temurin, WITH ct.sym + javac).
//                  NOT the system /usr/lib/jvm/java-21-openjdk-amd64 —
//                  that is openjdk-21-jre-headless: no javac, no ct.sym,
//                  its embedded compiler rejects --release for EVERY value
//                  ("release version 17 not supported", build #4).
//   - Maven 3.9+:  /opt/apache-maven-3.9.11 (world-readable copy of hunter's)
//   - offline repo seeded at /home/jenkins/.m2/repository
//   - ssh keypair for user jenkins, pubkey trusted by ranger@shinraedge2
//   - pigz (present), curl, python3
// Requires in Jenkins: secret-text credential `jenkins-rally-api-token`
// (rally's API token; API-token sessions are MFA-gate-exempt).

pipeline {
    agent { label 'yharnam' }

    options {
        timestamps()
        timeout(time: 45, unit: 'MINUTES')
        disableConcurrentBuilds() // never two self-deploys at once
    }

    environment {
        // Direct LAN route — the deploy path does not depend on nginx/TLS.
        CONTROLLER = 'http://192.168.7.35:8080'
        EDGE       = 'ranger@192.168.7.35'
        // Fresh CI user = empty known_hosts; never let ssh hang on a prompt.
        SSHOPTS    = '-o StrictHostKeyChecking=accept-new -o BatchMode=yes'
        // Temurin JDK with ct.sym — the hpi plugin compiles with
        // maven.compiler.release=17, which a JRE cannot honor.
        JAVA_HOME  = '/opt/jdk-21.0.12+8'
        JHOME      = '/var/lib/jenkins'
        SNAPDIR    = '/home/jenkins/backups/jenkins-snapshots'
        // Workspace-local, NOT shared /tmp: /tmp/jenkins-cli.jar can exist
        // hunter-owned from manual ops and a 1777 /tmp still won't let the
        // jenkins user overwrite it (curl exit 23, build #3).
        CLIJAR     = 'jenkins-cli.jar'
    }

    stages {
        stage('Toolchain') {
            steps {
                // Absolute paths: the agent user is `jenkins`, so $HOME is
                // /home/jenkins — never $HOME-relative toolchain paths here.
                sh '''
                    export PATH="/opt/jdk-21.0.12+8/bin:/opt/apache-maven-3.9.11/bin:$PATH"
                    java -version 2>&1 | head -1
                    mvn -version 2>&1 | head -2
                    # Fresh CLI jar matching the live controller, every run.
                    curl -fsS -o "$CLIJAR" "$CONTROLLER/jnlpJars/jenkins-cli.jar"
                '''
            }
        }

        stage('Verify') {
            steps {
                // The ONLY full validation — mirrors CI incl. SpotBugs.
                sh '''
                    export PATH="/opt/jdk-21.0.12+8/bin:/opt/apache-maven-3.9.11/bin:$PATH"
                    mvn -o -B clean verify
                '''
            }
        }

        stage('Compare artifact vs live') {
            steps {
                script {
                    def newSha = sh(
                        script: "sha256sum target/devcru-mfa.hpi | cut -d' ' -f1",
                        returnStdout: true).trim()
                    // Fails (and aborts) if the live file is unreadable —
                    // better to stop than to deploy blind.
                    def liveSha = sh(
                        script: "ssh $SSHOPTS $EDGE \"sha256sum $JHOME/plugins/devcru-mfa.jpi\" | cut -d' ' -f1",
                        returnStdout: true).trim()
                    env.NEW_SHA = newSha
                    env.DEPLOY_NEEDED = (newSha == liveSha) ? 'no' : 'yes'
                    echo "artifact sha ${newSha} | live sha ${liveSha} -> deploy ${env.DEPLOY_NEEDED == 'yes' ? 'NEEDED' : 'SKIPPED (identical bits)'}"
                }
            }
        }

        stage('Snapshot (pre-deploy, mandatory)') {
            when { expression { env.DEPLOY_NEEDED == 'yes' } }
            steps {
                // Hot snapshot (no sudo on the controller host — documented
                // deviation since the 2026-08-22 cutover). Off-host by
                // construction: it lands on this agent host, not the
                // controller. Never snapshot-with-Jenkins-stopped is NOT the
                // rule we break willingly; it is the only rung we have.
                sh '''
                    export PATH="/opt/jdk-21.0.12+8/bin:$PATH"
                    mkdir -p "$SNAPDIR"
                    TS=$(date +%Y%m%d-%H%M%S)
                    OUT="$SNAPDIR/jenkins-snapshot-$TS.tar.gz"
                    set -o pipefail
                    ssh $SSHOPTS "$EDGE" "tar cf - -C $JHOME --exclude=war/work --exclude=workspace . 2>/tmp/pipe-snapshot-err.log" \\
                      | pigz -p 8 > "$OUT"
                    sha256sum "$OUT" > "$OUT.sha256"
                    echo "snapshot: $OUT"
                    cat "$OUT.sha256"
                    ssh $SSHOPTS "$EDGE" "cat /tmp/pipe-snapshot-err.log | grep -v '.docker\\|.java/fonts' | head -5 || true"
                    # Retention: keep latest 2 snapshots.
                    ls -1t "$SNAPDIR"/jenkins-snapshot-*.tar.gz | tail -n +3 | while read -r old; do
                        rm -f "$old" "$old.sha256"
                        echo "pruned old snapshot: $old"
                    done
                '''
            }
        }

        stage('Install + restart') {
            when { expression { env.DEPLOY_NEEDED == 'yes' } }
            steps {
                withCredentials([string(credentialsId: 'jenkins-rally-api-token', variable: 'JK_TOKEN')]) {
                    sh '''
                        export PATH="/opt/jdk-21.0.12+8/bin:$PATH"
                        CLI="java -jar $CLIJAR -s $CONTROLLER -auth rally:$JK_TOKEN -http"
                        # RestartRequiredException (exit 1) is EXPECTED when
                        # re-installing a loaded plugin — the file still gets
                        # swapped on disk, which is the part we verify next.
                        $CLI install-plugin = -deploy < target/devcru-mfa.hpi || true
                        sleep 3
                        LIVE_AFTER=$(ssh $SSHOPTS "$EDGE" "sha256sum $JHOME/plugins/devcru-mfa.jpi" | cut -d' ' -f1)
                        if [ "$LIVE_AFTER" != "$NEW_SHA" ]; then
                            echo "FATAL: live .jpi sha ($LIVE_AFTER) != artifact sha ($NEW_SHA) after install — NOT restarting."
                            exit 1
                        fi
                        echo "on-disk swap confirmed — restarting controller (this build resumes after)"
                        $CLI restart || true
                    '''
                    // Give the restart a moment to begin before this step
                    // completes; the controller going down mid-build is fine —
                    // Pipeline durability resumes us after boot.
                    sleep 20
                }
            }
        }

        stage('Wait for ready') {
            steps {
                withCredentials([string(credentialsId: 'jenkins-rally-api-token', variable: 'JK_TOKEN')]) {
                    sh '''
                        for i in $(seq 1 30); do
                            CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "rally:$JK_TOKEN" "$CONTROLLER/api/json?tree=mode" || true)
                            if [ "$CODE" = "200" ]; then
                                echo "controller ready after ~$((i * 10))s"
                                exit 0
                            fi
                            sleep 10
                        done
                        echo "FATAL: controller did not come back within 5 minutes"
                        exit 1
                    '''
                }
            }
        }

        stage('Smoke') {
            steps {
                withCredentials([string(credentialsId: 'jenkins-rally-api-token', variable: 'JK_TOKEN')]) {
                    sh '''
                        set -e
                        A="curl -sf -u rally:$JK_TOKEN"
                        # 1. Plugin loaded and active.
                        $A "$CONTROLLER/pluginManager/api/json?depth=1" \\
                          | python3 -c "
import json, sys
ps = [p for p in json.load(sys.stdin)['plugins'] if p['shortName'] == 'devcru-mfa']
assert ps and ps[0]['active'] and ps[0]['enabled'], 'devcru-mfa not active'
print('plugin: devcru-mfa', ps[0]['version'], 'active')"
                        # 2. Admin surface renders for an admin AND carries the
                        #    dual-theme stylesheet (proves the new bits are live).
                        $A "$CONTROLLER/mfaAdmin/" -o /tmp/smoke-mfaadmin.html
                        grep -q "prefers-color-scheme: light" /tmp/smoke-mfaadmin.html \\
                          || { echo "FATAL: light theme block missing from rendered page"; exit 1; }
                        echo "admin surface: renders + light theme block present"
                        # 3. Static JS serves under an authed session.
                        $A -o /dev/null "$CONTROLLER/plugin/devcru-mfa/mfa-admin.js"
                        echo "mfa-admin.js: 200"
                        # 4. Gate page healthy.
                        $A -o /dev/null "$CONTROLLER/mfa/"
                        echo "gate page: 200"
                        rm -f /tmp/smoke-mfaadmin.html
                        echo "SMOKE GREEN"
                    '''
                }
            }
        }
    }

    post {
        success {
            echo 'Deploy pipeline green: artifact verified, snapshot kept, controller restarted, smoke passed.'
        }
        failure {
            // Deliberately human-readable: this is the moment the rollback
            // ladder matters. Snapshot location is in the stage above.
            echo 'Deploy pipeline FAILED. Rollback ladder: rung 1 DEVCRU_MFA_OFF=1; rung 2 uninstall plugin + restart; rung 3 restore the snapshot taken by this run (on the yharnam agent, sha256 sidecar beside it). Manual rungs only — do not retry blindly.'
        }
    }
}
