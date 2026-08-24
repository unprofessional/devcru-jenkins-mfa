import hudson.security.HudsonPrivateSecurityRealm
import hudson.util.Secret
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.UUID
import jenkins.model.Jenkins
import org.sebcru.mfa.MfaUserProperty
import org.sebcru.mfa.WalkAuthorizationStrategy

Jenkins j = Jenkins.get()
HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false)
j.setSecurityRealm(realm)
j.setAuthorizationStrategy(new WalkAuthorizationStrategy("admin"))

String adminPassword = UUID.randomUUID().toString() + "-A9!"
String sacPassword = UUID.randomUUID().toString() + "-S7!"
String readerPassword = UUID.randomUUID().toString() + "-R5!"

def admin = realm.createAccount("admin", adminPassword)
def sac = realm.createAccount("sac", sacPassword)
realm.createAccount("reader", readerPassword).save()

def adminMfa = MfaUserProperty.getOrCreate(admin)
adminMfa.setTotpSecret(Secret.fromString("KRSXG5CTMVRXEZLU"))
adminMfa.setRegisteredEmail("admin.example")
adminMfa.setTrustedUntilMs(0L)
admin.save()

def sacMfa = MfaUserProperty.getOrCreate(sac)
sacMfa.setTotpSecret(Secret.fromString("QWERTYUIOPJBSWY3"))
sacMfa.setRegisteredEmail("sac.example")
sacMfa.setTrustedUntilMs(0L)
sac.save()

j.save()

Path scratch = j.getRootDir().toPath().getParent().resolve(".scratch")
Files.createDirectories(scratch)
Path credentialFile = scratch.resolve("sandbox-credentials")
Files.writeString(credentialFile,
    "admin=" + adminPassword + "\n" +
    "sac=" + sacPassword + "\n" +
    "reader=" + readerPassword + "\n" +
    "admin_totp_seed=KRSXG5CTMVRXEZLU\n" +
    "sac_totp_seed=QWERTYUIOPJBSWY3\n")
Files.setPosixFilePermissions(
    credentialFile, PosixFilePermissions.fromString("rw-------"))

println("A22B_SANDBOX_SEEDED users=3 admin_enrolled=true victim_enrolled=true")
