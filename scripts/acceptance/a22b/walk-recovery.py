#!/usr/bin/env python3
"""A22-b sacrificial-user recovery and real self-enrolment leg."""
import base64, hashlib, hmac, struct, sys, time
from pathlib import Path
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SCRATCH = REPO / ".scratch"
sys.path.insert(0, str(HERE))
from cdp import Cdp
ROOT = "http://127.0.0.1:8081/jenkins"
OUT = SCRATCH / "screenshots"; OUT.mkdir(parents=True, exist_ok=True)
creds = dict(line.strip().split("=",1) for line in (SCRATCH/"sandbox-credentials").read_text().splitlines() if "=" in line)

def wait(c, expression, label, timeout=25):
    end=time.time()+timeout
    while time.time()<end:
        if c.js(expression): return
        time.sleep(.3)
    raise TimeoutError(label+" at "+c.url)

def setv(c, selector, value):
    ok=c.js("""(()=>{let e=document.querySelector(%r);if(!e)return false;e.focus();e.value=%r;e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));return true})()"""%(selector,value))
    assert ok, selector

def totp(seed):
    padded=seed + "="*((8-len(seed)%8)%8)
    key=base64.b32decode(padded,casefold=True); counter=struct.pack(">Q",int(time.time())//30)
    digest=hmac.new(key,counter,hashlib.sha1).digest(); o=digest[-1]&15
    return f"{((struct.unpack('>I',digest[o:o+4])[0]&0x7fffffff)%1000000):06d}"

c=Cdp()
try:
    c.raw("Network.enable"); c.raw("Network.clearBrowserCookies")
    c.go(ROOT+"/login?from=%2Fjenkins%2F")
    setv(c,"input[name='j_username']","sac"); setv(c,"input[name='j_password']",creds["sac"])
    c.js("document.querySelector('form[name=login]').requestSubmit()")
    wait(c,"location.pathname=='/jenkins/'","cleared sac reaches dashboard")
    c.shot(str(OUT/"08-sac-password-only-dashboard.png"))

    c.go(ROOT+"/user/sac/security/")
    wait(c,"!!document.querySelector('#mfaTotpGenerate')","unenrolled security section")
    assert "Not enabled" in c.js("document.querySelector('#mfaSection').innerText")
    c.shot(str(OUT/"09-sac-security-unenrolled.png"))
    c.js("document.querySelector('#mfaTotpGenerate').click()")
    wait(c,"document.querySelector('#mfaTotpManual').textContent.trim().length>0","candidate TOTP seed")
    seed=c.js("document.querySelector('#mfaTotpManual').textContent.trim()")
    assert seed == c.js("document.querySelector('#mfaTotpSeed').value")
    seed_file=SCRATCH/"sac-reenrol-seed"
    seed_file.write_text(seed+"\n"); seed_file.chmod(0o600)
    c.shot(str(OUT/"10-sac-enrol-qr.png"))
    setv(c,"#mfaTotpCode",totp(seed))
    c.js("document.querySelector('#mfaTotpConfirm').click()")
    wait(c,"location.href.includes('/mfa/') || !!document.querySelector('#mfaTotpDisable')",
         "post-confirm reload or MFA gate",30)
    if "/mfa/" in c.url:
        wait(c,"!!document.querySelector('#verifyForm')","newly-enrolled MFA gate")
        setv(c,"#code",totp(seed))
        c.js("document.querySelector('#verifyBtn').click()")
        wait(c,"!location.href.includes('/mfa/')","new factor verifies",25)
        c.go(ROOT+"/user/sac/security/")
    wait(c,"!!document.querySelector('#mfaTotpDisable')","TOTP enabled after verification",30)
    assert "Enabled" in c.js("document.querySelector('#mfaSection').innerText")
    c.shot(str(OUT/"11-sac-reenrolled.png"))
    print("RECOVERY_WALK_OK password_only_dashboard=true security_unenrolled=true candidate_qr=true live_totp_confirm=true reenrolled=true")
finally:
    c.close()
