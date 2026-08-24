#!/usr/bin/env python3
"""Post-restart A22-b browser persistence and privilege probes."""
import base64, hashlib, hmac, struct, sys, time
from pathlib import Path
HERE=Path(__file__).resolve().parent; REPO=HERE.parents[2]; SCRATCH=REPO/".scratch"
sys.path.insert(0,str(HERE)); from cdp import Cdp
ROOT="http://127.0.0.1:8081/jenkins"; OUT=SCRATCH/"screenshots"; OUT.mkdir(parents=True,exist_ok=True)
creds=dict(x.split("=",1) for x in (SCRATCH/"sandbox-credentials").read_text().splitlines() if "=" in x)
sac_seed=(SCRATCH/"sac-reenrol-seed").read_text().strip()

def code(seed):
    seed += "="*((8-len(seed)%8)%8); key=base64.b32decode(seed,casefold=True)
    d=hmac.new(key,struct.pack(">Q",int(time.time())//30),hashlib.sha1).digest(); o=d[-1]&15
    return f"{((struct.unpack('>I',d[o:o+4])[0]&0x7fffffff)%1000000):06d}"
def wait(c,e,label,t=25):
    end=time.time()+t
    while time.time()<end:
        if c.js(e): return
        time.sleep(.3)
    raise TimeoutError(label+" at "+c.url)
def setv(c,s,v):
    assert c.js("(()=>{let e=document.querySelector(%r);if(!e)return false;e.value=%r;e.dispatchEvent(new Event('input',{bubbles:true}));return true})()"%(s,v))
def login(c,user,password):
    c.raw("Network.clearBrowserCookies"); c.go(ROOT+"/login?from=%2Fjenkins%2F")
    setv(c,"input[name='j_username']",user); setv(c,"input[name='j_password']",password)
    c.js("document.querySelector('form[name=login]').requestSubmit()")
def verify(c,seed):
    wait(c,"location.href.includes('/mfa')","MFA redirect")
    wait(c,"!!document.querySelector('#code')","MFA form")
    setv(c,"#code",code(seed)); c.js("document.querySelector('#verifyBtn').click()")
    wait(c,"!location.href.includes('/mfa')","MFA verified")
def revoke_trust_then_login(c,user,password):
    # A successful pre-restart verify persisted remembered-device trust. Exercise
    # the real self-service revocation before requiring the factor again.
    time.sleep(1)
    if "/mfa" not in c.url:
        c.go(ROOT+f"/user/{user}/security/")
        wait(c,"!!document.querySelector('#mfaRevokeTrust')","revoke-trust control")
        c.js("document.querySelector('#mfaRevokeTrust').click()")
        wait(c,"document.querySelector('#mfaMsg').innerText.includes('revoked')","trust revoked")
        login(c,user,password)

c=Cdp(); c.raw("Network.enable")
try:
    login(c,"admin",creds["admin"]); revoke_trust_then_login(c,"admin",creds["admin"]); verify(c,creds["admin_totp_seed"])
    c.go(ROOT+"/mfaAdmin/"); wait(c,"!!document.querySelector('#adminRoster')","post-restart admin roster")
    users=c.js("Array.from(document.querySelectorAll('tr[data-user-id]')).map(x=>x.dataset.userId)")
    assert users==["admin","sac"],users
    c.shot(str(OUT/"12-post-restart-admin-roster.png"))

    login(c,"sac",creds["sac"]); revoke_trust_then_login(c,"sac",creds["sac"]); verify(c,sac_seed)
    assert c.js("location.pathname=='/jenkins/'")
    c.shot(str(OUT/"13-post-restart-sac-verified.png"))

    login(c,"reader",creds["reader"])
    wait(c,"location.pathname=='/jenkins/'","reader login")
    c.go(ROOT+"/mfaAdmin/")
    wait(c,"document.title.includes('403 Forbidden')","reader 403")
    assert "admin_permission_required" in c.js("document.body.innerText")
    c.shot(str(OUT/"14-post-restart-reader-403.png"))
    print("POST_RESTART_OK admin_totp=true roster=admin,sac sac_reenrol_totp=true reader_403=admin_permission_required")
finally: c.close()
