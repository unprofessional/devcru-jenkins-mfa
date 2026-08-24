#!/usr/bin/env python3
"""A22-b destructive admin acceptance leg in real headful Chromium."""
import base64, hashlib, hmac, struct, sys, time
from pathlib import Path
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SCRATCH = REPO / ".scratch"
sys.path.insert(0, str(HERE))
from cdp import Cdp

ROOT = "http://127.0.0.1:8081/jenkins"
OUT = SCRATCH / "screenshots"
OUT.mkdir(parents=True, exist_ok=True)
creds = dict(line.strip().split("=", 1) for line in
             (SCRATCH / "sandbox-credentials").read_text().splitlines() if "=" in line)

def totp(seed):
    key = base64.b32decode(seed, casefold=True)
    counter = struct.pack(">Q", int(time.time()) // 30)
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = (struct.unpack(">I", digest[offset:offset+4])[0] & 0x7fffffff) % 1000000
    return f"{value:06d}"

def wait(c, predicate, label, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        if c.js(predicate): return
        time.sleep(.3)
    raise TimeoutError(label + " at " + c.url)

def set_value(c, selector, value):
    c.js("""(() => { const e=document.querySelector(%r); if(!e) return false;
      e.focus(); e.value=%r; e.dispatchEvent(new Event('input',{bubbles:true}));
      e.dispatchEvent(new Event('change',{bubbles:true})); return true; })()""" % (selector, value))

c = Cdp()
try:
    # Real Jenkins login form.
    c.go(ROOT + "/login?from=%2Fjenkins%2FmfaAdmin%2F")
    set_value(c, "input[name='j_username']", "admin")
    set_value(c, "input[name='j_password']", creds["admin"])
    c.shot(str(OUT / "01-admin-login.png"))
    c.js("document.querySelector('form[name=login]').requestSubmit()")
    wait(c, "location.href.includes('/mfa')", "admin login -> MFA gate", 20)

    # Force the canonical post-verify destination and perform real TOTP UI submission.
    c.go(ROOT + "/mfa/?redirect=%2Fjenkins%2FmfaAdmin%2F")
    wait(c, "!!document.querySelector('#verifyForm')", "MFA form")
    c.shot(str(OUT / "02-admin-mfa.png"))
    set_value(c, "#code", totp(creds["admin_totp_seed"]))
    c.js("document.querySelector('#verifyBtn').click()")
    wait(c, "!location.href.includes('/mfa/')", "TOTP verify leaves MFA page", 20)
    post_verify_url = c.url
    c.go(ROOT + "/mfaAdmin/")
    wait(c, "!!document.querySelector('#adminRoster')", "admin roster")

    body = c.js("document.body.innerText")
    html = c.js("document.documentElement.outerHTML")
    users = c.js("Array.from(document.querySelectorAll('tr[data-user-id]')).map(x=>x.dataset.userId)")
    assert users == ["admin", "sac"], users
    assert "admin.example" not in html and "sac.example" not in html, "raw mailbox leaked into DOM"

    # Both real colour-scheme media modes on the standalone page.
    c.raw("Emulation.setEmulatedMedia", {"features":[{"name":"prefers-color-scheme","value":"dark"}]})
    c.shot(str(OUT / "03-admin-roster-dark.png"))
    c.raw("Emulation.setEmulatedMedia", {"features":[{"name":"prefers-color-scheme","value":"light"}]})
    c.shot(str(OUT / "04-admin-roster-light.png"))

    # Destructive action via the actual button and typed confirmation dialog.
    c.js("document.querySelector('button[data-op=clearFactors][data-user-id=sac]').click()")
    wait(c, "!!document.querySelector('.dialog input')", "typed confirmation dialog")
    disabled_before = c.js("document.querySelector('.dialog .btn-danger').disabled")
    assert disabled_before is True
    c.shot(str(OUT / "05-clear-dialog-disabled.png"))
    set_value(c, ".dialog input", "sac")
    assert c.js("document.querySelector('.dialog .btn-danger').disabled") is False
    c.shot(str(OUT / "06-clear-dialog-enabled.png"))
    c.js("document.querySelector('.dialog .btn-danger').click()")
    wait(c, "!document.querySelector('tr[data-user-id=sac]')", "sac removed after clear", 20)
    c.shot(str(OUT / "07-sac-cleared-roster.png"))

    print("BROWSER_WALK_OK login=true totp=true roster=admin,sac raw_mail=false themes=dark,light typed_confirm=true sac_cleared=true")
finally:
    c.close()
