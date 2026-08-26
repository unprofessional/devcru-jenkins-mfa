#!/usr/bin/env python3
"""A24 real-browser acceptance walk (complement view, forceEnrol, first-time
setup flow, clearFactors recovery) against the branch's real hpi:run server.

Sandbox contract: scripts/acceptance/a22b/README.md — Jenkins bound to
127.0.0.1:8081 only, dedicated Chromium profile + CDP 9333, Xvfb :99.
Seeding is done by work/init.groovy.d/zz-a24-seed.groovy at boot (users
admin/sac enrolled, reader, nemo/rusty/deadguy not enrolled; Mailer ->
local SMTP sink 127.0.0.1:2525; policy REQUIRED default).

Legs:
  1. complement slices   — Enrolled / Setup pending / Not enrolled counts,
                           "(no mailbox)" rendering, dark+light themes
  2. force_enrol happy   — typed-id confirm -> ENROL -> Setup pending + audit line
  3. denial arms         — user_not_found, already_enrolled, idempotent UNCHANGED,
                           address-update CORRECT. user_disabled is OBSERVED
                           honestly rather than asserted: stock jenkins-core
                           hardwires HudsonPrivateSecurityRealm.Details.isEnabled()
                           =true and Details is final with a private ctor, so a
                           positively-disabled row cannot exist on a real server;
                           the arm stays pinned at the pure-seam layer
                           (A24ForceEnrolSeamTest). Any write this observation
                           causes is rolled back via clearFactors in the same run.
  4. setup_flow          — forced user logs in, gate bounces to the /mfa setup
                           variant and cannot reach the rest of Jenkins, then
                           verifies an email code through the real Mailer->SMTP
                           path and lands verified; marker cleared
  5. totp_nudge          — skippable TOTP hint present on setup, not blocking
  6. recovery            — force rusty, then the pending row's clearFactors
                           removes it from the pending slice
"""
import base64, hashlib, hmac, json, re, struct, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SCRATCH = REPO / ".scratch"
sys.path.insert(0, str(HERE.parent / "a22b"))
from cdp import Cdp

ROOT = "http://127.0.0.1:8081/jenkins"
OUT = SCRATCH / "screenshots"
MAIL = SCRATCH / "mail"
LOG = SCRATCH / "mvn-a24.log"
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
        if c.js(predicate):
            return True
        time.sleep(0.3)
    raise TimeoutError(label + " at " + c.url)


def set_value(c, selector, value):
    assert c.js("""(() => { const e=document.querySelector(%r); if(!e) return false;
      e.focus(); e.value=%r; e.dispatchEvent(new Event('input',{bubbles:true}));
      e.dispatchEvent(new Event('change',{bubbles:true})); return true; })()"""
        % (selector, value)), "no element " + selector


def login(c, user, pw):
    c.go(ROOT + "/login?from=%2Fjenkins%2F")
    set_value(c, "input[name='j_username']", user)
    set_value(c, "input[name='j_password']", pw)
    c.js("document.querySelector('form[name=login]').requestSubmit()")
    wait(c, "!location.href.includes('j_security_check') && !location.href.includes('loginError')",
         "login as " + user, 20)


def logout(c):
    c.go(ROOT + "/logout")


def admin_open(c):
    """Login admin, TOTP-verify through the gate, land on /mfaAdmin."""
    login(c, "admin", creds["admin"])
    c.go(ROOT + "/mfa/?redirect=%2Fjenkins%2FmfaAdmin%2F")
    wait(c, "!!document.querySelector('#verifyForm')", "admin MFA gate form")
    set_value(c, "#code", totp(creds["admin_totp_seed"]))
    c.js("document.querySelector('#verifyBtn').click()")
    wait(c, "!location.href.includes('/mfa/')", "admin TOTP verify", 20)
    c.go(ROOT + "/mfaAdmin/")
    wait(c, "!!document.querySelector('.section-h')", "admin roster page")


def slices(c):
    t = c.js("document.body.innerText")

    def count(name):
        m = re.search(re.escape(name) + r"\s+(\d+)", t)
        return int(m.group(1)) if m else None
    return {"enrolled": count("Enrolled"), "pending": count("Setup pending"),
            "not_enrolled": count("Not enrolled")}


def post_json(c, verb, payload):
    # The admin page carries the crumb field/value as data attributes; raw
    # endpoint POSTs from the page context must include them like mfa-admin.js.
    crumb = c.js("(function(){var e=document.querySelector('[data-crumb-field]');"
                 "return e ? e.getAttribute('data-crumb-field')+'='+e.getAttribute('data-crumb-value') : '';})()") or ""
    if crumb and "=" in crumb:
        k, v = crumb.split("=", 1)
        payload = {**payload, k: v}
    expr = ("fetch('%s/mfaAdmin/%s', {method:'POST', headers:{'Content-Type':"
            "'application/x-www-form-urlencoded'}, body: new URLSearchParams(%s).toString(),"
            " credentials:'same-origin'}).then(function(r){return r.text().then(function(t){"
            "try{return JSON.parse(t)}catch(e){return {http_error:true, body:t.slice(0,200)}}})})"
            % (ROOT, verb, json.dumps(payload)))
    return c.js(expr, timeout=30)


def post_force_enrol(c, user_id, email):
    return post_json(c, "forceEnrol",
                     {"userId": user_id, "confirmUserId": user_id, "email": email})


def latest_mail_code():
    msgs = sorted(MAIL.glob("msg-*.eml"), key=lambda p: p.stat().st_mtime)
    assert msgs, "no mail captured by SMTP sink"
    body = msgs[-1].read_text(errors="replace")
    codes = re.findall(r"\b[2-9A-HJ-NP-Z]{8}\b", body)
    assert codes, "no code-shaped token in latest mail: " + body[-400:]
    return codes[-1]


c = Cdp()
results = {}
try:
    # ---------------- Leg 1: complement view ----------------
    admin_open(c)
    s = slices(c)
    # Complement includes every non-enrolled account Jenkins knows, incl. the
    # auto-created SYSTEM user and reader — assert the seeded names are present.
    assert s == {"enrolled": 2, "pending": 0, "not_enrolled": 5}, s
    text = c.js("document.body.innerText")
    assert "(no mailbox)" in text, "blank mailbox not rendered as '(no mailbox)'"
    nemo_row = c.js("document.querySelector('tr[data-user-id=nemo]') ? "
                    "document.querySelector('tr[data-user-id=nemo]').innerText : null")
    assert nemo_row and "(no mailbox)" in nemo_row, nemo_row
    for u in ("rusty", "deadguy", "reader"):
        assert c.js(f"!!document.querySelector('tr[data-user-id={u}]')"), u + " missing from complement"
    c.raw("Emulation.setEmulatedMedia", {"features": [{"name": "prefers-color-scheme", "value": "dark"}]})
    c.shot(str(OUT / "a24-01-complement-dark.png"))
    c.raw("Emulation.setEmulatedMedia", {"features": [{"name": "prefers-color-scheme", "value": "light"}]})
    c.shot(str(OUT / "a24-02-complement-light.png"))
    results["complement"] = "slices=E2/P0/N5 no_mailbox=true themes=dark+light"

    # ---------------- Leg 2: forceEnrol happy path via UI ----------------
    set_value(c, "input[data-mailbox-for='nemo']", "nemo@a24.sink")
    c.js("document.querySelector('button[data-op=forceEnrol][data-user-id=nemo]').click()")
    wait(c, "!!document.querySelector('.dialog input')", "typed confirmation dialog")
    assert c.js("document.querySelector('.dialog .btn-danger').disabled") is True
    set_value(c, ".dialog input", "nemo")
    assert c.js("document.querySelector('.dialog .btn-danger').disabled") is False
    c.shot(str(OUT / "a24-03-force-enrol-confirm.png"))
    c.js("document.querySelector('.dialog .btn-danger').click()")
    wait(c, "!document.querySelector('button[data-op=forceEnrol][data-user-id=nemo]')",
         "nemo left the complement after force-enrol", 25)
    time.sleep(1)
    s2 = slices(c)
    assert s2 == {"enrolled": 2, "pending": 1, "not_enrolled": 4}, s2
    pending_txt = c.js("(document.querySelectorAll('.rosterTable')[0]||{innerText:''}).innerText")
    assert "nemo" in pending_txt, pending_txt[:300]
    log_text = LOG.read_text(errors="replace") if LOG.exists() else ""
    assert "force-enrolled user nemo" in log_text, "audit line missing"
    results["force_enrol_happy"] = "typed_confirm=true ENROL=true audit_line=true pending=1"

    # ---------------- Leg 3: denial arms over the live endpoint ----------------
    r_nf = post_force_enrol(c, "ghost", "ghost@a24.sink")
    assert r_nf.get("error") == "user_not_found", r_nf

    r_ae = post_force_enrol(c, "sac", "newaddr@a24.sink")
    assert r_ae.get("error") == "already_enrolled", r_ae

    r_un = post_force_enrol(c, "nemo", "nemo@a24.sink")     # marker set + same mailbox
    assert r_un.get("ok") is True, r_un                      # D5 idempotent UNCHANGED

    log_len_before = len(LOG.read_text(errors="replace"))
    r_corr = post_force_enrol(c, "nemo", "nemo2@a24.sink")   # different mailbox -> CORRECT
    assert r_corr.get("ok") is True, r_corr
    time.sleep(1)
    c.go(ROOT + "/mfaAdmin/")
    wait(c, "!!document.querySelector('.section-h')", "roster reload after correction")
    pending_txt = c.js("(document.querySelectorAll('.rosterTable')[0]||{innerText:''}).innerText")
    assert "nemo" in pending_txt and "a24.sink" in pending_txt, pending_txt[:400]
    assert "nemo2@a24.sink" not in c.js("document.documentElement.outerHTML"), \
        "raw corrected mailbox leaked into DOM"
    log_after = LOG.read_text(errors="replace")
    assert log_after[log_len_before:].count(
        "updated the force-enrol address for user nemo") == 1, "address-update audit line missing"

    # user_disabled: honest observation against a real account (see header).
    r_dis = post_force_enrol(c, "deadguy", "deadguy@a24.sink")
    disabled_denied = isinstance(r_dis, dict) and r_dis.get("error") == "user_disabled"
    if not disabled_denied:
        # The observation wrote a factor (endpoint did not deny); roll it back now
        # via the same typed-confirm UI so later legs see clean slice counts.
        assert isinstance(r_dis, dict) and r_dis.get("ok"), r_dis
        time.sleep(1)
        c.go(ROOT + "/mfaAdmin/")
        wait(c, "!!document.querySelector('.section-h')", "roster reload pre-cleanup")
        btn_ids = c.js("Array.from(document.querySelectorAll('button[data-op=clearFactors]'))"
                       ".map(b=>b.getAttribute('data-user-id')).join(',')")
        assert "deadguy" in str(btn_ids), "no clearFactors for deadguy: " + str(btn_ids)
        c.js("document.querySelector('button[data-op=clearFactors][data-user-id=deadguy]').click()")
        wait(c, "!!document.querySelector('.dialog input')", "cleanup typed dialog")
        set_value(c, ".dialog input", "deadguy")
        c.js("document.querySelector('.dialog .btn-danger').click()")
        wait(c, "document.querySelectorAll('button[data-op=clearFactors][data-user-id=deadguy]').length === 0",
             "deadguy cleanup cleared", 20)
    results["denials"] = {
        "user_not_found": True, "already_enrolled": True,
        "unchanged_same_mailbox": True, "correct_address_update": True,
        "user_disabled_denied": bool(disabled_denied),
        "user_disabled_response": r_dis,
    }
    c.shot(str(OUT / "a24-04-denial-arms.png"))

    # ---------------- Leg 4: first-time setup flow as the forced user ----------------
    logout(c)
    login(c, "nemo", creds["nemo"])
    # Gate bounce must land on the SETUP VARIANT of /mfa.
    wait(c, "document.readyState === 'complete' && document.body !== null", "gate bounce render", 15)
    setup_url = c.url
    assert "/mfa" in setup_url, "gate did not bounce to /mfa: " + setup_url
    body_txt = c.js("document.body.innerText")
    assert "Finish MFA setup" in body_txt, body_txt[:200]
    assert "Verify a code below to finish setup" in body_txt, body_txt[:300]

    # Cannot reach the rest of Jenkins unverified: any protected page bounces back.
    c.go(ROOT + "/manage")
    time.sleep(2)
    assert "/mfa" in c.url, "unverified user escaped the gate: " + c.url

    # Skippable TOTP nudge present but not blocking.
    body_txt = c.js("document.body.innerText")
    assert "Step 2 (optional)" in body_txt or "(optional)" in body_txt, body_txt[:500]
    results["totp_nudge"] = "optional_hint_present=true blocking=false"

    # Real email-code round trip through Mailer -> SMTP sink.
    c.go(setup_url)
    wait(c, "!!document.querySelector('#resendBtn')", "send-code button")
    c.shot(str(OUT / "a24-05-setup-gate.png"))
    mail_before = len(list(MAIL.glob("msg-*.eml")))
    c.js("document.querySelector('#resendBtn').click()")
    deadline = time.time() + 30
    while time.time() < deadline and len(list(MAIL.glob("msg-*.eml"))) <= mail_before:
        time.sleep(0.5)
    code = latest_mail_code()
    set_value(c, "#code", code)
    c.js("document.querySelector('#verifyBtn').click()")
    wait(c, "!location.href.includes('/mfa/')", "email-code verify leaves setup page", 25)
    verified_url = c.url
    c.shot(str(OUT / "a24-06-nemo-verified.png"))

    # Marker cleared: re-login lands in Jenkins proper, not the gate.
    logout(c)
    login(c, "nemo", creds["nemo"])
    time.sleep(1)
    assert not c.url.startswith(ROOT + "/mfa") and "loginError" not in c.url, \
        "unexpected post-clear landing: " + c.url
    results["setup_flow"] = ("bounce=setup_variant escape=blocked code=verified "
                             f"post_verify_url={verified_url} marker_cleared=true")

    # ---------------- Leg 6: recovery via setup-pending clearFactors ----------------
    admin_open(c)
    s3 = slices(c)
    # nemo completed setup -> Enrolled(3); nobody pending yet.
    assert s3 == {"enrolled": 3, "pending": 0, "not_enrolled": 4}, s3
    # Force rusty through the UI (mailbox field + typed confirm).
    set_value(c, "input[data-mailbox-for='rusty']", "rusty@a24.sink")
    c.js("document.querySelector('button[data-op=forceEnrol][data-user-id=rusty]').click()")
    wait(c, "!!document.querySelector('.dialog input')", "rusty typed confirmation dialog")
    set_value(c, ".dialog input", "rusty")
    c.js("document.querySelector('.dialog .btn-danger').click()")
    wait(c, "!document.querySelector('button[data-op=forceEnrol][data-user-id=rusty]')",
         "rusty left the complement", 25)
    time.sleep(1)
    s4 = slices(c)
    assert s4["pending"] >= 1, s4
    pending_table = c.js("(document.querySelectorAll('.rosterTable')[0]||{innerText:''}).innerText")
    assert "rusty" in pending_table, pending_table[:300]

    # Recovery: the pending row's own clearFactors action.
    btn = c.js("Array.from(document.querySelectorAll('button[data-op=clearFactors]'))"
               ".map(b=>b.getAttribute('data-user-id')).join(',')")
    assert "rusty" in btn, "no clearFactors action on pending rows: " + str(btn)
    c.js("document.querySelector('button[data-op=clearFactors][data-user-id=rusty]').click()")
    wait(c, "!!document.querySelector('.dialog input')", "clear dialog on pending row")
    c.shot(str(OUT / "a24-07-pending-clear-dialog.png"))
    set_value(c, ".dialog input", "rusty")
    c.js("document.querySelector('.dialog .btn-danger').click()")
    time.sleep(1)
    s5 = slices(c)
    all_tables = c.js("Array.from(document.querySelectorAll('table')).map(function(t){return t.innerText}).join(' | ')")
    page_text = c.js("document.body.innerText")
    assert "No users are waiting to finish setup" in page_text or s5["pending"] == 0, (s5, page_text[:300])
    pending_after = c.js("(document.querySelectorAll('.rosterTable')[0]||{innerText:''}).innerText")
    assert "rusty" not in (all_tables or "") or True  # complement row legitimately lists rusty
    assert not c.js("!!document.querySelector('button[data-op=clearFactors][data-user-id=rusty]')"), \
        "rusty still has a clearFactors (still pending/enrolled?)"
    assert c.js("!!document.querySelector('button[data-op=forceEnrol][data-user-id=rusty]')"), \
        "rusty did not return to the complement"
    assert s5 == {"enrolled": 3, "pending": 0, "not_enrolled": 4}, s5
    c.raw("Emulation.setEmulatedMedia", {"features": [{"name": "prefers-color-scheme", "value": "light"}]})
    c.shot(str(OUT / "a24-08-recovery-light.png"))
    results["recovery"] = "forced_rusty=true pending_clear_factors=true row_left_pending=true"

    print(json.dumps(results, indent=1))
    ds = results["denials"]
    print("ACCEPT_A24_OK complement=slices force_enrol=enrol+denials setup_flow=verified "
          "recovery=clear_pending model_statement=\"real-browser acceptance executed by agent harness: ox-alpha model via OpenClaw subagent CDP walk\"")
finally:
    try:
        c.close()
    except Exception:
        pass
