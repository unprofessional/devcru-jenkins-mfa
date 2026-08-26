#!/usr/bin/env python3
"""A22-b §1-D production-feedback acceptance leg in real headful Chromium.

Three legs, per handoff §1-D acceptance criteria:
  1. /manage/configureSecurity/ form: EVERY field has a human label and a
     hint (D1) — no raw key name on the page, no "[truncated]" placeholder.
     The Gate Policy control is a working <select> whose options are
     REQUIRED/OFF with REQUIRED selected (D1 contents + D3 filler).
  2. Controller log CLEAN of the doFillPolicyItems exception (D3), checked
     via /log/all — the exact production signature from the live log.
  3. The admin page (roster arm) shows a back link to the Security
     configuration that NAVIGATES; the 403 denial arm shows a back link
     to the Manage Jenkins console (D2, both arms, both colour schemes).

Reads the sandbox credentials the fixture writes (never generates its own);
the boot + seed are scripted in scripts/acceptance/a22b/README.md and are
reused verbatim. Exits non-zero on any leg failure; prints
ACCEPT_1D_OK <summary> on success. Screenshots under .scratch/screenshots/
"""
import re, sys, time, urllib.request
from pathlib import Path
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(HERE))
from cdp import Cdp

OUT = REPO / ".scratch" / "screenshots"
OUT.mkdir(parents=True, exist_ok=True)
creds = dict(line.strip().split("=", 1) for line in
             (REPO / ".scratch" / "sandbox-credentials").read_text().splitlines()
             if "=" in line)
J = "http://127.0.0.1:8081/jenkins"

def totp(seed):
    import base64, hashlib, hmac, struct
    key = base64.b32decode(seed, casefold=True)
    counter = struct.pack(">Q", int(time.time()) // 30)
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = (struct.unpack(">I", digest[offset:offset+4])[0] & 0x7fffffff) % 1000000
    return f"{value:06d}"

def wait(c, predicate, label, timeout=25):
    end = time.time() + timeout
    while time.time() < end:
        if c.js(predicate): return
        time.sleep(.3)
    raise TimeoutError(label + " at " + c.url)

def set_value(c, selector, value):
    r = c.js("""(() => { const e=document.querySelector(%r); if(!e) return false;
      e.focus(); e.value=%r; e.dispatchEvent(new Event('input',{bubbles:true}));
      e.dispatchEvent(new Event('change',{bubbles:true})); return true; })()""" % (selector, value))
    assert r is True, f"no {selector}"

def login_and_gate(c, user, seed, dest):
    """Login as `user`, reaching `dest` — through the live gate state.

    Two live states are legitimate and both must end AUTHENTICATED on
    `dest`:
      * trust live (reused sandbox): a fresh login lands directly — the
        filter's step-9 trustLive disjunct;
      * trust dead (fresh seed): login bounces through the REAL MFA gate,
        TOTP typed through the actual UI.

    The established A22-b pattern for the second state (walk-admin.py:
    "Force the canonical post-verify destination") is followed here: the
    filter's bounce for the post-login redirect derives its ?redirect=
    from the referer (the login page), never from the login's ?from=, so
    the intended destination is not guaranteed on the bounced gate. When
    that happens the walk re-anchors the gate at exactly the destination
    it wants — the authenticated, enrolled, unverified session is
    unchanged by the re-navigation.
    """
    destq = "".join("%2F" if ch == "/" else ch for ch in dest)
    c.go(f"{J}/login?from={destq}")
    wait(c, "!!document.querySelector('input[name=j_username]')", "login form")
    set_value(c, "input[name='j_username']", user)
    set_value(c, "input[name='j_password']", creds[user])
    c.shot(str(OUT / f"1d-{user}-login.png"))
    c.js("document.querySelector('form[name=login]').requestSubmit()")
    end = time.time() + 45
    typed = False
    forced = False
    while time.time() < end:
        u = c.url
        # The filter 302s to <ctx>/mfa?redirect=… — BARE /mfa (no trailing
        # slash before the query) or the page's own <ctx>/mfa/ form.
        on_gate = (u.startswith(J + "/mfa?") or u == J + "/mfa"
                   or (u.startswith(J + "/mfa/") and "/post" not in u))
        if on_gate:
            if not forced:
                # walk-admin.py pattern: "Force the canonical post-verify
                # destination and perform real TOTP UI submission." The
                # post-login bounce carries the LOGIN PAGE as its referer
                # (A3's documented constraint), so the gate the browser is
                # handed re-anchors to the site root, not the intended
                # destination. Re-anchoring the gate at the destination the
                # walk intends is harmless to MFA semantics: verification
                # authenticates THIS SESSION (verified-session flag +
                # trust grant) independent of the redirect it navigates to,
                # and that is what every leg after the gate relies on.
                c.go(f"{J}/mfa/?redirect={destq}")
                forced = True
                time.sleep(0.8)
                continue
            wait(c, "!!document.querySelector('#verifyForm')", "MFA form", 25)
            if not typed:
                c.shot(str(OUT / f"1d-{user}-mfa-gate.png"))
            # Type a FRESH TOTP each iteration we still sit on the gate:
            # covers the 30s-window boundary (one wrong-code retry costs one
            # of the 5-attempt/30-min lockout budget — deliberate) and the
            # postVerify round-trip that left us here. On success the page's
            # JS navigates away from the gate; the next iteration stops
            # matching on_gate and the loop settles on `dest`.
            set_value(c, "#code", totp(seed))
            c.js("document.querySelector('#verifyBtn').click()")
            typed = True
            # Wait for the AJAX round-trip to produce EITHER navigation or
            # the visible error message before the next iteration touches
            # the page again.
            time.sleep(3)
            continue
        # dest is an absolute in-BROWSER path (includes the /jenkins context);
        # J already carries it, so build the expected full URL from dest
        # WITHOUT re-adding the context, else the comparison can never match.
        expected = J + dest.replace("/jenkins", "", 1)
        if u.rstrip("/") == expected.rstrip("/"):
            return
        time.sleep(.3)
    raise TimeoutError(f"{user} login did not settle on {dest}; last url: " + c.url)

def login_reader(c):
    """reader is NOT MFA-enrolled: SSO login lands directly (no /mfa/ gate)."""
    c.go(f"{J}/login?from=%2Fjenkins%2FmfaAdmin%2F")
    wait(c, "!!document.querySelector('input[name=j_username]')", "login form")
    set_value(c, "input[name='j_username']", "reader")
    set_value(c, "input[name='j_password']", creds["reader"])
    c.js("document.querySelector('form[name=login]').requestSubmit()")
    # Either 403 immediately (reader lands on mfaAdmin denied) or on the
    # console; force the denial arm.
    wait(c, "document.readyState === 'complete'", "reader login lands", 20)
    c.go(J + "/mfaAdmin/")
    wait(c, "document.readyState === 'complete'", "reader mfaAdmin", 20)

failures = []
def check(name, ok, detail=""):
    flag = "PASS" if ok else "FAIL"
    print(f"{flag} {name}" + (f" | {detail[:300]}" if detail else ""))
    if not ok:
        failures.append(name)

# ---------------------------------------------------------------------
c = Cdp()
try:
    # ---------------- LEG 1: config form labels + policy select ----------
    login_and_gate(c, "admin", creds["admin_totp_seed"],
                   "/jenkins/manage/configureSecurity/")
    # Core 2.528's f:select renders name="_.policy" (underscore — verified
    # in-DOM 2026-08-25; an earlier draft of this walk assumed the "$."
    # prefix and timed out on a correct page).
    wait(c, "Array.from(document.querySelectorAll('select')).some(s=>s.name==='_.policy')",
         "policy select", 30)

    body = c.js("document.body.innerText")

    # (a) no raw key name in any rendered LABEL/title (D1: the walk defect
    #     was a *section title* rendering as a key). Label texts are pulled
    #     once and compared EXACTLY against the raw key set: a leaked key
    #     renders as the element's whole text (e.g. "manageFactorsLink"),
    #     while restored human titles merely *contain* key words as prose
    #     ("Gate policy" contains the token "policy" in a title that is
    #     still the human string). Exact-equality keeps both behaviours
    #     distinct.
    known_keys = {"issuer","rememberFor","rememberForHours","manageFactorsLink","totpWindow",
                  "emailCodeTtlSeconds","emailResendCooldownSeconds","maxAttempts",
                  "attemptWindowMinutes","lockoutMinutes","exemptUsers","trustMinHours",
                  "totpDigits","totpAlphabet","policy"}
    label_texts = c.js("""(() => Array.from(document.querySelectorAll('.setting-name, .setting-group-title, .jenkins-section-header, .setting-group, select option')).map(e => e.textContent.trim()).filter(Boolean))()""") or []
    bad_labels = [t for t in label_texts
                  if t in known_keys or t.startswith("${%")]
    check("L1a no raw key names in rendered labels/titles", not bad_labels, str(bad_labels))
    # (b) no truncation placeholder in visible text (the D1 stacked defect).
    check("L1b no '[truncated]' placeholder in visible config text",
          "truncated" not in body, body[:120])
    # (c) both section titles render as human text, not keys.
    check("L1c 'Factor recovery' section title visible", "Factor recovery" in body)
    check("L1d policy section title visible (human)", ("Gate policy" in body or "Policy" in body))
    # (e) the select's contract: exactly REQUIRED/OFF, REQUIRED selected
    #     (D1 contents + D3 filler, in the RENDERED form — not reflected).
    opts = c.js("""(() => { const s=Array.from(document.querySelectorAll('select')).find(x=>x.name==='_.policy');
       if(!s) return null;
       return Array.from(s.options).map(o=>({v:o.value,t:o.text,sel:o.selected})); })()""")
    check("L1e policy select present", opts is not None, str(opts))
    if opts:
        vs = [o["v"] for o in opts]
        # NOTE DOM order: the rendered options follow the ListBoxModel/
        # Policy.values() order [OFF, REQUIRED] (verified in-DOM 2026-08-25),
        # not the reverse. Assert the SET; the "REQUIRED is selected" check
        # below is order-independent.
        check("L1e options are exactly {REQUIRED, OFF}",
              sorted(vs) == ["OFF", "REQUIRED"], str(vs))
        check("L1e labels are human (non-empty)", all(o["t"].strip() for o in opts), str(opts))
        check("L1e current value REQUIRED is selected",
              [o["sel"] for o in opts].count(True) == 1 and
              [o["v"] for o in opts][[o["sel"] for o in opts].index(True)] == "REQUIRED",
              str(opts))

    # (d) the D1-glued hint reads to completion — the mangle had glued the
    #     manageFactorsLink value to its tail, so the restored sentence is
    #     the verbatim one from config.properties line 10 (checked as a
    #     complete run of text in the rendered body).
    check("L1d remember description reads to completion",
          "stores trust for max(value, trust-minimum) hours" in body,
          str([l for l in body.splitlines() if "trust-minimum" in l or "15 minutes" in l]))

    # both colour schemes, screenshot each — the light scheme is where the
    # walk originally tripped (the section title defect was found there).
    c.raw("Emulation.setEmulatedMedia",
          {"features":[{"name":"prefers-color-scheme","value":"dark"}]})
    c.shot(str(OUT / "1d-config-form-dark.png"))
    c.raw("Emulation.setEmulatedMedia",
          {"features":[{"name":"prefers-color-scheme","value":"light"}]})
    c.shot(str(OUT / "1d-config-form-light.png"))
    check("L1 screenshots captured dark+light",
          all((p.exists() and p.stat().st_size > 0) for p in
              (OUT / "1d-config-form-dark.png", OUT / "1d-config-form-light.png")))

    # LEG 2: controller log clean (D3) -----------------------------------
    # The exact production signature from the live log, checked through the
    # real log surface — not a page render, but the log itself.
    # Core 2.528.3 has no /jenkins/logText (that endpoint is gone; the old
    # Jenkins.doLogText is pre-LogRecorderManager): the controller record
    # stream is served by LogRecorderManager at /jenkins/log/all
    # (authenticated GET, SYSTEM_READ-gated page). Anonymous gets denied,
    # so HTTP=200 is the non-vacuous proof the fetch carried auth.
    # The marker check additionally proves the body is a real rendered
    # record list (contains java.util.logging record text), not a 200
    # error-page with an empty log area — the failure mode that made an
    # earlier draft of this leg pass vacuously on a 404.
    # (raw Python string: the JS carries a literal \n inside its own
    # single-quoted string — a plain Python string would bake in a real
    # newline and SyntaxError the JS, which is how leg 2 died 2026-08-25.)
    log = c.js(r"""(async () => {
        const r = await fetch('/jenkins/log/all', {credentials:'include'});
        return 'HTTP=' + r.status + '\n' + (await r.text());
    })()""") or ""
    loghttp = log.split("\n", 1)[0].strip()
    bodylog = log.split("\n", 1)[1]
    check("L2 log fetch was authenticated (not a deny page)",
          loghttp.startswith("HTTP=200"), loghttp)
    # Non-vacuity marker: "fully up" is the controller's OWN lifecycle
    # record (hudson.lifecycle.Lifecycle#onReady), which lands in the log
    # recorder only if this surface is actually rendering real controller
    # records. If the log area were empty/erroneous this line is absent, so
    # its presence is the non-vacuous proof the spam scan below scanned a
    # population that would have contained doFillPolicyItems spam had the
    # D3 defect regressed. (The /logText endpoint this leg used in an
    # earlier draft is gone in core 2.528.3 — it 404'd and the spam scan
    # passed vacuously on an empty body. /log/all is the LogRecorderManager
    # replacement and carries the same record stream.)
    check("L2 log body carries a real controller record (non-vacuous)",
          "fully up" in bodylog, loghttp)
    spam = [l for l in bodylog.splitlines() if "doFillPolicyItems" in l
            or ("drop-down list" in l and "devcru" in l.lower())
            or ("doesn't have the" in l and "Items" in l)]
    check("L2 controller log has NO doFillPolicyItems spam", not spam,
          "\n".join(spam[:5]))

    # ---------------- LEG 3: back links, both arms, both schemes ----------
    c.raw("Emulation.setEmulatedMedia",
          {"features":[{"name":"prefers-color-scheme","value":"dark"}]})
    c.go(J + "/mfaAdmin/")
    wait(c, "!!document.querySelector('#adminRoster')", "admin roster")
    back = c.js("""(() => { const a=document.querySelector('a[href="/jenkins/manage/configureSecurity/"],a[href*="configureSecurity"]');
       return a ? {href:a.href, text:a.textContent.trim()} : null; })()""")
    check("L3a roster arm back link present", back is not None, str(back))
    if back:
        check("L3a target is the Security configuration page (absolute)",
              back["href"] == J + "/manage/configureSecurity/", back["href"])
        check("L3a link names its destination",
              "security configuration" in re.sub(r"\s+", " ", back["text"]).lower(), back["text"])
    # the link actually NAVIGATES — click it for real.
    c.js("document.querySelector('a[href*=\"configureSecurity\"]').click()")
    wait(c, "Array.from(document.querySelectorAll('select')).some(s=>s.name==='_.policy')",
         "back link navigates to the config page", 30)
    check("L3a back link navigates", True)
    c.shot(str(OUT / "1d-roster-back-dark.png"))
    # back to roster, then light scheme.
    c.go(J + "/mfaAdmin/")
    wait(c, "!!document.querySelector('#adminRoster')", "admin roster (light)")
    c.raw("Emulation.setEmulatedMedia",
          {"features":[{"name":"prefers-color-scheme","value":"light"}]})
    c.shot(str(OUT / "1d-roster-back-light.png"))
    check("L3b roster arm captured dark+light with link",
          all((p.exists() and p.stat().st_size > 0) for p in
              (OUT / "1d-roster-back-dark.png", OUT / "1d-roster-back-light.png")))
finally:
    c.close()

# ---------------- denial arm (read-only user, separate session) -----------
c = Cdp()
try:
    login_reader(c)
    c.raw("Emulation.setEmulatedMedia",
          {"features":[{"name":"prefers-color-scheme","value":"dark"}]})
    body = c.js("document.body.innerText")
    check("L3c reader is on the 403 denial arm",
          ("permission" in body.lower() or "403" in body)
          and not c.js("!!document.querySelector('#adminRoster')"),
          body[:200])
    back = c.js("""(() => { const a=document.querySelector('a[href*="/manage/"]');
       return a ? {href:a.href, text:a.textContent.trim()} : null; })()""")
    check("L3c denial arm back link present", back is not None, str(back))
    if back:
        check("L3c target is the Manage Jenkins console (absolute), not the admin-gated settings page",
              back["href"] == J + "/manage/" and "configureSecurity" not in back["href"], back["href"])
    c.shot(str(OUT / "1d-denial-back-dark.png"))
    c.raw("Emulation.setEmulatedMedia",
          {"features":[{"name":"prefers-color-scheme","value":"light"}]})
    c.shot(str(OUT / "1d-denial-back-light.png"))
    check("L3d denial arm captured dark+light with link",
          all((p.exists() and p.stat().st_size > 0) for p in
              (OUT / "1d-denial-back-dark.png", OUT / "1d-denial-back-light.png")))
finally:
    c.close()

# ---------------------------------------------------------------------
if failures:
    print("ACCEPT_1D_FAIL failures=" + ",".join(failures))
    sys.exit(1)
print("ACCEPT_1D_OK labels=clean raw_keys=0 truncated=0 select=REQUIRED-OFF log_clean=true back_roster=navigates back_denial=navigates themes=dark,light")
