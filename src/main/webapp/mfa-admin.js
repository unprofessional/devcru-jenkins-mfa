/*
 * The A22-b admin page's static verb script. Served from
 * <root>/plugin/devcru-mfa/mfa-admin.js — Jenkins' CSP is script-src
 * 'self' (no 'unsafe-inline', postmortem round 2), so this file cannot
 * live inline in index.jelly and carries no server-side interpolation:
 * its config arrives as data attributes on #mfaAdminConfig (the house
 * pattern from mfa-section.js).
 *
 * The two verbs (mads ruling 2: clear-all + revoke-trust only, for now):
 *   clearFactors — the lockout recovery; wipes the target's factor state.
 *   revokeTrust  — forces the target's browsers to re-verify next login.
 *
 * Both are destructive and BOTH require type-in confirmation (mads
 * ruling 5: "100% user typed confirmation"): the dialog demands the
 * target's user id verbatim before the POST fires, and the POST itself
 * carries the typed value — the ENDPOINT re-checks it matches the
 * target server-side (confirmTypedUserId), so a bypass of the dialog
 * still cannot clear the wrong account. The client check is UX; the
 * server check is the control.
 *
 * Single-flight: a button is disabled for the duration of its request
 * (the house pattern) — a double-click cannot double-fire, and a second
 * clear on an already-cleared user is the endpoint's idempotent
 * not_enrolled, not an error state.
 */
(function () {
  "use strict";
  var cfg = document.getElementById("mfaAdminConfig");
  if (!cfg) { return; }
  var BASE = cfg.getAttribute("data-base") || "mfaAdmin/"; // e.g. "http://host:port/jenkins/mfaAdmin/"
  var CRUMB_NAME = cfg.getAttribute("data-crumb-field") || "Jenkins-Crumb";
  var CRUMB = cfg.getAttribute("data-crumb-value") || "";
  var result = document.getElementById("adminResult");

  var MESSAGES = {
    admin_verification_required: "Your session needs a freshly verified sign-in to perform this action: complete the one-time code step first, then reload this page.",
    admin_self_management_forbidden: "You cannot clear your own factors from the admin page: use the Security tab of your own account.",
    self_management_forbidden: "You cannot clear your own factors from the admin page: use the Security tab of your own account.",
    // A24 stable errors
    already_enrolled: "That user is already enrolled.",
    invalid_email: "Enter a valid mailbox address first.",
    user_not_found: "That user no longer exists — reload the page.",
    user_disabled: "That account is disabled in the realm; it cannot be force-enrolled.",
    user_exempt: "That user is on the MFA exemption list; force-enrol does not apply.",
    persistence_failed: "The operation applied for this session, but saving it failed — try again, and if this repeats tell your admin (the change is lost on restart).",
    server_error: "Something went wrong on the server. Try again.",
    not_enrolled: "Nothing to clear — that user has no MFA factors registered."
  };

  function showResult(kind, text) {
    if (!result) { return; }
    result.style.display = "";
    result.className = "result result-" + (kind === "ok" ? "ok" : "err");
    result.textContent = text;
  }

  function post(endpoint, payload) {
    var body = new URLSearchParams();
    if (CRUMB) { body.append(CRUMB_NAME, CRUMB); }
    for (var k in (payload || {})) { if (payload.hasOwnProperty(k)) { body.append(k, payload[k]); } }
    return fetch(BASE + endpoint, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/x-www-form-urlencoded",
                 "X-Requested-With": "XMLHttpRequest" },
      body: body.toString()
    }).then(function (r) { return r.json(); })
      ["catch"](function () { return { ok: false, error: "server_error" }; });
  }

  // The typed-confirmation dialog (ruling 5). Builds itself once, reuses
  // thereafter; confirm fires only when the typed value EXACTLY equals
  // the target's user id. No window.confirm, no pre-filled value — the
  // id must be typed, which is the whole point of the confirmation.
  var veil = null;
  function confirmTyped(op, userId, display, onConfirm) {
    if (!veil) {
      veil = document.createElement("div");
      veil.className = "veil";
      veil.style.display = "none";
      document.body.appendChild(veil);
    }
    veil.style.display = "flex";
    veil.innerHTML = "";
    var dialog = document.createElement("div");
    dialog.className = "dialog";
    var h = document.createElement("h2");
    h.textContent = op === "clearFactors"
        ? "Clear ALL MFA factors for " + display + "?"
        : "Revoke remembered-device trust for " + display + "?";
    var p = document.createElement("p");
    p.textContent = op === "clearFactors"
        ? "Their TOTP seed, email factor, and registered address are removed. They can self-enrol again; this is the lockout recovery. Type the user id to confirm."
        : "Their remembered devices stop skipping the one-time code at next login. Type the user id to confirm.";
    var input = document.createElement("input");
    input.type = "text";
    input.autocomplete = "off";
    input.autocapitalize = "none";
    input.spellcheck = false;
    input.placeholder = "type user id: " + userId;
    var row = document.createElement("div");
    row.className = "row";
    var cancel = document.createElement("button");
    cancel.type = "button";
    cancel.className = "btn";
    cancel.textContent = "Cancel";
    var go = document.createElement("button");
    go.type = "button";
    go.className = "btn btn-danger";
    go.textContent = "Confirm";
    go.disabled = true;
    row.appendChild(cancel);
    row.appendChild(go);
    dialog.appendChild(h);
    dialog.appendChild(p);
    dialog.appendChild(input);
    dialog.appendChild(row);
    veil.appendChild(dialog);
    input.focus();
    input.oninput = function () {
      go.disabled = (input.value !== userId);
    };
    cancel.onclick = close;
    go.onclick = function () {
      if (input.value !== userId) { return; }
      close();
      onConfirm(userId);
    };
    input.onkeydown = function (e) {
      if (e.key === "Enter") { go.onclick(); }
      if (e.key === "Escape") { close(); }
    };
    veil.onclick = function (e) { if (e.target === veil) { close(); } };
    function close() {
      veil.style.display = "none";
      input.oninput = null;
      input.onkeydown = null;
    }
  }

  function wire(btn) {
    var op = btn.getAttribute("data-op");
    var userId = btn.getAttribute("data-user-id");
    var display = btn.getAttribute("data-display");
    if (op === "forceEnrol") {
      // A24: the force verb carries its own mailbox + consequence dialog;
      // the generic typed-confirm below would drop the email parameter.
      wireForceEnrol(btn, userId, display);
      return;
    }
    btn.addEventListener("click", function () {
      btn.disabled = true; // single-flight while the dialog is open
      confirmTyped(op, userId, display, function (typed) {
        // POST: the endpoint re-checks confirmUserId == its own userId
        // server-side; this field is the same value the dialog already
        // verified, so a mismatch here is a client race, not a user
        // action — the server's error tells the truth either way.
        post(op, { userId: userId, confirmUserId: typed }).then(function (res) {
          if (res.ok) {
            showResult("ok", op === "clearFactors"
                ? "Factors cleared for " + display + ". They can self-enrol again."
                : "Trust revoked for " + display + ". Their devices re-verify at next login.");
            window.location.reload();
          } else {
            showResult("err", MESSAGES[res.error] || MESSAGES.server_error);
            btn.disabled = false;
          }
        });
      });
    });
  }

  // A24: force enrol. Reads the per-row mailbox input, demands type-in
  // confirmation like every other verb (Ruling 5 — one rule for the whole
  // surface), then POSTs userId/confirmUserId/email. The endpoint re-checks
  // everything server-side; this is UX plus payload assembly.
  function wireForceEnrol(btn, userId, display) {
    var acctRow = btn.closest("tr");
    if (acctRow && acctRow.getAttribute("data-acct-state") === "disabled") {
      btn.disabled = true; // D6: positively disabled rows are not actionable
      return;
    }
    btn.addEventListener("click", function () {
      var mail = "";
      var input = document.querySelector('input[data-mailbox-for="' + userId + '"]');
      if (!input || !input.value.trim()) {
        showResult("err", MESSAGES.invalid_email);
        if (input) { input.focus(); }
        return;
      }
      mail = input.value.trim();
      btn.disabled = true;
      confirmTypedForce(userId, display, mail, function (typed) {
        post("forceEnrol", { userId: userId, confirmUserId: typed, email: mail })
          .then(function (res) {
            if (res.ok) {
              showResult("ok", "Force enrol recorded for " + display
                + ". They must verify at their next login.");
              window.location.reload();
            } else {
              showResult("err", MESSAGES[res.error] || MESSAGES.server_error);
              btn.disabled = false;
            }
          });
      });
    });
  }

  // Same shape as confirmTyped but with the force-enrol consequence copy and
  // the mailbox echoed in the dialog body.
  function confirmTypedForce(userId, display, email, onConfirm) {
    if (!veil) {
      veil = document.createElement("div");
      veil.className = "veil";
      veil.style.display = "none";
      document.body.appendChild(veil);
    }
    veil.style.display = "flex";
    veil.innerHTML = "";
    var dialog = document.createElement("div");
    dialog.className = "dialog";
    var h = document.createElement("h2");
    h.textContent = "Force-enrol " + display + "?";
    var p = document.createElement("p");
    p.textContent = userId + " will be required to complete MFA setup at their"
      + " next login. A code will be sent to " + email + "; nothing is verified"
      + " until THEY prove it. Type the user id to confirm.";
    var input = document.createElement("input");
    input.type = "text";
    input.autocomplete = "off";
    input.autocapitalize = "none";
    input.spellcheck = false;
    input.placeholder = "type user id: " + userId;
    var row = document.createElement("div");
    row.className = "row";
    var cancel = document.createElement("button");
    cancel.type = "button";
    cancel.className = "btn";
    cancel.textContent = "Cancel";
    var go = document.createElement("button");
    go.type = "button";
    go.className = "btn btn-danger";
    go.textContent = "Confirm";
    go.disabled = true;
    row.appendChild(cancel);
    row.appendChild(go);
    dialog.appendChild(h);
    dialog.appendChild(p);
    dialog.appendChild(input);
    dialog.appendChild(row);
    veil.appendChild(dialog);
    input.focus();
    input.oninput = function () { go.disabled = (input.value !== userId); };
    cancel.onclick = close;
    go.onclick = function () {
      if (input.value !== userId) { return; }
      close();
      onConfirm(userId);
    };
    input.onkeydown = function (e) {
      if (e.key === "Enter") { go.onclick(); }
      if (e.key === "Escape") { close(); }
    };
    veil.onclick = function (e) { if (e.target === veil) { close(); } };
    function close() {
      veil.style.display = "none";
      input.oninput = null;
      input.onkeydown = null;
    }
  }

  var buttons = document.querySelectorAll("button[data-op]");
  for (var i = 0; i < buttons.length; i++) { wire(buttons[i]); }
})();
