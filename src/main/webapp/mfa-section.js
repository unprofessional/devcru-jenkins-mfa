        (function () {
          "use strict";
          var section = document.getElementById("mfaSection");
          if (!section) { return; }
          // Config values ride as data attributes on #mfaSection: Jenkins'
          // CSP is script-src 'self' (no 'unsafe-inline'), so this file is
          // served statically and cannot carry server-side interpolation.
          var CRUMB_NAME = section.getAttribute("data-mfa-crumb-field") || "Jenkins-Crumb";
          var CRUMB = section.getAttribute("data-mfa-crumb-value") || "";
          var BASE = section.getAttribute("data-mfa-base") || "mfa/"; // e.g. "http://host:port/jenkins/mfa/"
          var msg = document.getElementById("mfaMsg");
          function $(id) { return document.getElementById(id); }
          var totpEnroll = $("mfaTotpEnroll");
          var totpQr = $("mfaTotpQr");
          var totpManual = $("mfaTotpManual");
          var totpSeed = $("mfaTotpSeed");
          var totpCode = $("mfaTotpCode");

          var MESSAGES = {
            wrong_code: "That code did not match. Try the current 6-digit code from your app.",
            invalid_seed: "That code is no longer valid — generate a fresh one and try again.",
            email_not_enrolled: "Set and save a registered email address first.",
            resend_cooldown: "Please wait a moment before requesting another code.",
            not_enrolled: "That factor is not enabled on this account.",
            not_authenticated: "Your session looks off — reload the page and try again.",
            verification_required: "This action needs a freshly verified sign-in: complete the one-time code step first, then reload this page.",
            server_error: "Something went wrong on the server. Try again."
          };

          function showMsg(kind, text) {
            msg.className = "mfa-msg mfa-msg--" + kind;
            msg.textContent = text;
          }
          function clearMsg() { msg.className = "mfa-msg"; msg.textContent = ""; }

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

          function showEnrollUI() { if (totpEnroll) { totpEnroll.hidden = false; } }
          function hideEnrollUI() { if (totpEnroll) { totpEnroll.hidden = true; } }
          function clearEnroll() {
            if (totpQr) { totpQr.removeAttribute("src"); }
            if (totpManual) { totpManual.textContent = ""; }
            if (totpSeed) { totpSeed.value = ""; }
            if (totpCode) { totpCode.value = ""; }
            hideEnrollUI();
          }
          function refreshState() { window.location.reload(); }

          var genBtn = $("mfaTotpGenerate");
          function generate() {
            if (genBtn) { genBtn.disabled = true; }
            clearMsg();
            post("postEnroll", {}).then(function (res) {
              if (genBtn) { genBtn.disabled = false; }
              if (!res.ok) { showMsg("error", MESSAGES[res.error] || MESSAGES.server_error); return; }
              if (totpSeed) { totpSeed.value = res.seed || ""; }
              if (totpQr && res.dataUriPng) { totpQr.setAttribute("src", res.dataUriPng); }
              else if (totpQr) { totpQr.remove(); }
              if (totpManual) { totpManual.textContent = res.seed || ""; }
              showEnrollUI();
            })["catch"](function () {
              if (genBtn) { genBtn.disabled = false; }
              showMsg("error", MESSAGES.server_error);
            });
          }
          if (genBtn) { genBtn.addEventListener("click", generate); }
          var regenBtn = $("mfaTotpRegenerate");
          if (regenBtn) { regenBtn.addEventListener("click", function () { clearEnroll(); generate(); }); }

          var confirmBtn = $("mfaTotpConfirm");
          if (confirmBtn) {
            confirmBtn.addEventListener("click", function () {
              clearMsg();
              confirmBtn.disabled = true;
              post("postEnrollConfirm", { seed: totpSeed ? totpSeed.value : "", code: (totpCode.value || "").trim() })
                .then(function (res) {
                  if (res.ok) { refreshState(); return; }
                  confirmBtn.disabled = false;
                  showMsg("error", MESSAGES[res.error] || MESSAGES.server_error);
                })["catch"](function () { confirmBtn.disabled = false; showMsg("error", MESSAGES.server_error); });
            });
          }

          var disableTotp = $("mfaTotpDisable");
          if (disableTotp) {
            disableTotp.addEventListener("click", function () {
              if (!window.confirm("Disable authenticator-app MFA for this account? It stops working immediately.")) { return; }
              clearMsg();
              post("postDisableTotp", {}).then(function (res) {
                if (res.ok) { refreshState(); return; }
                showMsg("error", MESSAGES[res.error] || MESSAGES.server_error);
              })["catch"](function () { showMsg("error", MESSAGES.server_error); });
            });
          }

          var testCodeBtn = $("mfaEmailTestCode");
          if (testCodeBtn) {
            testCodeBtn.addEventListener("click", function () {
              clearMsg();
              testCodeBtn.disabled = true;
              post("postEmailTestCode", {}).then(function (res) {
                testCodeBtn.disabled = false;
                if (res.ok) { showMsg("ok", "A one-time code is on its way to your registered address."); return; }
                if (res.error === "resend_cooldown" && res.retrySeconds) {
                  showMsg("error", MESSAGES.resend_cooldown + " (about " + res.retrySeconds + "s)");
                  return;
                }
                showMsg("error", MESSAGES[res.error] || MESSAGES.server_error);
              })["catch"](function () { testCodeBtn.disabled = false; showMsg("error", MESSAGES.server_error); });
            });
          }

          var disableEmail = $("mfaEmailDisable");
          if (disableEmail) {
            disableEmail.addEventListener("click", function () {
              if (!window.confirm("Disable email-code MFA and clear the registered address?")) { return; }
              clearMsg();
              post("postDisableEmail", {}).then(function (res) {
                if (res.ok) { refreshState(); return; }
                showMsg("error", MESSAGES[res.error] || MESSAGES.server_error);
              })["catch"](function () { showMsg("error", MESSAGES.server_error); });
            });
          }

          var revokeBtn = $("mfaRevokeTrust");
          if (revokeBtn) {
            revokeBtn.addEventListener("click", function () {
              clearMsg();
              post("postRevokeTrust", {}).then(function (res) {
                if (res.ok) { showMsg("ok", "Remembered devices revoked — the next sign-in will ask for a second factor."); return; }
                showMsg("error", MESSAGES[res.error] || MESSAGES.server_error);
              })["catch"](function () { showMsg("error", MESSAGES.server_error); });
            });
          }
        })();
