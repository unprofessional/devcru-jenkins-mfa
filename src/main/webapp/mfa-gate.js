        (function () {
          "use strict";
          function $(id) { return document.getElementById(id); }
          var form = $("verifyForm");
          var codeInput = $("code");
          var msgEl = $("msg");
          var verifyBtn = $("verifyBtn");
          var resendBtn = $("resendBtn");
          var cooldownEl = $("cooldown");
          var crumbInput = form.querySelector("input[type=hidden]");
          // The gate's ?redirect= parameter is the CANONICAL "back to where
          // you were" carrier (A3). It is already in this page's URL; we read
          // it once and re-attach it to every XHR POST below, so the server
          // sees the same parameter on the verify/resend requests it needs
          // it on. A Referer-only fallback remains on the server for the
          // (rare) case the page is opened without the parameter.
          var redirectParam = null;
          try {
            redirectParam = (new URLSearchParams(window.location.search)).get("redirect");
          } catch (e) { redirectParam = null; }
          var lockUntil = 0;

          var MESSAGES = {
            wrong_code: "That code is not correct.",
            no_pending_code: "No code is waiting for you — send a new one below.",
            expired: "That code has expired — send a new one below.",
            not_enrolled: "This account has no 2FA factors enrolled.",
            not_authenticated: "Sign in first, then complete verification.",
            email_not_enrolled: "Email codes are not enrolled for this account.",
            resend_cooldown: "Please wait before requesting another code.",
            server_error: "Something went wrong on the server. Try again."
          };
          var LOCKED = "locked";

          function now() { return Date.now(); }
          function showMsg(kind, text) {
            msgEl.className = "msg " + kind;
            msgEl.textContent = text;
          }
          function hideMsg() {
            msgEl.className = "msg hidden";
            msgEl.textContent = "";
          }
          // Drives the visible countdown span AND the lockUntil timer. The
          // timer is the source of truth for re-enabling the buttons; the
          // span is absent for accounts without the email factor, so every
          // write is guarded.
          function startCountdown(seconds) {
            lockUntil = now() + seconds * 1000;
            var t0 = now();
            if (cooldownEl) { cooldownEl.hidden = false; }
            function tick() {
              var left = Math.max(0, Math.ceil((lockUntil - now()) / 1000));
              if (left <= 0) {
                lockUntil = 0;
                if (cooldownEl) {
                  cooldownEl.hidden = true;
                  cooldownEl.textContent = "";
                }
                refreshButtons();
                return;
              }
              if (cooldownEl) {
                cooldownEl.textContent = "Try again in " + left + "s";
              }
              refreshButtons();
              setTimeout(tick, 1000);
            }
            tick();
          }
          function refreshButtons() {
            var locked = lockUntil > now();
            verifyBtn.disabled = locked;
            if (resendBtn) { resendBtn.disabled = locked; }
          }

          function formData(payload) {
            var data = {};
            if (crumbInput) { data[crumbInput.name] = crumbInput.value; }
            for (var k in payload) { if (payload.hasOwnProperty(k)) { data[k] = payload[k]; } }
            return Object.keys(data).map(function (k) {
              return encodeURIComponent(k) + "=" + encodeURIComponent(data[k]);
            }).join("&");
          }
          function postForm(endpoint, payload) {
            return new Promise(function (resolve, reject) {
              var xhr = new XMLHttpRequest();
              xhr.open("POST", endpoint, true);
              xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
              xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
              xhr.onload = function () {
                if (xhr.status !== 200) {
                  reject({ error: "server_error", status: xhr.status });
                  return;
                }
                try {
                  resolve(JSON.parse(xhr.responseText));
                } catch (e) {
                  reject({ error: "server_error" });
                }
              };
              xhr.onerror = function () { reject({ error: "server_error" }); };
              xhr.send(formData(payload || {}));
            });
          }

          form.addEventListener("submit", function (ev) {
            ev.preventDefault();
            if (lockUntil > now()) {
              startCountdown(Math.ceil((lockUntil - now()) / 1000));
              return;
            }
            hideMsg();
            verifyBtn.disabled = true;
            if (resendBtn) { resendBtn.disabled = true; }
            var verifyPayload = { code: codeInput.value.trim() };
            if (redirectParam !== null) { verifyPayload.redirect = redirectParam; }
            postForm("postVerify", verifyPayload).then(function (res) {
              if (res.ok) {
                // Navigate ONLY to the server-validated target — never the
                // raw Referer. The server already ran it through
                // resolveRedirectTarget; this line is what makes the
                // open-redirect guarantee hold end to end.
                window.location.replace(res.redirect || "/");
                return;
              }
              if (res.error === LOCKED && res.retrySeconds) {
                showMsg("error", "Too many attempts. This account is locked to further tries.");
                startCountdown(res.retrySeconds);
                codeInput.value = "";
              } else {
                showMsg("error", MESSAGES[res.error] || MESSAGES.server_error);
                refreshButtons();
              }
            })["catch"](function (err) {
              showMsg("error", MESSAGES[err && err.error] || MESSAGES.server_error);
              refreshButtons();
            });
          });

          if (resendBtn) {
            resendBtn.addEventListener("click", function () {
              if (lockUntil > now()) {
                startCountdown(Math.ceil((lockUntil - now()) / 1000));
                return;
              }
              resendBtn.disabled = true;
              postForm("postResendEmail", {}).then(function (res) {
                if (res.ok) {
                  showMsg("ok", "A fresh code is on its way. It stays valid for a few minutes.");
                  startCountdown(res.cooldown || 60);
                } else if (res.error === "resend_cooldown" && res.retrySeconds) {
                  showMsg("error", MESSAGES.resend_cooldown);
                  startCountdown(res.retrySeconds);
                } else {
                  showMsg("error", MESSAGES[res.error] || MESSAGES.server_error);
                  refreshButtons();
                }
              })["catch"](function (err) {
                showMsg("error", MESSAGES[err && err.error] || MESSAGES.server_error);
                refreshButtons();
              });
            });
          }
        })();
