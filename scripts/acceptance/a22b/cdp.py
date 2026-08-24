#!/tmp/cdp-venv/bin/python
"""Minimal CDP client for the A22-b walk. Talk to Chrome 151 on 127.0.0.1:9333.
API: Cdp().go(url), .shot(path), .js(expr) -> result, .sleep(s), .dump(url)
Each Cdp() opens its own dedicated tab so state is inspectable step-by-step."""
import base64, json, subprocess, sys, time, urllib.request
import websockets.sync.client as ws

def http_json(path, method="GET", data=None):
    req = urllib.request.Request(f"http://127.0.0.1:9333{path}", method=method,
                                 data=data.encode() if data else None)
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)

class Cdp:
    def __init__(self, url="about:blank"):
        tabs = http_json("/json/new?about:blank", method="PUT")
        self.target = tabs
        self.sock = ws.connect(self.target["webSocketDebuggerUrl"], max_size=None)
        self.id = 0
        self._enable()
    def _enable(self):
        for m in ["Page.enable", "Runtime.enable", "DOM.enable"]:
            self.raw(m)
    def raw(self, method, params=None, timeout=30):
        self.id += 1
        mid = self.id
        self.sock.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        end = time.time() + timeout
        while time.time() < end:
            msg = json.loads(self.sock.recv(timeout=timeout))
            if msg.get("id") == mid:
                if "error" in msg:
                    raise RuntimeError(f"CDP {method}: {msg['error']}")
                return msg.get("result", {})
        raise TimeoutError(method)
    def go(self, url, timeout=45):
        self.raw("Page.navigate", {"url": url}, timeout=timeout)
        time.sleep(2.0)
        self.wait_idle(timeout)
        return self.url
    def wait_idle(self, timeout=15):
        end = time.time() + timeout
        while time.time() < end:
            time.sleep(0.4)
            st = self.js("document.readyState")
            if st in ("complete", "interactive"):
                time.sleep(0.5)
                return
    @property
    def url(self):
        return self.js("location.href")
    def js(self, expr, timeout=20):
        r = self.raw("Runtime.evaluate", {
            "expression": expr, "returnByValue": True, "awaitPromise": True, "timeout": timeout*1000}, timeout=timeout+5)
        if r.get("exceptionDetails"):
            raise RuntimeError("JS exception: " + json.dumps(r["exceptionDetails"])[:500])
        return r.get("result", {}).get("value")
    def shot(self, path):
        r = self.raw("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": False})
        with open(path, "wb") as f:
            f.write(base64.b64decode(r["data"]))
        return path
    def close(self):
        try:
            self.sock.close()
            urllib.request.urlopen(f"http://127.0.0.1:9333/json/close/{self.target['id']}", timeout=5).read()
        except Exception:
            pass

if __name__ == "__main__":
    c = Cdp()
    print("tab:", c.target["id"][:12], "url:", c.url)
    c.close()
    print("OK")
