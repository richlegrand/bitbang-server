#!/usr/bin/env python3
"""A stand-in for a device, so the config page can be developed without one.

Temporary: moves out with settings.html when the config page becomes a plugin.

Serves the static files and answers /__bitbang/settings the way the firmware
does -- same declaration, same status codes, same error bodies. The page runs
its real default URL against this, so what gets exercised is the code that
will run for real, not a mock branch inside it.

    ./settings-mock-server.py        then open http://localhost:%s/settings.html" % __import__("os").environ.get("PORT", 8000)

Device behaviors deliberately mirrored, because they are what the page has to
render and they are awkward to provoke on hardware:
  - console_backlog quantizes down to its step and reports what it stored
  - out-of-range returns min/max so the page can say why
  - name rejects spaces and empty, with the device's own wording
  - log_test returns a msg
"""
import json, os, re, copy
from http.server import SimpleHTTPRequestHandler, HTTPServer

PATH = "/__bitbang/settings"

SETTINGS = json.load(open("settings-mock.json"))["settings"]

class Handler(SimpleHTTPRequestHandler):
    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _find(self, key):
        return next((s for s in SETTINGS if s["k"] == key), None)

    def do_GET(self):
        if self.path.split("?")[0] != PATH:
            return super().do_GET()
        m = re.search(r"[?&]g=([^&]*)", self.path)
        group = None
        if m:
            from urllib.parse import unquote_plus
            group = unquote_plus(m.group(1))
        out = [s for s in SETTINGS if group is None or s.get("g") == group]
        self._json(200, {"settings": copy.deepcopy(out)})

    def do_POST(self):
        if self.path.split("?")[0] != PATH:
            return self._json(404, {"error": "unknown"})
        n = int(self.headers.get("Content-Length") or 0)
        try:
            req = json.loads(self.rfile.read(n))
        except Exception:
            return self._json(400, {"error": "body is not JSON"})

        key = req.get("k")
        if not key:
            return self._json(400, {"error": "no key"})
        s = self._find(key)
        if s is None:
            return self._json(404, {"k": key, "error": "unknown"})
        if s.get("ro"):
            return self._json(403, {"k": key, "error": s["ro"] if isinstance(s["ro"], str) else "read-only"})

        v = req.get("v")
        t = s["t"]

        if t == "action":
            return self._json(200, {"k": key, "msg": "done"})
        if t == "bool":
            if not isinstance(v, bool):
                return self._json(400, {"k": key, "error": "expected bool"})
            s["v"] = v
        elif t == "int":
            if not isinstance(v, (int, float)) or isinstance(v, bool):
                return self._json(400, {"k": key, "error": "expected int"})
            if "min" in s and not (s["min"] <= v <= s["max"]):
                return self._json(400, {"k": key, "error": "out of range",
                                        "min": s["min"], "max": s["max"]})
            step = s.get("step")
            s["v"] = int(v // step * step) if step else int(v)
        elif t == "enum":
            if v not in s.get("o", []):
                return self._json(400, {"k": key, "error": "not one of the choices"})
            s["v"] = v
        else:                                     # str
            if not isinstance(v, str):
                return self._json(400, {"k": key, "error": "expected a string"})
            if s.get("maxlen") and len(v) > s["maxlen"]:
                return self._json(400, {"k": key, "error": "too long"})
            if key == "name":
                if v == "":
                    return self._json(400, {"k": key, "error": "a name cannot be empty"})
                if " " in v:
                    return self._json(400, {"k": key, "error": "no spaces -- try a dash"})
            s["v"] = v

        return self._json(200, {"k": key, "v": s["v"]})

    def log_message(self, fmt, *args):
        print("  %s" % (fmt % args))

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8000))
    print("mock device on http://localhost:%d/settings.html" % port)
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
