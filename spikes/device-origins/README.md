# Device-origins spike

The Nov 9 2026 prototype behind `bitbang-docs/device-origins.md` (see its
*Spike results*). Throwaway code: it proves the design, it isn't the start of
the implementation.

- `server.py` -- serves the top page on `bb.localhost`, and on any
  `<label>.bb.localhost` only the start page and the worker. The two names are
  same-site, as `bitba.ng` and `<label>.bitba.ng` are.
- `top.html`, `top.js` -- stand in for bitba.ng's bootstrap: compute the label
  (HMAC of the uid with a per-browser secret), hold a fake device behind a
  `MessageChannel` in place of the data channel, hand ports to their own iframe.
- `loader.html` -- the start page, `/__bb/start#<path>`: install the worker if
  needed, hand it a fresh port, replace itself with the device path.
- `sw.js` -- the label worker: serves one device, gets a port from its pages,
  keeps a cookie jar.
- `run.py` -- Playwright driver: first and second visit timings, navigation
  cases, cookies, isolation, popup, and navigation after forced worker stops.

Run it, from this directory:

    python3 server.py 8800 &
    ~/bitbang/bitbangproxy/tests/e2e/.venv/bin/python run.py chromium,firefox,webkit 10

`*.localhost` resolves to the loopback address on this machine (systemd's
`nss-myhostname`) and counts as a secure context, so no DNS or certificates
are needed. Chromium restarts the worker through CDP; Firefox through a 1 s
idle timeout; WebKit can't be forced.
