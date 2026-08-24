# BitBang Server

Signaling server for [BitBang](https://github.com/richlegrand/bitbang) -- a single static Go binary that brokers WebRTC connections between devices and browsers, and serves the browser-side bootstrap assets.

It is deliberately a **blind pipe**. It routes by device UID, relays SDP and ICE candidates, and hands out ephemeral TURN credentials. It never holds a private key, never terminates the peer-to-peer encryption, and never sees the access code -- that lives in the URL fragment, which browsers don't transmit. A full compromise of this server exposes which UIDs are online and their public keys, and nothing else.

## Requirements

- **Go 1.25+** to build (tested on 1.26). No CGo -- `CGO_ENABLED=0` produces a static binary, including the SQLite driver (pure-Go `modernc.org/sqlite`).
- Nothing else at runtime. No database server, no Python, no Node.
- For production: a TLS-terminating reverse proxy (nginx/caddy) and, optionally, a [coturn](https://github.com/coturn/coturn) server.

The server does **not** need Go installed on the host -- binaries are cross-compiled locally and shipped as static ELF.

## Repository layout

The Go module lives one level down, in `bitbang-server/`:

```
bitbang-server/            ← repo root (this README)
├── bitbang-server/        ← Go module, run all go commands from here
│   ├── cmd/signaling/            the server
│   ├── cmd/bitbang-metrics-dump/ companion CLI for reading metrics.db
│   ├── internal/
│   │   ├── handler/       HTTP + WebSocket endpoints
│   │   ├── registry/      in-memory device/client tables
│   │   ├── pairing/       6-digit pair-code table
│   │   ├── turn/          coturn REST credential minting
│   │   ├── metrics/       counters + periodic SQLite snapshots
│   │   └── identity/      UID derivation, signature verification
│   ├── web/               browser assets (bootstrap.js, sw.js, shims)
│   └── deploy/            systemd units, env templates, upload scripts
├── server_instructions.md  nginx + TLS + DNS setup
└── go_port.md              design notes from the Python → Go port
```

## Run a local instance

```bash
cd bitbang-server
go run ./cmd/signaling
```

Listens on **:8082**, serves `./web`, needs no config, env vars, or TURN. Check it with `curl -s localhost:8082/status`, and open <http://localhost:8082> for the pair-code entry page.

To attach a real device, note that the browser picks `ws://` or `wss://` from the page scheme but the `bitbang` CLI always dials **`wss://`** -- so a local server needs TLS in front of it. Any terminator works and the CLI doesn't verify the certificate (`InsecureSkipVerify`), so a self-signed one is fine:

```bash
socat OPENSSL-LISTEN:8443,cert=combined.pem,verify=0,reuseaddr,fork TCP:127.0.0.1:8082 &
bitbang serve shell --server localhost:8443
```

Browsers can keep using the plain `http://localhost:8082/<UID>#<code>` address -- `localhost` is a secure context, so WebRTC works without a certificate.

## Configuration

All configuration is environment variables. Everything has a working default except TURN.

| Variable | Default | Purpose |
|---|---|---|
| `BITBANG_SERVER_PORT` | `8082` | HTTP listen port (binds `0.0.0.0`) |
| `STATIC_DIR` | `./web` | Browser asset directory |
| `LOG_LEVEL` | `INFO` | `DEBUG` \| `INFO` \| `WARN` \| `ERROR` |
| `TRUST_PROXY_HEADERS` | `false` | Honor `X-Real-IP` for client-IP capture. **Only** enable behind a proxy that strips it from inbound requests. `X-Forwarded-For` is deliberately ignored |
| `COTURN_HOST` | -- | TURN hostname; empty disables TURN |
| `COTURN_SECRET` | -- | coturn `static-auth-secret` (sensitive) |
| `COTURN_TTL` | `86400` | TURN credential lifetime, seconds |
| `TURN_MAX_ACTIVE` | `0` | Cap on concurrent TURN grants; `0` = uncapped |
| `METRICS_PATH` | -- | SQLite file for periodic `/status` snapshots; empty disables |
| `METRICS_INTERVAL` | `300` | Snapshot cadence, seconds |
| `INSTALL_URL` | -- | `GET /install` 302s here; empty returns 404 |
| `FRONT_PAGE_PATH` | -- | HTML snippet spliced into the entry page at `<!-- FRONT_PAGE -->` |

Templates with commentary live in `deploy/production.env.example` and `deploy/test.env.example`.

**`FRONT_PAGE_PATH`** lets an operator brand the landing page without forking. The snippet should contain `<div id="bb-pair-input"></div>`, where the pair-code input renders (it appends to the end if the div is absent). The file is re-read on every request -- edit and reload, no restart.

**`INSTALL_URL`** backs `curl -sSfL <host>/install | sh`. It's config rather than a baked-in constant so each operator points it at the install script for the binary *they* ship. Left unset, the route 404s.


## TURN (coturn)

Without TURN, connections succeed only when peers can reach each other directly -- fine for a LAN, unreliable across symmetric NATs and most mobile networks.

The server mints **ephemeral credentials** using the [TURN REST API](https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest-00) scheme: a time-limited username and an HMAC of it under a shared secret. No per-user accounts on the TURN server, and nothing long-lived handed to a browser.

In `turnserver.conf`:

```
use-auth-secret
static-auth-secret=<same value as COTURN_SECRET>
realm=turn.example.com
```

Then set `COTURN_HOST` and `COTURN_SECRET`. They must match exactly, or every credential is rejected. Confirm from the log line at startup:

```
INFO TURN: using coturn host=turn.example.com ttl_s=3600 max_active=0
```

`TURN_MAX_ACTIVE` caps concurrent grants -- relay bandwidth is the expensive resource, so this is the lever that bounds cost. `0` means no cap.

## Deploying

Deployment is: build a static binary locally, ship it over SSH, restart a systemd unit. Two targets ship out of the box -- `production` and `test` -- with identical mechanics.

**One-time, on the server** (see `server_instructions.md` for the full nginx vhost, DNS, and certbot walkthrough):

1. Create the directory: `sudo mkdir -p /opt/bitbang && sudo chown -R $USER:$USER /opt/bitbang`
2. Point DNS at the host and issue a certificate.
3. Add an nginx vhost proxying `/` to `127.0.0.1:<port>`, with `Upgrade`/`Connection` headers set so WebSockets survive, and `X-Real-IP` set from the peer address. Do **not** expose the server port publicly.
4. Link and enable the systemd unit. These are **user** units -- the deploy script runs `systemctl --user`, so no root is involved and `sudo systemctl` won't find the service. The upload ships the unit file into `/opt/bitbang/` but doesn't install it; symlink it into `~/.config/systemd/user/` once.
5. `sudo loginctl enable-linger $USER`, or the service stops at logout and never returns after a reboot.

Production listens on **8081**, test on **8082** -- set by `BITBANG_SERVER_PORT` in each `.env`, and the nginx `proxy_pass` must match.

**One-time, locally:**

```bash
cd bitbang-server/deploy
cp production.deploy.example production.deploy   # SSH host, key, target dir
cp production.env.example  production.env        # runtime env + COTURN_SECRET
```

Both concrete files are gitignored -- only the `.example` templates are tracked. Keep `COTURN_SECRET` out of commits.

**Every deploy:**

```bash
cd bitbang-server
./deploy/upload_production      # or ./deploy/upload_test
```

The script cross-compiles for `linux/amd64` with `CGO_ENABLED=0`, tars the binary plus `bitbang-metrics-dump`, the env file, the front-page snippet, the unit file and `web/`, scps it, extracts it, moves `production.env` into place as `.env`, restarts the service, and prints `/status` from the remote so you can confirm the new version is live.

Rolling back means redeploying a previous commit -- there's no built-in versioned artifact store.

## Metrics

Set `METRICS_PATH` to also persist snapshots to SQLite on a timer. Counters survive restarts: on startup the server loads the most recent row, seeds its in-memory atomics, and writes a fresh row immediately so time-series queries don't show a phantom gap. At most one interval of un-flushed events is lost in a hard crash. Schema and PRAGMAs (WAL, `synchronous=NORMAL`) are applied on first open -- no setup. Budget roughly **30 MB/year** at the 5-minute default.

Read it back with the bundled tool (no `sqlite3` package required). The
deploy ships the binary to `/opt/bitbang` and sets `METRICS_PATH` only in
the service unit, so on the server point it at the database explicitly:

```bash
/opt/bitbang/bitbang-metrics-dump -db /opt/bitbang/metrics.db | jq .              # latest snapshot
/opt/bitbang/bitbang-metrics-dump -db /opt/bitbang/metrics.db -history 100 | jq . # last 100 rows
```

`-db` defaults to `$METRICS_PATH`, so if that variable is exported in your
shell you can drop the flag.

A bad `METRICS_PATH` is a **hard startup failure** -- better to refuse to boot than to silently discard metrics.

## Development

```bash
cd bitbang-server
go build ./...
go test ./...     # ~16s; pairing and handler suites include real timing waits
go vet ./...
node --test web_test/*.test.js
```

The handler and pairing suites exercise the 3-second lookup delay and full pair round-trips against a live `httptest` server, so they're slow by design.

Protocol constants (`ProtocolVersion`, `MinProtocolVersion`) live in `internal/wire`. UIDs are the first 32 hex characters of `SHA256(public_key_DER)`, and the server verifies device signatures across **RSA ≥2048, ECDSA P-256, and Ed25519** -- see `internal/identity`.

## License

MIT. See [LICENSE](LICENSE).

## Contributing

Issues and PRs welcome.
