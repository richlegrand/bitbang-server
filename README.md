# BitBang Server

![Tests](https://github.com/richlegrand/bitbang-server/actions/workflows/tests.yml/badge.svg)

Signaling server for [BitBang](https://github.com/richlegrand/bitbang). Handles WebSocket signaling between devices and browsers to establish WebRTC connections.

## Setup

Requires Python 3.10+ with a virtual environment:

```bash
python3 -m venv venv
venv/bin/pip install quart hypercorn cryptography
```

## TURN Server

The server generates ephemeral TURN credentials using the [TURN REST API](https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest-00) (coturn shared secret). Create a `.env` file in `signaling/`:

```
COTURN_HOST=turn.example.com
COTURN_SECRET=your-shared-secret
```

The `COTURN_SECRET` must match the `static-auth-secret` in your coturn server's `turnserver.conf`.

Optional: `COTURN_TTL=86400` (credential lifetime in seconds, default 24h).

Without TURN configured, connections only work when peers can reach each other directly.

## Running

```bash
cd signaling
./run.sh
```

Listens on port 8081. Use a reverse proxy (nginx/caddy) for TLS.

## Deployment

The `upload` script tars the `signaling/` directory, uploads it to the server via SCP, extracts it, and restarts the `signaling.service` systemd unit.
