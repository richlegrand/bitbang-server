// Command signaling is the BitBang signaling server.
//
// Environment variables:
//
//	BITBANG_SERVER_PORT  HTTP port to listen on (default 8082)
//	COTURN_HOST          TURN server hostname; empty disables coturn
//	COTURN_SECRET        TURN REST API shared secret
//	COTURN_TTL           TURN credential lifetime in seconds (default 86400)
//	TURN_MAX_ACTIVE      Max concurrent clients granted TURN (0 = no cap)
//	LOG_LEVEL            DEBUG | INFO | WARN | ERROR (default INFO)
//	STATIC_DIR           Path to web/ asset directory (default ./web)
//	STATUS_TOKEN         When set, /status needs "Authorization: Bearer <token>"
//	                     from anywhere but loopback. Empty leaves it public.
//	VERSION_REPOS        Comma-separated owner/repo=key pairs whose latest
//	                     release is reported to clients. Empty disables
//	                     polling entirely (no outbound requests).
//	VERSION_POLL_INTERVAL  Seconds between polls (default 3600)
//	TRUST_PROXY_HEADERS  When "true", honor X-Real-IP/X-Forwarded-For for
//	                     browser-IP capture. Enable only behind a proxy
//	                     that strips these headers from inbound requests.
//	METRICS_PATH         When set, periodically append /status counters
//	                     as JSONL to this file. Empty disables.
//	METRICS_INTERVAL     Snapshot cadence in seconds (default 300 = 5 min).
//	INSTALL_URL          When set, GET /install responds with a 302 to
//	                     this URL. Empty (default) responds 404. Lets
//	                     each operator point their `curl host/install`
//	                     at the script that installs the binary they
//	                     ship — no upstream URL baked into the binary.
//	FRONT_PAGE_PATH      Path to an HTML snippet spliced into the entry
//	                     page at `<!-- FRONT_PAGE -->`. Lets each
//	                     operator add branding, install hints, or links
//	                     above/around the pair-code form without
//	                     forking. The snippet should contain a
//	                     `<div id="bb-pair-input"></div>` somewhere;
//	                     the pair input renders there (or at the end if
//	                     the div is missing). Empty (default) = bare
//	                     pair-entry page. File is re-read on every
//	                     request — no restart needed after edits.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"

	"bitbang-server-go/internal/handler"
	"bitbang-server-go/internal/metrics"
	"bitbang-server-go/internal/pairing"
	"bitbang-server-go/internal/ratelimit"
	"bitbang-server-go/internal/registry"
	"bitbang-server-go/internal/releases"
	"bitbang-server-go/internal/turn"
)

func main() {
	cfg := loadConfig()
	logger := newLogger(cfg.LogLevel)
	slog.SetDefault(logger)

	devices := registry.NewMemoryRegistry()
	clients := registry.NewClientRegistry()
	turnProvider := turn.NewCoturn(cfg.CoturnHost, cfg.CoturnSecret, cfg.CoturnTTL, cfg.TURNMaxActive)
	limiter := ratelimit.NoOp{}
	pairingTable := pairing.NewTable()
	connMetrics := metrics.New()

	// Periodic snapshot recorder + counter resume. Disabled when
	// METRICS_PATH is unset; see internal/metrics/recorder.go for the
	// SQLite schema and durability story. Lifetime tied to recorderCtx
	// so the goroutine exits on shutdown via the same SIGINT/SIGTERM
	// that drains the HTTP server.
	tracker := releases.New(
		cfg.VersionRepos,
		time.Duration(cfg.VersionPollInterval)*time.Second,
		logger,
	)

	recorderCtx, stopRecorder := context.WithCancel(context.Background())
	defer stopRecorder()
	recorder, err := metrics.NewRecorder(
		connMetrics,
		devices,
		clients,
		cfg.MetricsPath,
		time.Duration(cfg.MetricsInterval)*time.Second,
		logger,
	)
	if err != nil {
		// Hard failure on bad METRICS_PATH (unwritable directory, etc.).
		// Better to refuse to start than to silently lose all metrics.
		logger.Error("metrics recorder failed to open", "err", err, "path", cfg.MetricsPath)
		os.Exit(1)
	}
	// recorder is nil when METRICS_PATH is empty (recorder disabled).
	if recorder != nil {
		defer recorder.Close()

		// Resume: load the most-recent persisted snapshot and seed the
		// in-memory atomics with its counter values. On a fresh deploy
		// (no DB file or no rows), LoadLastSnapshot returns the zero
		// Snapshot, which is exactly what New() already gave us — a
		// no-op. On subsequent restarts, counters resume from where
		// they left off, modulo at most one snapshot interval's worth
		// of un-flushed events.
		if snap, err := recorder.LoadLastSnapshot(); err != nil {
			// A read failure here usually means a corrupt or
			// version-mismatched DB file. Log loudly but continue —
			// the server can still serve traffic; counts just restart
			// from zero this round.
			logger.Warn("metrics resume: load failed, starting counters at zero", "err", err)
		} else {
			connMetrics.Load(snap)
			logger.Info("metrics resume: loaded snapshot",
				"requests", snap.Requests,
				"direct", snap.Direct,
				"relay", snap.Relay,
				"tcp_relay", snap.TCPRelay,
				"failed", snap.Failed)
		}

		// Write one snapshot immediately so the first post-restart row
		// reflects the seeded state — without this, the next periodic
		// tick is the first row after restart and the gap looks like
		// data loss in time-series queries.
		if err := recorder.WriteSnapshot(); err != nil {
			logger.Warn("metrics: initial snapshot write failed", "err", err)
		}

		go recorder.Run(recorderCtx)
	}

	if turnProvider.Configured() {
		logger.Info("TURN: using coturn",
			"host", turnProvider.Host(),
			"ttl_s", cfg.CoturnTTL,
			"max_active", cfg.TURNMaxActive)
	} else {
		logger.Info("TURN: no TURN server configured — devices must provide their own ICE servers")
	}

	deps := &handler.Deps{
		Devices:           devices,
		Clients:           clients,
		TURN:              turnProvider,
		Limiter:           limiter,
		Pairing:           pairingTable,
		Metrics:           connMetrics,
		Log:               logger,
		Upgrader:          websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }},
		PingInterval:      60 * time.Second,
		PongWait:          300 * time.Second,
		TrustProxyHeaders: cfg.TrustProxyHeaders,
		StatusToken:       cfg.StatusToken,
		Releases:          tracker,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", deps.Status)
	mux.HandleFunc("GET /ws/device/{uid}", func(w http.ResponseWriter, r *http.Request) {
		deps.DeviceWS(w, r, r.PathValue("uid"))
	})
	mux.HandleFunc("GET /ws/client/{uid}", func(w http.ResponseWriter, r *http.Request) {
		deps.ClientWS(w, r, r.PathValue("uid"))
	})
	mux.HandleFunc("GET /ws/pair", deps.PairWS)

	// `curl -sSfL host/install | sh` — short, memorable install URL that
	// 302s to a deployment-chosen install script (typically a raw URL on
	// GitHub serving install.sh). Off by default: empty INSTALL_URL means
	// the route returns 404, so a self-hosted deployment that doesn't
	// ship a CLI doesn't accidentally expose one. The URL is config, not
	// code, because each operator may ship their own fork's binary.
	mux.HandleFunc("GET /install", func(w http.ResponseWriter, r *http.Request) {
		if cfg.InstallURL == "" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, cfg.InstallURL, http.StatusFound)
	})

	mux.Handle("/", handler.Static(cfg.StaticDir, cfg.FrontPagePath))

	srv := &http.Server{
		Addr:    cfg.Bind,
		Handler: requestLogger(logger, mux, cfg.TrustProxyHeaders),
		// No ReadTimeout/WriteTimeout because WebSocket upgrades need
		// long-lived connections. Idle timeout protects against slow
		// HTTP clients on non-WS endpoints.
		IdleTimeout: 120 * time.Second,
	}

	// Release polling. Lifetime tied to recorderCtx like the metrics
	// recorder, so the same SIGINT/SIGTERM stops it. nil Tracker (no
	// VERSION_REPOS) makes Run a no-op and issues no requests.
	go tracker.Run(recorderCtx)

	// Graceful shutdown: SIGINT/SIGTERM → Server.Shutdown with 2s grace,
	// then hard exit.
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-stopChan
		logger.Info("shutting down", "signal", sig.String())
		// Stop the metrics recorder before draining HTTP — it owns its
		// own goroutine and the file handle. Order doesn't strictly
		// matter but stopping it first keeps "last snapshot at clean
		// shutdown" consistent across restarts.
		stopRecorder()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		// Hard exit even if Shutdown is hung on open WS connections.
		// Daemon-style: don't wait for clients to disconnect gracefully.
		os.Exit(0)
	}()

	logger.Info("listening", "addr", cfg.Bind, "static_dir", cfg.StaticDir)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server exited", "err", err)
		os.Exit(1)
	}
}

type config struct {
	Bind              string
	CoturnHost        string
	CoturnSecret      string
	CoturnTTL         int
	TURNMaxActive     int
	LogLevel          slog.Level
	StaticDir         string
	TrustProxyHeaders bool

	// StatusToken, when non-empty, requires a bearer token on /status
	// from anywhere but loopback. Empty leaves it public.
	StatusToken string

	// VersionRepos are the GitHub projects whose latest release is
	// reported to clients, and VersionPollInterval is how often to look.
	// Empty repos means no polling and no outbound requests.
	VersionRepos        []releases.Repo
	VersionPollInterval int

	// MetricsPath, when non-empty, enables the periodic JSONL snapshot of
	// /status counters at MetricsInterval seconds. Empty disables.
	MetricsPath     string
	MetricsInterval int

	// InstallURL, when non-empty, is the redirect target for GET /install.
	// Empty means the route returns 404 — deployments that don't ship a
	// CLI just don't expose an install path. The canonical bitba.ng host
	// sets this in its systemd unit; self-hosters pick their own URL.
	InstallURL string

	// FrontPagePath, when non-empty, points to an HTML snippet that gets
	// spliced into bootstrap.html at the `<!-- FRONT_PAGE -->` marker
	// when serving `/`. Read on every request — operators can edit the
	// snippet without restarting the service. See the package header for
	// the contract the snippet honors.
	FrontPagePath string
}

func loadConfig() config {
	port := envOr("BITBANG_SERVER_PORT", "8082")
	staticDir := envOr("STATIC_DIR", "./web")
	return config{
		Bind:                "0.0.0.0:" + port,
		CoturnHost:          os.Getenv("COTURN_HOST"),
		CoturnSecret:        os.Getenv("COTURN_SECRET"),
		CoturnTTL:           envOrInt("COTURN_TTL", 86400),
		TURNMaxActive:       envOrInt("TURN_MAX_ACTIVE", 0),
		LogLevel:            parseLogLevel(envOr("LOG_LEVEL", "INFO")),
		StaticDir:           staticDir,
		TrustProxyHeaders:   strings.EqualFold(os.Getenv("TRUST_PROXY_HEADERS"), "true"),
		StatusToken:         os.Getenv("STATUS_TOKEN"),
		VersionRepos:        parseVersionRepos(os.Getenv("VERSION_REPOS")),
		VersionPollInterval: envOrInt("VERSION_POLL_INTERVAL", 3600),
		MetricsPath:         os.Getenv("METRICS_PATH"),
		MetricsInterval:     envOrInt("METRICS_INTERVAL", 300),
		InstallURL:          os.Getenv("INSTALL_URL"),
		FrontPagePath:       os.Getenv("FRONT_PAGE_PATH"),
	}
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func envOrInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func parseLogLevel(s string) slog.Level {
	switch strings.ToUpper(s) {
	case "DEBUG":
		return slog.LevelDebug
	case "WARN", "WARNING":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func newLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
}

// requestLogger logs HTTP requests at DEBUG level. WebSocket upgrades log
// once and the handler takes over from there.
//
// When trustProxyHeaders is set, X-Real-IP takes precedence over
// r.RemoteAddr so the logged remote matches what the handlers see (and
// what's stamped on browser_ip). X-Forwarded-For is deliberately not
// consulted — see handler.clientIP for rationale.
func requestLogger(log *slog.Logger, next http.Handler, trustProxyHeaders bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remote := r.RemoteAddr
		if trustProxyHeaders {
			if real := r.Header.Get("X-Real-IP"); real != "" {
				remote = strings.TrimSpace(real)
			}
		}
		log.Debug("http", "method", r.Method, "path", r.URL.Path, "remote", remote)
		next.ServeHTTP(w, r)
	})
}

// parseVersionRepos reads VERSION_REPOS: comma-separated owner/repo=key
// pairs, e.g. "richlegrand/bitbang-cli=cli,richlegrand/Octoprint-BitBang=octoprint".
//
// The key is separate from the repo name because they differ, and
// because the key is what goes on the wire -- clients look themselves up
// by it, so it has to survive a repo being renamed.
//
// A malformed entry is skipped rather than fatal: one typo should cost
// one product's update notice, not the server's ability to start.
func parseVersionRepos(s string) []releases.Repo {
	var out []releases.Repo
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		repo, key, ok := strings.Cut(part, "=")
		repo, key = strings.TrimSpace(repo), strings.TrimSpace(key)
		if !ok || repo == "" || key == "" {
			continue
		}
		out = append(out, releases.Repo{Repo: repo, Key: key})
	}
	return out
}
