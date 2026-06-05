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
//	TRUST_PROXY_HEADERS  When "true", honor X-Real-IP/X-Forwarded-For for
//	                     browser-IP capture. Enable only behind a proxy
//	                     that strips these headers from inbound requests.
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
	"bitbang-server-go/internal/pairing"
	"bitbang-server-go/internal/ratelimit"
	"bitbang-server-go/internal/registry"
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
		Log:               logger,
		Upgrader:          websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }},
		PingInterval:      60 * time.Second,
		PongWait:          300 * time.Second,
		TrustProxyHeaders: cfg.TrustProxyHeaders,
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
	mux.Handle("/", handler.Static(cfg.StaticDir))

	srv := &http.Server{
		Addr:    cfg.Bind,
		Handler: requestLogger(logger, mux, cfg.TrustProxyHeaders),
		// No ReadTimeout/WriteTimeout because WebSocket upgrades need
		// long-lived connections. Idle timeout protects against slow
		// HTTP clients on non-WS endpoints.
		IdleTimeout: 120 * time.Second,
	}

	// Graceful shutdown: SIGINT/SIGTERM → Server.Shutdown with 2s grace,
	// then hard exit. Matches Python signaling.py behavior.
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-stopChan
		logger.Info("shutting down", "signal", sig.String())
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
}

func loadConfig() config {
	port := envOr("BITBANG_SERVER_PORT", "8082")
	staticDir := envOr("STATIC_DIR", "./web")
	return config{
		Bind:              "0.0.0.0:" + port,
		CoturnHost:        os.Getenv("COTURN_HOST"),
		CoturnSecret:      os.Getenv("COTURN_SECRET"),
		CoturnTTL:         envOrInt("COTURN_TTL", 86400),
		TURNMaxActive:     envOrInt("TURN_MAX_ACTIVE", 0),
		LogLevel:          parseLogLevel(envOr("LOG_LEVEL", "INFO")),
		StaticDir:         staticDir,
		TrustProxyHeaders: strings.EqualFold(os.Getenv("TRUST_PROXY_HEADERS"), "true"),
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
