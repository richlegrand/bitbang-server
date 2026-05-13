// Package ratelimit defines the seam for future hardening work.
//
// v1: no-op (Allow always returns true). v1.1 will swap in a
// token-bucket-per-IP implementation backed by golang.org/x/time/rate.
// v2 will swap that for a Redis-backed limiter for multi-server.
//
// Handler code calls limiter.Allow(key) at the right spots regardless of
// which implementation is wired in.
package ratelimit

// RateLimiter decides whether an action keyed by some string (typically an
// IP address or UID) is currently permitted.
type RateLimiter interface {
	Allow(key string) bool
}

// NoOp is a RateLimiter that allows everything.
type NoOp struct{}

func (NoOp) Allow(string) bool { return true }

// Compile-time check
var _ RateLimiter = NoOp{}
