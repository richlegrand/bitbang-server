// Package pairing implements the code-exchange table that lets a listener
// be addressable by a short 6-digit number for a short time, rather than
// by its 22-char UID.
//
// Lifecycle of a code:
//
//  1. Listener registers with want_code=true → server calls Issue(uid) and
//     returns the assigned 6-digit code in the Registered reply.
//  2. Connector sends pair_init with the code → server calls Lookup(code),
//     which sleeps 3 seconds (constant-time response, intentional brake
//     on enumeration) then returns the UID or "" if absent/expired.
//  3. Listener disconnects (or hits the 5-minute TTL) → Release(uid) drops
//     the entry so the code is reusable.
//
// The 3-second lookup delay is the per-connection brake. A per-IP rate
// limit at the WebSocket-upgrade layer is a separate concern handled by
// the existing handler.Deps.Limiter.
package pairing

import (
	"crypto/rand"
	"math/big"
	"sync"
	"time"
)

const (
	// CodeLength is the number of digits in an issued code. 6 = 1-in-1M
	// collision space, which comfortably absorbs tens of thousands of
	// concurrent codes without practical collision risk.
	CodeLength = 6

	// CodeTTL is how long an issued code stays valid before being swept.
	// Long enough for a human to share verbally + the connector to act;
	// short enough that the live table stays small.
	CodeTTL = 5 * time.Minute

	// LookupDelay is the intentional sleep on every Lookup, regardless of
	// outcome. Constant-time response prevents timing-based enumeration
	// from telling an attacker which codes exist.
	LookupDelay = 3 * time.Second

	// sweepInterval is how often the background goroutine evicts expired
	// entries. Doesn't affect correctness — Lookup re-checks TTL — but
	// caps the size of the live table when codes go un-lookup'd.
	sweepInterval = 1 * time.Minute
)

// Entry is a live code-to-UID binding.
type Entry struct {
	UID       string
	CreatedAt time.Time
}

// Table holds the active code-to-UID bindings. Safe for concurrent use.
type Table struct {
	mu    sync.RWMutex
	codes map[string]Entry  // code → entry
	byUID map[string]string // uid → code (reverse index for O(1) Release)
	now   func() time.Time  // injectable for tests

	stopCh chan struct{}
	stopWG sync.WaitGroup
}

// NewTable returns a Table with the background sweep goroutine running.
// Call Close when the table is no longer needed to stop the goroutine.
func NewTable() *Table {
	t := &Table{
		codes:  make(map[string]Entry),
		byUID:  make(map[string]string),
		now:    time.Now,
		stopCh: make(chan struct{}),
	}
	t.stopWG.Add(1)
	go t.sweepLoop()
	return t
}

// Close stops the background sweep goroutine. Safe to call once.
func (t *Table) Close() {
	close(t.stopCh)
	t.stopWG.Wait()
}

// Issue returns a 6-digit code for the given UID. If the UID already has a
// live code (re-register, same UID), the existing code is returned — the
// operation is idempotent within the TTL window. Otherwise a fresh
// collision-free code is generated.
func (t *Table) Issue(uid string) string {
	t.mu.Lock()
	defer t.mu.Unlock()

	if existing, ok := t.byUID[uid]; ok {
		if entry, alive := t.codes[existing]; alive && t.now().Sub(entry.CreatedAt) < CodeTTL {
			return existing
		}
		// Stale — clean up before issuing a fresh one.
		delete(t.codes, existing)
		delete(t.byUID, uid)
	}

	for {
		code := randomDigits(CodeLength)
		if _, exists := t.codes[code]; !exists {
			t.codes[code] = Entry{UID: uid, CreatedAt: t.now()}
			t.byUID[uid] = code
			return code
		}
		// Vanishingly unlikely with 10⁶ space and tens of thousands of
		// entries, but the loop terminates on the first miss.
	}
}

// Lookup returns the UID bound to code, or "" if the code is unknown or
// expired. The call always sleeps for LookupDelay before returning, so
// known and unknown codes are indistinguishable in timing.
func (t *Table) Lookup(code string) string {
	time.Sleep(LookupDelay)

	t.mu.RLock()
	defer t.mu.RUnlock()

	entry, ok := t.codes[code]
	if !ok {
		return ""
	}
	if t.now().Sub(entry.CreatedAt) > CodeTTL {
		return ""
	}
	return entry.UID
}

// Release drops the binding for uid if one exists. Called when the
// listener's WebSocket disconnects so the code becomes available again
// without waiting for TTL.
func (t *Table) Release(uid string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if code, ok := t.byUID[uid]; ok {
		delete(t.codes, code)
		delete(t.byUID, uid)
	}
}

// ActiveCount returns the number of live (non-expired) entries. Used by
// the status endpoint for operational visibility.
func (t *Table) ActiveCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.codes)
}

// sweepLoop evicts expired entries periodically. Without this, codes that
// expire without ever being looked up would accumulate forever (Lookup's
// TTL check only fires on access).
func (t *Table) sweepLoop() {
	defer t.stopWG.Done()
	tick := time.NewTicker(sweepInterval)
	defer tick.Stop()
	for {
		select {
		case <-t.stopCh:
			return
		case <-tick.C:
			t.sweepExpired()
		}
	}
}

func (t *Table) sweepExpired() {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	for code, entry := range t.codes {
		if now.Sub(entry.CreatedAt) > CodeTTL {
			delete(t.codes, code)
			delete(t.byUID, entry.UID)
		}
	}
}

// randomDigits returns an n-digit decimal string from crypto/rand. Using
// crypto/rand (not math/rand) so an attacker who knows the codes-so-far
// can't predict the next one.
func randomDigits(n int) string {
	buf := make([]byte, n)
	max := big.NewInt(10)
	for i := range buf {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			// crypto/rand reading the system source can't fail in
			// practice. If it ever does, panic — keeping operating
			// after rand failure would be worse than crashing.
			panic("pairing: crypto/rand.Int failed: " + err.Error())
		}
		buf[i] = '0' + byte(v.Int64())
	}
	return string(buf)
}
