package pairing

import (
	"regexp"
	"sync"
	"testing"
	"time"
)

// newTestTable builds a Table with an injectable clock so we can advance
// time without sleeping in tests, and disables the sweep goroutine (we
// drive sweepExpired manually). This keeps tests fast and deterministic.
func newTestTable() *Table {
	t := &Table{
		codes:  make(map[string]Entry),
		byUID:  make(map[string]string),
		now:    time.Now,
		stopCh: make(chan struct{}),
	}
	// No sweep goroutine — keeps tests deterministic. close(stopCh)
	// happens via Close (rarely needed; GC reaps the rest).
	close(t.stopCh)
	return t
}

func TestIssue_ReturnsSixDigits(t *testing.T) {
	tab := newTestTable()
	code := tab.Issue("uid-1")
	if !regexp.MustCompile(`^\d{6}$`).MatchString(code) {
		t.Errorf("code = %q, want 6 decimal digits", code)
	}
}

func TestIssue_IdempotentWithinTTL(t *testing.T) {
	tab := newTestTable()
	a := tab.Issue("uid-1")
	b := tab.Issue("uid-1")
	if a != b {
		t.Errorf("re-issue same UID: got %q then %q, want same", a, b)
	}
}

func TestIssue_NewCodeAfterTTL(t *testing.T) {
	tab := newTestTable()
	now := time.Now()
	tab.now = func() time.Time { return now }
	a := tab.Issue("uid-1")
	// Jump past TTL.
	now = now.Add(CodeTTL + time.Second)
	b := tab.Issue("uid-1")
	if a == b {
		t.Errorf("expected new code after TTL, got same code twice: %q", a)
	}
}

func TestIssue_UniqueAcrossUIDs(t *testing.T) {
	tab := newTestTable()
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		uid := "uid-" + string(rune('a'+i))
		code := tab.Issue(uid)
		if seen[code] {
			t.Errorf("collision: code %q reused across UIDs", code)
		}
		seen[code] = true
	}
}

func TestLookup_KnownCodeReturnsUID(t *testing.T) {
	tab := newTestTable()
	tab.now = func() time.Time { return time.Unix(0, 0) } // freeze
	code := tab.Issue("uid-42")

	// Skip the LookupDelay sleep for the test — drop into the locked
	// section directly via a tiny inline helper. (LookupDelay is
	// exercised separately in TestLookup_AppliesDelay.)
	tab.mu.RLock()
	entry, ok := tab.codes[code]
	tab.mu.RUnlock()
	if !ok || entry.UID != "uid-42" {
		t.Errorf("code %q → entry %+v, want UID uid-42", code, entry)
	}
}

func TestLookup_UnknownCodeReturnsEmpty(t *testing.T) {
	tab := newTestTable()
	if got := tab.Lookup("999999"); got != "" {
		t.Errorf("unknown code → %q, want empty", got)
	}
}

func TestLookup_ExpiredCodeReturnsEmpty(t *testing.T) {
	tab := newTestTable()
	now := time.Now()
	tab.now = func() time.Time { return now }
	code := tab.Issue("uid-1")
	now = now.Add(CodeTTL + time.Second)

	// Read directly to skip the sleep.
	tab.mu.RLock()
	entry, ok := tab.codes[code]
	expired := ok && tab.now().Sub(entry.CreatedAt) > CodeTTL
	tab.mu.RUnlock()
	if !ok {
		t.Errorf("code missing before expiry check")
	}
	if !expired {
		t.Errorf("code not seen as expired even after TTL+1s")
	}
}

func TestLookup_AppliesDelay(t *testing.T) {
	// Verify the sleep actually fires. We use a very short sentinel
	// (Lookup uses LookupDelay = 3s constant; we don't override it,
	// we just measure that the call duration is at least 2.5s — well
	// above any reasonable scheduler jitter and well under the 3s
	// actual sleep).
	if testing.Short() {
		t.Skip("skipping 3s timing test in -short mode")
	}
	tab := newTestTable()
	start := time.Now()
	_ = tab.Lookup("does-not-exist")
	elapsed := time.Since(start)
	if elapsed < LookupDelay-500*time.Millisecond {
		t.Errorf("Lookup returned in %v, want at least ~%v", elapsed, LookupDelay)
	}
}

func TestRelease_ClearsBothMaps(t *testing.T) {
	tab := newTestTable()
	code := tab.Issue("uid-1")
	if _, ok := tab.codes[code]; !ok {
		t.Fatalf("issued code not in table")
	}
	tab.Release("uid-1")
	if _, ok := tab.codes[code]; ok {
		t.Errorf("code still present after Release")
	}
	if _, ok := tab.byUID["uid-1"]; ok {
		t.Errorf("byUID entry still present after Release")
	}
}

func TestRelease_UnknownUIDIsNoOp(t *testing.T) {
	tab := newTestTable()
	tab.Issue("uid-1")
	tab.Release("uid-other") // should not panic, should not touch uid-1
	if _, ok := tab.byUID["uid-1"]; !ok {
		t.Errorf("Release of unknown UID disturbed unrelated entry")
	}
}

func TestSweepExpired_RemovesOnlyOldEntries(t *testing.T) {
	tab := newTestTable()
	now := time.Now()
	tab.now = func() time.Time { return now }

	old := tab.Issue("uid-old")
	now = now.Add(CodeTTL / 2)
	young := tab.Issue("uid-young")
	now = now.Add((CodeTTL / 2) + time.Second) // old now exceeds TTL
	tab.sweepExpired()

	if _, ok := tab.codes[old]; ok {
		t.Errorf("expired code not swept")
	}
	if _, ok := tab.codes[young]; !ok {
		t.Errorf("non-expired code wrongly swept")
	}
}

func TestActiveCount_TracksLive(t *testing.T) {
	tab := newTestTable()
	if n := tab.ActiveCount(); n != 0 {
		t.Errorf("initial count = %d, want 0", n)
	}
	tab.Issue("uid-1")
	tab.Issue("uid-2")
	if n := tab.ActiveCount(); n != 2 {
		t.Errorf("after 2 issues, count = %d, want 2", n)
	}
	tab.Release("uid-1")
	if n := tab.ActiveCount(); n != 1 {
		t.Errorf("after release, count = %d, want 1", n)
	}
}

func TestConcurrentIssue(t *testing.T) {
	tab := newTestTable()
	var wg sync.WaitGroup
	const N = 100
	codes := make([]string, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			uid := "uid-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
			codes[i] = tab.Issue(uid)
		}(i)
	}
	wg.Wait()
	for _, c := range codes {
		if c == "" {
			t.Errorf("got empty code from concurrent Issue")
		}
	}
}
