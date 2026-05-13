package registry

import "sync"

// DeviceRegistry stores live device connections and supports atomic
// preemption (replacing an existing connection with a new one).
//
// In v1 this is in-memory only. For multi-server scale, swap in a
// Redis-backed implementation behind the same interface — handler code
// doesn't change.
type DeviceRegistry interface {
	// Add stores conn at uid. If an existing connection had this UID,
	// the old conn is returned so the caller can preempt it. Returns
	// nil if the slot was empty.
	Add(uid string, conn *DeviceConn) (preempted *DeviceConn)
	// Remove deletes uid only if the currently-stored conn matches.
	// Prevents a stale defer/finally from kicking out a fresh successor.
	Remove(uid string, conn *DeviceConn)
	// Get returns the current connection for uid, if any.
	Get(uid string) (*DeviceConn, bool)
	// Count returns the number of registered devices.
	Count() int
}

// MemoryRegistry is the in-memory DeviceRegistry implementation.
type MemoryRegistry struct {
	mu    sync.RWMutex
	conns map[string]*DeviceConn
}

func NewMemoryRegistry() *MemoryRegistry {
	return &MemoryRegistry{conns: make(map[string]*DeviceConn)}
}

func (r *MemoryRegistry) Add(uid string, conn *DeviceConn) *DeviceConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	old := r.conns[uid]
	r.conns[uid] = conn
	return old
}

func (r *MemoryRegistry) Remove(uid string, conn *DeviceConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conns[uid] == conn {
		delete(r.conns, uid)
	}
}

func (r *MemoryRegistry) Get(uid string) (*DeviceConn, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.conns[uid]
	return c, ok
}

func (r *MemoryRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.conns)
}

// ClientRegistry holds live client connections keyed by client_id.
// Clients aren't preempted (they're 1:1 with a WS), but we need iteration
// to boot all clients of a preempted device.
type ClientRegistry struct {
	mu      sync.RWMutex
	clients map[string]*ClientConn
}

func NewClientRegistry() *ClientRegistry {
	return &ClientRegistry{clients: make(map[string]*ClientConn)}
}

func (r *ClientRegistry) Add(c *ClientConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clients[c.ClientID] = c
}

func (r *ClientRegistry) Remove(clientID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.clients, clientID)
}

func (r *ClientRegistry) Get(clientID string) (*ClientConn, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.clients[clientID]
	return c, ok
}

func (r *ClientRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.clients)
}

// ForTarget returns a snapshot of all clients whose TargetUID matches uid.
// Snapshot semantics let callers iterate without holding the lock — safe
// for the preemption sweep which closes connections.
func (r *ClientRegistry) ForTarget(uid string) []*ClientConn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*ClientConn
	for _, c := range r.clients {
		if c.TargetUID == uid {
			out = append(out, c)
		}
	}
	return out
}
