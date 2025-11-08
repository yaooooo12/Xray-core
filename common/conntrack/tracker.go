package conntrack

import (
	"sync"
)

// Tracker tracks concurrent connections per user
type Tracker struct {
	mu          sync.RWMutex
	connections map[string]int32
}

// NewTracker creates a new connection tracker
func NewTracker() *Tracker {
	return &Tracker{
		connections: make(map[string]int32),
	}
}

// Increment attempts to increment the connection count for a user.
// Returns true if the connection is allowed, false if the limit is reached.
// A maxConnections value of 0 means unlimited.
func (t *Tracker) Increment(userEmail string, maxConnections int32) bool {
	if maxConnections <= 0 {
		// No limit
		return true
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	current := t.connections[userEmail]
	if current >= maxConnections {
		return false
	}

	t.connections[userEmail] = current + 1
	return true
}

// Decrement decrements the connection count for a user
func (t *Tracker) Decrement(userEmail string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if count, exists := t.connections[userEmail]; exists {
		if count <= 1 {
			delete(t.connections, userEmail)
		} else {
			t.connections[userEmail] = count - 1
		}
	}
}

// GetCount returns the current connection count for a user
func (t *Tracker) GetCount(userEmail string) int32 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.connections[userEmail]
}
