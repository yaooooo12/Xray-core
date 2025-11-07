package trojan

import (
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// Validator stores valid trojan users.
type Validator struct {
	// Considering email's usage here, map + sync.Mutex/RWMutex may have better performance.
	email sync.Map
	users sync.Map
	// Track active connection counts per user email
	activeConnections sync.Map // email -> int32 (connection count)
}

// Add a trojan user, Email must be empty or unique.
func (v *Validator) Add(u *protocol.MemoryUser) error {
	if u.Email != "" {
		_, loaded := v.email.LoadOrStore(strings.ToLower(u.Email), u)
		if loaded {
			return errors.New("User ", u.Email, " already exists.")
		}
	}
	v.users.Store(hexString(u.Account.(*MemoryAccount).Key), u)
	return nil
}

// Del a trojan user with a non-empty Email.
func (v *Validator) Del(e string) error {
	if e == "" {
		return errors.New("Email must not be empty.")
	}
	le := strings.ToLower(e)
	u, _ := v.email.Load(le)
	if u == nil {
		return errors.New("User ", e, " not found.")
	}
	v.email.Delete(le)
	v.users.Delete(hexString(u.(*protocol.MemoryUser).Account.(*MemoryAccount).Key))
	return nil
}

// Get a trojan user with hashed key, nil if user doesn't exist.
func (v *Validator) Get(hash string) *protocol.MemoryUser {
	u, _ := v.users.Load(hash)
	if u != nil {
		return u.(*protocol.MemoryUser)
	}
	return nil
}

// Get a trojan user with hashed key, nil if user doesn't exist.
func (v *Validator) GetByEmail(email string) *protocol.MemoryUser {
	email = strings.ToLower(email)
	u, _ := v.email.Load(email)
	if u != nil {
		return u.(*protocol.MemoryUser)
	}
	return nil
}

// Get all users
func (v *Validator) GetAll() []*protocol.MemoryUser {
	var u = make([]*protocol.MemoryUser, 0, 100)
	v.email.Range(func(key, value interface{}) bool {
		u = append(u, value.(*protocol.MemoryUser))
		return true
	})
	return u
}

// Get users count
func (v *Validator) GetCount() int64 {
	var c int64 = 0
	v.email.Range(func(key, value interface{}) bool {
		c++
		return true
	})
	return c
}

// IncrementConnection increments the active connection count for a user.
// Returns true if the connection can be accepted (within limit), false otherwise.
func (v *Validator) IncrementConnection(email string, maxConnections int32) bool {
	if email == "" {
		// If no email, allow connection (no way to track)
		return true
	}

	if maxConnections <= 0 {
		// No limit set (0 or negative means unlimited)
		return true
	}

	email = strings.ToLower(email)

	for {
		// Load current count
		val, _ := v.activeConnections.LoadOrStore(email, int32(0))
		currentCount := val.(int32)

		// Check if limit would be exceeded
		if currentCount >= maxConnections {
			return false
		}

		// Try to increment atomically
		if v.activeConnections.CompareAndSwap(email, currentCount, currentCount+1) {
			return true
		}
		// If CAS failed, retry the loop
	}
}

// DecrementConnection decrements the active connection count for a user.
func (v *Validator) DecrementConnection(email string) {
	if email == "" {
		return
	}

	email = strings.ToLower(email)

	for {
		val, loaded := v.activeConnections.Load(email)
		if !loaded {
			// No entry exists, nothing to decrement
			return
		}

		currentCount := val.(int32)
		if currentCount <= 0 {
			// Already at 0, nothing to decrement
			return
		}

		// Try to decrement atomically
		if v.activeConnections.CompareAndSwap(email, currentCount, currentCount-1) {
			return
		}
		// If CAS failed, retry the loop
	}
}

// GetActiveConnections returns the current active connection count for a user.
func (v *Validator) GetActiveConnections(email string) int32 {
	if email == "" {
		return 0
	}

	email = strings.ToLower(email)
	val, loaded := v.activeConnections.Load(email)
	if !loaded {
		return 0
	}
	return val.(int32)
}
