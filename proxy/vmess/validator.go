package vmess

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash/crc64"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vmess/aead"
)

// TimedUserValidator is a user Validator based on time.
type TimedUserValidator struct {
	sync.RWMutex
	users []*protocol.MemoryUser

	behaviorSeed  uint64
	behaviorFused bool

	aeadDecoderHolder *aead.AuthIDDecoderHolder

	// Track active connection counts per user email
	activeConnections sync.Map // email -> int32 (connection count)
}

// NewTimedUserValidator creates a new TimedUserValidator.
func NewTimedUserValidator() *TimedUserValidator {
	tuv := &TimedUserValidator{
		users:             make([]*protocol.MemoryUser, 0, 16),
		aeadDecoderHolder: aead.NewAuthIDDecoderHolder(),
	}
	return tuv
}

func (v *TimedUserValidator) Add(u *protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()

	v.users = append(v.users, u)

	account, ok := u.Account.(*MemoryAccount)
	if !ok {
		return errors.New("account type is incorrect")
	}
	if !v.behaviorFused {
		hashkdf := hmac.New(sha256.New, []byte("VMESSBSKDF"))
		hashkdf.Write(account.ID.Bytes())
		v.behaviorSeed = crc64.Update(v.behaviorSeed, crc64.MakeTable(crc64.ECMA), hashkdf.Sum(nil))
	}

	var cmdkeyfl [16]byte
	copy(cmdkeyfl[:], account.ID.CmdKey())
	v.aeadDecoderHolder.AddUser(cmdkeyfl, u)

	return nil
}

func (v *TimedUserValidator) GetUsers() []*protocol.MemoryUser {
	v.Lock()
	defer v.Unlock()
	dst := make([]*protocol.MemoryUser, len(v.users))
	copy(dst, v.users)
	return dst
}

func (v *TimedUserValidator) GetCount() int64 {
	v.Lock()
	defer v.Unlock()
	return int64(len(v.users))
}

func (v *TimedUserValidator) GetAEAD(userHash []byte) (*protocol.MemoryUser, bool, error) {
	v.RLock()
	defer v.RUnlock()

	var userHashFL [16]byte
	copy(userHashFL[:], userHash)

	userd, err := v.aeadDecoderHolder.Match(userHashFL)
	if err != nil {
		return nil, false, err
	}
	return userd.(*protocol.MemoryUser), true, nil
}

func (v *TimedUserValidator) Remove(email string) bool {
	v.Lock()
	defer v.Unlock()

	email = strings.ToLower(email)
	idx := -1
	for i, u := range v.users {
		if strings.EqualFold(u.Email, email) {
			idx = i
			var cmdkeyfl [16]byte
			copy(cmdkeyfl[:], u.Account.(*MemoryAccount).ID.CmdKey())
			v.aeadDecoderHolder.RemoveUser(cmdkeyfl)
			break
		}
	}
	if idx == -1 {
		return false
	}
	ulen := len(v.users)

	v.users[idx] = v.users[ulen-1]
	v.users[ulen-1] = nil
	v.users = v.users[:ulen-1]

	return true
}

func (v *TimedUserValidator) GetBehaviorSeed() uint64 {
	v.Lock()
	defer v.Unlock()

	v.behaviorFused = true
	if v.behaviorSeed == 0 {
		v.behaviorSeed = dice.RollUint64()
	}
	return v.behaviorSeed
}

var ErrNotFound = errors.New("Not Found")

var ErrTainted = errors.New("ErrTainted")

// IncrementConnection increments the active connection count for a user.
// Returns true if the connection can be accepted (within limit), false otherwise.
func (v *TimedUserValidator) IncrementConnection(email string, maxConnections int32) bool {
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
func (v *TimedUserValidator) DecrementConnection(email string) {
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
func (v *TimedUserValidator) GetActiveConnections(email string) int32 {
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
