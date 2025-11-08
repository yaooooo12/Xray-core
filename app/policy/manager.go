package policy

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/conntrack"
	"github.com/xtls/xray-core/features/policy"
)

// Instance is an instance of Policy manager.
type Instance struct {
	levels  map[uint32]*Policy
	system  *SystemPolicy
	tracker *conntrack.Tracker
}

// New creates new Policy manager instance.
func New(ctx context.Context, config *Config) (*Instance, error) {
	m := &Instance{
		levels:  make(map[uint32]*Policy),
		system:  config.System,
		tracker: conntrack.NewTracker(),
	}
	if len(config.Level) > 0 {
		for lv, p := range config.Level {
			pp := defaultPolicy()
			pp.overrideWith(p)
			m.levels[lv] = pp
		}
	}

	return m, nil
}

// Type implements common.HasType.
func (*Instance) Type() interface{} {
	return policy.ManagerType()
}

// ForLevel implements policy.Manager.
func (m *Instance) ForLevel(level uint32) policy.Session {
	if p, ok := m.levels[level]; ok {
		return p.ToCorePolicy()
	}
	return policy.SessionDefault()
}

// ForSystem implements policy.Manager.
func (m *Instance) ForSystem() policy.System {
	if m.system == nil {
		return policy.System{}
	}
	return m.system.ToCorePolicy()
}

// Start implements common.Runnable.Start().
func (m *Instance) Start() error {
	return nil
}

// Close implements common.Closable.Close().
func (m *Instance) Close() error {
	return nil
}

// IncrementConnection increments the connection count for a user.
// Returns true if the connection is allowed, false if the limit is reached.
func (m *Instance) IncrementConnection(userEmail string, maxConnections int32) bool {
	return m.tracker.Increment(userEmail, maxConnections)
}

// DecrementConnection decrements the connection count for a user.
func (m *Instance) DecrementConnection(userEmail string) {
	m.tracker.Decrement(userEmail)
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}
