package session

import "github.com/hashicorp/boundary/internal/errors"

const (
	defaultSessionHostSetHostTableName = "session_host_set_host"
)

// SessionHostSetHost contains information about a user's session with a target that has a host source association.
type SessionHostSetHost struct {
	// SessionId of the session
	SessionId string `json:"session_id,omitempty" gorm:"primary_key"`
	// HostSetId of the session
	HostSetId string `json:"host_set_id,omitempty" gorm:"default:null"`
	// HostId of the session
	HostId string `json:"host_id,omitempty" gorm:"default:null"`

	tableName string `gorm:"-"`
}

func NewSessionHostSetHost(sessionId, hostSetId, hostId string) (*SessionHostSetHost, error) {
	const op = "session.NewSessionHostSetHost"
	if sessionId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing session id")
	}
	if hostSetId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing host set id")
	}
	if hostId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing host id")
	}
	shs := &SessionHostSetHost{
		SessionId: sessionId,
		HostSetId: hostSetId,
		HostId:    hostId,
	}
	return shs, nil
}

// TableName returns the tablename to override the default gorm table name
func (s *SessionHostSetHost) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return defaultSessionHostSetHostTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (s *SessionHostSetHost) SetTableName(n string) {
	s.tableName = n
}

// AllocSessionHostSet will allocate a SessionHostSetHost
func AllocSessionHostSetHost() *SessionHostSetHost {
	return &SessionHostSetHost{}
}

// Clone creates a clone of the SessionHostSetHost
func (s *SessionHostSetHost) Clone() any {
	clone := &SessionHostSetHost{
		SessionId: s.SessionId,
		HostSetId: s.HostSetId,
		HostId:    s.HostId,
	}
	return clone
}
