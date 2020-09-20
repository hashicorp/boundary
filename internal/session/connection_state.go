package session

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"google.golang.org/protobuf/types/known/timestamppb"

	workerpbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
)

const (
	defaultConnectionStateTableName = "session_connection_state"
)

// ConnectionStatus of the connection's state
type ConnectionStatus string

const (
	StatusAuthorized ConnectionStatus = "authorized"
	StatusConnected  ConnectionStatus = "connected"
	StatusClosed     ConnectionStatus = "closed"
)

// String representation of the state's status
func (s ConnectionStatus) String() string {
	return string(s)
}

// ProtoVal returns the enum value corresponding to the state
func (s ConnectionStatus) ProtoVal() workerpbs.CONNECTIONSTATUS {
	switch s {
	case StatusAuthorized:
		return workerpbs.CONNECTIONSTATUS_CONNECTIONSTATUS_AUTHORIZED
	case StatusConnected:
		return workerpbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED
	case StatusClosed:
		return workerpbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED
	}
	return workerpbs.CONNECTIONSTATUS_CONNECTIONSTATUS_UNSPECIFIED
}

// ConnectionState of the state of the connection
type ConnectionState struct {
	// ConnectionId is used to access the state via an API
	ConnectionId string `json:"public_id,omitempty" gorm:"primary_key"`
	// status of the connection
	Status ConnectionStatus `protobuf:"bytes,20,opt,name=status,proto3" json:"status,omitempty" gorm:"column:state"`
	// PreviousEndTime from the RDBMS
	PreviousEndTime *timestamp.Timestamp `json:"previous_end_time,omitempty" gorm:"default:current_timestamp"`
	// StartTime from the RDBMS
	StartTime *timestamp.Timestamp `json:"start_time,omitempty" gorm:"default:current_timestamp;primary_key"`
	// EndTime from the RDBMS
	EndTime *timestamp.Timestamp `json:"end_time,omitempty" gorm:"default:current_timestamp"`

	tableName string `gorm:"-"`
}

var _ Cloneable = (*ConnectionState)(nil)
var _ db.VetForWriter = (*ConnectionState)(nil)

// NewConnectionState creates a new in memory connection state.  No options
// are currently supported.
func NewConnectionState(connectionId string, state ConnectionStatus, opt ...Option) (*ConnectionState, error) {
	s := ConnectionState{
		ConnectionId: connectionId,
		Status:       state,
	}
	if err := s.validate("new connection state:"); err != nil {
		return nil, err
	}
	return &s, nil
}

// allocConnectionState will allocate a connection State
func allocConnectionState() ConnectionState {
	return ConnectionState{}
}

// Clone creates a clone of the State
func (s *ConnectionState) Clone() interface{} {
	clone := &ConnectionState{
		ConnectionId: s.ConnectionId,
		Status:       s.Status,
	}
	if s.PreviousEndTime != nil {
		clone.PreviousEndTime = &timestamp.Timestamp{
			Timestamp: &timestamppb.Timestamp{
				Seconds: s.PreviousEndTime.Timestamp.Seconds,
				Nanos:   s.PreviousEndTime.Timestamp.Nanos,
			},
		}
	}

	if s.StartTime != nil {
		clone.StartTime = &timestamp.Timestamp{
			Timestamp: &timestamppb.Timestamp{
				Seconds: s.StartTime.Timestamp.Seconds,
				Nanos:   s.StartTime.Timestamp.Nanos,
			},
		}
	}
	if s.EndTime != nil {
		clone.EndTime = &timestamp.Timestamp{
			Timestamp: &timestamppb.Timestamp{
				Seconds: s.EndTime.Timestamp.Seconds,
				Nanos:   s.EndTime.Timestamp.Nanos,
			},
		}
	}
	return clone
}

// VetForWrite implements db.VetForWrite() interface and validates the state
// before it's written.
func (s *ConnectionState) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if err := s.validate("connection state vet for write:"); err != nil {
		return err
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (s *ConnectionState) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return defaultConnectionStateTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (s *ConnectionState) SetTableName(n string) {
	s.tableName = n
}

// validate checks the session state
func (s *ConnectionState) validate(errorPrefix string) error {
	if s.Status == "" {
		return fmt.Errorf("%s missing status: %w", errorPrefix, db.ErrInvalidParameter)
	}
	if s.ConnectionId == "" {
		return fmt.Errorf("%s missing connection id: %w", errorPrefix, db.ErrInvalidParameter)
	}
	if s.StartTime != nil {
		return fmt.Errorf("%s start time is not settable: %w", errorPrefix, db.ErrInvalidParameter)
	}
	if s.EndTime != nil {
		return fmt.Errorf("%s end time is not settable: %w", errorPrefix, db.ErrInvalidParameter)
	}
	if s.PreviousEndTime != nil {
		return fmt.Errorf("%s previous end time is not settable: %w", errorPrefix, db.ErrInvalidParameter)
	}
	return nil
}
