package session

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	defaultStateTableName = "session_state"
)

// Status of the session's state
type Status string

const (
	StatusPending    Status = "pending"
	StatusActive     Status = "active"
	StatusCanceling  Status = "canceling"
	StatusTerminated Status = "terminated"
)

// String representation of the state's status
func (s Status) String() string {
	return string(s)
}

// State of the session
type State struct {
	// SessionId references the session public id
	SessionId string `json:"session_id,omitempty" gorm:"primary_key"`
	// status of the session
	Status string `json:"status,omitempty" gorm:"column:state"`
	// PreviousEndTime from the RDBMS
	PreviousEndTime *timestamp.Timestamp `json:"previous_end_time,omitempty" gorm:"default:current_timestamp"`
	// StartTime from the RDBMS
	StartTime *timestamp.Timestamp `json:"start_time,omitempty" gorm:"default:current_timestamp;primary_key"`
	// EndTime from the RDBMS
	EndTime *timestamp.Timestamp `json:"end_time,omitempty" gorm:"default:current_timestamp"`

	tableName string `gorm:"-"`
}

var _ Cloneable = (*State)(nil)
var _ db.VetForWriter = (*State)(nil)

// NewState creates a new in memory session state.  No options
// are currently supported.
func NewState(session_id string, state Status, opt ...Option) (*State, error) {
	s := State{
		SessionId: session_id,
		Status:    state.String(),
	}

	if err := s.validate("new session state:"); err != nil {
		return nil, err
	}
	return &s, nil
}

// allocState will allocate a State
func allocState() State {
	return State{}
}

// Clone creates a clone of the State
func (s *State) Clone() interface{} {
	clone := &State{
		SessionId: s.SessionId,
		Status:    s.Status,
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
func (s *State) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if err := s.validate("session state vet for write:"); err != nil {
		return err
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (s *State) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return defaultStateTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (s *State) SetTableName(n string) {
	s.tableName = n
}

// validate checks the session state
func (s *State) validate(errorPrefix string) error {
	if s.Status == "" {
		return fmt.Errorf("%s missing status: %w", errorPrefix, db.ErrInvalidParameter)
	}
	if s.SessionId == "" {
		return fmt.Errorf("%s missing session id: %w", errorPrefix, db.ErrInvalidParameter)
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
